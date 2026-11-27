const std = @import("std");
const Router = @import("router");

const Cli = Router.Debug.Cli;
const CsvParser = ICMPv4Fixtures.CsvParser;
const DestinationUnreachable = Router.Protocols.ICMPv4Messages.DestinationUnreachable;
const Echo = Router.Protocols.ICMPv4Messages.Echo;
const Ethernet = Router.Protocols.Ethernet;
const Format = Router.Meta.Format;
const ICMPv4Fixtures = Router.TestFixtures.ICMPv4;
const IFace = Router.Nic.Api.IFace;
const IPv4 = Router.Protocols.IPv4.IPv4;
const IPv4PacketView = Router.Protocols.IPv4.IPv4PacketView;
const IPv4Protocol = Router.Protocols.IPv4;
const NicApi = Router.Nic.Api.Api;
const PcapParser = Router.TestFixtures.PcapParser;
const TimeExceeded = Router.Protocols.ICMPv4Messages.TimeExceeded;
const View = Router.Meta.View.View;
const ViewStack = Router.Protocols.ViewStack;

const checksumContribution = Router.Meta.Checksum.checksumContribution;
const classifyDestination = Router.Protocols.IPv4.classifyDestination;
const forward = Router.Protocols.IPv4.forward;
const parseQuoted = Router.Protocols.IPv4.parseQuoted;
const updateChecksum = Router.Meta.Checksum.update;

const nat_table = &Router.State.nat_table;
const wan_lease = &Router.State.wan_lease;

pub const MessageType = enum(u8) {
    echo_reply = 0,
    destination_unreachable = 3,
    echo_request = 8,
    time_exceeded = 11,
    _,
};

pub const ICMPv4Packet = struct {
    message_type: MessageType,
    code: u8,
    checksum: u16,
    payload: []u8,
};

pub const ICMPv4PacketView = View(ICMPv4Packet);

const QuotedTransportView = View(struct {
    src_port: u16,
    dst_port: u16,
    checksum: ?u16,
});

pub fn validate(view: ICMPv4PacketView) !void {
    if (view.get(.checksum) == 0) return;
    var checksum = view.checksum();
    checksum.addFields(.message_type, .payload);
    try checksum.validate();
}

pub fn parse(buffer: []const u8) !ICMPv4PacketView {
    var view: ICMPv4PacketView = undefined;
    var reader: std.Io.Reader = .fixed(buffer);
    try view.takeFields(.message_type, .checksum, &reader);
    try view.takeBytes(.payload, reader.bufferedLen(), &reader);
    try validate(view);
    return view;
}

pub fn handle(
    buffer: []u8,
    device: NicApi,
    iface: IFace,
    views: *ViewStack,
) !void {
    var view = try parse(views.getView(.ipv4).get(.payload));
    Cli.enter(.icmpv4, view);
    views.setView(.icmpv4, &view);
    const message_type = view.get(.message_type);
    switch (message_type) {
        .echo_reply, .echo_request => {
            try Echo.handle(buffer, device, iface, views);
        },
        .destination_unreachable => {
            try DestinationUnreachable.handle(buffer, device, iface, views);
        },
        .time_exceeded => {
            try TimeExceeded.handle(buffer, device, iface, views);
        },
        else => {
            std.debug.print(
                "ICMPv4: packet with type: {f} unhandled by {s} interface\n",
                .{ Format.enumLabel(message_type), @tagName(iface) },
            );
            device.release(buffer);
        },
    }
}

pub fn forwardQuotedError(
    buffer: []u8,
    device: NicApi,
    iface: IFace,
    views: *ViewStack,
    quoted_packet: []u8,
) !void {
    const outer = views.getView(.ipv4);
    if (outer.get(.ttl) <= 1) return device.release(buffer);

    const lease = wan_lease.* orelse return device.release(buffer);
    const icmp = views.getView(.icmpv4);

    var quote = try parseQuoted(quoted_packet);
    const payload = quote.get(.payload);
    const protocol = quote.get(.protocol);

    if (quote.get(.fragment_offset) != 0 or payload.len < 8)
        return device.release(buffer);

    const checksum_offset: usize = switch (protocol) {
        .tcp => 16,
        .udp => 6,
        else => return device.release(buffer),
    };

    var transport: QuotedTransportView = undefined;
    var reader: std.Io.Reader = .fixed(payload);
    try transport.takeFields(.src_port, .dst_port, &reader);
    if (payload.len >= checksum_offset + 2) {
        try reader.discardAll(checksum_offset - 4);
        try transport.takeField(.checksum, &reader);
    } else {
        transport.set(.checksum, null);
    }

    const egress, const next_hop = switch (iface) {
        .wan => wan: {
            if (!outer.fieldCmp(.dst, .{ .eq = lease.ip }) or
                !quote.fieldCmp(.src, .{ .eq = lease.ip }))
                return device.release(buffer);

            const client_ip, const client_port = nat_table.inboundLookup(.{
                .protocol = protocol,
                .ip = quote.get(.src),
                .port = transport.get(.src_port),
            }) orelse return device.release(buffer);

            rewriteQuotedEndpoint(&quote, &transport, .src, client_ip, client_port);
            outer.setUpdateChecksum(.dst, client_ip, views);
            break :wan .{ IFace.lan, client_ip };
        },
        .lan => lan: {
            const remote_ip = outer.get(.dst);
            if (classifyDestination(remote_ip) != .wan or
                !quote.fieldCmp(.src, .{ .eq = remote_ip }))
                return device.release(buffer);

            const public_ip, const public_port = nat_table.outboundLookup(.{
                .protocol = protocol,
                .ip = quote.get(.dst),
                .port = transport.get(.dst_port),
            }, lease.ip) orelse return device.release(buffer);

            rewriteQuotedEndpoint(&quote, &transport, .dst, public_ip, public_port);
            outer.setUpdateChecksum(.src, public_ip, views);
            break :lan .{ IFace.wan, lease.router };
        },
    };

    icmp.set(.checksum, 0);
    var checksum = icmp.checksum();
    checksum.addFields(.message_type, .payload);
    icmp.set(.checksum, checksum.finish());

    return forward(buffer, device, egress, next_hop, views);
}

fn rewriteQuotedEndpoint(
    quote: *IPv4PacketView,
    transport: *QuotedTransportView,
    comptime field: IPv4PacketView.Field,
    ip: IPv4,
    port: u16,
) void {
    const old_ip = quote.get(field);
    const old_ip_sum = checksumContribution(&old_ip);
    const new_ip_sum = checksumContribution(&ip);

    const port_field: QuotedTransportView.Field = if (field == .src) .src_port else .dst_port;
    const old_port = transport.get(port_field);

    quote.set(field, ip);
    quote.set(.header_checksum, updateChecksum(
        quote.get(.header_checksum),
        old_ip_sum,
        new_ip_sum,
        2,
    ));
    transport.set(port_field, port);

    const is_udp = quote.get(.protocol) == .udp;
    const old_checksum = transport.get(.checksum) orelse return;
    if (is_udp and old_checksum == 0) return;

    const updated = updateChecksum(
        old_checksum,
        old_ip_sum + old_port,
        new_ip_sum + port,
        3,
    );
    transport.set(.checksum, if (is_udp and updated == 0) 0xffff else updated);
}

const test_packet = [_]u8{ 0x08, 0x00, 0x21, 0x68, 0x12, 0x34, 0x00, 0x01, 0x61, 0x62, 0x63 };

test "parse() reads ICMPv4 fields from wire bytes" {
    const view = try parse(&test_packet);
    try std.testing.expectEqual(MessageType.echo_request, view.get(.message_type));
    try std.testing.expectEqual(@as(u8, 0), view.get(.code));
    try std.testing.expectEqual(@as(u16, 0x2168), view.get(.checksum));
    try std.testing.expectEqualSlices(u8, test_packet[4..], view.get(.payload));
}

test "parse() reads an empty payload" {
    const packet = [_]u8{ 0x08, 0x00, 0xf7, 0xff };
    const view = try parse(&packet);
    try std.testing.expectEqual(@as(usize, 0), view.get(.payload).len);
}

test "parse() rejects truncated headers" {
    for (0..4) |len| {
        try std.testing.expectError(error.EndOfStream, parse(test_packet[0..len]));
    }
}

test "parse() rejects invalid checksums" {
    var packet = test_packet;
    packet[8] = 'z';
    try std.testing.expectError(error.BadChecksum, parse(&packet));
}

test "parse() on wireshark captured frames matches wireshark's parsed output" {
    const pcap_file = ICMPv4Fixtures.pcap_file;
    const csv_file = ICMPv4Fixtures.csv_file;

    var parsed_pcap = try PcapParser.parse(pcap_file, std.testing.allocator);
    defer parsed_pcap.deinit(std.testing.allocator);
    const parsed_packets = try CsvParser.parse(csv_file, std.testing.allocator);
    defer std.testing.allocator.free(parsed_packets);

    try std.testing.expectEqual(parsed_packets.len, parsed_pcap.packet_bytes.len);
    for (parsed_packets, 0..) |ws_packet, i| {
        const frame = try Ethernet.parse(parsed_pcap.packet_bytes[i]);
        try std.testing.expectEqual(Ethernet.Ethertype.ipv4, frame.get(.ethertype));
        const ip_view = try IPv4Protocol.parse(frame.get(.payload));
        try std.testing.expectEqual(IPv4Protocol.Protocol.icmp, ip_view.get(.protocol));
        const view = try parse(ip_view.get(.payload));
        try std.testing.expect(view.isEqualIgnoringSlices(&ws_packet));
    }
}

test "parse() then serialize() returns the original bytes" {
    const pcap_file = ICMPv4Fixtures.pcap_file;

    var parsed_pcap = try PcapParser.parse(pcap_file, std.testing.allocator);
    defer parsed_pcap.deinit(std.testing.allocator);

    for (parsed_pcap.packet_bytes) |packet| {
        const frame = try Ethernet.parse(packet);
        try std.testing.expectEqual(Ethernet.Ethertype.ipv4, frame.get(.ethertype));
        const ip_view = try IPv4Protocol.parse(frame.get(.payload));
        try std.testing.expectEqual(IPv4Protocol.Protocol.icmp, ip_view.get(.protocol));
        const icmp_bytes = ip_view.get(.payload);
        var view = try parse(icmp_bytes);
        const buffer = try std.testing.allocator.alloc(u8, icmp_bytes.len);
        defer std.testing.allocator.free(buffer);
        var writer: std.Io.Writer = .fixed(buffer);

        try ICMPv4PacketView.serialize(view.copy(), &writer);
        try std.testing.expectEqual(icmp_bytes.len, writer.end);
        try std.testing.expectEqualSlices(u8, icmp_bytes, buffer);
    }
}
