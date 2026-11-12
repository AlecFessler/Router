const std = @import("std");
const Router = @import("router");

const Cli = Router.Debug.Cli;
const IFace = Router.Nic.Api.IFace;
const IPv4 = Router.Protocols.IPv4.IPv4;
const IPv4PacketView = Router.Protocols.IPv4.IPv4PacketView;
const NicApi = Router.Nic.Api.Api;
const View = Router.Meta.View.View;

pub const TypeField = enum(u8) {
    echo_reply = 0,
    destination_unreachable = 3,
    redirect = 5,
    echo_request = 8,
    time_exceeded = 11,
    parameter_problem = 12,
    _,
};

pub const ICMPv4Packet = struct {
    type_field: TypeField,
    code: u8,
    checksum: u16,
    payload: []u8,
};

pub const ICMPv4PacketView = View(ICMPv4Packet);

pub fn validate(view: ICMPv4PacketView) !void {
    if (view.get(.checksum) == 0) return;
    var checksum = view.checksum();
    checksum.addFields(.type_field, .payload);
    try checksum.validate();
}

pub fn parse(buffer: []const u8) !ICMPv4PacketView {
    var view: ICMPv4PacketView = undefined;
    var reader: std.Io.Reader = .fixed(buffer);
    try view.takeFields(.type_field, .checksum, &reader);
    try view.takeBytes(.payload, reader.bufferedLen(), &reader);
    try validate(view);
    return view;
}

pub fn handle(
    buffer: []u8, // the full ethernet frame
    packet: []u8, // the ipv4 payload
    device: NicApi,
    iface: IFace,
) !void {
    const view = try parse(packet);
    Cli.enter(.icmpv4, view);
    const type_field = view.get(.type_field);
    switch (type_field) {
        else => {
            const name = std.enums.tagName(TypeField, type_field);
            if (name) |tag| {
                std.debug.print(
                    "ICMPv4: packet with type: {s} unhandled by {s} interface\n",
                    .{ tag, @tagName(iface) },
                );
            } else {
                std.debug.print(
                    "ICMPv4: packet with type: {} unhandled by {s} interface\n",
                    .{ @intFromEnum(type_field), @tagName(iface) },
                );
            }
            device.release(buffer);
        },
    }
}

const test_packet = [_]u8{ 0x08, 0x00, 0x21, 0x68, 0x12, 0x34, 0x00, 0x01, 0x61, 0x62, 0x63 };

test "parse() reads ICMPv4 fields from wire bytes" {
    const view = try parse(&test_packet);
    try std.testing.expectEqual(TypeField.echo_request, view.get(.type_field));
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
    const PcapParser = Router.TestFixtures.PcapParser;
    const CsvParser = Router.TestFixtures.ICMPv4.CsvParser;
    const pcap_file = Router.TestFixtures.ICMPv4.pcap_file;
    const csv_file = Router.TestFixtures.ICMPv4.csv_file;

    var parsed_pcap = try PcapParser.parse(pcap_file, std.testing.allocator);
    defer parsed_pcap.deinit(std.testing.allocator);
    const parsed_packets = try CsvParser.parse(csv_file, std.testing.allocator);
    defer std.testing.allocator.free(parsed_packets);

    try std.testing.expectEqual(parsed_packets.len, parsed_pcap.packet_bytes.len);
    for (parsed_packets, 0..) |ws_packet, i| {
        const frame = try Router.Protocols.Ethernet.parse(parsed_pcap.packet_bytes[i]);
        try std.testing.expectEqual(Router.Protocols.Ethernet.Ethertype.ipv4, frame.get(.ethertype));
        const ip_view = try Router.Protocols.IPv4.parse(frame.get(.payload));
        try std.testing.expectEqual(Router.Protocols.IPv4.Protocol.icmp, ip_view.get(.protocol));
        const view = try parse(ip_view.get(.payload));
        try std.testing.expect(view.isEqualIgnoringSlices(&ws_packet));
    }
}

test "parse() then serialize() returns the original bytes" {
    const PcapParser = Router.TestFixtures.PcapParser;
    const pcap_file = Router.TestFixtures.ICMPv4.pcap_file;

    var parsed_pcap = try PcapParser.parse(pcap_file, std.testing.allocator);
    defer parsed_pcap.deinit(std.testing.allocator);

    for (parsed_pcap.packet_bytes) |packet| {
        const frame = try Router.Protocols.Ethernet.parse(packet);
        try std.testing.expectEqual(Router.Protocols.Ethernet.Ethertype.ipv4, frame.get(.ethertype));
        const ip_view = try Router.Protocols.IPv4.parse(frame.get(.payload));
        try std.testing.expectEqual(Router.Protocols.IPv4.Protocol.icmp, ip_view.get(.protocol));
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
