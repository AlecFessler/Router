const std = @import("std");
const Router = @import("router");

const Cli = Router.Debug.Cli;
const CsvParser = TcpFixtures.CsvParser;
const Ethernet = Router.Protocols.Ethernet;
const EthernetFrameView = Router.Protocols.Ethernet.EthernetFrameView;
const IFace = Router.Nic.Api.IFace;
const IPv4PacketView = Router.Protocols.IPv4.IPv4PacketView;
const IPv4Protocol = Router.Protocols.IPv4;
const NatTable = Router.Tables.NatTable.NatTable;
const NicApi = Router.Nic.Api.Api;
const PcapParser = Router.TestFixtures.PcapParser;
const PortAllocator = Router.Tables.NatTable.PortAllocator;
const TcpFixtures = Router.TestFixtures.Tcp;
const View = Router.Meta.View.View;
const ViewStack = Router.Protocols.ViewStack;

const classifyDestination = Router.Protocols.IPv4.classifyDestination;
const queueForArpResolution = Router.Protocols.Arp.queueForArpResolution;

const lan_arp_table = &Router.State.lan_arp_table;
const lan_ip = &Router.State.lan_ip;
const nat_table = &Router.State.nat_table;
const wan_lease = &Router.State.wan_lease;
const wan_arp_table = &Router.State.wan_arp_table;

const NAT_TIMEOUT = std.Io.Duration.fromSeconds(7440);

var port_allocator: PortAllocator = .{};

pub const TcpPacket = struct {
    src_port: u16,
    dst_port: u16,
    seq_number: u32,
    ack_number: u32,
    data_offset: u4,
    reserved: u3,
    ae: bool, // accurate ECN
    cwr: bool, // congestion window reduced
    ece: bool, // If SYN: ECN capability; otherwise: echoes experienced congestion from received IP packet
    urg: bool, // urgent ptr is significant
    ack: bool, // ack number is significant
    psh: bool, // push function
    rst: bool, // reset the connection
    syn: bool, // synchronize sequence numbers
    fin: bool, // last packet from sender
    window: u16,
    checksum: u16,
    urgent_ptr: u16,
    options: []u8,
    payload: []u8,
};

pub const TcpPacketView = View(TcpPacket);

pub fn validate(view: TcpPacketView, ip_view: IPv4PacketView) !void {
    var checksum = view.checksum();
    try checksum.addPseudoheader(ip_view);
    checksum.addFields(.src_port, .payload);
    try checksum.validate();
}

pub fn parse(buffer: []const u8, ip_view: IPv4PacketView) !TcpPacketView {
    var view: TcpPacketView = undefined;
    var reader: std.Io.Reader = .fixed(buffer);
    try view.takeFields(.src_port, .urgent_ptr, &reader);

    try view.validate(.data_offset, .{ .gte = 5 });
    const header_bytes = @as(usize, view.get(.data_offset)) * 4;
    const options_bytes = header_bytes - 20;
    try view.takeBytes(.options, options_bytes, &reader);
    try view.takeBytes(.payload, reader.bufferedLen(), &reader);

    try validate(view, ip_view);
    return view;
}

pub fn handle(
    buffer: []u8,
    device: NicApi,
    iface: IFace,
    views: *ViewStack,
) !void {
    const ethernet_view = views.getView(.ethernet);
    const ip_view = views.getView(.ipv4);
    var view = try parse(ip_view.get(.payload), ip_view.*);
    Cli.enter(.tcp, view);
    views.setView(.tcp, &view);

    const ttl = ip_view.get(.ttl);
    if (ttl <= 1) {
        device.release(buffer);
        return;
    }

    const lease = wan_lease.* orelse {
        device.release(buffer);
        return;
    };

    switch (iface) {
        .lan => {
            const dst = ip_view.get(.dst);
            if (classifyDestination(dst) != .wan) {
                device.release(buffer);
                return;
            }

            const key: NatTable.Key = .{
                .protocol = .tcp,
                .ip = ip_view.get(.src),
                .port = view.get(.src_port),
            };

            const src_ip, const src_port = if (nat_table.outboundLookup(key, lease.ip)) |existing| hit: {
                try nat_table.refresh(key, NAT_TIMEOUT);
                break :hit existing;
            } else miss: {
                const entry = try nat_table.insert(
                    &port_allocator,
                    key,
                    lease.ip,
                    NAT_TIMEOUT,
                );
                break :miss .{
                    entry.outside.ip,
                    entry.outside.port,
                };
            };

            ip_view.setUpdateChecksum(.src, src_ip, views);
            view.setUpdateChecksum(.src_port, src_port, views);
            ip_view.setUpdateChecksum(.ttl, ttl - 1, views);

            ethernet_view.set(.src_mac, device.macAddress(.wan));
            const gateway_mac = wan_arp_table.lookup(lease.router) orelse
                return queueForArpResolution(
                    buffer,
                    device,
                    .{ .iface = .wan, .ip = lease.router },
                );
            ethernet_view.set(.dst_mac, gateway_mac);

            device.transmit(buffer);
        },
        .wan => {
            if (!ip_view.fieldCmp(.dst, .{ .eq = lease.ip })) {
                device.release(buffer);
                return;
            }

            const dst_ip, const dst_port = nat_table.inboundLookup(.{
                .ip = ip_view.get(.dst),
                .port = view.get(.dst_port),
                .protocol = .tcp,
            }) orelse {
                device.release(buffer);
                return;
            };

            ip_view.setUpdateChecksum(.dst, dst_ip, views);
            view.setUpdateChecksum(.dst_port, dst_port, views);
            ip_view.setUpdateChecksum(.ttl, ttl - 1, views);

            ethernet_view.set(.src_mac, device.macAddress(.lan));
            const dst_mac = lan_arp_table.lookup(dst_ip) orelse
                return queueForArpResolution(
                    buffer,
                    device,
                    .{ .iface = .lan, .ip = dst_ip },
                );
            ethernet_view.set(.dst_mac, dst_mac);

            device.transmit(buffer);
        },
    }
}

const test_ip_packet = [_]u8{
    0x45, 0x00, 0x00, 0x2c, 0x12, 0x34, 0x40, 0x00,
    0x40, 0x06, 0xa5, 0x44, 0xc0, 0xa8, 0x01, 0x01,
    0xc0, 0xa8, 0x01, 0x02, 0x04, 0xd2, 0x01, 0xbb,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x50, 0x18, 0x10, 0x00, 0x3f, 0xcc, 0x00, 0x00,
    0x61, 0x62, 0x63, 0x64,
};

const test_ip_packet_with_options = [_]u8{
    0x45, 0x00, 0x00, 0x30, 0x12, 0x34, 0x40, 0x00,
    0x40, 0x06, 0xa5, 0x40, 0xc0, 0xa8, 0x01, 0x01,
    0xc0, 0xa8, 0x01, 0x02, 0x04, 0xd2, 0x01, 0xbb,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x60, 0x18, 0x10, 0x00, 0x2d, 0xc6, 0x00, 0x00,
    0x01, 0x01, 0x01, 0x01, 0x61, 0x62, 0x63, 0x64,
};

test "parse() reads TCP fields from wire bytes" {
    const ip_view = try IPv4Protocol.parse(&test_ip_packet);
    const view = try parse(ip_view.get(.payload), ip_view);

    try std.testing.expectEqual(@as(u16, 1234), view.get(.src_port));
    try std.testing.expectEqual(@as(u16, 443), view.get(.dst_port));
    try std.testing.expectEqual(@as(u32, 0x11223344), view.get(.seq_number));
    try std.testing.expectEqual(@as(u32, 0x55667788), view.get(.ack_number));
    try std.testing.expectEqual(@as(u4, 5), view.get(.data_offset));
    try std.testing.expectEqual(@as(u3, 0), view.get(.reserved));
    try std.testing.expect(!view.get(.ae));
    try std.testing.expect(!view.get(.cwr));
    try std.testing.expect(!view.get(.ece));
    try std.testing.expect(!view.get(.urg));
    try std.testing.expect(view.get(.ack));
    try std.testing.expect(view.get(.psh));
    try std.testing.expect(!view.get(.rst));
    try std.testing.expect(!view.get(.syn));
    try std.testing.expect(!view.get(.fin));
    try std.testing.expectEqual(@as(u16, 4096), view.get(.window));
    try std.testing.expectEqual(@as(u16, 0x3fcc), view.get(.checksum));
    try std.testing.expectEqual(@as(u16, 0), view.get(.urgent_ptr));
    try std.testing.expectEqual(@as(usize, 0), view.get(.options).len);
    try std.testing.expectEqualSlices(u8, "abcd", view.get(.payload));
}

test "parse() rejects truncated headers" {
    const ip_view = try IPv4Protocol.parse(&test_ip_packet);
    const tcp_bytes = ip_view.get(.payload);

    for (0..20) |len| {
        try std.testing.expectError(error.EndOfStream, parse(tcp_bytes[0..len], ip_view));
    }
}

test "parse() reads TCP options according to the data offset" {
    const ip_view = try IPv4Protocol.parse(&test_ip_packet_with_options);
    const view = try parse(ip_view.get(.payload), ip_view);
    try std.testing.expectEqual(@as(u4, 6), view.get(.data_offset));
    try std.testing.expectEqualSlices(u8, &.{ 1, 1, 1, 1 }, view.get(.options));
    try std.testing.expectEqualSlices(u8, "abcd", view.get(.payload));
    try std.testing.expectError(error.EndOfStream, parse(ip_view.get(.payload)[0..23], ip_view));
}

test "parse() rejects invalid data offsets" {
    var packet = test_ip_packet;
    packet[32] = 0x40;
    const ip_view = try IPv4Protocol.parse(&packet);
    try std.testing.expectError(error.InvalidField, parse(ip_view.get(.payload), ip_view));
}

test "parse() rejects invalid checksums" {
    var packet = test_ip_packet;
    packet[40] = 'z';
    const ip_view = try IPv4Protocol.parse(&packet);
    try std.testing.expectError(error.BadChecksum, parse(ip_view.get(.payload), ip_view));
}

test "parse() on wireshark captured frames matches wireshark's parsed output" {
    const pcap_file = TcpFixtures.pcap_file;
    const csv_file = TcpFixtures.csv_file;

    var parsed_pcap = try PcapParser.parse(pcap_file, std.testing.allocator);
    defer parsed_pcap.deinit(std.testing.allocator);
    const parsed_packets = try CsvParser.parse(csv_file, std.testing.allocator);
    defer std.testing.allocator.free(parsed_packets);

    try std.testing.expectEqual(parsed_packets.len, parsed_pcap.packet_bytes.len);
    for (parsed_packets, 0..) |ws_packet, i| {
        const frame = try Ethernet.parse(parsed_pcap.packet_bytes[i]);
        try std.testing.expectEqual(Ethernet.Ethertype.ipv4, frame.get(.ethertype));
        const ip_view = try IPv4Protocol.parse(frame.get(.payload));
        try std.testing.expectEqual(IPv4Protocol.Protocol.tcp, ip_view.get(.protocol));
        const view = try parse(ip_view.get(.payload), ip_view);
        try std.testing.expect(view.isEqualIgnoringSlices(&ws_packet));
    }
}

test "parse() then serialize() returns the original bytes" {
    const pcap_file = TcpFixtures.pcap_file;

    var parsed_pcap = try PcapParser.parse(pcap_file, std.testing.allocator);
    defer parsed_pcap.deinit(std.testing.allocator);

    for (parsed_pcap.packet_bytes) |packet| {
        const frame = try Ethernet.parse(packet);
        try std.testing.expectEqual(Ethernet.Ethertype.ipv4, frame.get(.ethertype));
        const ip_view = try IPv4Protocol.parse(frame.get(.payload));
        try std.testing.expectEqual(IPv4Protocol.Protocol.tcp, ip_view.get(.protocol));
        const tcp_bytes = ip_view.get(.payload);
        var view = try parse(tcp_bytes, ip_view);
        const buffer = try std.testing.allocator.alloc(u8, tcp_bytes.len);
        defer std.testing.allocator.free(buffer);
        var writer: std.Io.Writer = .fixed(buffer);

        try TcpPacketView.serialize(view.copy(), &writer);
        try std.testing.expectEqual(tcp_bytes.len, writer.end);
        try std.testing.expectEqualSlices(u8, tcp_bytes, buffer);
    }
}
