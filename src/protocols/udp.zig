const std = @import("std");
const Router = @import("router");

const Cli = Router.Debug.Cli;
const IFace = Router.Nic.Api.IFace;
const IPv4 = Router.Protocols.IPv4.IPv4;
const IPv4PacketView = Router.Protocols.IPv4.IPv4PacketView;
const NicApi = Router.Nic.Api.Api;
const View = Router.Meta.View.View;

pub const UdpPacket = struct {
    src_port: u16,
    dst_port: u16,
    length: u16,
    checksum: u16,
    payload: []u8,
};

pub const UdpPacketView = View(UdpPacket);

pub fn validate(view: UdpPacketView, ip_view: IPv4PacketView) !void {
    try view.validate(.length, .{ .gte = 4 });
    if (view.get(.checksum) == 0) return;
    var checksum = view.checksum();
    try checksum.addPseudoheader(ip_view);
    checksum.addFields(.src_port, .payload);
    try checksum.validate();
}

pub fn parse(buffer: []const u8, ip_view: IPv4PacketView) !UdpPacketView {
    var view: UdpPacketView = undefined;
    var reader: std.Io.Reader = .fixed(buffer);
    try view.takeFields(.src_port, .checksum, &reader);
    const payload_len = view.get(.length) - 8;
    try view.takeBytes(.payload, payload_len, &reader);
    try validate(view, ip_view);
    return view;
}

pub fn handle(
    buffer: []u8, // the full ethernet frame
    packet: []u8, // the ipv4 payload
    device: NicApi,
    iface: IFace,
    ip_view: IPv4PacketView,
) !void {
    const view = try parse(packet, ip_view);
    Cli.enter(.udp, view);
    const dst_port = view.get(.dst_port);
    switch (dst_port) {
        // in general, check if the router is the recipient ip, if not,
        // forward the packet, if yes, check if the router has a service
        // that listens on that port (such as dns or dhcp)
        else => {
            std.debug.print(
                "UDP: packet with dst port: {} unhandled by {s} interface\n",
                .{ dst_port, @tagName(iface) },
            );
            device.release(buffer);
        },
    }
}

const test_ip_packet = [_]u8{
    0x45, 0x00, 0x00, 0x20, 0x12, 0x34, 0x40, 0x00,
    0x40, 0x11, 0xa5, 0x45, 0xc0, 0xa8, 0x01, 0x01,
    0xc0, 0xa8, 0x01, 0x02, 0x04, 0xd2, 0x00, 0x35,
    0x00, 0x0c, 0xb2, 0xb4, 0x61, 0x62, 0x63, 0x64,
};

test "parse() reads UDP fields from wire bytes" {
    const ip_view = try Router.Protocols.IPv4.parse(&test_ip_packet);
    const view = try parse(ip_view.get(.payload), ip_view);

    try std.testing.expectEqual(@as(u16, 1234), view.get(.src_port));
    try std.testing.expectEqual(@as(u16, 53), view.get(.dst_port));
    try std.testing.expectEqual(@as(u16, 12), view.get(.length));
    try std.testing.expectEqual(@as(u16, 0xb2b4), view.get(.checksum));
    try std.testing.expectEqualSlices(u8, "abcd", view.get(.payload));
}

test "parse() rejects truncated packets and accepts trailing bytes" {
    const ip_view = try Router.Protocols.IPv4.parse(&test_ip_packet);
    const udp_bytes = ip_view.get(.payload);

    for (0..udp_bytes.len) |len| {
        try std.testing.expectError(error.EndOfStream, parse(udp_bytes[0..len], ip_view));
    }

    const with_trailing_byte = test_ip_packet ++ [_]u8{0xff};
    const view = try parse(with_trailing_byte[20..], ip_view);
    try std.testing.expectEqualSlices(u8, "abcd", view.get(.payload));
}

test "parse() accepts a zero checksum" {
    var packet = test_ip_packet;
    packet[26] = 0;
    packet[27] = 0;
    const ip_view = try Router.Protocols.IPv4.parse(&packet);
    const view = try parse(ip_view.get(.payload), ip_view);
    try std.testing.expectEqual(@as(u16, 0), view.get(.checksum));
}

test "parse() reads an empty payload" {
    var packet = test_ip_packet;
    packet[3] = 0x1c;
    packet[11] = 0x49;
    packet[24] = 0;
    packet[25] = 8;
    packet[26] = 0;
    packet[27] = 0;
    const ip_view = try Router.Protocols.IPv4.parse(&packet);
    const view = try parse(ip_view.get(.payload), ip_view);
    try std.testing.expectEqual(@as(u16, 8), view.get(.length));
    try std.testing.expectEqual(@as(usize, 0), view.get(.payload).len);
}

test "parse() rejects invalid checksums" {
    var packet = test_ip_packet;
    packet[28] = 'z';
    const ip_view = try Router.Protocols.IPv4.parse(&packet);
    try std.testing.expectError(error.BadChecksum, parse(ip_view.get(.payload), ip_view));
}

test "parse() on wireshark captured frames matches wireshark's parsed output" {
    const PcapParser = Router.TestFixtures.PcapParser;
    const CsvParser = Router.TestFixtures.Udp.CsvParser;
    const pcap_file = Router.TestFixtures.Udp.pcap_file;
    const csv_file = Router.TestFixtures.Udp.csv_file;

    var parsed_pcap = try PcapParser.parse(pcap_file, std.testing.allocator);
    defer parsed_pcap.deinit(std.testing.allocator);
    const parsed_packets = try CsvParser.parse(csv_file, std.testing.allocator);
    defer std.testing.allocator.free(parsed_packets);

    try std.testing.expectEqual(parsed_packets.len, parsed_pcap.packet_bytes.len);
    for (parsed_packets, 0..) |ws_packet, i| {
        const frame = try Router.Protocols.Ethernet.parse(parsed_pcap.packet_bytes[i]);
        if (frame.get(.ethertype) != .ipv4) continue;
        const ip_view = try Router.Protocols.IPv4.parse(frame.get(.payload));
        try std.testing.expectEqual(Router.Protocols.IPv4.Protocol.udp, ip_view.get(.protocol));
        const view = try parse(ip_view.get(.payload), ip_view);
        try std.testing.expect(view.isEqualIgnoringSlices(&ws_packet));
    }
}

test "parse() then serialize() returns the original bytes" {
    const PcapParser = Router.TestFixtures.PcapParser;
    const pcap_file = Router.TestFixtures.Udp.pcap_file;

    var parsed_pcap = try PcapParser.parse(pcap_file, std.testing.allocator);
    defer parsed_pcap.deinit(std.testing.allocator);

    for (parsed_pcap.packet_bytes) |packet| {
        const frame = try Router.Protocols.Ethernet.parse(packet);
        if (frame.get(.ethertype) != .ipv4) continue;
        const ip_view = try Router.Protocols.IPv4.parse(frame.get(.payload));
        try std.testing.expectEqual(Router.Protocols.IPv4.Protocol.udp, ip_view.get(.protocol));
        const udp_bytes = ip_view.get(.payload);
        var view = try parse(udp_bytes, ip_view);
        const parsed_len = view.get(.length);
        const buffer = try std.testing.allocator.alloc(u8, parsed_len);
        defer std.testing.allocator.free(buffer);
        var writer: std.Io.Writer = .fixed(buffer);

        try UdpPacketView.serialize(view.copy(), &writer);
        try std.testing.expectEqual(parsed_len, writer.end);
        try std.testing.expectEqualSlices(u8, udp_bytes[0..parsed_len], buffer);
    }
}
