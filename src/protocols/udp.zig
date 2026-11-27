const std = @import("std");
const Router = @import("router");

const Cli = Router.Debug.Cli;
const CsvParser = UdpFixtures.CsvParser;
const DHCPv4 = Router.Protocols.DHCPv4;
const Ethernet = Router.Protocols.Ethernet;
const IFace = Router.Nic.Api.IFace;
const IPv4PacketView = Router.Protocols.IPv4.IPv4PacketView;
const IPv4Protocol = Router.Protocols.IPv4;
const NicApi = Router.Nic.Api.Api;
const PcapParser = Router.TestFixtures.PcapParser;
const PortAllocator = Router.Tables.NatTable.PortAllocator;
const UdpFixtures = Router.TestFixtures.Udp;
const View = Router.Meta.View.View;
const ViewStack = Router.Protocols.ViewStack;

const forwardNat = Router.Protocols.IPv4.forwardNat;

const UDP_NAT_TIMEOUT = std.Io.Duration.fromSeconds(300);

var port_allocator: PortAllocator = .{};

pub const UdpPacket = struct {
    src_port: u16,
    dst_port: u16,
    length: u16,
    checksum: u16,
    payload: []u8,
};

pub const UdpPacketView = View(UdpPacket);

pub fn validate(view: UdpPacketView, ip_view: IPv4PacketView) !void {
    if (ip_view.get(.more_fragments) or view.get(.checksum) == 0) return;

    var checksum = view.checksum();
    try checksum.addPseudoheaderLength(ip_view, view.get(.length));
    checksum.addFields(.src_port, .payload);
    try checksum.validate();
}

pub fn parse(buffer: []const u8, ip_view: IPv4PacketView) !UdpPacketView {
    var view: UdpPacketView = undefined;
    var reader: std.Io.Reader = .fixed(buffer);
    try view.takeFields(.src_port, .checksum, &reader);
    try view.validate(.length, .{ .gte = 8 });

    const payload_len = if (ip_view.get(.more_fragments))
        reader.bufferedLen()
    else
        @as(usize, view.get(.length)) - 8;
    try view.takeBytes(.payload, payload_len, &reader);

    try validate(view, ip_view);
    return view;
}

pub fn handle(
    buffer: []u8,
    device: NicApi,
    iface: IFace,
    views: *ViewStack,
) !void {
    const ip_view = views.getView(.ipv4);
    const first_fragment = ip_view.get(.more_fragments);
    var view = try parse(ip_view.get(.payload), ip_view.*);
    Cli.enter(.udp, view);
    views.setView(.udp, &view);

    const src_port = view.get(.src_port);
    const dst_port = view.get(.dst_port);
    const is_dhcp = switch (iface) {
        .lan => src_port == 68 and dst_port == 67,
        .wan => src_port == 67 and dst_port == 68,
    };
    if (is_dhcp) {
        if (first_fragment) return error.NeedsReassembly;
        return DHCPv4.handle(buffer, device, iface, views);
    }

    return forwardNat(
        buffer,
        device,
        iface,
        views,
        &view,
        .{ .lan = .src_port, .wan = .dst_port },
        &port_allocator,
        UDP_NAT_TIMEOUT,
    );
}

const test_ip_packet = [_]u8{
    0x45, 0x00, 0x00, 0x20, 0x12, 0x34, 0x40, 0x00,
    0x40, 0x11, 0xa5, 0x45, 0xc0, 0xa8, 0x01, 0x01,
    0xc0, 0xa8, 0x01, 0x02, 0x04, 0xd2, 0x00, 0x35,
    0x00, 0x0c, 0xb2, 0xb4, 0x61, 0x62, 0x63, 0x64,
};

test "parse() reads UDP fields from wire bytes" {
    const ip_view = try IPv4Protocol.parse(&test_ip_packet);
    const view = try parse(ip_view.get(.payload), ip_view);

    try std.testing.expectEqual(@as(u16, 1234), view.get(.src_port));
    try std.testing.expectEqual(@as(u16, 53), view.get(.dst_port));
    try std.testing.expectEqual(@as(u16, 12), view.get(.length));
    try std.testing.expectEqual(@as(u16, 0xb2b4), view.get(.checksum));
    try std.testing.expectEqualSlices(u8, "abcd", view.get(.payload));
}

test "parse() rejects truncated packets and accepts trailing bytes" {
    const ip_view = try IPv4Protocol.parse(&test_ip_packet);
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
    const ip_view = try IPv4Protocol.parse(&packet);
    const view = try parse(ip_view.get(.payload), ip_view);
    try std.testing.expectEqual(@as(u16, 0), view.get(.checksum));
}

test "parse() rejects lengths smaller than the UDP header" {
    var packet = test_ip_packet;
    packet[25] = 7;

    const ip_view = try IPv4Protocol.parse(&packet);
    try std.testing.expectError(error.InvalidField, parse(ip_view.get(.payload), ip_view));
}

test "parse() reads only the payload present in the first fragment" {
    var packet = test_ip_packet ++ [_]u8{ 'e', 'f', 'g', 'h' };
    packet[3] = packet.len;
    packet[6] = 0x20;
    packet[10..12].* = .{ 0xc5, 0x41 };
    packet[25] = 24;

    const ip_view = try IPv4Protocol.parse(&packet);
    const view = try parse(ip_view.get(.payload), ip_view);
    try std.testing.expectEqual(@as(u16, 24), view.get(.length));
    try std.testing.expectEqualSlices(u8, "abcdefgh", view.get(.payload));
}

test "parse() reads an empty payload" {
    var packet = test_ip_packet;
    packet[3] = 0x1c;
    packet[11] = 0x49;
    packet[24] = 0;
    packet[25] = 8;
    packet[26] = 0;
    packet[27] = 0;
    const ip_view = try IPv4Protocol.parse(&packet);
    const view = try parse(ip_view.get(.payload), ip_view);
    try std.testing.expectEqual(@as(u16, 8), view.get(.length));
    try std.testing.expectEqual(@as(usize, 0), view.get(.payload).len);
}

test "parse() rejects invalid checksums" {
    var packet = test_ip_packet;
    packet[28] = 'z';
    const ip_view = try IPv4Protocol.parse(&packet);
    try std.testing.expectError(error.BadChecksum, parse(ip_view.get(.payload), ip_view));
}

test "parse() on wireshark captured frames matches wireshark's parsed output" {
    const pcap_file = UdpFixtures.pcap_file;
    const csv_file = UdpFixtures.csv_file;

    var parsed_pcap = try PcapParser.parse(pcap_file, std.testing.allocator);
    defer parsed_pcap.deinit(std.testing.allocator);
    const parsed_packets = try CsvParser.parse(csv_file, std.testing.allocator);
    defer std.testing.allocator.free(parsed_packets);

    try std.testing.expectEqual(parsed_packets.len, parsed_pcap.packet_bytes.len);
    for (parsed_packets, 0..) |ws_packet, i| {
        const frame = try Ethernet.parse(parsed_pcap.packet_bytes[i]);
        if (frame.get(.ethertype) != .ipv4) continue;
        const ip_view = try IPv4Protocol.parse(frame.get(.payload));
        try std.testing.expectEqual(IPv4Protocol.Protocol.udp, ip_view.get(.protocol));
        const view = try parse(ip_view.get(.payload), ip_view);
        try std.testing.expect(view.isEqualIgnoringSlices(&ws_packet));
    }
}

test "parse() then serialize() returns the original bytes" {
    const pcap_file = UdpFixtures.pcap_file;

    var parsed_pcap = try PcapParser.parse(pcap_file, std.testing.allocator);
    defer parsed_pcap.deinit(std.testing.allocator);

    for (parsed_pcap.packet_bytes) |packet| {
        const frame = try Ethernet.parse(packet);
        if (frame.get(.ethertype) != .ipv4) continue;
        const ip_view = try IPv4Protocol.parse(frame.get(.payload));
        try std.testing.expectEqual(IPv4Protocol.Protocol.udp, ip_view.get(.protocol));
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
