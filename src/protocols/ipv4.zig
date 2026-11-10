const std = @import("std");
const Router = @import("router");

const Cli = Router.Debug.Cli;
const IFace = Router.Nic.Api.IFace;
const NicApi = Router.Nic.Api.Api;
const View = Router.Meta.View.View;

pub const IPv4 = [4]u8;

pub const Protocol = enum(u8) {
    icmp = 1, // internet control message protocol
    igmp = 2, // internet group management protocol
    tcp = 6, // transmission control protocol
    udp = 17, // user datagram protocol
    encap = 41, // IPv6 encapsulation
    ospf = 89, // open shortest path first
    sctp = 132, // stream control transmission protocol
    _,
};

pub const IPv4Packet = struct {
    version: u4,
    ihl: u4, // internet header length
    dscp: u6, // differentiated services code point
    ecn: u2, // explicit congestion notification
    total_length: u16,
    identification: u16,
    reserved: u1,
    dont_fragment: bool,
    more_fragments: bool,
    fragment_offset: u13,
    ttl: u8,
    protocol: Protocol,
    header_checksum: u16,
    src: IPv4,
    dst: IPv4,
    options: []u8,
    payload: []u8,
};

pub const IPv4PacketView = View(IPv4Packet);

pub fn validate(view: IPv4PacketView) !void {
    const version = view.get(.version);
    if (version != 4) return error.InvalidField;

    const ihl: usize = view.get(.ihl);
    if (ihl < 5) return error.InvalidField;

    const reserved = view.get(.reserved);
    if (reserved != 0) return error.InvalidField;

    const total_length = view.get(.total_length);
    if (total_length < ihl * 4) return error.InvalidField;

    const more_fragments = view.get(.more_fragments);
    const payload_bytes = total_length - (ihl * 4);
    if (more_fragments and payload_bytes % 8 != 0) return error.InvalidField;

    const packet_words: [*]align(1) const u16 = @ptrFromInt(@intFromPtr(view.fields.version));
    const num_words = ihl * 2;
    var sum: u32 = 0;
    for (packet_words[0..num_words]) |word| sum += std.mem.bigToNative(u16, word);
    for (0..2) |_| sum = (sum & 0xFFFF) + (sum >> 16);
    if (sum != 0xFFFF) return error.InvalidField;
}

pub fn parse(buffer: []const u8) !IPv4PacketView {
    var view: IPv4PacketView = undefined;
    var reader: std.Io.Reader = .fixed(buffer);

    try view.takeField(.version, &reader);
    try view.takeField(.ihl, &reader);
    try view.takeField(.dscp, &reader);
    try view.takeField(.ecn, &reader);
    try view.takeField(.total_length, &reader);
    try view.takeField(.identification, &reader);
    try view.takeField(.reserved, &reader);
    try view.takeField(.dont_fragment, &reader);
    try view.takeField(.more_fragments, &reader);
    try view.takeField(.fragment_offset, &reader);
    try view.takeField(.ttl, &reader);
    try view.takeField(.protocol, &reader);
    try view.takeField(.header_checksum, &reader);
    try view.takeField(.src, &reader);
    try view.takeField(.dst, &reader);

    const header_bytes = @as(usize, view.get(.ihl)) * 4;
    const options_bytes = header_bytes - 20;
    try view.takeBytes(.options, options_bytes, &reader);

    // validate before taking the payload to verify the header checksum
    try validate(view);

    const payload_bytes = view.get(.total_length) - header_bytes;
    try view.takeBytes(.payload, payload_bytes, &reader);

    return view;
}

pub fn handle(
    buffer: []u8,
    packet: []u8,
    device: NicApi,
    iface: IFace,
) !void {
    const view = try parse(packet);
    Cli.enter(.ipv4, view);
    const protocol = view.get(.protocol);
    switch (protocol) {
        else => {
            const name = std.enums.tagName(Protocol, protocol);
            if (name) |tag| {
                std.debug.print(
                    "IPv4: packet with protocol: {s} unhandled by {s} interface\n",
                    .{ tag, @tagName(iface) },
                );
            } else {
                std.debug.print(
                    "IPv4: packet with protocol: {} unhandled by {s} interface\n",
                    .{ @intFromEnum(protocol), @tagName(iface) },
                );
            }
            device.release(buffer);
        },
    }
}

const test_packet = [_]u8{
    0x45, 0x00, 0x00, 0x18, 0x12, 0x34, 0x40, 0x00,
    0x40, 0x11, 0xa5, 0x4d, 0xc0, 0xa8, 0x01, 0x01,
    0xc0, 0xa8, 0x01, 0x02, 0xde, 0xad, 0xbe, 0xef,
};

const test_packet_with_options = [_]u8{
    0x46, 0x00, 0x00, 0x18, 0x12, 0x34, 0x40, 0x00,
    0x40, 0x11, 0xa0, 0x47, 0xc0, 0xa8, 0x01, 0x01,
    0xc0, 0xa8, 0x01, 0x02, 0x01, 0x02, 0x03, 0x04,
};

test "parse() reads IPv4 fields from wire bytes" {
    const view = try parse(&test_packet);

    try std.testing.expectEqual(@as(u4, 4), view.get(.version));
    try std.testing.expectEqual(@as(u4, 5), view.get(.ihl));
    try std.testing.expectEqual(@as(u6, 0), view.get(.dscp));
    try std.testing.expectEqual(@as(u2, 0), view.get(.ecn));
    try std.testing.expectEqual(@as(u16, 24), view.get(.total_length));
    try std.testing.expectEqual(@as(u16, 0x1234), view.get(.identification));
    try std.testing.expectEqual(@as(u1, 0), view.get(.reserved));
    try std.testing.expectEqual(true, view.get(.dont_fragment));
    try std.testing.expectEqual(false, view.get(.more_fragments));
    try std.testing.expectEqual(@as(u13, 0), view.get(.fragment_offset));
    try std.testing.expectEqual(@as(u8, 64), view.get(.ttl));
    try std.testing.expectEqual(Protocol.udp, view.get(.protocol));
    try std.testing.expectEqual(@as(u16, 0xa54d), view.get(.header_checksum));
    try std.testing.expectEqualDeep(IPv4{ 192, 168, 1, 1 }, view.get(.src));
    try std.testing.expectEqualDeep(IPv4{ 192, 168, 1, 2 }, view.get(.dst));
    try std.testing.expectEqual(@as(usize, 0), view.get(.options).len);
    try std.testing.expectEqualSlices(u8, test_packet[20..24], view.get(.payload));
}

test "parse() rejects truncated packets and accepts trailing bytes" {
    const buffer = test_packet ++ [_]u8{0xff};

    for (0..test_packet.len) |len| {
        try std.testing.expectError(error.EndOfStream, parse(buffer[0..len]));
    }

    const view = try parse(&buffer);
    try std.testing.expectEqualSlices(u8, test_packet[20..24], view.get(.payload));
    try std.testing.expectEqual(@as(usize, 4), view.get(.payload).len);
}

test "parse() reads header options according to the IHL" {
    const view = try parse(&test_packet_with_options);
    try std.testing.expectEqual(@as(u4, 6), view.get(.ihl));
    try std.testing.expectEqualSlices(u8, test_packet_with_options[20..24], view.get(.options));
    try std.testing.expectEqual(@as(usize, 0), view.get(.payload).len);
    try std.testing.expectError(
        error.EndOfStream,
        parse(test_packet_with_options[0 .. test_packet_with_options.len - 1]),
    );
}

test "parse() reads a nonzero fragment offset" {
    var packet = test_packet;
    packet[6] = 0x00;
    packet[7] = 0x01;
    packet[10] = 0xe5;
    packet[11] = 0x4c;

    var view = try parse(&packet);
    try std.testing.expectEqual(@as(u13, 1), view.get(.fragment_offset));
    try std.testing.expect(!view.get(.dont_fragment));
    try std.testing.expect(!view.get(.more_fragments));

    var buffer: [packet.len]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    try IPv4PacketView.serialize(view.copy(), &writer);
    try std.testing.expectEqualSlices(u8, &packet, &buffer);
}

test "parse() rejects invalid metadata fields" {
    const invalid_fields = [_]struct { offset: usize, value: u8 }{
        .{ .offset = 0, .value = 0x65 }, // version 6
        .{ .offset = 6, .value = 0xc0 }, // reserved flag set
        .{ .offset = 3, .value = 0x13 }, // total length below header length
        .{ .offset = 6, .value = 0x60 }, // more fragments with a four-byte payload
        .{ .offset = 8, .value = 0x41 }, // checksum no longer matches
    };

    for (invalid_fields) |invalid| {
        var buffer = test_packet;
        buffer[invalid.offset] = invalid.value;
        try std.testing.expectError(error.InvalidField, parse(&buffer));
    }
}

test "parse() on wireshark captured frames matches wireshark's parsed output" {
    const PcapParser = Router.TestFixtures.PcapParser;
    const CsvParser = Router.TestFixtures.IPv4.CsvParser;
    const pcap_file = Router.TestFixtures.IPv4.pcap_file;
    const csv_file = Router.TestFixtures.IPv4.csv_file;

    var parsed_pcap = try PcapParser.parse(pcap_file, std.testing.allocator);
    defer parsed_pcap.deinit(std.testing.allocator);
    const parsed_packets = try CsvParser.parse(csv_file, std.testing.allocator);
    defer std.testing.allocator.free(parsed_packets);

    try std.testing.expectEqual(parsed_packets.len, parsed_pcap.packet_bytes.len);
    for (parsed_packets, 0..) |ws_packet, i| {
        const frame = try Router.Protocols.Ethernet.parse(parsed_pcap.packet_bytes[i]);
        try std.testing.expectEqual(Router.Protocols.Ethernet.Ethertype.ipv4, frame.get(.ethertype));
        const view = try parse(frame.get(.payload));
        try std.testing.expect(view.isEqualIgnoringSlices(&ws_packet));
    }
}

test "parse() then serialize() returns the original bytes" {
    const PcapParser = Router.TestFixtures.PcapParser;
    const pcap_file = Router.TestFixtures.IPv4.pcap_file;

    var parsed_pcap = try PcapParser.parse(pcap_file, std.testing.allocator);
    defer parsed_pcap.deinit(std.testing.allocator);

    for (parsed_pcap.packet_bytes) |packet| {
        const frame = try Router.Protocols.Ethernet.parse(packet);
        try std.testing.expectEqual(Router.Protocols.Ethernet.Ethertype.ipv4, frame.get(.ethertype));
        const ipv4_bytes = frame.get(.payload);
        var view = try parse(ipv4_bytes);
        const parsed_len = view.get(.total_length);
        const buffer = try std.testing.allocator.alloc(u8, parsed_len);
        defer std.testing.allocator.free(buffer);
        var writer: std.Io.Writer = .fixed(buffer);

        try IPv4PacketView.serialize(view.copy(), &writer);
        try std.testing.expectEqual(parsed_len, writer.end);
        try std.testing.expectEqualSlices(u8, ipv4_bytes[0..parsed_len], buffer);
    }
}
