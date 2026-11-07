//! "The world is a jungle in general, and the networking game contributes many animals" - David C. Plummer 1982 RFC #826
//! ARP packet structure:
//!         ________________________________________________________________________________________
//! Field: | Hardware | Protocol | HW Size | PRTCL Size | Opcode | Tx MAC | Tx IP | Rx MAC | Rx IP |
//!        -----------------------------------------------------------------------------------------
//! Bytes: |     2    |     2    |    1    |      1     |    2   |    6   |   4   |    6   |   4   |
//!        -----------------------------------------------------------------------------------------
//!
//! Generally the first four fields are expected to be 1, 0x0800, 6, and 4 for Ethernet, IP, MAC len, and IP len, respectively.
//!
//! An opcode of 1 indicates a request, and 2 indicates a reply.

const std = @import("std");
const router = @import("router");

const View = router.meta.view.View;
const IPv4 = router.protocols.ipv4.IPv4;
const Mac = router.protocols.ethernet.Mac;

pub const OpCode = enum(u16) {
    request = 1,
    reply = 2,
};

pub const ArpPacket = struct {
    hardware_type: u16 = 1,
    protocol_type: u16 = 0x0800,
    hardware_size: u8 = 6,
    protocol_size: u8 = 4,
    opcode: OpCode = .request,
    sender_mac: Mac = .{0} ** 6,
    sender_ip: IPv4 = .{0} ** 4,
    target_mac: Mac = .{0} ** 6,
    target_ip: IPv4 = .{0} ** 4,
};

pub const ArpPacketView = View(ArpPacket);

pub fn validate(view: ArpPacketView) !void {
    try view.validate(.hardware_type, 1);
    try view.validate(.protocol_type, 0x0800);
    try view.validate(.hardware_size, 6);
    try view.validate(.protocol_size, 4);
    try view.validate(.opcode, null);
}

pub fn parse(buffer: []const u8) !ArpPacketView {
    if (buffer.len != @sizeOf(ArpPacket)) return error.InvalidBuffer;

    var view: ArpPacketView = undefined;
    var reader: std.Io.Reader = .fixed(buffer);

    try view.takeField(.hardware_type, &reader);
    try view.takeField(.protocol_type, &reader);
    try view.takeField(.hardware_size, &reader);
    try view.takeField(.protocol_size, &reader);
    try view.takeField(.opcode, &reader);
    try view.takeField(.sender_mac, &reader);
    try view.takeField(.sender_ip, &reader);
    try view.takeField(.target_mac, &reader);
    try view.takeField(.target_ip, &reader);

    try validate(view);
    return view;
}

pub fn reply(
    sender_mac: Mac, // this is me
    req: ArpPacket, // my ip is already here, that's why I'm replying
) ArpPacket {
    var packet = ArpPacket{};
    packet.opcode = .reply;
    packet.sender_ip = req.target_ip;
    packet.sender_mac = sender_mac;
    packet.target_ip = req.sender_ip;
    packet.target_mac = req.sender_mac;
    return packet;
}

pub fn request(
    sender_ip: IPv4, // this is me
    sender_mac: Mac, // this is also me
    target_ip: IPv4, // who has this? tell me
    target_mac: ?Mac, // non-null for confirmation unicast, null for broadcast
) ArpPacket {
    var packet = ArpPacket{};
    packet.opcode = .request;
    packet.sender_ip = sender_ip;
    packet.sender_mac = sender_mac;
    packet.target_ip = target_ip;
    if (target_mac != null) packet.target_mac = target_mac.?;
    return packet;
}

test "ArpPacketView.serialize() writes a wire-sized packet" {
    const packet = ArpPacket{};
    var buffer: [@sizeOf(ArpPacket)]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    try ArpPacketView.serialize(packet, &writer);

    const expected = [_]u8{
        0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01,
    } ++ ([_]u8{0} ** 20);
    try std.testing.expectEqualSlices(u8, &expected, &buffer);

    var parsed = try parse(&buffer);
    try std.testing.expectEqualDeep(packet, parsed.copy());
}

test "parse() rejects serialized packets containing invalid metadata" {
    const default_packet = ArpPacket{};
    const invalid_packets = [_]ArpPacket{
        .{ .hardware_type = default_packet.hardware_type + 1 },
        .{ .protocol_type = default_packet.protocol_type + 1 },
        .{ .hardware_size = default_packet.hardware_size + 1 },
        .{ .protocol_size = default_packet.protocol_size + 1 },
    };

    for (invalid_packets) |packet| {
        var buffer: [@sizeOf(ArpPacket)]u8 = undefined;
        var writer: std.Io.Writer = .fixed(&buffer);
        try ArpPacketView.serialize(packet, &writer);
        try std.testing.expectError(error.InvalidField, parse(&buffer));
    }
}

test "parse() rejects buffers not ArpPacket sized" {
    var small_buffer: [@sizeOf(ArpPacket) - 1]u8 = undefined;
    try std.testing.expectError(error.InvalidBuffer, parse(&small_buffer));
    var large_buffer: [@sizeOf(ArpPacket) + 1]u8 = undefined;
    try std.testing.expectError(error.InvalidBuffer, parse(&large_buffer));
}

test "parse() rejects packet buffers containing invalid metadata fields" {
    var valid_buffer: [@sizeOf(ArpPacket)]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&valid_buffer);
    try ArpPacketView.serialize(ArpPacket{}, &writer);

    const invalid_fields = [_]struct { offset: usize, value: u8 }{
        .{ .offset = 1, .value = 2 },
        .{ .offset = 3, .value = 1 },
        .{ .offset = 4, .value = 7 },
        .{ .offset = 5, .value = 5 },
        .{ .offset = 7, .value = 3 },
    };

    for (invalid_fields) |invalid| {
        var buffer = valid_buffer;
        buffer[invalid.offset] = invalid.value;
        try std.testing.expectError(error.InvalidField, parse(&buffer));
    }
}

test "parse() on wireshark captured frames matches wireshark's parsed output" {
    // TODO: implement this
}

test "parse() then serialize() returns the original bytes" {
    // TODO: implement this
}

test "request() returns a packet struct with valid metadata fields" {
    const default_packet = ArpPacket{};
    const request_value = request(
        default_packet.sender_ip,
        default_packet.sender_mac,
        default_packet.target_ip,
        default_packet.target_mac,
    );
    try std.testing.expectEqual(default_packet.hardware_type, request_value.hardware_type);
    try std.testing.expectEqual(default_packet.hardware_size, request_value.hardware_size);
    try std.testing.expectEqual(default_packet.protocol_type, request_value.protocol_type);
    try std.testing.expectEqual(default_packet.protocol_size, request_value.protocol_size);
    try std.testing.expectEqual(.request, request_value.opcode);
}

test "request() populates the packet struct's address fields and sets the request opcode" {
    const sender_mac: Mac = .{ 0x90, 0xca, 0xfa, 0x60, 0x3c, 0xec };
    const sender_ip: IPv4 = .{ 192, 168, 86, 1 };
    const target_mac: Mac = .{ 0xf8, 0x54, 0xf6, 0x41, 0x3a, 0xe8 };
    const target_ip: IPv4 = .{ 192, 168, 86, 198 };
    try std.testing.expectEqualDeep(
        ArpPacket{
            .sender_mac = sender_mac,
            .sender_ip = sender_ip,
            .target_mac = target_mac,
            .target_ip = target_ip,
            .opcode = .request,
        },
        request(sender_ip, sender_mac, target_ip, target_mac),
    );
}

test "request() sets target mac to 00:00:00:00:00:00 if the corresponding argument is null" {
    const sender_mac: Mac = .{ 0x90, 0xca, 0xfa, 0x60, 0x3c, 0xec };
    const sender_ip: IPv4 = .{ 192, 168, 86, 1 };
    const target_mac: Mac = .{ 0, 0, 0, 0, 0, 0 };
    const target_ip: IPv4 = .{ 192, 168, 86, 198 };
    try std.testing.expectEqualDeep(
        ArpPacket{
            .sender_mac = sender_mac,
            .sender_ip = sender_ip,
            .target_mac = target_mac,
            .target_ip = target_ip,
            .opcode = .request,
        },
        request(sender_ip, sender_mac, target_ip, null),
    );
}

test "reply() returns a packet struct with valid metadata fields" {
    const default_packet = ArpPacket{};
    const reply_value = reply(default_packet.sender_mac, default_packet);
    try std.testing.expectEqual(default_packet.hardware_type, reply_value.hardware_type);
    try std.testing.expectEqual(default_packet.hardware_size, reply_value.hardware_size);
    try std.testing.expectEqual(default_packet.protocol_type, reply_value.protocol_type);
    try std.testing.expectEqual(default_packet.protocol_size, reply_value.protocol_size);
    try std.testing.expectEqual(.reply, reply_value.opcode);
}

test "reply() swaps the request's address fields, sets the sender mac, and sets the reply opcode" {
    const sender_mac: Mac = .{ 0xf8, 0x54, 0xf6, 0x41, 0x3a, 0xe8 };
    const sender_ip: IPv4 = .{ 192, 168, 86, 198 };
    const target_mac: Mac = .{ 0x90, 0xca, 0xfa, 0x60, 0x3c, 0xec };
    const target_ip: IPv4 = .{ 192, 168, 86, 1 };
    const expected = ArpPacket{
        .sender_mac = sender_mac,
        .sender_ip = sender_ip,
        .target_mac = target_mac,
        .target_ip = target_ip,
        .opcode = .reply,
    };
    const request_packet = request(target_ip, target_mac, sender_ip, null);
    try std.testing.expectEqualDeep(expected, reply(sender_mac, request_packet));

    var buffer: [@sizeOf(ArpPacket)]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    try ArpPacketView.serialize(request_packet, &writer);
    var request_view = try parse(&buffer);
    try std.testing.expectEqualDeep(expected, reply(sender_mac, request_view.copy()));
}
