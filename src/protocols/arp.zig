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

const ethernet = @import("ethernet.zig");
const ipv4 = @import("ipv4.zig");

const IPv4 = ipv4.IPv4;
const Mac = ethernet.Mac;

pub const OpCode = enum(u16) {
    request,
    reply,
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

pub fn parse(buffer: []const u8) !ArpPacket {
    if (buffer.len != @sizeOf(ArpPacket)) return error.InvalidBuffer;

    var packet: ArpPacket = undefined;
    var reader: std.Io.Reader = .fixed(buffer);

    packet.hardware_type = try reader.takeInt(u16, .big);
    if (packet.hardware_type != 1) return error.InvalidPacket;
    packet.protocol_type = try reader.takeInt(u16, .big);
    if (packet.protocol_type != 0x0800) return error.InvalidPacket;
    packet.hardware_size = try reader.takeInt(u8, .big);
    if (packet.hardware_size != 6) return error.InvalidPacket;
    packet.protocol_size = try reader.takeInt(u8, .big);
    if (packet.protocol_size != 4) return error.InvalidPacket;

    const opcode = try reader.takeInt(u16, .big);
    if (opcode != 1 or opcode != 2) return error.InvalidPacket;
    packet.opcode = @enumFromInt(opcode);

    try reader.readSliceAll(&packet.sender_mac);
    try reader.readSliceAll(&packet.sender_ip);
    try reader.readSliceAll(&packet.target_mac);
    try reader.readSliceAll(&packet.target_ip);

    return packet;
}

pub fn serialize(packet: ArpPacket, buffer: []u8) !void {
    if (buffer.len != @sizeOf(ArpPacket)) return error.InvalidBuffer;
    if (packet.hardware_type != 1) return error.InvalidPacket;
    if (packet.protocol_type != 0x0800) return error.InvalidPacket;
    if (packet.hardware_size != 6) return error.InvalidPacket;
    if (packet.protocol_size != 4) return error.InvalidPacket;

    var writer: std.Io.Writer = .fixed(buffer);
    try writer.writeInt(u16, packet.hardware_type, .big);
    try writer.writeInt(u16, packet.protocol_type, .big);
    try writer.writeInt(u8, packet.hardware_size, .big);
    try writer.writeInt(u8, packet.protocol_size, .big);
    try writer.writeInt(u16, @intFromEnum(packet.opcode), .big);
    try writer.writeAll(&packet.sender_mac);
    try writer.writeAll(&packet.sender_ip);
    try writer.writeAll(&packet.target_mac);
    try writer.writeAll(&packet.target_ip);
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

test "serialize() rejects buffers not ArpPacket sized" {
    const packet = ArpPacket{};
    var small_buffer: [@sizeOf(ArpPacket) - 1]u8 = undefined;
    try std.testing.expectError(error.InvalidBuffer, serialize(packet, &small_buffer));
    var large_buffer: [@sizeOf(ArpPacket) + 1]u8 = undefined;
    try std.testing.expectError(error.InvalidBuffer, serialize(packet, &large_buffer));
}

test "serialize() rejects packet structs containing invalid metadata" {
    const default_packet = ArpPacket{};
    var buffer: [@sizeOf(ArpPacket)]u8 = undefined;

    const invalid_hardware_type = ArpPacket{ .hardware_type = default_packet.hardware_type + 1 };
    try std.testing.expectError(error.InvalidPacket, serialize(invalid_hardware_type, &buffer));

    const invalid_protocol_type = ArpPacket{ .protocol_type = default_packet.protocol_type + 1 };
    try std.testing.expectError(error.InvalidPacket, serialize(invalid_protocol_type, &buffer));

    const invalid_hardware_size = ArpPacket{ .hardware_type = default_packet.hardware_size + 1 };
    try std.testing.expectError(error.InvalidPacket, serialize(invalid_hardware_size, &buffer));

    const invalid_protocol_size = ArpPacket{ .protocol_size = default_packet.protocol_size + 1 };
    try std.testing.expectError(error.InvalidPacket, serialize(invalid_protocol_size, &buffer));
}

test "parse() rejects buffers not ArpPacket sized" {
    var small_buffer: [@sizeOf(ArpPacket) - 1]u8 = undefined;
    try std.testing.expectError(error.InvalidBuffer, parse(&small_buffer));
    var large_buffer: [@sizeOf(ArpPacket) + 1]u8 = undefined;
    try std.testing.expectError(error.InvalidBuffer, parse(&large_buffer));
}

test "parse() rejects packet buffers containing invalid metadata fields" {
    const default_packet = ArpPacket{};

    var invalid_hardware_type: [@sizeOf(ArpPacket)]u8 = undefined;
    var invalid_hardware_type_writer: std.Io.Writer = .fixed(&invalid_hardware_type);
    try invalid_hardware_type_writer.writeInt(u16, default_packet.hardware_type + 1, .big);
    try invalid_hardware_type_writer.writeInt(u16, default_packet.protocol_type, .big);
    try invalid_hardware_type_writer.writeInt(u8, default_packet.hardware_size, .big);
    try invalid_hardware_type_writer.writeInt(u8, default_packet.protocol_size, .big);
    try invalid_hardware_type_writer.writeInt(u16, @intFromEnum(default_packet.opcode), .big);
    try std.testing.expectError(error.InvalidPacket, parse(&invalid_hardware_type));

    var invalid_protocol_type: [@sizeOf(ArpPacket)]u8 = undefined;
    var invalid_protocol_type_writer: std.Io.Writer = .fixed(&invalid_protocol_type);
    try invalid_protocol_type_writer.writeInt(u16, default_packet.hardware_type, .big);
    try invalid_protocol_type_writer.writeInt(u16, default_packet.protocol_type + 1, .big);
    try invalid_protocol_type_writer.writeInt(u8, default_packet.hardware_size, .big);
    try invalid_protocol_type_writer.writeInt(u8, default_packet.protocol_size, .big);
    try invalid_protocol_type_writer.writeInt(u16, @intFromEnum(default_packet.opcode), .big);
    try std.testing.expectError(error.InvalidPacket, parse(&invalid_protocol_type));

    var invalid_hardware_size: [@sizeOf(ArpPacket)]u8 = undefined;
    var invalid_hardware_size_writer: std.Io.Writer = .fixed(&invalid_hardware_size);
    try invalid_hardware_size_writer.writeInt(u16, default_packet.hardware_type, .big);
    try invalid_hardware_size_writer.writeInt(u16, default_packet.protocol_type, .big);
    try invalid_hardware_size_writer.writeInt(u8, default_packet.hardware_size + 1, .big);
    try invalid_hardware_size_writer.writeInt(u8, default_packet.protocol_size, .big);
    try invalid_hardware_size_writer.writeInt(u16, @intFromEnum(default_packet.opcode), .big);
    try std.testing.expectError(error.InvalidPacket, parse(&invalid_hardware_size));

    var invalid_protocol_size: [@sizeOf(ArpPacket)]u8 = undefined;
    var invalid_protocol_size_writer: std.Io.Writer = .fixed(&invalid_protocol_size);
    try invalid_protocol_size_writer.writeInt(u16, default_packet.hardware_type, .big);
    try invalid_protocol_size_writer.writeInt(u16, default_packet.protocol_type, .big);
    try invalid_protocol_size_writer.writeInt(u8, default_packet.hardware_size, .big);
    try invalid_protocol_size_writer.writeInt(u8, default_packet.protocol_size + 1, .big);
    try invalid_protocol_size_writer.writeInt(u16, @intFromEnum(default_packet.opcode), .big);
    try std.testing.expectError(error.InvalidPacket, parse(&invalid_protocol_size));

    var invalid_opcode: [@sizeOf(ArpPacket)]u8 = undefined;
    var invalid_opcode_writer: std.Io.Writer = .fixed(&invalid_opcode);
    try invalid_opcode_writer.writeInt(u16, default_packet.hardware_type, .big);
    try invalid_opcode_writer.writeInt(u16, default_packet.protocol_type, .big);
    try invalid_opcode_writer.writeInt(u8, default_packet.hardware_size, .big);
    try invalid_opcode_writer.writeInt(u8, default_packet.protocol_size, .big);
    try invalid_opcode_writer.writeInt(u16, @intFromEnum(default_packet.opcode) + 2, .big);
    try std.testing.expectError(error.InvalidPacket, parse(&invalid_opcode));
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
    try std.testing.expectEqualDeep(
        ArpPacket{
            .sender_mac = sender_mac,
            .sender_ip = sender_ip,
            .target_mac = target_mac,
            .target_ip = target_ip,
            .opcode = .reply,
        },
        reply(
            sender_mac,
            request(target_ip, target_mac, sender_ip, null), // request args are reversed of local names
        ),
    );
}
