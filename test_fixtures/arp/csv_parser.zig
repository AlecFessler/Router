const std = @import("std");
const Router = @import("router");

const ArpPacket = Router.Protocols.Arp.ArpPacket;
const OpCode = Router.Protocols.Arp.OpCode;
const Mac = Router.Protocols.Ethernet.Mac;
const IPv4 = Router.Protocols.IPv4.IPv4;

fn unquote(str: []const u8) ![]const u8 {
    if (str.len < 2 or str[0] != '"' or str[str.len - 1] != '"')
        return error.UnexpectedFileFormat;
    return str[1 .. str.len - 1];
}

fn parseMac(str: []const u8) !Mac {
    var parts = std.mem.splitScalar(u8, str, ':');
    var mac: Mac = undefined;
    for (&mac) |*byte| {
        const hex = parts.next() orelse return error.InvalidMac;
        byte.* = try std.fmt.parseInt(u8, hex, 16);
    }
    if (parts.next() != null) return error.InvalidMac;
    return mac;
}

fn parseIPv4(str: []const u8) !IPv4 {
    var parts = std.mem.splitScalar(u8, str, '.');
    var ip: IPv4 = undefined;
    for (&ip) |*byte| {
        const decimal = parts.next() orelse return error.InvalidIPv4;
        byte.* = try std.fmt.parseInt(u8, decimal, 10);
    }
    if (parts.next() != null) return error.InvalidIPv4;
    return ip;
}

pub fn parse(file: []const u8, alloc: std.mem.Allocator) ![]ArpPacket {
    var reader: std.Io.Reader = .fixed(file);

    var packets: std.ArrayList(ArpPacket) = .empty;
    defer packets.deinit(alloc);

    _ = try reader.takeDelimiter('\n') orelse return error.UnexpectedFileFormat;

    while (true) {
        const row = try reader.takeDelimiter('\n') orelse break;
        var row_reader: std.Io.Reader = .fixed(row);

        const hardware_type_str = try row_reader.takeDelimiter(',') orelse return error.UnexpectedFileFormat;
        const protocol_type_str = try row_reader.takeDelimiter(',') orelse return error.UnexpectedFileFormat;
        const hardware_size_str = try row_reader.takeDelimiter(',') orelse return error.UnexpectedFileFormat;
        const protocol_size_str = try row_reader.takeDelimiter(',') orelse return error.UnexpectedFileFormat;
        const opcode_str = try row_reader.takeDelimiter(',') orelse return error.UnexpectedFileFormat;
        const sender_mac_str = try row_reader.takeDelimiter(',') orelse return error.UnexpectedFileFormat;
        const sender_ip_str = try row_reader.takeDelimiter(',') orelse return error.UnexpectedFileFormat;
        const target_mac_str = try row_reader.takeDelimiter(',') orelse return error.UnexpectedFileFormat;
        const target_ip_str = row_reader.buffer[row_reader.seek..row_reader.end];

        var packet: ArpPacket = undefined;
        packet.hardware_type = try std.fmt.parseInt(u16, try unquote(hardware_type_str), 10);
        const protocol_type = try unquote(protocol_type_str);
        if (!std.mem.startsWith(u8, protocol_type, "0x")) return error.UnexpectedFileFormat;
        packet.protocol_type = try std.fmt.parseInt(u16, protocol_type[2..], 16);
        packet.hardware_size = try std.fmt.parseInt(u8, try unquote(hardware_size_str), 10);
        packet.protocol_size = try std.fmt.parseInt(u8, try unquote(protocol_size_str), 10);
        const opcode = try std.fmt.parseInt(u16, try unquote(opcode_str), 10);
        packet.opcode = std.enums.fromInt(OpCode, opcode) orelse return error.UnexpectedFileFormat;
        packet.sender_mac = try parseMac(try unquote(sender_mac_str));
        packet.sender_ip = try parseIPv4(try unquote(sender_ip_str));
        packet.target_mac = try parseMac(try unquote(target_mac_str));
        packet.target_ip = try parseIPv4(try unquote(std.mem.trimEnd(u8, target_ip_str, "\r")));

        try packets.append(alloc, packet);
    }

    return try packets.toOwnedSlice(alloc);
}
