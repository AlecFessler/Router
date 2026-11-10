const std = @import("std");
const Router = @import("router");

const IPv4 = Router.Protocols.IPv4.IPv4;
const IPv4Packet = Router.Protocols.IPv4.IPv4Packet;

fn unquote(str: []const u8) ![]const u8 {
    if (str.len < 2 or str[0] != '"' or str[str.len - 1] != '"')
        return error.UnexpectedFileFormat;
    return str[1 .. str.len - 1];
}

fn parseDecimal(comptime T: type, str: []const u8) !T {
    return std.fmt.parseInt(T, try unquote(str), 10);
}

fn parseHex(comptime T: type, str: []const u8) !T {
    const value = try unquote(str);
    if (!std.mem.startsWith(u8, value, "0x")) return error.UnexpectedFileFormat;
    return std.fmt.parseInt(T, value[2..], 16);
}

fn parseBool(str: []const u8) !bool {
    const value = try unquote(str);
    if (std.mem.eql(u8, value, "True")) return true;
    if (std.mem.eql(u8, value, "False")) return false;
    return error.UnexpectedFileFormat;
}

fn parseIPv4(str: []const u8) !IPv4 {
    var parts = std.mem.splitScalar(u8, try unquote(str), '.');
    var ip: IPv4 = undefined;
    for (&ip) |*byte| {
        const decimal = parts.next() orelse return error.InvalidIPv4;
        byte.* = try std.fmt.parseInt(u8, decimal, 10);
    }
    if (parts.next() != null) return error.InvalidIPv4;
    return ip;
}

pub fn parse(file: []const u8, alloc: std.mem.Allocator) ![]IPv4Packet {
    var reader: std.Io.Reader = .fixed(file);
    var packets: std.ArrayList(IPv4Packet) = .empty;
    defer packets.deinit(alloc);

    _ = try reader.takeDelimiter('\n') orelse return error.UnexpectedFileFormat;

    while (true) {
        const row = try reader.takeDelimiter('\n') orelse break;
        var row_reader: std.Io.Reader = .fixed(row);
        var columns: [16][]const u8 = undefined;
        for (columns[0 .. columns.len - 1]) |*column| {
            column.* = try row_reader.takeDelimiter(',') orelse return error.UnexpectedFileFormat;
        }
        columns[columns.len - 1] = std.mem.trimEnd(u8, row_reader.buffer[row_reader.seek..row_reader.end], "\r");

        var packet: IPv4Packet = undefined;
        const header_bytes = try parseDecimal(u8, columns[1]);
        if (header_bytes % 4 != 0) return error.UnexpectedFileFormat;
        packet.version = try parseDecimal(u4, columns[0]);
        packet.ihl = @intCast(header_bytes / 4);
        packet.dscp = try parseDecimal(u6, columns[2]);
        packet.ecn = try parseDecimal(u2, columns[3]);
        packet.total_length = try parseDecimal(u16, columns[4]);
        packet.identification = try parseHex(u16, columns[5]);
        packet.reserved = @intFromBool(try parseBool(columns[6]));
        packet.dont_fragment = try parseBool(columns[7]);
        packet.more_fragments = try parseBool(columns[8]);
        packet.fragment_offset = try parseDecimal(u13, columns[9]);
        packet.ttl = try parseDecimal(u8, columns[10]);
        packet.protocol = @enumFromInt(try parseDecimal(u8, columns[11]));
        packet.header_checksum = try parseHex(u16, columns[12]);
        packet.src = try parseIPv4(columns[13]);
        packet.dst = try parseIPv4(columns[14]);

        // The CSV has only option lengths. Packet bytes supply both slices.
        const options_len = if (columns[15].len == 0) 0 else try parseDecimal(u8, columns[15]);
        if (options_len != header_bytes - 20) return error.UnexpectedFileFormat;
        packet.options = undefined;
        packet.payload = undefined;

        try packets.append(alloc, packet);
    }

    return try packets.toOwnedSlice(alloc);
}
