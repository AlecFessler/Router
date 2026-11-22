const std = @import("std");
const Router = @import("router");

const DHCPv4Packet = Router.Protocols.DHCPv4.DHCPv4Packet;
const IPv4 = Router.Protocols.IPv4.IPv4;

pub const ExpectedPacket = struct {
    packet: DHCPv4Packet,
    option_types: []const u8,
    option_values: []const u8,
    message_type: u8,
};

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

fn parseHexBytes(comptime N: usize, str: []const u8) ![N]u8 {
    const value = try unquote(str);
    if (value.len != N * 2) return error.UnexpectedFileFormat;
    var bytes: [N]u8 = undefined;
    for (&bytes, 0..) |*byte, i| {
        byte.* = try std.fmt.parseInt(u8, value[i * 2 ..][0..2], 16);
    }
    return bytes;
}

fn parseClientHardwareAddress(mac_field: []const u8, padding_field: []const u8) ![16]u8 {
    var address: [16]u8 = undefined;
    var parts = std.mem.splitScalar(u8, try unquote(mac_field), ':');
    for (0..6) |i| {
        const part = parts.next() orelse return error.UnexpectedFileFormat;
        address[i] = try std.fmt.parseInt(u8, part, 16);
    }
    if (parts.next() != null) return error.UnexpectedFileFormat;
    const padding = try parseHexBytes(10, padding_field);
    for (padding, 0..) |byte, i| address[i + 6] = byte;
    return address;
}

fn parseFixedString(comptime N: usize, str: []const u8) ![N]u8 {
    const value = try unquote(str);
    if (value.len > N) return error.UnexpectedFileFormat;
    var bytes = [_]u8{0} ** N;
    @memcpy(bytes[0..value.len], value);
    return bytes;
}

pub fn parse(file: []const u8, alloc: std.mem.Allocator) ![]ExpectedPacket {
    var reader: std.Io.Reader = .fixed(file);
    var packets: std.ArrayList(ExpectedPacket) = .empty;
    defer packets.deinit(alloc);

    _ = try reader.takeDelimiter('\n') orelse return error.UnexpectedFileFormat;

    while (true) {
        const row = try reader.takeDelimiter('\n') orelse break;
        var row_reader: std.Io.Reader = .fixed(row);
        var columns: [21][]const u8 = undefined;
        for (columns[0 .. columns.len - 1]) |*column| {
            column.* = try row_reader.takeDelimiter(',') orelse return error.UnexpectedFileFormat;
        }
        columns[columns.len - 1] = std.mem.trimEnd(u8, row_reader.buffer[row_reader.seek..row_reader.end], "\r");

        _ = try parseDecimal(usize, columns[0]);
        const magic_bytes = try parseIPv4(columns[17]);
        try packets.append(alloc, .{
            .packet = .{
                .op = @enumFromInt(try parseDecimal(u8, columns[1])),
                .htype = try parseHex(u8, columns[2]),
                .hlen = try parseDecimal(u8, columns[3]),
                .hops = try parseDecimal(u8, columns[4]),
                .xid = try parseHex(u32, columns[5]),
                .secs = try parseDecimal(u16, columns[6]),
                .broadcast_flag = try parseBool(columns[7]),
                .reserved_flags = try parseHex(u15, columns[8]),
                .client_ip = try parseIPv4(columns[9]),
                .your_ip = try parseIPv4(columns[10]),
                .next_server_ip = try parseIPv4(columns[11]),
                .relay_agent_ip = try parseIPv4(columns[12]),
                .client_hw_addr = try parseClientHardwareAddress(columns[13], columns[14]),
                .server_name = try parseFixedString(64, columns[15]),
                .file = try parseFixedString(128, columns[16]),
                .magic = std.mem.readInt(u32, &magic_bytes, .big),
                .options = undefined,
            },
            .option_types = try unquote(columns[18]),
            .option_values = try unquote(columns[19]),
            .message_type = try parseDecimal(u8, columns[20]),
        });
    }

    return try packets.toOwnedSlice(alloc);
}
