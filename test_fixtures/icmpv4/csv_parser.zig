const std = @import("std");
const Router = @import("router");

const ICMPv4Packet = Router.Protocols.ICMPv4.ICMPv4Packet;

fn unquote(str: []const u8) ![]const u8 {
    if (str.len < 2 or str[0] != '"' or str[str.len - 1] != '"')
        return error.UnexpectedFileFormat;
    return str[1 .. str.len - 1];
}

fn parseDecimal(comptime T: type, str: []const u8) !T {
    return std.fmt.parseInt(T, try unquote(str), 10);
}

fn parseHex(str: []const u8) !u16 {
    const value = try unquote(str);
    if (!std.mem.startsWith(u8, value, "0x")) return error.UnexpectedFileFormat;
    return std.fmt.parseInt(u16, value[2..], 16);
}

pub fn parse(file: []const u8, alloc: std.mem.Allocator) ![]ICMPv4Packet {
    var reader: std.Io.Reader = .fixed(file);
    var packets: std.ArrayList(ICMPv4Packet) = .empty;
    defer packets.deinit(alloc);

    _ = try reader.takeDelimiter('\n') orelse return error.UnexpectedFileFormat;

    while (true) {
        const row = try reader.takeDelimiter('\n') orelse break;
        var row_reader: std.Io.Reader = .fixed(row);
        var columns: [4][]const u8 = undefined;
        for (columns[0 .. columns.len - 1]) |*column| {
            column.* = try row_reader.takeDelimiter(',') orelse return error.UnexpectedFileFormat;
        }
        columns[columns.len - 1] = std.mem.trimEnd(u8, row_reader.buffer[row_reader.seek..row_reader.end], "\r");

        _ = try parseDecimal(usize, columns[0]);
        try packets.append(alloc, .{
            .type_field = @enumFromInt(try parseDecimal(u8, columns[1])),
            .code = try parseDecimal(u8, columns[2]),
            .checksum = try parseHex(columns[3]),
            .payload = undefined,
        });
    }

    return try packets.toOwnedSlice(alloc);
}
