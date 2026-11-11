const std = @import("std");
const Router = @import("router");

const UdpPacket = Router.Protocols.Udp.UdpPacket;

fn unquote(str: []const u8) ![]const u8 {
    if (str.len < 2 or str[0] != '"' or str[str.len - 1] != '"')
        return error.UnexpectedFileFormat;
    return str[1 .. str.len - 1];
}

fn parseDecimal(str: []const u8) !u16 {
    return std.fmt.parseInt(u16, try unquote(str), 10);
}

fn parseHex(str: []const u8) !u16 {
    const value = try unquote(str);
    if (!std.mem.startsWith(u8, value, "0x")) return error.UnexpectedFileFormat;
    return std.fmt.parseInt(u16, value[2..], 16);
}

pub fn parse(file: []const u8, alloc: std.mem.Allocator) ![]UdpPacket {
    var reader: std.Io.Reader = .fixed(file);
    var packets: std.ArrayList(UdpPacket) = .empty;
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

        try packets.append(alloc, .{
            .src_port = try parseDecimal(columns[0]),
            .dst_port = try parseDecimal(columns[1]),
            .length = try parseDecimal(columns[2]),
            .checksum = try parseHex(columns[3]),
            .payload = undefined,
        });
    }

    return try packets.toOwnedSlice(alloc);
}
