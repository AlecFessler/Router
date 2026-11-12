const std = @import("std");
const Router = @import("router");

const TcpPacket = Router.Protocols.Tcp.TcpPacket;

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

fn parseBool(str: []const u8) !bool {
    const value = try unquote(str);
    if (std.mem.eql(u8, value, "True")) return true;
    if (std.mem.eql(u8, value, "False")) return false;
    return error.UnexpectedFileFormat;
}

pub fn parse(file: []const u8, alloc: std.mem.Allocator) ![]TcpPacket {
    var reader: std.Io.Reader = .fixed(file);
    var packets: std.ArrayList(TcpPacket) = .empty;
    defer packets.deinit(alloc);

    _ = try reader.takeDelimiter('\n') orelse return error.UnexpectedFileFormat;

    while (true) {
        const row = try reader.takeDelimiter('\n') orelse break;
        var row_reader: std.Io.Reader = .fixed(row);
        var columns: [19][]const u8 = undefined;
        for (columns[0 .. columns.len - 1]) |*column| {
            column.* = try row_reader.takeDelimiter(',') orelse return error.UnexpectedFileFormat;
        }
        columns[columns.len - 1] = std.mem.trimEnd(u8, row_reader.buffer[row_reader.seek..row_reader.end], "\r");

        const header_bytes = try parseDecimal(u8, columns[4]);
        if (header_bytes < 20 or header_bytes % 4 != 0) return error.UnexpectedFileFormat;
        const options = try unquote(columns[18]);
        if (options.len != (@as(usize, header_bytes) - 20) * 2)
            return error.UnexpectedFileFormat;

        try packets.append(alloc, .{
            .src_port = try parseDecimal(u16, columns[0]),
            .dst_port = try parseDecimal(u16, columns[1]),
            .seq_number = try parseDecimal(u32, columns[2]),
            .ack_number = try parseDecimal(u32, columns[3]),
            .data_offset = @intCast(header_bytes / 4),
            .reserved = @intFromBool(try parseBool(columns[5])),
            .ae = try parseBool(columns[6]),
            .cwr = try parseBool(columns[7]),
            .ece = try parseBool(columns[8]),
            .urg = try parseBool(columns[9]),
            .ack = try parseBool(columns[10]),
            .psh = try parseBool(columns[11]),
            .rst = try parseBool(columns[12]),
            .syn = try parseBool(columns[13]),
            .fin = try parseBool(columns[14]),
            .window = try parseDecimal(u16, columns[15]),
            .checksum = try parseHex(columns[16]),
            .urgent_ptr = try parseDecimal(u16, columns[17]),
            .options = undefined,
            .payload = undefined,
        });
    }

    return try packets.toOwnedSlice(alloc);
}
