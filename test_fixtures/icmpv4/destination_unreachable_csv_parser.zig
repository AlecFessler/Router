const std = @import("std");
const Router = @import("router");
const Code = Router.Protocols.ICMPv4Messages.DestinationUnreachable.Code;

pub const Row = struct {
    frame_number: usize,
    code: Code,
    reserved: u16,
    next_hop_mtu: u16,
};

fn unquote(text: []const u8) ![]const u8 {
    if (text.len < 2 or text[0] != '"' or text[text.len - 1] != '"')
        return error.UnexpectedFileFormat;
    return text[1 .. text.len - 1];
}

fn decimal(comptime T: type, text: []const u8) !T {
    return std.fmt.parseInt(T, try unquote(text), 10);
}

pub fn parse(file: []const u8, alloc: std.mem.Allocator) ![]Row {
    var rows: std.ArrayList(Row) = .empty;
    defer rows.deinit(alloc);
    var lines = std.mem.splitScalar(u8, file, '\n');
    _ = lines.next() orelse return error.UnexpectedFileFormat;
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        var parts = std.mem.splitScalar(u8, std.mem.trimEnd(u8, line, "\r"), ',');
        const frame_number = try decimal(usize, parts.next() orelse return error.UnexpectedFileFormat);
        if (try decimal(u8, parts.next() orelse return error.UnexpectedFileFormat) != 3)
            return error.UnexpectedFileFormat;
        const code: Code = @enumFromInt(try decimal(u8, parts.next() orelse return error.UnexpectedFileFormat));
        const unused = try unquote(parts.next() orelse return error.UnexpectedFileFormat);
        const mtu_column = parts.next() orelse return error.UnexpectedFileFormat;
        const mtu_text = if (mtu_column.len == 0) "" else try unquote(mtu_column);
        if (parts.next() != null) return error.UnexpectedFileFormat;
        if (unused.len != 4 and unused.len != 8) return error.UnexpectedFileFormat;
        const reserved = try std.fmt.parseInt(u16, unused[0..4], 16);
        const next_hop_mtu = if (mtu_text.len != 0)
            try std.fmt.parseInt(u16, mtu_text, 10)
        else if (unused.len == 8)
            try std.fmt.parseInt(u16, unused[4..8], 16)
        else
            return error.UnexpectedFileFormat;
        try rows.append(alloc, .{
            .frame_number = frame_number,
            .code = code,
            .reserved = reserved,
            .next_hop_mtu = next_hop_mtu,
        });
    }
    return rows.toOwnedSlice(alloc);
}
