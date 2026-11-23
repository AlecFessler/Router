const std = @import("std");
const Router = @import("router");

const Code = Router.Protocols.ICMPv4Messages.TimeExceeded.Code;

pub const Row = struct {
    frame_number: usize,
    code: Code,
    reserved: u32,
};

fn unquote(text: []const u8) ![]const u8 {
    if (text.len < 2 or text[0] != '"' or text[text.len - 1] != '"')
        return error.UnexpectedFileFormat;
    return text[1 .. text.len - 1];
}

pub fn parse(file: []const u8, alloc: std.mem.Allocator) ![]Row {
    var rows: std.ArrayList(Row) = .empty;
    defer rows.deinit(alloc);
    var lines = std.mem.splitScalar(u8, file, '\n');
    _ = lines.next() orelse return error.UnexpectedFileFormat;
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        var parts = std.mem.splitScalar(u8, std.mem.trimEnd(u8, line, "\r"), ',');
        const frame_number = try std.fmt.parseInt(usize, try unquote(parts.next() orelse return error.UnexpectedFileFormat), 10);
        const message_type = try std.fmt.parseInt(u8, try unquote(parts.next() orelse return error.UnexpectedFileFormat), 10);
        if (message_type != 11) return error.UnexpectedFileFormat;
        const code_number = try std.fmt.parseInt(u8, try unquote(parts.next() orelse return error.UnexpectedFileFormat), 10);
        const code = std.enums.fromInt(Code, code_number) orelse return error.UnexpectedFileFormat;
        const unused = try unquote(parts.next() orelse return error.UnexpectedFileFormat);
        if (unused.len != 8 or parts.next() != null) return error.UnexpectedFileFormat;
        const reserved = try std.fmt.parseInt(u32, unused, 16);
        try rows.append(alloc, .{
            .frame_number = frame_number,
            .code = code,
            .reserved = reserved,
        });
    }
    return rows.toOwnedSlice(alloc);
}
