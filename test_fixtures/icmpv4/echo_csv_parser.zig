const std = @import("std");
const Router = @import("router");

pub const Row = struct {
    frame_number: usize,
    message_type: Router.Protocols.ICMPv4.MessageType,
    identifier: u16,
    sequence_number: u16,
};

fn decimal(comptime T: type, text: []const u8) !T {
    if (text.len < 2 or text[0] != '"' or text[text.len - 1] != '"')
        return error.UnexpectedFileFormat;
    return std.fmt.parseInt(T, text[1 .. text.len - 1], 10);
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
        const message_type: Router.Protocols.ICMPv4.MessageType = @enumFromInt(try decimal(u8, parts.next() orelse return error.UnexpectedFileFormat));
        const identifier = try decimal(u16, parts.next() orelse return error.UnexpectedFileFormat);
        const sequence_number = try decimal(u16, parts.next() orelse return error.UnexpectedFileFormat);
        if (parts.next() != null) return error.UnexpectedFileFormat;
        try rows.append(alloc, .{
            .frame_number = frame_number,
            .message_type = message_type,
            .identifier = identifier,
            .sequence_number = sequence_number,
        });
    }
    return rows.toOwnedSlice(alloc);
}
