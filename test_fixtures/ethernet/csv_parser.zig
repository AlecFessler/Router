const std = @import("std");
const Router = @import("router");

const Ethernet = Router.Protocols.Ethernet;
const Mac = Ethernet.Mac;

pub const Frame = struct {
    number: usize,
    dst_mac: Mac,
    src_mac: Mac,
    ethertype: Ethernet.Ethertype,
    vlan: ?Ethernet.VlanTag,
};

fn parseMac(str: []const u8) !Mac {
    var parts = std.mem.splitScalar(u8, str, ':');
    var mac: Mac = undefined;
    for (&mac) |*byte| {
        byte.* = try std.fmt.parseInt(u8, parts.next() orelse return error.InvalidMac, 16);
    }
    if (parts.next() != null) return error.InvalidMac;
    return mac;
}

fn parseHex(str: []const u8) !u16 {
    if (!std.mem.startsWith(u8, str, "0x")) return error.UnexpectedFileFormat;
    return std.fmt.parseInt(u16, str[2..], 16);
}

pub fn parse(file: []const u8, alloc: std.mem.Allocator) ![]Frame {
    var frames: std.ArrayList(Frame) = .empty;
    defer frames.deinit(alloc);

    var lines = std.mem.splitScalar(u8, file, '\n');
    _ = lines.next() orelse return error.UnexpectedFileFormat;
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        var columns: [9][]const u8 = undefined;
        var parts = std.mem.splitScalar(u8, std.mem.trimEnd(u8, line, "\r"), ',');
        for (&columns) |*column| column.* = parts.next() orelse return error.UnexpectedFileFormat;
        if (parts.next() != null) return error.UnexpectedFileFormat;

        const has_vlan = columns[5].len != 0;
        const type_text = if (has_vlan) columns[8] else columns[3];
        const raw_type: u16 = if (type_text.len != 0)
            try parseHex(type_text)
        else
            try std.fmt.parseInt(u16, columns[4], 10);
        const vlan: ?Ethernet.VlanTag = if (has_vlan) .{
            .tpid = @enumFromInt(try parseHex(columns[3])),
            .pcp = try std.fmt.parseInt(u3, columns[6], 10),
            .dei = if (std.mem.eql(u8, columns[7], "True")) true else if (std.mem.eql(u8, columns[7], "False")) false else return error.UnexpectedFileFormat,
            .vid = try std.fmt.parseInt(u12, columns[5], 10),
        } else null;
        try frames.append(alloc, .{
            .number = try std.fmt.parseInt(usize, columns[0], 10),
            .dst_mac = try parseMac(columns[1]),
            .src_mac = try parseMac(columns[2]),
            .ethertype = @enumFromInt(raw_type),
            .vlan = vlan,
        });
    }
    return frames.toOwnedSlice(alloc);
}
