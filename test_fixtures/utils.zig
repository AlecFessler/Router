const std = @import("std");

/// Wireshark CSV fixtures omit the variable-length fields of a packet.
pub fn expectHeaderFields(expected: anytype, view: anytype) !void {
    inline for (std.meta.fields(@TypeOf(expected))) |field| {
        const T = switch (@typeInfo(field.type)) {
            .optional => |optional| optional.child,
            else => field.type,
        };
        if (@typeInfo(T) != .pointer) {
            const actual = view.get(@field(@TypeOf(view).Field, field.name));
            try std.testing.expectEqual(@field(expected, field.name), actual);
        }
    }
}

pub fn expectHexBytes(bytes: []const u8, hex: []const u8) !void {
    try std.testing.expectEqual(bytes.len * 2, hex.len);
    for (bytes, 0..) |byte, i| {
        try std.testing.expectEqual(byte, try std.fmt.parseInt(u8, hex[i * 2 ..][0..2], 16));
    }
}

/// Fill in the ICMPv4 checksum field of `bytes` (which must start with the
/// 4-byte ICMP header). Test-only helper for messages that are built by hand.
pub fn writeIcmpv4Checksum(bytes: []u8) void {
    std.debug.assert(bytes.len >= 4);
    bytes[2] = 0;
    bytes[3] = 0;
    var sum: u32 = 0;
    var i: usize = 0;
    while (i + 1 < bytes.len) : (i += 2) {
        sum += (@as(u32, bytes[i]) << 8) | bytes[i + 1];
    }
    if (i < bytes.len) sum += @as(u32, bytes[i]) << 8;
    while (sum >> 16 != 0) sum = (sum & 0xffff) + (sum >> 16);
    std.mem.writeInt(u16, bytes[2..4], ~@as(u16, @intCast(sum)), .big);
}
