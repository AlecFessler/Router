const std = @import("std");

pub fn expectHexBytes(bytes: []const u8, hex: []const u8) !void {
    try std.testing.expectEqual(bytes.len * 2, hex.len);
    for (bytes, 0..) |byte, i| {
        try std.testing.expectEqual(byte, try std.fmt.parseInt(u8, hex[i * 2 ..][0..2], 16));
    }
}
