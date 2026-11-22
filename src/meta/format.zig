const std = @import("std");

fn EnumLabel(comptime E: type) type {
    if (@typeInfo(E) != .@"enum") @compileError("enumLabel expects an enum value");

    return struct {
        value: E,

        pub fn format(self: @This(), writer: *std.Io.Writer) std.Io.Writer.Error!void {
            if (std.enums.tagName(E, self.value)) |name| {
                try writer.writeAll(name);
            } else {
                try writer.print("{}", .{@intFromEnum(self.value)});
            }
        }
    };
}

/// Formats an enum's tag name or numeric value with a `{f}` placeholder.
pub fn enumLabel(value: anytype) EnumLabel(@TypeOf(value)) {
    return .{ .value = value };
}
