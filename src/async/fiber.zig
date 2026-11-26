const std = @import("std");

pub const MIN_STACK_SIZE = 4 * 1024;

pub const Fiber = struct {
    pub const Start = *const fn (fiber: *Fiber, arg: *anyopaque) noreturn;

    context: std.Io.fiber.Context,
    stack: []align(16) u8,
    start: Start,
    arg: *anyopaque,

    pub fn init(
        allocator: std.mem.Allocator,
        stack_size: usize,
        start: Start,
        arg: *anyopaque,
    ) !Fiber {
        if (stack_size < MIN_STACK_SIZE) return error.StackTooSmall;
        const stack = try allocator.alignedAlloc(u8, .@"16", stack_size);
        const stack_top = std.mem.alignBackward(usize, @intFromPtr(stack.ptr) + stack.len, 16);
        const context: std.Io.fiber.Context = switch (@import("builtin").cpu.arch) {
            .x86_64 => .{
                .rsp = @intCast(stack_top - 8),
                .rbp = 0,
                .rip = @intFromPtr(&entry),
            },
            .aarch64, .riscv64 => .{
                .sp = @intCast(stack_top),
                .fp = 0,
                .pc = @intFromPtr(&entry),
            },
            else => @compileError("std.Io.fiber does not support this architecture"),
        };
        return .{
            .context = context,
            .stack = stack,
            .start = start,
            .arg = arg,
        };
    }

    pub fn deinit(self: *Fiber, allocator: std.mem.Allocator) void {
        allocator.free(self.stack);
        self.* = undefined;
    }

    pub fn switchTo(from: anytype, to: anytype) void {
        if (comptime @TypeOf(to) == *Fiber) starting_fiber = to;
        const sw: std.Io.fiber.Switch = .{
            .old = contextOf(from),
            .new = contextOf(to),
        };
        _ = std.Io.fiber.contextSwitch(&sw);
        starting_fiber = null;
    }

    fn contextOf(value: anytype) *std.Io.fiber.Context {
        return switch (@TypeOf(value)) {
            *Fiber => &value.context,
            *std.Io.fiber.Context => value,
            else => @compileError("switchTo expects a Fiber or Context pointer"),
        };
    }

    fn entry() callconv(.c) noreturn {
        const fiber = starting_fiber.?;
        starting_fiber = null;
        fiber.start(fiber, fiber.arg);
    }
};

threadlocal var starting_fiber: ?*Fiber = null;

test "fiber switches to the loop and resumes" {
    const Test = struct {
        loop_context: *std.Io.fiber.Context,
        steps: usize = 0,

        fn start(fiber: *Fiber, arg: *anyopaque) noreturn {
            const self: *@This() = @ptrCast(@alignCast(arg));
            self.steps += 1;
            Fiber.switchTo(fiber, self.loop_context);
            self.steps += 1;
            Fiber.switchTo(fiber, self.loop_context);
            unreachable;
        }
    };

    var loop_context: std.Io.fiber.Context = undefined;
    var test_state: Test = .{ .loop_context = &loop_context };
    var fiber = try Fiber.init(std.testing.allocator, 8 * 1024, Test.start, &test_state);
    defer fiber.deinit(std.testing.allocator);

    Fiber.switchTo(&loop_context, &fiber);
    try std.testing.expectEqual(@as(usize, 1), test_state.steps);
    Fiber.switchTo(&loop_context, &fiber);
    try std.testing.expectEqual(@as(usize, 2), test_state.steps);
}

test "fiber rejects a stack below the minimum size" {
    const Test = struct {
        fn start(_: *Fiber, _: *anyopaque) noreturn {
            unreachable;
        }
    };

    var arg: u8 = 0;
    try std.testing.expectError(error.StackTooSmall, Fiber.init(std.testing.allocator, MIN_STACK_SIZE - 1, Test.start, &arg));
}
