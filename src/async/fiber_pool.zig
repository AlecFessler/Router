const std = @import("std");

const Fiber = @import("fiber.zig").Fiber;
const MIN_STACK_SIZE = @import("fiber.zig").MIN_STACK_SIZE;

pub const FiberPool = struct {
    const Slot = struct {
        fiber: Fiber,
        initial_context: std.Io.fiber.Context,
    };

    allocator: std.mem.Allocator,
    stack_size: usize,
    cache: []*Slot,
    cache_len: usize = 0,

    pub fn init(
        allocator: std.mem.Allocator,
        stack_size: usize,
        cache_capacity: usize,
    ) !FiberPool {
        if (stack_size < MIN_STACK_SIZE) return error.StackTooSmall;
        return .{
            .allocator = allocator,
            .stack_size = stack_size,
            .cache = try allocator.alloc(*Slot, cache_capacity),
        };
    }

    pub fn deinit(self: *FiberPool) void {
        for (self.cache[0..self.cache_len]) |slot| {
            slot.fiber.deinit(self.allocator);
            self.allocator.destroy(slot);
        }
        self.allocator.free(self.cache);
        self.* = undefined;
    }

    pub fn acquire(self: *FiberPool, start: Fiber.Start, arg: *anyopaque) !*Fiber {
        if (self.cache_len > 0) {
            self.cache_len -= 1;
            const slot = self.cache[self.cache_len];
            slot.fiber.context = slot.initial_context;
            slot.fiber.start = start;
            slot.fiber.arg = arg;
            return &slot.fiber;
        }

        const slot = try self.allocator.create(Slot);
        errdefer self.allocator.destroy(slot);
        slot.fiber = try Fiber.init(self.allocator, self.stack_size, start, arg);
        slot.initial_context = slot.fiber.context;
        return &slot.fiber;
    }

    pub fn release(self: *FiberPool, fiber: *Fiber) void {
        const slot: *Slot = @fieldParentPtr("fiber", fiber);
        if (self.cache_len < self.cache.len) {
            self.cache[self.cache_len] = slot;
            self.cache_len += 1;
        } else {
            slot.fiber.deinit(self.allocator);
            self.allocator.destroy(slot);
        }
    }
};

test "pool caches a returned fiber and frees returns past capacity" {
    const Test = struct {
        loop_context: *std.Io.fiber.Context,
        calls: usize = 0,

        fn start(fiber: *Fiber, arg: *anyopaque) noreturn {
            const self: *@This() = @ptrCast(@alignCast(arg));
            self.calls += 1;
            Fiber.switchTo(fiber, self.loop_context);
            unreachable;
        }
    };

    var pool = try FiberPool.init(std.testing.allocator, 8 * 1024, 1);
    defer pool.deinit();
    var loop_context: std.Io.fiber.Context = undefined;
    var first_state: Test = .{ .loop_context = &loop_context };
    var second_state: Test = .{ .loop_context = &loop_context };

    const first = try pool.acquire(Test.start, &first_state);
    const first_stack = first.stack.ptr;
    const second = try pool.acquire(Test.start, &second_state);
    try std.testing.expect(first != second);

    Fiber.switchTo(&loop_context, first);
    Fiber.switchTo(&loop_context, second);
    try std.testing.expectEqual(@as(usize, 1), first_state.calls);
    try std.testing.expectEqual(@as(usize, 1), second_state.calls);

    pool.release(first);
    pool.release(second);
    try std.testing.expectEqual(@as(usize, 1), pool.cache_len);

    const reused = try pool.acquire(Test.start, &second_state);
    try std.testing.expect(reused == first);
    try std.testing.expect(reused.stack.ptr == first_stack);
    Fiber.switchTo(&loop_context, reused);
    try std.testing.expectEqual(@as(usize, 2), second_state.calls);
    pool.release(reused);
}

test "pool rejects an undersized stack" {
    try std.testing.expectError(error.StackTooSmall, FiberPool.init(std.testing.allocator, MIN_STACK_SIZE - 1, 1));
}
