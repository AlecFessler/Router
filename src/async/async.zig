const std = @import("std");

const IFace = @import("../nic/api.zig").IFace;

pub const Fiber = @import("fiber.zig");
pub const FiberPool = @import("fiber_pool.zig");
pub const ReadyQueue = @import("ready_queue.zig");

pub const Running = struct {
    fiber: *Fiber.Fiber,
    loop_context: *std.Io.fiber.Context,
    owner: IFace,
};

threadlocal var running: ?Running = null;

pub fn setRunning(value: ?Running) void {
    running = value;
}

pub fn getRunning() ?Running {
    return running;
}
