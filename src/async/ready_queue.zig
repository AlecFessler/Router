const std = @import("std");

const Fiber = @import("fiber.zig").Fiber;

pub const ReadyQueue = struct {
    pub const Node = struct {
        fiber: *Fiber,
        next: ?*Node = null,
    };

    io: std.Io,
    mutex: std.Io.Mutex = .init,
    head: ?*Node = null,
    tail: ?*Node = null,

    pub fn init(io: std.Io) ReadyQueue {
        return .{ .io = io };
    }

    pub fn push(self: *ReadyQueue, node: *Node) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);

        node.next = null;
        if (self.tail) |tail| {
            tail.next = node;
        } else {
            self.head = node;
        }
        self.tail = node;
    }

    pub fn pop(self: *ReadyQueue) ?*Fiber {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);

        const node = self.head orelse return null;
        self.head = node.next;
        if (self.head == null) self.tail = null;
        node.next = null;
        return node.fiber;
    }
};

test "ready queue returns fibers in insertion order" {
    const Test = struct {
        fn start(_: *Fiber, _: *anyopaque) noreturn {
            unreachable;
        }
    };

    var arg: u8 = 0;
    var first = try Fiber.init(std.testing.allocator, 4 * 1024, Test.start, &arg);
    defer first.deinit(std.testing.allocator);
    var second = try Fiber.init(std.testing.allocator, 4 * 1024, Test.start, &arg);
    defer second.deinit(std.testing.allocator);
    var first_node: ReadyQueue.Node = .{ .fiber = &first };
    var second_node: ReadyQueue.Node = .{ .fiber = &second };
    var queue = ReadyQueue.init(std.testing.io);

    try std.testing.expect(queue.pop() == null);
    queue.push(&first_node);
    queue.push(&second_node);
    try std.testing.expect(queue.pop() == &first);
    try std.testing.expect(queue.pop() == &second);
    try std.testing.expect(queue.pop() == null);
}
