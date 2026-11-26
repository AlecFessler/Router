const std = @import("std");
const Router = @import("router");

const IFace = Router.Nic.Api.IFace;
const IPv4 = Router.Protocols.IPv4.IPv4;
const Mac = Router.Protocols.Ethernet.Mac;
const ReadyQueue = Router.Async.ReadyQueue.ReadyQueue;

pub const ArpWaitersTable = struct {
    pub const MAX_WAITERS_PER_NEIGHBOR = 16;

    pub const Key = struct {
        iface: IFace,
        ip: IPv4,
    };

    pub const Outcome = union(enum) {
        resolved: Mac,
        timed_out,
    };

    pub const Waiter = struct {
        node: *ReadyQueue.Node,
        ready_queue: *ReadyQueue,
        outcome: *Outcome,
    };

    const Entry = struct {
        deadline: std.Io.Timestamp,
        waiters: [MAX_WAITERS_PER_NEIGHBOR]Waiter = undefined,
        len: usize = 0,
    };

    io: std.Io,
    timeout: std.Io.Duration,
    capacity: usize,
    mutex: std.Io.Mutex = .init,
    table: std.AutoArrayHashMapUnmanaged(Key, Entry) = .empty,

    pub fn init(
        alloc: std.mem.Allocator,
        io: std.Io,
        capacity: usize,
        timeout: std.Io.Duration,
    ) !ArpWaitersTable {
        var self: ArpWaitersTable = .{
            .io = io,
            .timeout = timeout,
            .capacity = capacity,
        };
        try self.table.ensureTotalCapacity(alloc, capacity);
        return self;
    }

    pub fn deinit(self: *ArpWaitersTable, alloc: std.mem.Allocator) void {
        std.debug.assert(self.table.count() == 0);
        self.table.deinit(alloc);
    }

    fn complete(entry: *Entry, outcome: Outcome) void {
        for (entry.waiters[0..entry.len]) |waiter| {
            waiter.outcome.* = outcome;
            waiter.ready_queue.push(waiter.node);
        }
    }

    fn expireLocked(self: *ArpWaitersTable, now: std.Io.Timestamp) void {
        var i: usize = 0;
        while (i < self.table.count()) {
            const entry = &self.table.values()[i];
            if (entry.deadline.durationTo(now).toNanoseconds() < 0) {
                i += 1;
                continue;
            }
            complete(entry, .timed_out);
            self.table.swapRemoveAt(i);
        }
    }

    pub fn expire(self: *ArpWaitersTable) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        self.expireLocked(std.Io.Timestamp.now(self.io, .boot));
    }

    pub fn expireAll(self: *ArpWaitersTable) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        while (self.table.count() > 0) {
            complete(&self.table.values()[self.table.count() - 1], .timed_out);
            self.table.swapRemoveAt(self.table.count() - 1);
        }
    }

    pub fn register(self: *ArpWaitersTable, key: Key, waiter: Waiter) !bool {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);

        const now = std.Io.Timestamp.now(self.io, .boot);
        self.expireLocked(now);
        if (self.table.getPtr(key)) |entry| {
            if (entry.len == MAX_WAITERS_PER_NEIGHBOR) return error.ArpWaitersFull;
            entry.waiters[entry.len] = waiter;
            entry.len += 1;
            return false;
        }
        if (self.table.count() == self.capacity) return error.ArpWaitersTableFull;
        self.table.putAssumeCapacityNoClobber(key, .{
            .deadline = now.addDuration(self.timeout),
        });
        const entry = self.table.getPtr(key).?;
        entry.waiters[0] = waiter;
        entry.len = 1;
        return true;
    }

    pub fn resolve(self: *ArpWaitersTable, key: Key, mac: Mac) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        const index = self.table.getIndex(key) orelse return;
        complete(&self.table.values()[index], .{ .resolved = mac });
        self.table.swapRemoveAt(index);
    }
};

test "neighbor waits share a request and resolve every waiter" {
    const Fiber = Router.Async.Fiber.Fiber;
    const Test = struct {
        fn start(_: *Fiber, _: *anyopaque) noreturn {
            unreachable;
        }
    };

    var queue = ReadyQueue.init(std.testing.io);
    var table = try ArpWaitersTable.init(std.testing.allocator, std.testing.io, 1, .fromSeconds(30));
    defer table.deinit(std.testing.allocator);
    var arg: u8 = 0;
    var first = try Fiber.init(std.testing.allocator, 4096, Test.start, &arg);
    defer first.deinit(std.testing.allocator);
    var second = try Fiber.init(std.testing.allocator, 4096, Test.start, &arg);
    defer second.deinit(std.testing.allocator);
    var first_node: ReadyQueue.Node = .{ .fiber = &first };
    var second_node: ReadyQueue.Node = .{ .fiber = &second };
    var first_outcome: ArpWaitersTable.Outcome = undefined;
    var second_outcome: ArpWaitersTable.Outcome = undefined;
    const key: ArpWaitersTable.Key = .{ .iface = .lan, .ip = .{ 192, 168, 86, 2 } };

    try std.testing.expect(try table.register(key, .{ .node = &first_node, .ready_queue = &queue, .outcome = &first_outcome }));
    try std.testing.expect(!(try table.register(key, .{ .node = &second_node, .ready_queue = &queue, .outcome = &second_outcome })));
    try std.testing.expectError(error.ArpWaitersTableFull, table.register(.{ .iface = .wan, .ip = key.ip }, .{ .node = &second_node, .ready_queue = &queue, .outcome = &second_outcome }));

    const mac: Mac = .{ 1, 2, 3, 4, 5, 6 };
    table.resolve(key, mac);
    try std.testing.expectEqualDeep(ArpWaitersTable.Outcome{ .resolved = mac }, first_outcome);
    try std.testing.expectEqualDeep(ArpWaitersTable.Outcome{ .resolved = mac }, second_outcome);
    try std.testing.expect(queue.pop() == &first);
    try std.testing.expect(queue.pop() == &second);
    try std.testing.expect(queue.pop() == null);
}

test "neighbor wait expiry queues a timeout" {
    const Fiber = Router.Async.Fiber.Fiber;
    const Test = struct {
        fn start(_: *Fiber, _: *anyopaque) noreturn {
            unreachable;
        }
    };

    var queue = ReadyQueue.init(std.testing.io);
    var table = try ArpWaitersTable.init(std.testing.allocator, std.testing.io, 1, .fromNanoseconds(0));
    defer table.deinit(std.testing.allocator);
    var arg: u8 = 0;
    var fiber = try Fiber.init(std.testing.allocator, 4096, Test.start, &arg);
    defer fiber.deinit(std.testing.allocator);
    var node: ReadyQueue.Node = .{ .fiber = &fiber };
    var outcome: ArpWaitersTable.Outcome = undefined;
    const key: ArpWaitersTable.Key = .{ .iface = .lan, .ip = .{ 192, 168, 86, 3 } };

    try std.testing.expect(try table.register(key, .{ .node = &node, .ready_queue = &queue, .outcome = &outcome }));
    table.expire();
    try std.testing.expectEqualDeep(ArpWaitersTable.Outcome.timed_out, outcome);
    try std.testing.expect(queue.pop() == &fiber);
    try std.testing.expect(queue.pop() == null);
}

test "neighbor waiters have a fixed per-key limit" {
    const Fiber = Router.Async.Fiber.Fiber;
    const Test = struct {
        fn start(_: *Fiber, _: *anyopaque) noreturn {
            unreachable;
        }
    };

    var queue = ReadyQueue.init(std.testing.io);
    var table = try ArpWaitersTable.init(std.testing.allocator, std.testing.io, 1, .fromSeconds(30));
    defer table.deinit(std.testing.allocator);
    var arg: u8 = 0;
    var fiber = try Fiber.init(std.testing.allocator, 4096, Test.start, &arg);
    defer fiber.deinit(std.testing.allocator);
    var nodes: [ArpWaitersTable.MAX_WAITERS_PER_NEIGHBOR + 1]ReadyQueue.Node = undefined;
    var outcomes: [ArpWaitersTable.MAX_WAITERS_PER_NEIGHBOR + 1]ArpWaitersTable.Outcome = undefined;
    const key: ArpWaitersTable.Key = .{ .iface = .lan, .ip = .{ 192, 168, 86, 4 } };

    for (0..ArpWaitersTable.MAX_WAITERS_PER_NEIGHBOR) |i| {
        nodes[i] = .{ .fiber = &fiber };
        _ = try table.register(key, .{ .node = &nodes[i], .ready_queue = &queue, .outcome = &outcomes[i] });
    }
    const last = ArpWaitersTable.MAX_WAITERS_PER_NEIGHBOR;
    nodes[last] = .{ .fiber = &fiber };
    try std.testing.expectError(error.ArpWaitersFull, table.register(key, .{
        .node = &nodes[last],
        .ready_queue = &queue,
        .outcome = &outcomes[last],
    }));
    table.expireAll();
    for (0..ArpWaitersTable.MAX_WAITERS_PER_NEIGHBOR) |_| {
        try std.testing.expect(queue.pop() == &fiber);
    }
    try std.testing.expect(queue.pop() == null);
}
