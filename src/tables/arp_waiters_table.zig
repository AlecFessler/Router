const std = @import("std");
const Router = @import("router");

const IFace = Router.Nic.Api.IFace;
const IPv4 = Router.Protocols.IPv4.IPv4;
const NicApi = Router.Nic.Api.Api;

pub const ArpWaitersTable = struct {
    pub const MAX_WAITERS_PER_NEIGHBOR = 16;

    pub const Key = struct {
        iface: IFace,
        ip: IPv4,
    };

    pub const Frame = struct {
        buffer: []u8,
        device: NicApi,
    };

    pub const Entry = struct {
        deadline: std.Io.Timestamp,
        frames: [MAX_WAITERS_PER_NEIGHBOR]Frame = undefined,
        len: usize = 0,

        pub fn release(self: *const Entry) void {
            for (self.frames[0..self.len]) |frame| frame.device.release(frame.buffer);
        }
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

    fn expireLocked(self: *ArpWaitersTable, now: std.Io.Timestamp) void {
        var i: usize = 0;
        while (i < self.table.count()) {
            const entry = &self.table.values()[i];
            if (entry.deadline.durationTo(now).toNanoseconds() < 0) {
                i += 1;
                continue;
            }
            entry.release();
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
            self.table.values()[self.table.count() - 1].release();
            self.table.swapRemoveAt(self.table.count() - 1);
        }
    }

    pub fn register(self: *ArpWaitersTable, key: Key, frame: Frame) !bool {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);

        const now = std.Io.Timestamp.now(self.io, .boot);
        self.expireLocked(now);
        if (self.table.getPtr(key)) |entry| {
            if (entry.len == MAX_WAITERS_PER_NEIGHBOR) return error.ArpWaitersFull;
            entry.frames[entry.len] = frame;
            entry.len += 1;
            return false;
        }
        if (self.table.count() == self.capacity) return error.ArpWaitersTableFull;
        var entry: Entry = .{ .deadline = now.addDuration(self.timeout), .len = 1 };
        entry.frames[0] = frame;
        self.table.putAssumeCapacityNoClobber(key, entry);
        return true;
    }

    pub fn take(self: *ArpWaitersTable, key: Key) ?Entry {
        const pending = blk: {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            const removed = self.table.fetchSwapRemove(key) orelse return null;
            break :blk removed.value;
        };
        const now = std.Io.Timestamp.now(self.io, .boot);
        if (pending.deadline.durationTo(now).toNanoseconds() >= 0) {
            pending.release();
            return null;
        }
        return pending;
    }
};
