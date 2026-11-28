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

    pub const Entry = struct {
        deadline: std.Io.Timestamp,
        buffers: [MAX_WAITERS_PER_NEIGHBOR][]u8 = undefined,
        len: usize = 0,

        fn append(self: *Entry, buffer: []u8) !void {
            if (self.len == MAX_WAITERS_PER_NEIGHBOR) return error.ArpWaitersFull;

            self.buffers[self.len] = buffer;
            self.len += 1;
        }

        pub fn release(self: *const Entry, device: NicApi) void {
            for (self.buffers[0..self.len]) |buffer| device.release(buffer);
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

    pub fn expire(self: *ArpWaitersTable, device: NicApi) void {
        const now = std.Io.Timestamp.now(self.io, .boot);
        self.mutex.lockUncancelable(self.io);
        var i: usize = 0;
        while (i < self.table.count()) {
            const entry = self.table.values()[i];
            if (entry.deadline.durationTo(now).toNanoseconds() < 0) {
                i += 1;
                continue;
            }
            self.table.swapRemoveAt(i);
            self.mutex.unlock(self.io);
            entry.release(device);
            self.mutex.lockUncancelable(self.io);
            i = 0; // Another worker may have moved a neighbor while the lock was released.
        }
        self.mutex.unlock(self.io);
    }

    /// Both interface workers have stopped at teardown.
    pub fn expireAll(self: *ArpWaitersTable, device: NicApi) void {
        for (self.table.values()) |*entry| entry.release(device);
        self.table.clearRetainingCapacity();
    }

    pub fn appendIfPending(self: *ArpWaitersTable, key: Key, buffer: []u8) !bool {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);

        const entry = self.table.getPtr(key) orelse return false;
        const now = std.Io.Timestamp.now(self.io, .boot);
        if (entry.deadline.durationTo(now).toNanoseconds() >= 0) return false;

        try entry.append(buffer);
        return true;
    }

    pub fn register(
        self: *ArpWaitersTable,
        key: Key,
        buffer: []u8,
        expired: *?Entry,
    ) !bool {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);

        const now = std.Io.Timestamp.now(self.io, .boot);

        if (self.table.getPtr(key)) |entry| {
            if (entry.deadline.durationTo(now).toNanoseconds() < 0) {
                try entry.append(buffer);
                return false;
            }
            expired.* = entry.*;
            _ = self.table.swapRemove(key);
        }

        if (self.table.count() == self.capacity) return error.ArpWaitersTableFull;

        var entry: Entry = .{
            .deadline = now.addDuration(self.timeout),
            .len = 1,
        };
        entry.buffers[0] = buffer;
        self.table.putAssumeCapacityNoClobber(key, entry);
        return true;
    }

    pub fn take(self: *ArpWaitersTable, key: Key) ?Entry {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        const removed = self.table.fetchSwapRemove(key) orelse return null;
        return removed.value;
    }
};
