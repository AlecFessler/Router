const std = @import("std");
const Router = @import("router");

const IPv4 = Router.Protocols.IPv4.IPv4;
const NatTable = Router.Tables.NatTable.NatTable;
const NicApi = Router.Nic.Api.Api;
const Protocol = Router.Protocols.IPv4.Protocol;

pub const IPv4FragmentTable = struct {
    pub const MAX_PENDING_FRAGMENTS = 16;

    pub const Key = struct {
        src: IPv4,
        dst: IPv4,
        identification: u16,
        protocol: Protocol,
    };

    pub const Translation = struct {
        nat_key: NatTable.Key,
        nat_generation: u64,
        identification: u16,
        first_payload_len: usize,
    };

    pub const Batch = struct {
        buffers: [MAX_PENDING_FRAGMENTS][]u8 = undefined,
        len: usize = 0,

        fn release(self: *const Batch, device: NicApi) void {
            for (self.buffers[0..self.len]) |buffer| device.release(buffer);
        }
    };

    pub const AppendResult = union(enum) {
        queued,
        resolved: Translation,
    };

    const Entry = struct {
        deadline: std.Io.Timestamp,
        state: union(enum) {
            waiting: Batch,
            resolved: Translation,
        } = .{ .waiting = .{} },
    };

    io: std.Io,
    capacity: u32,
    timeout: std.Io.Duration,
    next_identification: u16 = 0,
    id_reuse_after: std.Io.Timestamp = .zero,
    table: std.AutoHashMapUnmanaged(Key, Entry) = .empty,

    pub fn init(
        alloc: std.mem.Allocator,
        io: std.Io,
        capacity: u32,
        timeout: std.Io.Duration,
    ) !IPv4FragmentTable {
        var self: IPv4FragmentTable = .{
            .io = io,
            .capacity = capacity,
            .timeout = timeout,
        };

        try self.table.ensureTotalCapacity(alloc, capacity);
        return self;
    }

    pub fn deinit(
        self: *IPv4FragmentTable,
        alloc: std.mem.Allocator,
        device: NicApi,
    ) void {
        var entries = self.table.valueIterator();
        while (entries.next()) |entry| {
            if (entry.state == .waiting) entry.state.waiting.release(device);
        }

        self.table.deinit(alloc);
    }

    pub fn append(
        self: *IPv4FragmentTable,
        key: Key,
        buffer: []u8,
        device: NicApi,
    ) !AppendResult {
        const entry = try self.getOrCreate(key, device);

        switch (entry.state) {
            .resolved => |translation| return .{ .resolved = translation },
            .waiting => |*batch| {
                if (batch.len == MAX_PENDING_FRAGMENTS) return error.FragmentBatchFull;

                batch.buffers[batch.len] = buffer;
                batch.len += 1;
                return .queued;
            },
        }
    }

    pub fn resolve(
        self: *IPv4FragmentTable,
        key: Key,
        translation: Translation,
        device: NicApi,
    ) !Batch {
        const entry = try self.getOrCreate(key, device);
        const batch: Batch = switch (entry.state) {
            .waiting => |waiting| waiting,
            .resolved => .{},
        };

        entry.state = .{ .resolved = translation };
        return batch;
    }

    pub fn get(self: *const IPv4FragmentTable, key: Key) ?Translation {
        const entry = self.table.getPtr(key) orelse return null;
        const now = std.Io.Timestamp.now(self.io, .boot);
        if (entry.deadline.durationTo(now).toNanoseconds() >= 0) return null;

        return switch (entry.state) {
            .waiting => null,
            .resolved => |translation| translation,
        };
    }

    pub fn allocateIdentification(self: *IPv4FragmentTable) !u16 {
        const now = std.Io.Timestamp.now(self.io, .boot);
        const identification = self.next_identification;
        if (identification == 0 and self.id_reuse_after.durationTo(now).toNanoseconds() < 0) {
            return error.FragmentIdentificationExhausted;
        }

        self.next_identification +%= 1;
        if (self.next_identification == 0) self.id_reuse_after = now.addDuration(self.timeout);
        return identification;
    }

    fn getOrCreate(self: *IPv4FragmentTable, key: Key, device: NicApi) !*Entry {
        const now = std.Io.Timestamp.now(self.io, .boot);
        var entries = self.table.iterator();
        while (entries.next()) |item| {
            const entry = item.value_ptr;
            if (entry.deadline.durationTo(now).toNanoseconds() < 0) continue;

            if (entry.state == .waiting) entry.state.waiting.release(device);
            self.table.removeByPtr(item.key_ptr);
        }

        if (self.table.getPtr(key)) |entry| return entry;
        if (self.table.count() == self.capacity) return error.FragmentTableFull;

        const entry = self.table.getOrPutAssumeCapacity(key).value_ptr;
        entry.* = .{ .deadline = now.addDuration(self.timeout) };
        return entry;
    }
};

test "fragment table drains queued buffers and reclaims expired entries" {
    const TestNic = struct {
        released: [2][]u8 = undefined,
        len: usize = 0,

        fn release(ctx: *anyopaque, buffer: []u8) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.released[self.len] = buffer;
            self.len += 1;
        }
    };

    var nic: TestNic = .{};
    const device: NicApi = .{
        .ptr = &nic,
        .vtable = &.{
            .receive = undefined,
            .nextTxBuffer = undefined,
            .macAddress = undefined,
            .release = TestNic.release,
            .transmit = undefined,
        },
    };

    const alloc = std.testing.allocator;
    var table = try IPv4FragmentTable.init(alloc, std.testing.io, 1, .fromSeconds(30));
    defer table.deinit(alloc, device);

    const key: IPv4FragmentTable.Key = .{
        .src = .{ 192, 168, 86, 2 },
        .dst = .{ 203, 0, 113, 2 },
        .identification = 1,
        .protocol = .tcp,
    };
    var next_key = key;
    next_key.identification += 1;

    const translation: IPv4FragmentTable.Translation = .{
        .nat_key = .{ .ip = key.src, .protocol = .tcp, .port = 50000 },
        .nat_generation = 1,
        .identification = 42,
        .first_payload_len = 24,
    };

    var first: [1]u8 = undefined;
    var second: [1]u8 = undefined;
    try std.testing.expect((try table.append(key, &first, device)) == .queued);
    try std.testing.expect((try table.append(key, &second, device)) == .queued);
    try std.testing.expectError(error.FragmentTableFull, table.resolve(next_key, translation, device));

    const batch = try table.resolve(key, translation, device);
    try std.testing.expectEqual(@as(usize, 2), batch.len);
    try std.testing.expect(batch.buffers[0].ptr == first[0..].ptr);
    try std.testing.expect(batch.buffers[1].ptr == second[0..].ptr);

    const result = try table.append(key, &first, device);
    try std.testing.expectEqualDeep(translation, result.resolved);
    try std.testing.expectEqual(@as(usize, 0), nic.len);

    table.table.getPtr(key).?.deadline = .zero;
    try std.testing.expect((try table.append(next_key, &first, device)) == .queued);
    table.table.getPtr(next_key).?.deadline = .zero;
    try std.testing.expect((try table.append(key, &second, device)) == .queued);

    try std.testing.expectEqual(@as(usize, 1), nic.len);
    try std.testing.expect(nic.released[0].ptr == first[0..].ptr);
}
