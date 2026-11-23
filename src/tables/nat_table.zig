const std = @import("std");
const Router = @import("router");

const IPv4 = Router.Protocols.IPv4.IPv4;
const Protocol = Router.Protocols.IPv4.Protocol;

pub const NatTable = struct {
    pub const Key = struct {
        protocol: Protocol,
        ip: IPv4,
        port: u16,
    };

    pub const Entry = struct {
        outside: Key,
        deadline: std.Io.Timestamp,
    };

    io: std.Io,
    inside: std.AutoArrayHashMapUnmanaged(Key, Entry) = .empty,
    outside: std.AutoHashMapUnmanaged(Key, Key) = .empty,

    pub fn init(io: std.Io) NatTable {
        return .{
            .io = io,
        };
    }

    pub fn deinit(self: *NatTable, alloc: std.mem.Allocator) void {
        self.inside.deinit(alloc);
        self.outside.deinit(alloc);
    }

    fn isExpired(deadline: std.Io.Timestamp, now: std.Io.Timestamp) bool {
        return deadline.durationTo(now).toNanoseconds() >= 0;
    }

    pub fn reclaimExpired(self: *NatTable) void {
        const now = std.Io.Timestamp.now(self.io, .boot);
        var index: usize = 0;
        while (index < self.inside.count()) {
            const entry = self.inside.values()[index];
            if (!isExpired(entry.deadline, now)) {
                index += 1;
                continue;
            }
            self.inside.swapRemoveAt(index);
            const reverse_removed = self.outside.remove(entry.outside);
            std.debug.assert(reverse_removed);
        }
    }

    pub fn inboundLookup(
        self: *NatTable,
        key: Key,
    ) ?struct { Key, Entry } {
        const inside_key = self.outside.get(key) orelse return null;
        const entry = self.inside.get(inside_key) orelse unreachable;
        const now = std.Io.Timestamp.now(self.io, .boot);
        if (isExpired(entry.deadline, now)) {
            self.remove(inside_key);
            return null;
        }
        return .{ inside_key, entry };
    }

    pub fn outboundLookup(
        self: *NatTable,
        key: Key,
    ) ?Entry {
        const entry = self.inside.get(key) orelse return null;
        const now = std.Io.Timestamp.now(self.io, .boot);
        if (isExpired(entry.deadline, now)) {
            self.remove(key);
            return null;
        }
        return entry;
    }

    pub fn insert(
        self: *NatTable,
        alloc: std.mem.Allocator,
        key: Key,
        entry: Entry,
    ) !void {
        if (key.protocol != entry.outside.protocol) return error.ProtocolMismatch;

        const now = std.Io.Timestamp.now(self.io, .boot);
        if (self.inside.get(key)) |existing| {
            if (!isExpired(existing.deadline, now)) return error.InsideKeyInUse;
            self.remove(key);
        }
        if (self.outside.get(entry.outside)) |existing_key| {
            const existing = self.inside.get(existing_key) orelse unreachable;
            if (!isExpired(existing.deadline, now)) return error.OutsideKeyInUse;
            self.remove(existing_key);
        }

        try self.inside.ensureUnusedCapacity(alloc, 1);
        try self.outside.ensureUnusedCapacity(alloc, 1);
        self.inside.putAssumeCapacityNoClobber(key, entry);
        self.outside.putAssumeCapacityNoClobber(entry.outside, key);
    }

    pub fn refresh(
        self: *NatTable,
        key: Key,
        duration: std.Io.Duration,
    ) !void {
        const now = std.Io.Timestamp.now(self.io, .boot);
        const entry = self.inside.getPtr(key) orelse return error.NotFound;
        if (isExpired(entry.deadline, now)) {
            self.remove(key);
            return error.NotFound;
        }
        entry.deadline = now.addDuration(duration);
    }

    pub fn remove(
        self: *NatTable,
        key: Key,
    ) void {
        const removed = self.inside.fetchSwapRemove(key) orelse return;
        const reverse_removed = self.outside.remove(removed.value.outside);
        std.debug.assert(reverse_removed);
    }
};

test "NAT mappings resolve in both directions, refresh, and remove together" {
    const alloc = std.testing.allocator;
    var table = NatTable.init(std.testing.io);
    defer table.deinit(alloc);
    const inside: NatTable.Key = .{ .protocol = .tcp, .ip = .{ 192, 168, 1, 10 }, .port = 50000 };
    const outside: NatTable.Key = .{ .protocol = .tcp, .ip = .{ 203, 0, 113, 5 }, .port = 60000 };
    const deadline = std.Io.Timestamp.now(std.testing.io, .boot).addDuration(.fromSeconds(60));

    try table.insert(alloc, inside, .{ .outside = outside, .deadline = deadline });
    try std.testing.expectEqualDeep(outside, table.outboundLookup(inside).?.outside);
    const inbound = table.inboundLookup(outside).?;
    try std.testing.expectEqualDeep(inside, inbound[0]);
    try std.testing.expectEqualDeep(outside, inbound[1].outside);

    try table.refresh(inside, .fromSeconds(120));
    try std.testing.expect(table.outboundLookup(inside).?.deadline.toNanoseconds() > deadline.toNanoseconds());

    table.remove(inside);
    try std.testing.expect(table.outboundLookup(inside) == null);
    try std.testing.expect(table.inboundLookup(outside) == null);
    try std.testing.expectError(error.NotFound, table.refresh(inside, .fromSeconds(60)));
}

test "NAT insert rejects occupied endpoints and keeps protocols separate" {
    const alloc = std.testing.allocator;
    var table = NatTable.init(std.testing.io);
    defer table.deinit(alloc);
    const inside: NatTable.Key = .{ .protocol = .tcp, .ip = .{ 192, 168, 1, 10 }, .port = 50000 };
    const outside: NatTable.Key = .{ .protocol = .tcp, .ip = .{ 203, 0, 113, 5 }, .port = 60000 };
    const other_inside: NatTable.Key = .{ .protocol = .tcp, .ip = .{ 192, 168, 1, 11 }, .port = 50000 };
    const other_outside: NatTable.Key = .{ .protocol = .tcp, .ip = .{ 203, 0, 113, 5 }, .port = 60001 };
    const deadline = std.Io.Timestamp.now(std.testing.io, .boot).addDuration(.fromSeconds(60));

    try table.insert(alloc, inside, .{ .outside = outside, .deadline = deadline });
    try std.testing.expectError(error.InsideKeyInUse, table.insert(alloc, inside, .{ .outside = other_outside, .deadline = deadline }));
    try std.testing.expectError(error.OutsideKeyInUse, table.insert(alloc, other_inside, .{ .outside = outside, .deadline = deadline }));
    try std.testing.expectError(error.ProtocolMismatch, table.insert(alloc, other_inside, .{ .outside = .{ .protocol = .udp, .ip = outside.ip, .port = outside.port }, .deadline = deadline }));
    try std.testing.expectEqual(@as(usize, 1), table.inside.count());
    try std.testing.expectEqual(@as(usize, 1), table.outside.count());
    try std.testing.expectEqualDeep(inside, table.inboundLookup(outside).?[0]);

    const udp_inside: NatTable.Key = .{ .protocol = .udp, .ip = inside.ip, .port = inside.port };
    const udp_outside: NatTable.Key = .{ .protocol = .udp, .ip = outside.ip, .port = outside.port };
    try table.insert(alloc, udp_inside, .{ .outside = udp_outside, .deadline = deadline });
    try std.testing.expectEqual(@as(usize, 2), table.inside.count());
    try std.testing.expectEqual(@as(usize, 2), table.outside.count());
}

test "NAT lookup and sweep remove expired mappings from both indexes" {
    const alloc = std.testing.allocator;
    var table = NatTable.init(std.testing.io);
    defer table.deinit(alloc);
    const inside_a: NatTable.Key = .{ .protocol = .udp, .ip = .{ 192, 168, 1, 10 }, .port = 50000 };
    const outside_a: NatTable.Key = .{ .protocol = .udp, .ip = .{ 203, 0, 113, 5 }, .port = 60000 };
    const inside_b: NatTable.Key = .{ .protocol = .udp, .ip = .{ 192, 168, 1, 11 }, .port = 50001 };
    const outside_b: NatTable.Key = .{ .protocol = .udp, .ip = .{ 203, 0, 113, 5 }, .port = 60001 };
    const inside_c: NatTable.Key = .{ .protocol = .udp, .ip = .{ 192, 168, 1, 12 }, .port = 50002 };
    const outside_c: NatTable.Key = .{ .protocol = .udp, .ip = .{ 203, 0, 113, 5 }, .port = 60002 };
    const expired: std.Io.Timestamp = .fromNanoseconds(0);
    const live = std.Io.Timestamp.now(std.testing.io, .boot).addDuration(.fromSeconds(60));

    try table.insert(alloc, inside_a, .{ .outside = outside_a, .deadline = expired });
    try std.testing.expect(table.inboundLookup(outside_a) == null);
    try std.testing.expectEqual(@as(usize, 0), table.inside.count());
    try std.testing.expectEqual(@as(usize, 0), table.outside.count());

    try table.insert(alloc, inside_a, .{ .outside = outside_a, .deadline = expired });
    try table.insert(alloc, inside_b, .{ .outside = outside_b, .deadline = live });
    try table.insert(alloc, inside_c, .{ .outside = outside_c, .deadline = expired });
    table.reclaimExpired();
    try std.testing.expect(table.outboundLookup(inside_a) == null);
    try std.testing.expect(table.inboundLookup(outside_a) == null);
    try std.testing.expect(table.outboundLookup(inside_c) == null);
    try std.testing.expect(table.inboundLookup(outside_c) == null);
    try std.testing.expect(table.outboundLookup(inside_b) != null);
    try std.testing.expectEqual(@as(usize, 1), table.inside.count());
    try std.testing.expectEqual(@as(usize, 1), table.outside.count());
}

test "NAT insert leaves both indexes empty when allocation fails" {
    var table = NatTable.init(std.testing.io);
    var bytes: [0]u8 = .{};
    var fixed = std.heap.FixedBufferAllocator.init(&bytes);
    const alloc = fixed.allocator();
    defer table.deinit(alloc);
    const inside: NatTable.Key = .{ .protocol = .icmp, .ip = .{ 192, 168, 1, 10 }, .port = 1234 };
    const outside: NatTable.Key = .{ .protocol = .icmp, .ip = .{ 203, 0, 113, 5 }, .port = 5678 };
    const deadline = std.Io.Timestamp.now(std.testing.io, .boot).addDuration(.fromSeconds(60));

    try std.testing.expectError(error.OutOfMemory, table.insert(alloc, inside, .{ .outside = outside, .deadline = deadline }));
    try std.testing.expectEqual(@as(usize, 0), table.inside.count());
    try std.testing.expectEqual(@as(usize, 0), table.outside.count());
}
