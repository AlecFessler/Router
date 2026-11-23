const std = @import("std");
const Router = @import("router");

const IPv4 = Router.Protocols.IPv4.IPv4;
const Protocol = Router.Protocols.IPv4.Protocol;

// Each protocol that accesses the NAT table needs to initialize its own Port Allocator
pub const PortAllocator = struct {
    const PortSet = std.StaticBitSet(1 << 16);

    pub const first_port: u16 = 1024;
    pub const last_port: u16 = 65535;
    const port_count: usize = @as(usize, last_port) - first_port + 1;

    used: PortSet = PortSet.initEmpty(),
    next: u16 = 49152,

    fn nextPort(port: u16) u16 {
        return if (port == last_port) first_port else port + 1;
    }

    pub fn allocate(self: *PortAllocator, preferred: u16) !u16 {
        if (preferred >= first_port and !self.used.isSet(preferred)) {
            self.used.set(preferred);
            return preferred;
        }

        var candidate = self.next;
        for (0..port_count) |_| {
            if (!self.used.isSet(candidate)) {
                self.used.set(candidate);
                self.next = nextPort(candidate);
                return candidate;
            }
            candidate = nextPort(candidate);
        }
        return error.NoPortsAvailable;
    }

    pub fn release(self: *PortAllocator, port: u16) void {
        std.debug.assert(port >= first_port and self.used.isSet(port));
        self.used.unset(port);
    }

    pub fn isAllocated(self: *const PortAllocator, port: u16) bool {
        return self.used.isSet(port);
    }
};

// There is intended to be one global NAT table
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

    pub fn reclaimExpired(self: *NatTable, protocol: Protocol, port_allocator: *PortAllocator) void {
        const now = std.Io.Timestamp.now(self.io, .boot);
        var index: usize = 0;
        while (index < self.inside.count()) {
            const entry = self.inside.values()[index];
            if (entry.outside.protocol != protocol or !isExpired(entry.deadline, now)) {
                index += 1;
                continue;
            }
            self.inside.swapRemoveAt(index);
            const reverse_removed = self.outside.remove(entry.outside);
            std.debug.assert(reverse_removed);
            port_allocator.release(entry.outside.port);
        }
    }

    pub fn inboundLookup(
        self: *NatTable,
        port_allocator: *PortAllocator,
        key: Key,
    ) ?struct { Key, Entry } {
        const inside_key = self.outside.get(key) orelse return null;
        const entry = self.inside.get(inside_key) orelse unreachable;
        const now = std.Io.Timestamp.now(self.io, .boot);
        if (isExpired(entry.deadline, now)) {
            self.remove(port_allocator, inside_key);
            return null;
        }
        return .{ inside_key, entry };
    }

    pub fn outboundLookup(
        self: *NatTable,
        port_allocator: *PortAllocator,
        key: Key,
    ) ?Entry {
        const entry = self.inside.get(key) orelse return null;
        const now = std.Io.Timestamp.now(self.io, .boot);
        if (isExpired(entry.deadline, now)) {
            self.remove(port_allocator, key);
            return null;
        }
        return entry;
    }

    pub fn insert(
        self: *NatTable,
        alloc: std.mem.Allocator,
        port_allocator: *PortAllocator,
        key: Key,
        outside_ip: IPv4,
        duration: std.Io.Duration,
    ) !Entry {
        const now = std.Io.Timestamp.now(self.io, .boot);
        if (self.inside.get(key)) |existing| {
            if (!isExpired(existing.deadline, now)) return error.InsideKeyInUse;
            self.remove(port_allocator, key);
        }

        try self.inside.ensureUnusedCapacity(alloc, 1);
        try self.outside.ensureUnusedCapacity(alloc, 1);
        const outside_port = port_allocator.allocate(key.port) catch |err| switch (err) {
            error.NoPortsAvailable => blk: {
                self.reclaimExpired(key.protocol, port_allocator);
                break :blk try port_allocator.allocate(key.port);
            },
        };
        const entry: Entry = .{
            .outside = .{ .protocol = key.protocol, .ip = outside_ip, .port = outside_port },
            .deadline = now.addDuration(duration),
        };
        std.debug.assert(!self.outside.contains(entry.outside));
        self.inside.putAssumeCapacityNoClobber(key, entry);
        self.outside.putAssumeCapacityNoClobber(entry.outside, key);
        return entry;
    }

    pub fn refresh(
        self: *NatTable,
        port_allocator: *PortAllocator,
        key: Key,
        duration: std.Io.Duration,
    ) !void {
        const now = std.Io.Timestamp.now(self.io, .boot);
        const entry = self.inside.getPtr(key) orelse return error.NotFound;
        if (isExpired(entry.deadline, now)) {
            self.remove(port_allocator, key);
            return error.NotFound;
        }
        entry.deadline = now.addDuration(duration);
    }

    pub fn remove(
        self: *NatTable,
        port_allocator: *PortAllocator,
        key: Key,
    ) void {
        const removed = self.inside.fetchSwapRemove(key) orelse return;
        const reverse_removed = self.outside.remove(removed.value.outside);
        std.debug.assert(reverse_removed);
        port_allocator.release(removed.value.outside.port);
    }
};

test "NAT mappings resolve in both directions, refresh, and release their port" {
    const alloc = std.testing.allocator;
    var table = NatTable.init(std.testing.io);
    defer table.deinit(alloc);
    var port_allocator: PortAllocator = .{};
    const inside: NatTable.Key = .{ .protocol = .tcp, .ip = .{ 192, 168, 1, 10 }, .port = 50000 };
    const outside_ip: IPv4 = .{ 203, 0, 113, 5 };

    const entry = try table.insert(alloc, &port_allocator, inside, outside_ip, .fromSeconds(60));
    try std.testing.expectEqualDeep(outside_ip, entry.outside.ip);
    try std.testing.expectEqual(inside.port, entry.outside.port);
    try std.testing.expect(port_allocator.isAllocated(entry.outside.port));
    try std.testing.expectEqualDeep(entry, table.outboundLookup(&port_allocator, inside).?);
    const inbound = table.inboundLookup(&port_allocator, entry.outside).?;
    try std.testing.expectEqualDeep(inside, inbound[0]);
    try std.testing.expectEqualDeep(entry, inbound[1]);

    try table.refresh(&port_allocator, inside, .fromSeconds(120));
    try std.testing.expect(table.outboundLookup(&port_allocator, inside).?.deadline.toNanoseconds() > entry.deadline.toNanoseconds());

    table.remove(&port_allocator, inside);
    try std.testing.expect(!port_allocator.isAllocated(entry.outside.port));
    try std.testing.expect(table.outboundLookup(&port_allocator, inside) == null);
    try std.testing.expect(table.inboundLookup(&port_allocator, entry.outside) == null);
    try std.testing.expectError(error.NotFound, table.refresh(&port_allocator, inside, .fromSeconds(60)));
}

test "NAT insert uses another occupied port and keeps protocol spaces separate" {
    const alloc = std.testing.allocator;
    var table = NatTable.init(std.testing.io);
    defer table.deinit(alloc);
    var tcp_port_allocator: PortAllocator = .{};
    var udp_port_allocator: PortAllocator = .{};
    const outside_ip: IPv4 = .{ 203, 0, 113, 5 };
    const inside_a: NatTable.Key = .{ .protocol = .tcp, .ip = .{ 192, 168, 1, 10 }, .port = 50000 };
    const inside_b: NatTable.Key = .{ .protocol = .tcp, .ip = .{ 192, 168, 1, 11 }, .port = 50000 };

    const first = try table.insert(alloc, &tcp_port_allocator, inside_a, outside_ip, .fromSeconds(60));
    try std.testing.expectError(error.InsideKeyInUse, table.insert(alloc, &tcp_port_allocator, inside_a, outside_ip, .fromSeconds(60)));
    const second = try table.insert(alloc, &tcp_port_allocator, inside_b, outside_ip, .fromSeconds(60));
    try std.testing.expect(first.outside.port != second.outside.port);
    try std.testing.expectEqualDeep(inside_b, table.inboundLookup(&tcp_port_allocator, second.outside).?[0]);

    const udp_inside: NatTable.Key = .{ .protocol = .udp, .ip = inside_a.ip, .port = inside_a.port };
    const udp_entry = try table.insert(alloc, &udp_port_allocator, udp_inside, outside_ip, .fromSeconds(60));
    try std.testing.expectEqual(first.outside.port, udp_entry.outside.port);
    try std.testing.expectEqual(@as(usize, 3), table.inside.count());
    try std.testing.expectEqual(@as(usize, 3), table.outside.count());

    table.remove(&tcp_port_allocator, inside_a);
    try std.testing.expect(!tcp_port_allocator.isAllocated(first.outside.port));
    try std.testing.expect(udp_port_allocator.isAllocated(udp_entry.outside.port));
    try std.testing.expect(table.inboundLookup(&udp_port_allocator, udp_entry.outside) != null);
}

test "NAT lookup and protocol sweep release expired ports" {
    const alloc = std.testing.allocator;
    var table = NatTable.init(std.testing.io);
    defer table.deinit(alloc);
    var udp_port_allocator: PortAllocator = .{};
    var tcp_port_allocator: PortAllocator = .{};
    const outside_ip: IPv4 = .{ 203, 0, 113, 5 };
    const inside_a: NatTable.Key = .{ .protocol = .udp, .ip = .{ 192, 168, 1, 10 }, .port = 50000 };
    const inside_b: NatTable.Key = .{ .protocol = .udp, .ip = .{ 192, 168, 1, 11 }, .port = 50001 };
    const inside_c: NatTable.Key = .{ .protocol = .udp, .ip = .{ 192, 168, 1, 12 }, .port = 50002 };
    const tcp_inside: NatTable.Key = .{ .protocol = .tcp, .ip = .{ 192, 168, 1, 13 }, .port = 50003 };

    const expired = try table.insert(alloc, &udp_port_allocator, inside_a, outside_ip, .zero);
    try std.testing.expect(table.inboundLookup(&udp_port_allocator, expired.outside) == null);
    try std.testing.expect(!udp_port_allocator.isAllocated(expired.outside.port));
    try std.testing.expectEqual(@as(usize, 0), table.inside.count());

    const expired_a = try table.insert(alloc, &udp_port_allocator, inside_a, outside_ip, .zero);
    const live = try table.insert(alloc, &udp_port_allocator, inside_b, outside_ip, .fromSeconds(60));
    const expired_c = try table.insert(alloc, &udp_port_allocator, inside_c, outside_ip, .zero);
    const expired_tcp = try table.insert(alloc, &tcp_port_allocator, tcp_inside, outside_ip, .zero);
    table.reclaimExpired(.udp, &udp_port_allocator);
    try std.testing.expect(!udp_port_allocator.isAllocated(expired_a.outside.port));
    try std.testing.expect(!udp_port_allocator.isAllocated(expired_c.outside.port));
    try std.testing.expect(udp_port_allocator.isAllocated(live.outside.port));
    try std.testing.expect(tcp_port_allocator.isAllocated(expired_tcp.outside.port));
    try std.testing.expectEqual(@as(usize, 2), table.inside.count());

    table.reclaimExpired(.tcp, &tcp_port_allocator);
    try std.testing.expect(!tcp_port_allocator.isAllocated(expired_tcp.outside.port));
    try std.testing.expectEqual(@as(usize, 1), table.inside.count());
    try std.testing.expectEqual(@as(usize, 1), table.outside.count());
}

test "NAT insert leaves port free when map allocation fails" {
    var table = NatTable.init(std.testing.io);
    var port_allocator: PortAllocator = .{};
    var bytes: [0]u8 = .{};
    var fixed = std.heap.FixedBufferAllocator.init(&bytes);
    const alloc = fixed.allocator();
    defer table.deinit(alloc);
    const inside: NatTable.Key = .{ .protocol = .icmp, .ip = .{ 192, 168, 1, 10 }, .port = 1234 };
    const outside_ip: IPv4 = .{ 203, 0, 113, 5 };

    try std.testing.expectError(error.OutOfMemory, table.insert(alloc, &port_allocator, inside, outside_ip, .fromSeconds(60)));
    try std.testing.expect(!port_allocator.isAllocated(inside.port));
    try std.testing.expectEqual(@as(usize, 0), table.inside.count());
    try std.testing.expectEqual(@as(usize, 0), table.outside.count());
}

test "PortAllocator reuses a released preferred port" {
    var port_allocator: PortAllocator = .{};
    const preferred: u16 = 60000;
    try std.testing.expectEqual(preferred, try port_allocator.allocate(preferred));
    const alternate = try port_allocator.allocate(preferred);
    try std.testing.expect(alternate != preferred);
    try std.testing.expect(port_allocator.isAllocated(alternate));

    port_allocator.release(preferred);
    try std.testing.expect(!port_allocator.isAllocated(preferred));
    try std.testing.expectEqual(preferred, try port_allocator.allocate(preferred));
}

test "PortAllocator chooses a port in range for a low preference" {
    var port_allocator: PortAllocator = .{};
    const selected = try port_allocator.allocate(53);
    try std.testing.expect(selected >= PortAllocator.first_port);
    try std.testing.expect(port_allocator.isAllocated(selected));
}
