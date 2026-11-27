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

pub const NatTable = struct {
    pub const Key = struct {
        protocol: Protocol,
        ip: IPv4,
        port: u16,
    };

    pub const IpPort = struct { IPv4, u16 };

    pub const Entry = struct {
        outside: Key,
        generation: u64,
        deadline: std.Io.Timestamp,
        port_allocator: *PortAllocator,
    };

    io: std.Io,
    capacity: usize,
    next_generation: u64 = 0,
    inside: std.AutoArrayHashMapUnmanaged(Key, Entry) = .empty,
    outside: std.AutoHashMapUnmanaged(Key, Key) = .empty,

    pub fn init(alloc: std.mem.Allocator, io: std.Io, capacity: u32) !NatTable {
        var table: NatTable = .{
            .io = io,
            .capacity = capacity,
        };
        errdefer table.deinit(alloc);
        try table.inside.ensureTotalCapacity(alloc, capacity);
        try table.outside.ensureTotalCapacity(alloc, capacity);
        return table;
    }

    pub fn deinit(self: *NatTable, alloc: std.mem.Allocator) void {
        for (self.inside.values()) |entry| {
            entry.port_allocator.release(entry.outside.port);
        }
        self.inside.deinit(alloc);
        self.outside.deinit(alloc);
    }

    fn isExpired(deadline: std.Io.Timestamp, now: std.Io.Timestamp) bool {
        return deadline.durationTo(now).toNanoseconds() >= 0;
    }

    pub fn inboundLookup(
        self: *NatTable,
        key: Key,
    ) ?IpPort {
        const inside_key, _ = self.inboundEntry(key) orelse return null;
        return .{ inside_key.ip, inside_key.port };
    }

    pub fn inboundEntry(self: *NatTable, key: Key) ?struct { Key, Entry } {
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
        outside_ip: IPv4,
    ) ?IpPort {
        const entry = self.outboundEntry(key, outside_ip) orelse return null;
        return .{ entry.outside.ip, entry.outside.port };
    }

    pub fn outboundEntry(self: *NatTable, key: Key, outside_ip: IPv4) ?Entry {
        const entry = self.inside.get(key) orelse return null;
        const now = std.Io.Timestamp.now(self.io, .boot);
        if (!std.mem.eql(u8, &entry.outside.ip, &outside_ip) or isExpired(entry.deadline, now)) {
            self.remove(key);
            return null;
        }
        return entry;
    }

    pub fn insert(
        self: *NatTable,
        port_allocator: *PortAllocator,
        key: Key,
        outside_ip: IPv4,
        duration: std.Io.Duration,
    ) !Entry {
        const now = std.Io.Timestamp.now(self.io, .boot);
        if (self.inside.get(key)) |existing| {
            if (!isExpired(existing.deadline, now)) return error.InsideKeyInUse;
            self.remove(key);
        }

        if (self.inside.count() == self.capacity) {
            for (self.inside.keys(), self.inside.values()) |inside_key, entry| {
                if (!isExpired(entry.deadline, now)) continue;
                self.remove(inside_key);
                break;
            } else return error.NoCapacity;
        }

        const outside_port = port_allocator.allocate(key.port) catch |err| switch (err) {
            error.NoPortsAvailable => blk: {
                for (self.inside.keys(), self.inside.values()) |inside_key, entry| {
                    if (entry.outside.protocol != key.protocol or
                        !isExpired(entry.deadline, now)) continue;
                    self.remove(inside_key);
                    break;
                } else return error.NoPortsAvailable;
                break :blk try port_allocator.allocate(key.port);
            },
        };
        const entry: Entry = .{
            .outside = .{ .protocol = key.protocol, .ip = outside_ip, .port = outside_port },
            .generation = self.next_generation,
            .deadline = now.addDuration(duration),
            .port_allocator = port_allocator,
        };
        std.debug.assert(!self.outside.contains(entry.outside));
        self.inside.putAssumeCapacityNoClobber(key, entry);
        self.outside.putAssumeCapacityNoClobber(entry.outside, key);
        self.next_generation +%= 1;
        return entry;
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

    pub fn remove(self: *NatTable, key: Key) void {
        const removed = self.inside.fetchSwapRemove(key) orelse return;
        const reverse_removed = self.outside.remove(removed.value.outside);
        std.debug.assert(reverse_removed);
        removed.value.port_allocator.release(removed.value.outside.port);
    }
};

test "NAT mappings resolve in both directions, refresh, and release their port" {
    const alloc = std.testing.allocator;
    var table = try NatTable.init(alloc, std.testing.io, 8);
    defer table.deinit(alloc);
    var port_allocator: PortAllocator = .{};
    const inside: NatTable.Key = .{ .protocol = .tcp, .ip = .{ 192, 168, 1, 10 }, .port = 50000 };
    const outside_ip: IPv4 = .{ 203, 0, 113, 5 };

    const entry = try table.insert(&port_allocator, inside, outside_ip, .fromSeconds(60));
    try std.testing.expectEqualDeep(outside_ip, entry.outside.ip);
    try std.testing.expectEqual(inside.port, entry.outside.port);
    try std.testing.expect(port_allocator.isAllocated(entry.outside.port));
    const outbound_ip, const outbound_port = table.outboundLookup(inside, outside_ip).?;
    try std.testing.expectEqualDeep(outside_ip, outbound_ip);
    try std.testing.expectEqual(entry.outside.port, outbound_port);
    const inbound = table.inboundLookup(entry.outside).?;
    try std.testing.expectEqualDeep(inside.ip, inbound[0]);
    try std.testing.expectEqual(inside.port, inbound[1]);

    try table.refresh(inside, .fromSeconds(120));
    try std.testing.expect(table.inside.get(inside).?.deadline.toNanoseconds() > entry.deadline.toNanoseconds());

    table.remove(inside);
    try std.testing.expect(!port_allocator.isAllocated(entry.outside.port));
    try std.testing.expect(table.outboundLookup(inside, outside_ip) == null);
    try std.testing.expect(table.inboundLookup(entry.outside) == null);
    try std.testing.expectError(error.NotFound, table.refresh(inside, .fromSeconds(60)));
}

test "NAT outbound lookup removes mappings for the old WAN IP" {
    const alloc = std.testing.allocator;
    var port_allocator: PortAllocator = .{};
    var table = try NatTable.init(alloc, std.testing.io, 1);
    defer table.deinit(alloc);
    const inside: NatTable.Key = .{ .protocol = .tcp, .ip = .{ 192, 168, 1, 10 }, .port = 50000 };
    const current_ip: IPv4 = .{ 203, 0, 113, 6 };

    const old = try table.insert(&port_allocator, inside, .{ 203, 0, 113, 5 }, .fromSeconds(60));
    try std.testing.expectEqual(null, table.outboundLookup(inside, current_ip));
    try std.testing.expectEqual(null, table.inboundLookup(old.outside));
    try std.testing.expect(!port_allocator.isAllocated(old.outside.port));

    const replacement = try table.insert(&port_allocator, inside, current_ip, .fromSeconds(60));
    try std.testing.expectEqual(old.outside.port, replacement.outside.port);
}

test "NAT insert uses another occupied port and keeps protocol spaces separate" {
    const alloc = std.testing.allocator;
    var table = try NatTable.init(alloc, std.testing.io, 8);
    defer table.deinit(alloc);
    var tcp_port_allocator: PortAllocator = .{};
    var udp_port_allocator: PortAllocator = .{};
    const outside_ip: IPv4 = .{ 203, 0, 113, 5 };
    const inside_a: NatTable.Key = .{ .protocol = .tcp, .ip = .{ 192, 168, 1, 10 }, .port = 50000 };
    const inside_b: NatTable.Key = .{ .protocol = .tcp, .ip = .{ 192, 168, 1, 11 }, .port = 50000 };

    const first = try table.insert(&tcp_port_allocator, inside_a, outside_ip, .fromSeconds(60));
    try std.testing.expectError(error.InsideKeyInUse, table.insert(&tcp_port_allocator, inside_a, outside_ip, .fromSeconds(60)));
    const second = try table.insert(&tcp_port_allocator, inside_b, outside_ip, .fromSeconds(60));
    try std.testing.expect(first.outside.port != second.outside.port);
    const inbound_ip, const inbound_port = table.inboundLookup(second.outside).?;
    try std.testing.expectEqualDeep(inside_b.ip, inbound_ip);
    try std.testing.expectEqual(inside_b.port, inbound_port);

    const udp_inside: NatTable.Key = .{ .protocol = .udp, .ip = inside_a.ip, .port = inside_a.port };
    const udp_entry = try table.insert(&udp_port_allocator, udp_inside, outside_ip, .fromSeconds(60));
    try std.testing.expectEqual(first.outside.port, udp_entry.outside.port);
    try std.testing.expectEqual(@as(usize, 3), table.inside.count());
    try std.testing.expectEqual(@as(usize, 3), table.outside.count());

    table.remove(inside_a);
    try std.testing.expect(!tcp_port_allocator.isAllocated(first.outside.port));
    try std.testing.expect(udp_port_allocator.isAllocated(udp_entry.outside.port));
    try std.testing.expect(table.inboundLookup(udp_entry.outside) != null);
}

test "NAT lookups release expired ports and insertion reuses expired capacity" {
    const alloc = std.testing.allocator;
    var table = try NatTable.init(alloc, std.testing.io, 2);
    defer table.deinit(alloc);
    var udp_port_allocator: PortAllocator = .{};
    var tcp_port_allocator: PortAllocator = .{};
    const outside_ip: IPv4 = .{ 203, 0, 113, 5 };
    const inside_a: NatTable.Key = .{ .protocol = .udp, .ip = .{ 192, 168, 1, 10 }, .port = 50000 };
    const inside_b: NatTable.Key = .{ .protocol = .udp, .ip = .{ 192, 168, 1, 11 }, .port = 50001 };
    const inside_c: NatTable.Key = .{ .protocol = .udp, .ip = .{ 192, 168, 1, 12 }, .port = 50002 };
    const tcp_inside: NatTable.Key = .{ .protocol = .tcp, .ip = .{ 192, 168, 1, 13 }, .port = 50003 };

    const expired = try table.insert(&udp_port_allocator, inside_a, outside_ip, .zero);
    try std.testing.expect(table.inboundLookup(expired.outside) == null);
    try std.testing.expect(!udp_port_allocator.isAllocated(expired.outside.port));
    try std.testing.expectEqual(@as(usize, 0), table.inside.count());

    const live = try table.insert(&udp_port_allocator, inside_b, outside_ip, .fromSeconds(60));
    const expired_tcp = try table.insert(&tcp_port_allocator, tcp_inside, outside_ip, .zero);
    const replacement = try table.insert(&udp_port_allocator, inside_c, outside_ip, .fromSeconds(60));
    try std.testing.expect(!tcp_port_allocator.isAllocated(expired_tcp.outside.port));
    try std.testing.expect(udp_port_allocator.isAllocated(live.outside.port));
    try std.testing.expect(udp_port_allocator.isAllocated(replacement.outside.port));
    try std.testing.expectEqual(@as(usize, 2), table.inside.count());
    try std.testing.expect(table.outboundLookup(tcp_inside, outside_ip) == null);
    try std.testing.expect(table.inboundLookup(live.outside) != null);
    try std.testing.expect(table.inboundLookup(replacement.outside) != null);

    try std.testing.expectError(error.NoCapacity, table.insert(&tcp_port_allocator, tcp_inside, outside_ip, .fromSeconds(60)));
    try std.testing.expectEqual(@as(usize, 2), table.outside.count());
}

test "NAT initialization fails without storage" {
    var bytes: [0]u8 = .{};
    var fixed = std.heap.FixedBufferAllocator.init(&bytes);
    const alloc = fixed.allocator();
    try std.testing.expectError(error.OutOfMemory, NatTable.init(alloc, std.testing.io, 1));
}

test "NAT deinit releases ports held by live mappings" {
    const alloc = std.testing.allocator;
    var table = try NatTable.init(alloc, std.testing.io, 1);
    var port_allocator: PortAllocator = .{};
    const inside: NatTable.Key = .{ .protocol = .icmp, .ip = .{ 192, 168, 1, 10 }, .port = 1234 };
    _ = try table.insert(&port_allocator, inside, .{ 203, 0, 113, 5 }, .fromSeconds(60));
    try std.testing.expect(port_allocator.isAllocated(inside.port));
    table.deinit(alloc);
    try std.testing.expect(!port_allocator.isAllocated(inside.port));
}

test "NAT expired mapping gives its port to a new mapping at capacity" {
    const alloc = std.testing.allocator;
    var table = try NatTable.init(alloc, std.testing.io, 1);
    defer table.deinit(alloc);
    var port_allocator: PortAllocator = .{};
    const outside_ip: IPv4 = .{ 203, 0, 113, 5 };
    const old_key: NatTable.Key = .{ .protocol = .udp, .ip = .{ 192, 168, 1, 10 }, .port = 50000 };
    const new_key: NatTable.Key = .{ .protocol = .udp, .ip = .{ 192, 168, 1, 11 }, .port = 50000 };

    const old_entry = try table.insert(&port_allocator, old_key, outside_ip, .zero);
    const new_entry = try table.insert(&port_allocator, new_key, outside_ip, .fromSeconds(60));
    try std.testing.expectEqual(old_entry.outside.port, new_entry.outside.port);
    try std.testing.expect(table.outboundLookup(old_key, outside_ip) == null);
    const inbound_ip, const inbound_port = table.inboundLookup(new_entry.outside).?;
    try std.testing.expectEqualDeep(new_key.ip, inbound_ip);
    try std.testing.expectEqual(new_key.port, inbound_port);
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
