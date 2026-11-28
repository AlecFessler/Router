const std = @import("std");
const Router = @import("router");

const IPv4 = Router.Protocols.IPv4.IPv4;
const Protocol = Router.Protocols.IPv4.Protocol;

// TCP, UDP and ICMP identifiers have independent allocation spaces.
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
};

pub const NatTable = struct {
    pub const Key = struct {
        protocol: Protocol,
        ip: IPv4,
        port: u16,
        // A client can use the same local socket for direct and gateway DNS.
        service_peer: ?Peer = null,

        pub fn permitsReply(self: Key, entry: Entry, peer: Peer) bool {
            if (self.service_peer) |upstream| return std.meta.eql(upstream, peer);
            return entry.acceptsPeer(peer);
        }
    };

    pub const IpPort = struct { IPv4, u16 };

    /// RFC 4787 filtering modes. The mapping itself is always
    /// endpoint-independent; this only controls which remote peers may send
    /// inbound packets through a live mapping.
    pub const FilteringMode = enum {
        full_cone, // any remote peer
        address_restricted, // only peer addresses the inside host contacted
        endpoint_dependent, // only the exact peer endpoints contacted
    };

    pub const Peer = struct {
        ip: IPv4,
        port: u16,
    };

    const MAX_PEERS = 4;
    const empty_peer: Peer = .{ .ip = .{ 0, 0, 0, 0 }, .port = 0 };

    pub const Entry = struct {
        outside: Key,
        generation: u64,
        deadline: std.Io.Timestamp,
        port_allocator: *PortAllocator,
        peers: [MAX_PEERS]Peer = .{ empty_peer, empty_peer, empty_peer, empty_peer },
        peer_count: u8 = 0,

        pub fn acceptsPeer(self: Entry, peer: Peer) bool {
            return switch (Router.State.nat_filtering_mode) {
                .full_cone => true,
                .address_restricted => self.acceptsPeerIp(peer.ip),
                .endpoint_dependent => self.acceptsPeerExact(peer),
            };
        }

        /// Fragments carry no transport port, so endpoint-dependent mode can
        /// only check the peer address there.
        pub fn acceptsPeerIp(self: Entry, ip: IPv4) bool {
            if (Router.State.nat_filtering_mode == .full_cone) return true;
            for (self.peers[0..@as(usize, self.peer_count)]) |candidate| {
                if (std.meta.eql(candidate.ip, ip)) return true;
            }
            return false;
        }

        fn acceptsPeerExact(self: Entry, peer: Peer) bool {
            for (self.peers[0..@as(usize, self.peer_count)]) |candidate| {
                if (std.meta.eql(candidate, peer)) return true;
            }
            return false;
        }
    };

    io: std.Io,
    capacity: usize,
    next_generation: u64 = 0,
    inside: std.AutoArrayHashMapUnmanaged(Key, Entry) = .empty,
    outside: std.AutoHashMapUnmanaged(Key, Key) = .empty,
    mutex: std.Io.Mutex = .init,
    tcp_ports: PortAllocator = .{},
    udp_ports: PortAllocator = .{},
    icmp_ports: PortAllocator = .{},

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

    pub fn mapOutbound(self: *NatTable, ports: *PortAllocator, key: Key, outside_ip: IPv4, duration: std.Io.Duration, peer: Peer) !Entry {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        const entry = if (self.outboundEntryLocked(key, outside_ip)) |existing| hit: {
            self.inside.getPtr(key).?.deadline = std.Io.Timestamp.now(self.io, .boot).addDuration(duration);
            break :hit existing;
        } else try self.insert(ports, key, outside_ip, duration);
        self.appendPeer(key, peer);
        return entry;
    }

    pub fn inboundEntry(self: *NatTable, key: Key) ?struct { Key, Entry } {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
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
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        return self.outboundEntryLocked(key, outside_ip);
    }

    fn outboundEntryLocked(self: *NatTable, key: Key, outside_ip: IPv4) ?Entry {
        const entry = self.inside.get(key) orelse return null;
        const now = std.Io.Timestamp.now(self.io, .boot);
        if (!std.mem.eql(u8, &entry.outside.ip, &outside_ip) or isExpired(entry.deadline, now)) {
            self.remove(key);
            return null;
        }
        return entry;
    }

    fn insert(
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
            var reclaimed_expired = false;
            var victim: ?Key = null;
            var victim_deadline: i96 = 0;
            for (self.inside.keys(), self.inside.values()) |inside_key, entry| {
                if (isExpired(entry.deadline, now)) {
                    self.remove(inside_key);
                    reclaimed_expired = true;
                    break;
                }
                // Reclaim the least-recently-refreshed entry for the new flow.
                const deadline = entry.deadline.toNanoseconds();
                if (victim == null or deadline < victim_deadline) {
                    victim = inside_key;
                    victim_deadline = deadline;
                }
            }
            if (!reclaimed_expired) {
                self.remove(victim.?);
            }
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

    fn appendPeer(self: *NatTable, key: Key, peer: Peer) void {
        const entry = self.inside.getPtr(key) orelse return;
        const count = @as(usize, entry.peer_count);
        for (entry.peers[0..count]) |candidate| {
            if (std.meta.eql(candidate, peer)) return;
        }
        if (count < MAX_PEERS) {
            entry.peers[count] = peer;
            entry.peer_count += 1;
            return;
        }
        std.mem.copyForwards(Peer, entry.peers[0 .. MAX_PEERS - 1], entry.peers[1..MAX_PEERS]);
        entry.peers[MAX_PEERS - 1] = peer;
    }

    pub fn removeAllForInsideIp(self: *NatTable, ip: IPv4) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        var index: usize = 0;
        while (index < self.inside.count()) {
            const key = self.inside.keys()[index];
            if (std.meta.eql(key.ip, ip)) self.remove(key) else index += 1;
        }
    }

    fn remove(self: *NatTable, key: Key) void {
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
    try std.testing.expect(port_allocator.used.isSet(entry.outside.port));
    const outbound_ip, const outbound_port = table.outboundLookup(inside, outside_ip).?;
    try std.testing.expectEqualDeep(outside_ip, outbound_ip);
    try std.testing.expectEqual(entry.outside.port, outbound_port);
    const inbound, _ = table.inboundEntry(entry.outside).?;
    try std.testing.expectEqualDeep(inside.ip, inbound.ip);
    try std.testing.expectEqual(inside.port, inbound.port);

    _ = try table.mapOutbound(&port_allocator, inside, outside_ip, .fromSeconds(120), .{ .ip = .{ 8, 8, 8, 8 }, .port = 443 });
    try std.testing.expect(table.inside.get(inside).?.deadline.toNanoseconds() > entry.deadline.toNanoseconds());

    table.remove(inside);
    try std.testing.expect(!port_allocator.used.isSet(entry.outside.port));
    try std.testing.expect(table.outboundLookup(inside, outside_ip) == null);
    try std.testing.expect(table.inboundEntry(entry.outside) == null);
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
    try std.testing.expectEqual(null, table.inboundEntry(old.outside));
    try std.testing.expect(!port_allocator.used.isSet(old.outside.port));

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
    const inbound, _ = table.inboundEntry(second.outside).?;
    try std.testing.expectEqualDeep(inside_b.ip, inbound.ip);
    try std.testing.expectEqual(inside_b.port, inbound.port);

    const udp_inside: NatTable.Key = .{ .protocol = .udp, .ip = inside_a.ip, .port = inside_a.port };
    const udp_entry = try table.insert(&udp_port_allocator, udp_inside, outside_ip, .fromSeconds(60));
    try std.testing.expectEqual(first.outside.port, udp_entry.outside.port);
    try std.testing.expectEqual(@as(usize, 3), table.inside.count());
    try std.testing.expectEqual(@as(usize, 3), table.outside.count());

    table.remove(inside_a);
    try std.testing.expect(!tcp_port_allocator.used.isSet(first.outside.port));
    try std.testing.expect(udp_port_allocator.used.isSet(udp_entry.outside.port));
    try std.testing.expect(table.inboundEntry(udp_entry.outside) != null);
}

test "NAT lookups release expired ports and insertion reclaims capacity" {
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
    try std.testing.expect(table.inboundEntry(expired.outside) == null);
    try std.testing.expect(!udp_port_allocator.used.isSet(expired.outside.port));
    try std.testing.expectEqual(@as(usize, 0), table.inside.count());

    const live = try table.insert(&udp_port_allocator, inside_b, outside_ip, .fromSeconds(60));
    const expired_tcp = try table.insert(&tcp_port_allocator, tcp_inside, outside_ip, .zero);
    const replacement = try table.insert(&udp_port_allocator, inside_c, outside_ip, .fromSeconds(60));
    try std.testing.expect(!tcp_port_allocator.used.isSet(expired_tcp.outside.port));
    try std.testing.expect(udp_port_allocator.used.isSet(live.outside.port));
    try std.testing.expect(udp_port_allocator.used.isSet(replacement.outside.port));
    try std.testing.expectEqual(@as(usize, 2), table.inside.count());
    try std.testing.expect(table.outboundLookup(tcp_inside, outside_ip) == null);
    try std.testing.expect(table.inboundEntry(live.outside) != null);
    try std.testing.expect(table.inboundEntry(replacement.outside) != null);

    _ = try table.insert(&tcp_port_allocator, tcp_inside, outside_ip, .fromSeconds(60));
    try std.testing.expect(table.outboundLookup(tcp_inside, outside_ip) != null);
    try std.testing.expectEqual(@as(usize, 2), table.outside.count());
    try std.testing.expect(table.inboundEntry(live.outside) == null or
        table.inboundEntry(replacement.outside) == null);
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
    try std.testing.expect(port_allocator.used.isSet(inside.port));
    table.deinit(alloc);
    try std.testing.expect(!port_allocator.used.isSet(inside.port));
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
    const inbound, _ = table.inboundEntry(new_entry.outside).?;
    try std.testing.expectEqualDeep(new_key.ip, inbound.ip);
    try std.testing.expectEqual(new_key.port, inbound.port);
}

test "PortAllocator reuses a released preferred port" {
    var port_allocator: PortAllocator = .{};
    const preferred: u16 = 60000;
    try std.testing.expectEqual(preferred, try port_allocator.allocate(preferred));
    const alternate = try port_allocator.allocate(preferred);
    try std.testing.expect(alternate != preferred);
    try std.testing.expect(port_allocator.used.isSet(alternate));

    port_allocator.release(preferred);
    try std.testing.expect(!port_allocator.used.isSet(preferred));
    try std.testing.expectEqual(preferred, try port_allocator.allocate(preferred));
}

test "PortAllocator chooses a port in range for a low preference" {
    var port_allocator: PortAllocator = .{};
    const selected = try port_allocator.allocate(53);
    try std.testing.expect(selected >= PortAllocator.first_port);
    try std.testing.expect(port_allocator.used.isSet(selected));
}

test "NAT filtering modes accept only the configured peers" {
    const alloc = std.testing.allocator;
    var table = try NatTable.init(alloc, std.testing.io, 1);
    defer table.deinit(alloc);
    var port_allocator: PortAllocator = .{};
    const inside: NatTable.Key = .{ .protocol = .udp, .ip = .{ 192, 168, 1, 10 }, .port = 50000 };
    const outside_ip: IPv4 = .{ 203, 0, 113, 5 };
    const contacted: NatTable.Peer = .{ .ip = .{ 8, 8, 8, 8 }, .port = 53 };
    const same_ip_other_port: NatTable.Peer = .{ .ip = .{ 8, 8, 8, 8 }, .port = 1234 };
    const other_ip: NatTable.Peer = .{ .ip = .{ 6, 6, 6, 6 }, .port = 53 };

    _ = try table.insert(&port_allocator, inside, outside_ip, .fromSeconds(60));
    table.appendPeer(inside, contacted);
    const entry = table.inside.get(inside).?;
    const previous_mode = Router.State.nat_filtering_mode;
    defer Router.State.nat_filtering_mode = previous_mode;

    Router.State.nat_filtering_mode = .full_cone;
    try std.testing.expect(entry.acceptsPeer(other_ip));
    try std.testing.expect(entry.acceptsPeerIp(other_ip.ip));

    Router.State.nat_filtering_mode = .address_restricted;
    try std.testing.expect(entry.acceptsPeer(contacted));
    try std.testing.expect(entry.acceptsPeer(same_ip_other_port));
    try std.testing.expect(!entry.acceptsPeer(other_ip));
    try std.testing.expect(entry.acceptsPeerIp(contacted.ip));
    try std.testing.expect(!entry.acceptsPeerIp(other_ip.ip));

    Router.State.nat_filtering_mode = .endpoint_dependent;
    try std.testing.expect(entry.acceptsPeer(contacted));
    try std.testing.expect(!entry.acceptsPeer(same_ip_other_port));
    try std.testing.expect(!entry.acceptsPeer(other_ip));
    try std.testing.expect(entry.acceptsPeerIp(contacted.ip));
    try std.testing.expect(!entry.acceptsPeerIp(other_ip.ip));
}
