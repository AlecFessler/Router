const std = @import("std");
const Router = @import("router");

const IPv4 = Router.Protocols.IPv4.IPv4;
const Mac = Router.Protocols.Ethernet.Mac;

pub const DhcpTable = struct {
    pub const Client = union(enum) {
        id: []const u8,
        mac: Mac,
    };

    pub const LeaseState = enum {
        offered,
        bound,
    };

    pub const Entry = struct {
        client: Client,
        client_bytes: ?[]u8,
        mac: Mac,
        ip: IPv4,
        state: LeaseState,
        deadline: std.Io.Timestamp,
    };

    pub const Table = std.MultiArrayList(Entry);
    pub const IpPool = std.ArrayList(IPv4);

    io: std.Io,
    table: Table,
    ip_pool: IpPool,
    excluded_ips: IpPool = .empty,

    pub fn init(
        alloc: std.mem.Allocator,
        io: std.Io,
        ip_pool: IpPool,
    ) !DhcpTable {
        var table: Table = .empty;
        try table.setCapacity(alloc, ip_pool.items.len);
        return .{
            .io = io,
            .table = table,
            .ip_pool = ip_pool,
        };
    }

    pub fn deinit(self: *DhcpTable, alloc: std.mem.Allocator) void {
        for (0..self.table.len) |i| {
            const entry = self.table.get(i);
            if (entry.client_bytes) |bytes| {
                alloc.free(bytes);
            }
        }
        self.table.deinit(alloc);
        self.ip_pool.deinit(alloc);
        self.excluded_ips.deinit(alloc);
    }

    fn isExpired(self: *DhcpTable, deadline: std.Io.Timestamp) bool {
        return deadline.untilNow(self.io, .boot).toNanoseconds() >= 0;
    }

    fn sameClient(a: Client, b: Client) bool {
        if (std.meta.activeTag(a) != std.meta.activeTag(b)) return false;
        return switch (a) {
            .id => |id| std.mem.eql(u8, id, b.id),
            .mac => |mac| std.mem.eql(u8, mac[0..], b.mac[0..]),
        };
    }

    fn removeAtIndex(self: *DhcpTable, alloc: std.mem.Allocator, index: usize) void {
        const entry = self.table.get(index);
        if (entry.client_bytes) |bytes| alloc.free(bytes);
        self.table.swapRemove(index);
    }

    fn reclaimExpired(self: *DhcpTable, alloc: std.mem.Allocator) void {
        var index: usize = 0;
        while (index < self.table.len) {
            if (!self.isExpired(self.table.items(.deadline)[index])) {
                index += 1;
                continue;
            }
            const ip = self.table.items(.ip)[index];
            self.removeAtIndex(alloc, index);
            self.ip_pool.appendAssumeCapacity(ip);
        }
    }

    fn removeEntry(
        self: *DhcpTable,
        alloc: std.mem.Allocator,
        client: Client,
        ip: IPv4,
    ) bool {
        const client_index = self.lookupByClient(alloc, client) orelse return false;
        const found_entry_ip = self.table.items(.ip)[client_index];
        if (!std.meta.eql(found_entry_ip, ip)) return false;
        self.removeAtIndex(alloc, client_index);
        return true;
    }

    pub fn lookupByClient(
        self: *DhcpTable,
        alloc: std.mem.Allocator,
        client: Client,
    ) ?usize {
        self.reclaimExpired(alloc);
        for (self.table.items(.client), 0..) |item, i| {
            if (sameClient(item, client)) return i;
        }
        return null;
    }

    pub fn lookupByIp(
        self: *DhcpTable,
        alloc: std.mem.Allocator,
        ip: IPv4,
    ) ?usize {
        self.reclaimExpired(alloc);
        for (self.table.items(.ip), 0..) |item, i| {
            if (std.meta.eql(item, ip)) return i;
        }
        return null;
    }

    fn addNewEntry(
        self: *DhcpTable,
        alloc: std.mem.Allocator,
        client: Client,
        mac: Mac,
        candidate_ip: IPv4,
        duration: std.Io.Duration,
        state: LeaseState,
    ) !void {
        if (self.lookupByIp(alloc, candidate_ip) != null) return error.InvalidIP;
        if (self.table.len == self.table.capacity) return error.NoCapacity;
        const ip_index = for (self.ip_pool.items, 0..) |ip, i| {
            if (std.meta.eql(ip, candidate_ip)) break i;
        } else return error.InvalidIP;

        const owned_client_bytes = if (std.meta.activeTag(client) == .id)
            try alloc.dupe(u8, client.id)
        else
            null;

        const now = std.Io.Timestamp.now(self.io, .boot);

        _ = self.ip_pool.swapRemove(ip_index);

        self.table.appendAssumeCapacity(.{
            .client = if (owned_client_bytes) |bytes|
                .{ .id = bytes }
            else
                .{ .mac = mac },
            .client_bytes = owned_client_bytes,
            .mac = mac,
            .ip = candidate_ip,
            .state = state,
            .deadline = now.addDuration(duration),
        });
    }

    pub fn offer(
        self: *DhcpTable,
        alloc: std.mem.Allocator,
        client: Client,
        mac: Mac,
        candidate_ip: IPv4,
        offer_duration: std.Io.Duration,
    ) !IPv4 {
        if (self.lookupByClient(alloc, client)) |index| {
            return self.table.items(.ip)[index];
        }
        try self.addNewEntry(
            alloc,
            client,
            mac,
            candidate_ip,
            offer_duration,
            .offered,
        );
        return candidate_ip;
    }

    pub fn bindOrRenew(
        self: *DhcpTable,
        alloc: std.mem.Allocator,
        client: Client,
        mac: Mac,
        ip: IPv4,
        lease_duration: std.Io.Duration,
    ) !void {
        const client_index = self.lookupByClient(alloc, client) orelse {
            return self.addNewEntry(
                alloc,
                client,
                mac,
                ip,
                lease_duration,
                .bound,
            );
        };
        var entry = self.table.get(client_index);
        if (!std.meta.eql(entry.mac, mac)) return error.InvalidMac;
        if (!std.meta.eql(entry.ip, ip)) return error.InvalidIP;
        const now = std.Io.Timestamp.now(self.io, .boot);
        entry.deadline = now.addDuration(lease_duration);
        entry.state = .bound;
        self.table.set(client_index, entry);
    }

    pub fn release(
        self: *DhcpTable,
        alloc: std.mem.Allocator,
        client: Client,
        ip: IPv4,
    ) void {
        const removed = self.removeEntry(alloc, client, ip);
        if (!removed) return;
        self.ip_pool.appendAssumeCapacity(ip);
    }

    pub fn decline(
        self: *DhcpTable,
        alloc: std.mem.Allocator,
        client: Client,
        ip: IPv4,
    ) !void {
        const client_index = self.lookupByClient(alloc, client) orelse return;
        if (!std.meta.eql(self.table.items(.ip)[client_index], ip)) return;
        // TODO: right now excluded IPs are excluded forever. Later, maybe setup something
        // like a repeating timer that does an arp probe to determine if the address conflict is over.
        try self.excluded_ips.append(alloc, ip);
        self.removeAtIndex(alloc, client_index);
    }
};

const test_ip1: IPv4 = .{ 192, 168, 1, 10 };
const test_ip2: IPv4 = .{ 192, 168, 1, 11 };
const test_ip3: IPv4 = .{ 192, 168, 1, 12 };
const test_mac: Mac = .{ 1, 2, 3, 4, 5, 6 };

fn testTable(ips: []const IPv4) !DhcpTable {
    const alloc = std.testing.allocator;
    var pool: DhcpTable.IpPool = .empty;
    errdefer pool.deinit(alloc);
    try pool.appendSlice(alloc, ips);
    return DhcpTable.init(alloc, std.testing.io, pool);
}

test "DHCP offer, bind, reconnect, and renew keep an active client's address" {
    const alloc = std.testing.allocator;
    var table = try testTable(&.{ test_ip1, test_ip2 });
    defer table.deinit(alloc);
    const client: DhcpTable.Client = .{ .id = "client-a" };

    try std.testing.expectEqual(test_ip1, try table.offer(alloc, client, test_mac, test_ip1, .fromSeconds(30)));
    const offer_index = table.lookupByClient(alloc, client).?;
    try std.testing.expectEqual(DhcpTable.LeaseState.offered, table.table.items(.state)[offer_index]);

    try std.testing.expectEqual(test_ip1, try table.offer(alloc, client, test_mac, test_ip2, .fromSeconds(30)));
    try std.testing.expectEqual(@as(usize, 1), table.table.len);
    try table.bindOrRenew(alloc, client, test_mac, test_ip1, .fromSeconds(60));
    const bound_entry = table.table.get(table.lookupByClient(alloc, client).?);
    try std.testing.expectEqual(DhcpTable.LeaseState.bound, bound_entry.state);

    try std.testing.expectEqual(test_ip1, try table.offer(alloc, client, test_mac, test_ip2, .fromSeconds(30)));
    const reconnected_entry = table.table.get(table.lookupByClient(alloc, client).?);
    try std.testing.expectEqual(bound_entry.deadline, reconnected_entry.deadline);
    try std.testing.expectEqual(DhcpTable.LeaseState.bound, reconnected_entry.state);

    try table.bindOrRenew(alloc, client, test_mac, test_ip1, .fromSeconds(120));
    const renewed_entry = table.table.get(table.lookupByClient(alloc, client).?);
    try std.testing.expect(renewed_entry.deadline.toNanoseconds() > bound_entry.deadline.toNanoseconds());
    try std.testing.expectEqual(@as(usize, 1), table.table.len);
    try std.testing.expectEqual(@as(usize, 1), table.ip_pool.items.len);
}

test "DHCP rejects another client's address and invalid renewals without changing the lease" {
    const alloc = std.testing.allocator;
    var table = try testTable(&.{ test_ip1, test_ip2 });
    defer table.deinit(alloc);
    const client_a: DhcpTable.Client = .{ .id = "client-a" };
    const other_mac: Mac = .{ 6, 5, 4, 3, 2, 1 };
    const client_b: DhcpTable.Client = .{ .mac = other_mac };

    try table.bindOrRenew(alloc, client_a, test_mac, test_ip1, .fromSeconds(60));
    try std.testing.expectError(error.InvalidIP, table.offer(alloc, client_b, other_mac, test_ip1, .fromSeconds(30)));
    try std.testing.expectError(error.InvalidMac, table.bindOrRenew(alloc, client_a, other_mac, test_ip1, .fromSeconds(60)));
    try std.testing.expectError(error.InvalidIP, table.bindOrRenew(alloc, client_a, test_mac, test_ip2, .fromSeconds(60)));
    table.release(alloc, client_b, test_ip1);
    table.release(alloc, client_a, test_ip2);
    try std.testing.expectEqual(@as(usize, 1), table.table.len);
    try std.testing.expectEqual(test_ip1, table.table.items(.ip)[0]);

    table.release(alloc, client_a, test_ip1);
    try std.testing.expectEqual(@as(usize, 0), table.table.len);
    try std.testing.expectEqual(test_ip1, try table.offer(alloc, client_b, other_mac, test_ip1, .fromSeconds(30)));
}

test "DHCP expiry reclaims multiple addresses while retaining a live lease" {
    const alloc = std.testing.allocator;
    var table = try testTable(&.{ test_ip1, test_ip2, test_ip3 });
    defer table.deinit(alloc);
    const client_a: DhcpTable.Client = .{ .id = "client-a" };
    const client_b: DhcpTable.Client = .{ .id = "client-b" };
    const client_c: DhcpTable.Client = .{ .id = "client-c" };

    _ = try table.offer(alloc, client_a, test_mac, test_ip1, .fromSeconds(60));
    _ = try table.offer(alloc, client_b, test_mac, test_ip2, .fromSeconds(60));
    try table.bindOrRenew(alloc, client_c, test_mac, test_ip3, .fromSeconds(60));
    table.table.items(.deadline)[table.lookupByClient(alloc, client_a).?] = .fromNanoseconds(0);
    table.table.items(.deadline)[table.lookupByClient(alloc, client_b).?] = .fromNanoseconds(0);

    try std.testing.expect(table.lookupByClient(alloc, client_a) == null);
    try std.testing.expect(table.lookupByClient(alloc, client_b) == null);
    try std.testing.expect(table.lookupByClient(alloc, client_c) != null);
    try std.testing.expectEqual(@as(usize, 1), table.table.len);
    try std.testing.expectEqual(@as(usize, 2), table.ip_pool.items.len);

    try table.bindOrRenew(alloc, client_a, test_mac, test_ip1, .fromSeconds(60));
    try std.testing.expectEqual(test_ip2, try table.offer(alloc, client_b, test_mac, test_ip2, .fromSeconds(60)));
    try std.testing.expectEqual(@as(usize, 3), table.table.len);
}

test "DHCP decline excludes an address and release makes another address reusable" {
    const alloc = std.testing.allocator;
    var table = try testTable(&.{ test_ip1, test_ip2 });
    defer table.deinit(alloc);
    const client_a: DhcpTable.Client = .{ .id = "client-a" };
    const client_b: DhcpTable.Client = .{ .id = "client-b" };

    _ = try table.offer(alloc, client_a, test_mac, test_ip1, .fromSeconds(60));
    try table.decline(alloc, client_b, test_ip1);
    try std.testing.expectEqual(@as(usize, 0), table.excluded_ips.items.len);
    try std.testing.expectEqual(@as(usize, 1), table.table.len);

    try table.decline(alloc, client_a, test_ip1);
    try std.testing.expectEqual(@as(usize, 1), table.excluded_ips.items.len);
    try std.testing.expectEqual(test_ip1, table.excluded_ips.items[0]);
    try std.testing.expectError(error.InvalidIP, table.offer(alloc, client_b, test_mac, test_ip1, .fromSeconds(60)));

    _ = try table.offer(alloc, client_b, test_mac, test_ip2, .fromSeconds(60));
    table.release(alloc, client_b, test_ip2);
    try std.testing.expectEqual(@as(usize, 1), table.ip_pool.items.len);
    try std.testing.expectEqual(test_ip2, table.ip_pool.items[0]);
}

test "DHCP table owns client identifier bytes" {
    const alloc = std.testing.allocator;
    var table = try testTable(&.{test_ip1});
    defer table.deinit(alloc);
    var client_bytes = [_]u8{ 'a', 'b', 'c' };
    const client: DhcpTable.Client = .{ .id = client_bytes[0..] };

    _ = try table.offer(alloc, client, test_mac, test_ip1, .fromSeconds(60));
    client_bytes[0] = 'x';
    try std.testing.expect(table.lookupByClient(alloc, .{ .id = "abc" }) != null);
    try std.testing.expect(table.lookupByClient(alloc, .{ .id = "xbc" }) == null);
}
