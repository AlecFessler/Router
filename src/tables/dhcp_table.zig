const std = @import("std");
const Router = @import("router");

const IPv4 = Router.Protocols.IPv4.IPv4;
const Mac = Router.Protocols.Ethernet.Mac;

pub const DhcpTable = struct {
    pub const MAX_CLIENT_ID_LEN = 255;

    pub const Client = union(enum) {
        id: []const u8,
        mac: Mac,
    };

    pub const OwnedClient = union(enum) {
        id: struct {
            len: u8,
            bytes: [MAX_CLIENT_ID_LEN]u8,
        },
        mac: Mac,
    };

    pub const LeaseState = enum {
        offered,
        bound,
    };

    pub const Entry = struct {
        client: OwnedClient,
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
        errdefer table.deinit(alloc);
        try table.setCapacity(alloc, ip_pool.items.len);
        var excluded_ips: IpPool = .empty;
        errdefer excluded_ips.deinit(alloc);
        try excluded_ips.ensureTotalCapacity(alloc, ip_pool.items.len);
        return .{
            .io = io,
            .table = table,
            .ip_pool = ip_pool,
            .excluded_ips = excluded_ips,
        };
    }

    pub fn deinit(self: *DhcpTable, alloc: std.mem.Allocator) void {
        self.table.deinit(alloc);
        self.ip_pool.deinit(alloc);
        self.excluded_ips.deinit(alloc);
    }

    fn isExpired(self: *DhcpTable, deadline: std.Io.Timestamp) bool {
        return deadline.untilNow(self.io, .boot).toNanoseconds() >= 0;
    }

    fn sameClient(a: OwnedClient, b: Client) bool {
        return switch (a) {
            .id => |id| switch (b) {
                .id => |bytes| std.mem.eql(u8, id.bytes[0..id.len], bytes),
                .mac => false,
            },
            .mac => |mac| switch (b) {
                .id => false,
                .mac => |other| std.mem.eql(u8, mac[0..], other[0..]),
            },
        };
    }

    fn ownedClient(client: Client) !OwnedClient {
        return switch (client) {
            .mac => |mac| .{ .mac = mac },
            .id => |bytes| blk: {
                if (bytes.len > MAX_CLIENT_ID_LEN) return error.ClientIdTooLong;
                var id: OwnedClient = .{ .id = .{
                    .len = @intCast(bytes.len),
                    .bytes = undefined,
                } };
                @memcpy(id.id.bytes[0..bytes.len], bytes);
                break :blk id;
            },
        };
    }

    fn removeAtIndex(self: *DhcpTable, index: usize) void {
        self.table.swapRemove(index);
    }

    fn removeEntry(
        self: *DhcpTable,
        client: Client,
        ip: IPv4,
    ) bool {
        const client_index = self.lookupByClient(client) orelse return false;
        const found_entry_ip = self.table.items(.ip)[client_index];
        if (!std.meta.eql(found_entry_ip, ip)) return false;
        self.removeAtIndex(client_index);
        return true;
    }

    pub fn lookupByClient(
        self: *DhcpTable,
        client: Client,
    ) ?usize {
        for (self.table.items(.client), 0..) |item, i| {
            if (!sameClient(item, client)) continue;
            if (self.isExpired(self.table.items(.deadline)[i])) {
                const ip = self.table.items(.ip)[i];
                self.removeAtIndex(i);
                self.ip_pool.appendAssumeCapacity(ip);
                return null;
            }
            return i;
        }
        return null;
    }

    pub fn lookupByIp(
        self: *DhcpTable,
        ip: IPv4,
    ) ?usize {
        for (self.table.items(.ip), 0..) |item, i| {
            if (!std.meta.eql(item, ip)) continue;
            if (self.isExpired(self.table.items(.deadline)[i])) {
                self.removeAtIndex(i);
                self.ip_pool.appendAssumeCapacity(ip);
                return null;
            }
            return i;
        }
        return null;
    }

    fn addNewEntry(
        self: *DhcpTable,
        client: Client,
        mac: Mac,
        candidate_ip: IPv4,
        duration: std.Io.Duration,
        state: LeaseState,
    ) !void {
        if (self.lookupByIp(candidate_ip) != null) return error.InvalidIP;
        if (self.table.len == self.table.capacity) return error.NoCapacity;
        const ip_index = for (self.ip_pool.items, 0..) |ip, i| {
            if (std.meta.eql(ip, candidate_ip)) break i;
        } else return error.InvalidIP;

        const stored_client = try ownedClient(client);

        const now = std.Io.Timestamp.now(self.io, .boot);

        _ = self.ip_pool.swapRemove(ip_index);

        self.table.appendAssumeCapacity(.{
            .client = stored_client,
            .mac = mac,
            .ip = candidate_ip,
            .state = state,
            .deadline = now.addDuration(duration),
        });
    }

    pub fn offer(
        self: *DhcpTable,
        client: Client,
        mac: Mac,
        candidate_ip: IPv4,
        offer_duration: std.Io.Duration,
    ) !IPv4 {
        if (self.lookupByClient(client)) |index| {
            return self.table.items(.ip)[index];
        }
        try self.addNewEntry(
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
        client: Client,
        mac: Mac,
        ip: IPv4,
        lease_duration: std.Io.Duration,
    ) !void {
        const client_index = self.lookupByClient(client) orelse {
            return self.addNewEntry(
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
        client: Client,
        ip: IPv4,
    ) void {
        const removed = self.removeEntry(client, ip);
        if (!removed) return;
        self.ip_pool.appendAssumeCapacity(ip);
    }

    pub fn decline(
        self: *DhcpTable,
        client: Client,
        ip: IPv4,
    ) void {
        const client_index = self.lookupByClient(client) orelse return;
        if (!std.meta.eql(self.table.items(.ip)[client_index], ip)) return;
        // TODO: right now excluded IPs are excluded forever. Later, maybe setup something
        // like a repeating timer that does an arp probe to determine if the address conflict is over.
        self.excluded_ips.appendAssumeCapacity(ip);
        self.removeAtIndex(client_index);
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

    try std.testing.expectEqual(test_ip1, try table.offer(client, test_mac, test_ip1, .fromSeconds(30)));
    const offer_index = table.lookupByClient(client).?;
    try std.testing.expectEqual(DhcpTable.LeaseState.offered, table.table.items(.state)[offer_index]);

    try std.testing.expectEqual(test_ip1, try table.offer(client, test_mac, test_ip2, .fromSeconds(30)));
    try std.testing.expectEqual(@as(usize, 1), table.table.len);
    try table.bindOrRenew(client, test_mac, test_ip1, .fromSeconds(60));
    const bound_entry = table.table.get(table.lookupByClient(client).?);
    try std.testing.expectEqual(DhcpTable.LeaseState.bound, bound_entry.state);

    try std.testing.expectEqual(test_ip1, try table.offer(client, test_mac, test_ip2, .fromSeconds(30)));
    const reconnected_entry = table.table.get(table.lookupByClient(client).?);
    try std.testing.expectEqual(bound_entry.deadline, reconnected_entry.deadline);
    try std.testing.expectEqual(DhcpTable.LeaseState.bound, reconnected_entry.state);

    try table.bindOrRenew(client, test_mac, test_ip1, .fromSeconds(120));
    const renewed_entry = table.table.get(table.lookupByClient(client).?);
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

    try table.bindOrRenew(client_a, test_mac, test_ip1, .fromSeconds(60));
    try std.testing.expectError(error.InvalidIP, table.offer(client_b, other_mac, test_ip1, .fromSeconds(30)));
    try std.testing.expectError(error.InvalidMac, table.bindOrRenew(client_a, other_mac, test_ip1, .fromSeconds(60)));
    try std.testing.expectError(error.InvalidIP, table.bindOrRenew(client_a, test_mac, test_ip2, .fromSeconds(60)));
    table.release(client_b, test_ip1);
    table.release(client_a, test_ip2);
    try std.testing.expectEqual(@as(usize, 1), table.table.len);
    try std.testing.expectEqual(test_ip1, table.table.items(.ip)[0]);

    table.release(client_a, test_ip1);
    try std.testing.expectEqual(@as(usize, 0), table.table.len);
    try std.testing.expectEqual(test_ip1, try table.offer(client_b, other_mac, test_ip1, .fromSeconds(30)));
}

test "DHCP expiry reclaims multiple addresses while retaining a live lease" {
    const alloc = std.testing.allocator;
    var table = try testTable(&.{ test_ip1, test_ip2, test_ip3 });
    defer table.deinit(alloc);
    const client_a: DhcpTable.Client = .{ .id = "client-a" };
    const client_b: DhcpTable.Client = .{ .id = "client-b" };
    const client_c: DhcpTable.Client = .{ .id = "client-c" };

    _ = try table.offer(client_a, test_mac, test_ip1, .fromSeconds(60));
    _ = try table.offer(client_b, test_mac, test_ip2, .fromSeconds(60));
    try table.bindOrRenew(client_c, test_mac, test_ip3, .fromSeconds(60));
    table.table.items(.deadline)[table.lookupByClient(client_a).?] = .fromNanoseconds(0);
    table.table.items(.deadline)[table.lookupByClient(client_b).?] = .fromNanoseconds(0);

    try std.testing.expect(table.lookupByClient(client_a) == null);
    try std.testing.expect(table.lookupByClient(client_b) == null);
    try std.testing.expect(table.lookupByClient(client_c) != null);
    try std.testing.expectEqual(@as(usize, 1), table.table.len);
    try std.testing.expectEqual(@as(usize, 2), table.ip_pool.items.len);

    try table.bindOrRenew(client_a, test_mac, test_ip1, .fromSeconds(60));
    try std.testing.expectEqual(test_ip2, try table.offer(client_b, test_mac, test_ip2, .fromSeconds(60)));
    try std.testing.expectEqual(@as(usize, 3), table.table.len);
}

test "DHCP decline excludes an address and release makes another address reusable" {
    const alloc = std.testing.allocator;
    var table = try testTable(&.{ test_ip1, test_ip2 });
    defer table.deinit(alloc);
    const client_a: DhcpTable.Client = .{ .id = "client-a" };
    const client_b: DhcpTable.Client = .{ .id = "client-b" };

    _ = try table.offer(client_a, test_mac, test_ip1, .fromSeconds(60));
    table.decline(client_b, test_ip1);
    try std.testing.expectEqual(@as(usize, 0), table.excluded_ips.items.len);
    try std.testing.expectEqual(@as(usize, 1), table.table.len);

    table.decline(client_a, test_ip1);
    try std.testing.expectEqual(@as(usize, 1), table.excluded_ips.items.len);
    try std.testing.expectEqual(test_ip1, table.excluded_ips.items[0]);
    try std.testing.expectError(error.InvalidIP, table.offer(client_b, test_mac, test_ip1, .fromSeconds(60)));

    _ = try table.offer(client_b, test_mac, test_ip2, .fromSeconds(60));
    table.release(client_b, test_ip2);
    try std.testing.expectEqual(@as(usize, 1), table.ip_pool.items.len);
    try std.testing.expectEqual(test_ip2, table.ip_pool.items[0]);
}

test "DHCP table owns client identifier bytes" {
    const alloc = std.testing.allocator;
    var table = try testTable(&.{test_ip1});
    defer table.deinit(alloc);
    var client_bytes = [_]u8{ 'a', 'b', 'c' };
    const client: DhcpTable.Client = .{ .id = client_bytes[0..] };

    _ = try table.offer(client, test_mac, test_ip1, .fromSeconds(60));
    client_bytes[0] = 'x';
    try std.testing.expect(table.lookupByClient(.{ .id = "abc" }) != null);
    try std.testing.expect(table.lookupByClient(.{ .id = "xbc" }) == null);
}

test "DHCP client identifiers survive removal and slot reuse" {
    const alloc = std.testing.allocator;
    var table = try testTable(&.{ test_ip1, test_ip2 });
    defer table.deinit(alloc);
    const first: DhcpTable.Client = .{ .id = "first" };
    const second: DhcpTable.Client = .{ .id = "second" };
    const third: DhcpTable.Client = .{ .id = "third" };

    _ = try table.offer(first, test_mac, test_ip1, .fromSeconds(60));
    _ = try table.offer(second, test_mac, test_ip2, .fromSeconds(60));
    table.release(first, test_ip1);
    try std.testing.expect(table.lookupByClient(second) != null);
    _ = try table.offer(third, test_mac, test_ip1, .fromSeconds(60));
    try std.testing.expect(table.lookupByClient(second) != null);
    try std.testing.expect(table.lookupByClient(third) != null);
}

test "DHCP client identifier storage is bounded by the option length" {
    const alloc = std.testing.allocator;
    var table = try testTable(&.{test_ip1});
    defer table.deinit(alloc);
    const max_id = [_]u8{42} ** DhcpTable.MAX_CLIENT_ID_LEN;
    const too_long = [_]u8{42} ** (DhcpTable.MAX_CLIENT_ID_LEN + 1);

    try std.testing.expectError(error.ClientIdTooLong, table.offer(.{ .id = &too_long }, test_mac, test_ip1, .fromSeconds(60)));
    try std.testing.expectEqual(@as(usize, 0), table.table.len);
    try std.testing.expectEqual(@as(usize, 1), table.ip_pool.items.len);
    _ = try table.offer(.{ .id = &max_id }, test_mac, test_ip1, .fromSeconds(60));
    try std.testing.expect(table.lookupByClient(.{ .id = &max_id }) != null);
}
