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

    const initial_quarantine_seconds = 600;

    pub const ExcludedIp = struct {
        ip: IPv4,
        deadline: std.Io.Timestamp,
        quarantine_seconds: i64 = initial_quarantine_seconds,
        // null if the incoming VLAN stack could not be saved for probing.
        vlan_tags: ?[]u8,
    };

    const Reclaim = struct {
        // Exclusions are appended; only this sequence can remove its entry.
        index: usize,
        probes_sent: u2 = 0,
    };

    alloc: std.mem.Allocator,
    reclaim: ?Reclaim = null,
    probe_timer: std.Io.Group = .init,
    probe_due: std.Io.Event = .unset,
    io: std.Io,
    table: Table,
    ip_pool: IpPool,
    excluded_ips: std.ArrayList(ExcludedIp) = .empty,

    pub fn init(
        alloc: std.mem.Allocator,
        io: std.Io,
        ip_pool: IpPool,
    ) !DhcpTable {
        var table: Table = .empty;
        errdefer table.deinit(alloc);
        try table.setCapacity(alloc, ip_pool.items.len);
        var excluded_ips: std.ArrayList(ExcludedIp) = .empty;
        errdefer excluded_ips.deinit(alloc);
        try excluded_ips.ensureTotalCapacity(alloc, ip_pool.items.len);
        return .{
            .alloc = alloc,
            .io = io,
            .table = table,
            .ip_pool = ip_pool,
            .excluded_ips = excluded_ips,
        };
    }

    pub fn deinit(self: *DhcpTable, alloc: std.mem.Allocator) void {
        self.probe_timer.cancel(self.io);
        for (self.excluded_ips.items) |entry| {
            if (entry.vlan_tags) |tags| alloc.free(tags);
        }
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
        mac: Mac,
        ip: IPv4,
    ) bool {
        const client_index = self.lookupByClient(client) orelse return false;
        if (!std.meta.eql(self.table.items(.mac)[client_index], mac)) return false;
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
        preferred_ip: ?IPv4,
        offer_duration: std.Io.Duration,
    ) !?IPv4 {
        if (self.lookupByClient(client)) |index| {
            return self.table.items(.ip)[index];
        }

        const candidate_ip = pick: {
            if (preferred_ip) |preferred| {
                _ = self.lookupByIp(preferred);
                for (self.ip_pool.items) |ip| {
                    if (std.meta.eql(ip, preferred)) break :pick ip;
                }
            }

            if (self.ip_pool.items.len > 0) break :pick self.ip_pool.items[0];

            var expired_ip: ?IPv4 = null;
            var oldest_offered: ?usize = null;
            var oldest_deadline: i96 = 0;
            for (self.table.items(.deadline), 0..) |deadline, index| {
                if (self.isExpired(deadline)) {
                    const ip = self.table.items(.ip)[index];
                    self.removeAtIndex(index);
                    self.ip_pool.appendAssumeCapacity(ip);
                    expired_ip = ip;
                    break;
                }
                if (self.table.items(.state)[index] != .offered) continue;

                const deadline_ns = deadline.toNanoseconds();
                if (oldest_offered == null or deadline_ns < oldest_deadline) {
                    oldest_offered = index;
                    oldest_deadline = deadline_ns;
                }
            }

            if (expired_ip) |ip| break :pick ip;

            // The pool is empty but one or more leases are still in the
            // short-lived offered state. Reclaim the oldest offer instead
            // of letting one client reserve the whole pool.
            if (oldest_offered) |index| {
                const ip = self.table.items(.ip)[index];
                self.removeAtIndex(index);
                self.ip_pool.appendAssumeCapacity(ip);
                break :pick ip;
            }
            try self.startReclaim();
            return null;
        };

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
        mac: Mac,
        ip: IPv4,
    ) void {
        const removed = self.removeEntry(client, mac, ip);
        if (!removed) return;
        self.ip_pool.appendAssumeCapacity(ip);
    }

    pub fn decline(
        self: *DhcpTable,
        client: Client,
        mac: Mac,
        ip: IPv4,
        vlan_tags: []const u8,
    ) void {
        if (!self.removeEntry(client, mac, ip)) return;

        const now = std.Io.Timestamp.now(self.io, .boot);
        const tags = self.alloc.dupe(u8, vlan_tags) catch blk: {
            std.log.scoped(.dhcp).warn("Keeping declined IP {any} excluded: could not save VLAN tags", .{ip});
            break :blk null;
        };
        self.excluded_ips.appendAssumeCapacity(.{
            .ip = ip,
            .deadline = now.addDuration(.fromSeconds(initial_quarantine_seconds)),
            .vlan_tags = tags,
        });
    }

    fn probeDelay(self: *DhcpTable, min_ms: u32) std.Io.Duration {
        const source: std.Random.IoSource = .{ .io = self.io };
        return .fromMilliseconds(source.interface().intRangeAtMost(u32, min_ms, min_ms + 1000));
    }

    fn armProbeTimer(self: *DhcpTable, delay: std.Io.Duration) !void {
        self.probe_due.reset();
        const deadline = std.Io.Timestamp.now(self.io, .boot).addDuration(delay).withClock(.boot);
        try self.probe_timer.concurrent(self.io, signalAt, .{ self.io, deadline, &self.probe_due });
    }

    fn signalAt(io: std.Io, deadline: std.Io.Clock.Timestamp, due: *std.Io.Event) std.Io.Cancelable!void {
        try deadline.wait(io);
        due.set(io);
    }

    fn startReclaim(self: *DhcpTable) !void {
        if (self.reclaim != null) return;
        for (self.excluded_ips.items, 0..) |entry, i| {
            if (entry.vlan_tags == null or !self.isExpired(entry.deadline)) continue;
            try self.armProbeTimer(self.probeDelay(0));
            self.reclaim = .{ .index = i };
            return;
        }
    }

    pub fn tickReclaim(self: *DhcpTable, device: Router.Nic.Api.Api) !void {
        const probe = if (self.reclaim) |*p| p else return;
        if (!self.probe_due.isSet()) return;
        const entry = self.excluded_ips.items[probe.index];
        if (probe.probes_sent == 3) {
            _ = self.excluded_ips.swapRemove(probe.index);
            self.alloc.free(entry.vlan_tags.?);
            self.ip_pool.appendAssumeCapacity(entry.ip);
            self.reclaim = null;
            return;
        }

        errdefer self.reclaim = null;
        device.transmit(try Router.Protocols.Arp.requestFrame(device, .lan, .{0} ** 4, entry.ip, entry.vlan_tags.?));
        probe.probes_sent += 1;
        const delay: std.Io.Duration = if (probe.probes_sent == 3) .fromSeconds(2) else self.probeDelay(1000);
        try self.armProbeTimer(delay);
    }

    pub fn observeConflict(self: *DhcpTable, ip: IPv4, mac: Mac, vlan_tags: []const u8) void {
        const probe = self.reclaim orelse return;
        const entry = &self.excluded_ips.items[probe.index];
        if (!std.meta.eql(entry.ip, ip)) return;
        if (!Router.Protocols.Ethernet.sameVlan(entry.vlan_tags.?, vlan_tags)) return;
        entry.quarantine_seconds = @min(2 * entry.quarantine_seconds, 3600);
        entry.deadline = std.Io.Timestamp.now(self.io, .boot).addDuration(.fromSeconds(entry.quarantine_seconds));
        self.probe_timer.cancel(self.io);
        self.reclaim = null;
        std.log.scoped(.dhcp).warn("ARP conflict for {d}.{d}.{d}.{d} from {x}; quarantining for {d}s", .{
            ip[0], ip[1], ip[2], ip[3], &mac, entry.quarantine_seconds,
        });
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
    try std.testing.expectError(error.InvalidIP, table.bindOrRenew(client_b, other_mac, test_ip1, .fromSeconds(30)));
    try std.testing.expectError(error.InvalidMac, table.bindOrRenew(client_a, other_mac, test_ip1, .fromSeconds(60)));
    try std.testing.expectError(error.InvalidIP, table.bindOrRenew(client_a, test_mac, test_ip2, .fromSeconds(60)));
    table.release(client_b, test_mac, test_ip1);
    table.release(client_a, test_mac, test_ip2);
    try std.testing.expectEqual(@as(usize, 1), table.table.len);
    try std.testing.expectEqual(test_ip1, table.table.items(.ip)[0]);

    table.release(client_a, test_mac, test_ip1);
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

    // Bind these so the full-pool case is not eligible for oldest-offer
    // reclamation; this test is about expiry.
    try table.bindOrRenew(client_a, test_mac, test_ip1, .fromSeconds(60));
    try table.bindOrRenew(client_b, test_mac, test_ip2, .fromSeconds(60));
    try table.bindOrRenew(client_c, test_mac, test_ip3, .fromSeconds(60));
    const replacement: DhcpTable.Client = .{ .id = "client-d" };
    try std.testing.expect(try table.offer(replacement, test_mac, null, .fromSeconds(60)) == null);

    table.table.items(.deadline)[table.lookupByClient(client_a).?] = .fromNanoseconds(0);
    table.table.items(.deadline)[table.lookupByClient(client_b).?] = .fromNanoseconds(0);
    try std.testing.expectEqual(test_ip1, try table.offer(replacement, test_mac, null, .fromSeconds(60)));
    table.release(replacement, test_mac, test_ip1);

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
    table.decline(client_b, test_mac, test_ip1, &.{});
    try std.testing.expectEqual(@as(usize, 0), table.excluded_ips.items.len);
    try std.testing.expectEqual(@as(usize, 1), table.table.len);

    table.decline(client_a, test_mac, test_ip1, &.{});
    try std.testing.expectEqual(@as(usize, 1), table.excluded_ips.items.len);
    try std.testing.expectEqual(test_ip1, table.excluded_ips.items[0].ip);
    table.excluded_ips.items[0].deadline = .zero;
    try std.testing.expectEqual(test_ip2, try table.offer(client_b, test_mac, test_ip1, .fromSeconds(60)));
    try std.testing.expect(table.reclaim == null);
    table.release(client_b, test_mac, test_ip2);
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
    table.release(first, test_mac, test_ip1);
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

test "pool pressure starts a probe only after the decline quarantine" {
    const alloc = std.testing.allocator;
    var table = try testTable(&.{test_ip1});
    defer table.deinit(alloc);
    const client: DhcpTable.Client = .{ .id = "self-decliner" };
    const other: DhcpTable.Client = .{ .id = "next-client" };

    _ = try table.offer(client, test_mac, test_ip1, .fromSeconds(60));
    table.decline(client, test_mac, test_ip1, &.{});
    try std.testing.expectEqual(@as(usize, 1), table.excluded_ips.items.len);

    try std.testing.expect((try table.offer(other, test_mac, null, .fromSeconds(60))) == null);

    try std.testing.expect(table.reclaim == null);
    table.excluded_ips.items[0].deadline = .fromNanoseconds(0);
    try std.testing.expect(try table.offer(other, test_mac, null, .fromSeconds(60)) == null);
    try std.testing.expect(table.reclaim != null);
}
