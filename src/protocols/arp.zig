//! "The world is a jungle in general, and the networking game contributes many animals" - David C. Plummer 1982 RFC #826
//! ARP packet structure:
//!         ________________________________________________________________________________________
//! Field: | Hardware | Protocol | HW Size | PRTCL Size | Opcode | Tx MAC | Tx IP | Rx MAC | Rx IP |
//!        -----------------------------------------------------------------------------------------
//! Bytes: |     2    |     2    |    1    |      1     |    2   |    6   |   4   |    6   |   4   |
//!        -----------------------------------------------------------------------------------------
//!
//! Generally the first four fields are expected to be 1, 0x0800, 6, and 4 for Ethernet, IP, MAC len, and IP len, respectively.
//!
//! An opcode of 1 indicates a request, and 2 indicates a reply.

const std = @import("std");

const ethernet = @import("ethernet.zig");
const ipv4 = @import("ipv4.zig");

const IPv4 = ipv4.IPv4;
const Mac = ethernet.Mac;

pub const ArpTable = struct {
    pub const Entry = struct {
        mac: Mac,
        timestamp: std.Io.Timestamp,
    };

    pub const Table = std.AutoHashMapUnmanaged(u32, Entry);

    pub const KVPair = struct {
        ip: IPv4,
        mac: Mac,
        timestamp: std.Io.Timestamp,
    };

    io: std.Io,
    table: Table,
    ttl: std.Io.Duration,

    pub fn init(
        alloc: std.mem.Allocator,
        io: std.Io,
        capacity: u32,
        ttl: std.Io.Duration,
    ) !ArpTable {
        var table: Table = .empty;
        try table.ensureTotalCapacity(alloc, capacity);
        return .{
            .io = io,
            .table = table,
            .ttl = ttl,
        };
    }

    pub fn deinit(self: *ArpTable, alloc: std.mem.Allocator) void {
        self.table.deinit(alloc);
    }

    pub fn lookup(self: *ArpTable, ip: IPv4) ?Mac {
        const entry = self.table.get(@bitCast(ip)) orelse return null;
        const age = entry.timestamp.untilNow(self.io, .boot);
        const is_expired = (self.ttl.toNanoseconds() - age.toNanoseconds()) <= 0;
        if (is_expired) {
            const removed = self.table.remove(@bitCast(ip));
            std.debug.assert(removed);
            return null;
        }
        return entry.mac;
    }

    pub fn cache(self: *ArpTable, ip: IPv4, mac: Mac) void {
        const entry: Entry = .{
            .mac = mac,
            .timestamp = std.Io.Timestamp.now(self.io, .boot),
        };
        const key: u32 = std.mem.readInt(u32, &ip, .little);

        if (self.lookup(ip) != null) {
            self.table.putAssumeCapacity(key, entry);
            return;
        }

        if (self.table.available == 0) {
            var target: u32 = undefined;
            var target_age: std.Io.Duration = std.Io.Duration.fromMilliseconds(0);
            var it = self.table.iterator();
            while (it.next()) |kv| {
                const age = kv.value_ptr.timestamp.untilNow(self.io, .boot);
                const found_new_oldest = age.toNanoseconds() >= target_age.toNanoseconds();
                if (!found_new_oldest) continue;
                target = kv.key_ptr.*;
                target_age = age;
            }
            const removed = self.table.remove(target);
            std.debug.assert(removed);
        }

        self.table.putAssumeCapacity(key, entry);
    }

    pub fn dump(self: *ArpTable, alloc: std.mem.Allocator) ![]KVPair {
        const buffer = try alloc.alloc(KVPair, self.table.size);
        var it = self.table.iterator();
        var i: u32 = 0;
        while (it.next()) |kv| : (i += 1) {
            const ip: IPv4 = std.mem.toBytes(kv.key_ptr.*)[0..4].*;
            buffer[i] = KVPair{
                .ip = ip,
                .mac = kv.value_ptr.mac,
                .timestamp = kv.value_ptr.timestamp,
            };
        }
        return buffer;
    }
};

pub const ArpPacket = struct {};

//pub fn parse(buffer: []const u8) !ArpPacket {}

//pub fn serialize(packet: ArpPacket, buffer: []u8) ![]u8 {}

//pub fn reply(sender_mac: Mac, sender_ip: IPv4, target_mac: Mac, target_ip: IPv4) ArpPacket {}

//pub fn request(sender_mac: Mac, sender_ip: IPv4, target_mac: Mac, target_ip: IPv4) ArpPacket {}

test "ArpTable.cache() stores the IP->MAC key value pair" {
    var table = try ArpTable.init(
        std.testing.allocator,
        std.testing.io,
        256,
        std.Io.Duration.fromMilliseconds(10_000),
    );
    defer table.deinit(std.testing.allocator);
    const test_ip: IPv4 = .{ 255, 255, 255, 255 };
    const test_mac: Mac = .{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };

    table.cache(test_ip, test_mac);
    const entry = table.table.get(@bitCast(test_ip));
    try std.testing.expectEqual(test_mac, entry.?.mac);
}

test "ArpTable.cache() evicts one entry on full capacity" {
    var table = try ArpTable.init(
        std.testing.allocator,
        std.testing.io,
        1,
        std.Io.Duration.fromMilliseconds(10_000),
    );
    defer table.deinit(std.testing.allocator);
    const target_test_ip: IPv4 = .{ 255, 255, 255, 255 };
    const test_mac: Mac = .{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
    table.cache(target_test_ip, test_mac);
    try std.testing.io.sleep(.fromMilliseconds(1), .boot);

    for (0..table.table.available + 1) |i| {
        const as_u8: u8 = @intCast(i);
        const test_ip: IPv4 = .{ as_u8, as_u8, as_u8, as_u8 };
        table.cache(test_ip, test_mac);
    }

    const expected_null = table.table.get(@bitCast(target_test_ip));
    try std.testing.expectEqual(null, expected_null);
}

test "ArpTable.cache() updates the timestamp on existing entries" {
    var table = try ArpTable.init(
        std.testing.allocator,
        std.testing.io,
        256,
        std.Io.Duration.fromMilliseconds(10_000),
    );
    defer table.deinit(std.testing.allocator);
    const test_ip: IPv4 = .{ 255, 255, 255, 255 };
    const test_mac: Mac = .{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };

    table.cache(test_ip, test_mac);
    const entry_timestamp1 = table.table.get(@bitCast(test_ip)).?.timestamp;
    try std.testing.io.sleep(.fromMilliseconds(1), .boot);
    table.cache(test_ip, test_mac);
    const entry_timestamp2 = table.table.get(@bitCast(test_ip)).?.timestamp;
    try std.testing.expect(entry_timestamp1.toNanoseconds() < entry_timestamp2.toNanoseconds());
}

test "ArpTable.lookup() returns null for IPs that aren't cached" {
    var table = try ArpTable.init(
        std.testing.allocator,
        std.testing.io,
        256,
        std.Io.Duration.fromMilliseconds(10_000),
    );
    defer table.deinit(std.testing.allocator);
    const test_ip: IPv4 = .{ 255, 255, 255, 255 };

    try std.testing.expectEqual(null, table.lookup(test_ip));
}

test "ArpTable.lookup() returns null for expired cache entries" {
    var table = try ArpTable.init(
        std.testing.allocator,
        std.testing.io,
        256,
        std.Io.Duration.fromMilliseconds(1),
    );
    defer table.deinit(std.testing.allocator);
    const test_ip: IPv4 = .{ 255, 255, 255, 255 };
    const test_mac: Mac = .{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };

    table.cache(test_ip, test_mac);
    const entry = table.table.get(@bitCast(test_ip));
    try std.testing.expectEqual(test_mac, entry.?.mac);
    try std.testing.io.sleep(.fromMilliseconds(2), .boot);
    try std.testing.expectEqual(null, table.lookup(test_ip));
}

test "ArpTable.lookup() returns the MAC for IPs that are cached and not expired" {
    var table = try ArpTable.init(
        std.testing.allocator,
        std.testing.io,
        256,
        std.Io.Duration.fromMilliseconds(10_000),
    );
    defer table.deinit(std.testing.allocator);
    const test_ip: IPv4 = .{ 255, 255, 255, 255 };
    const test_mac: Mac = .{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };

    table.cache(test_ip, test_mac);
    try std.testing.expectEqual(test_mac, table.lookup(test_ip));
}
