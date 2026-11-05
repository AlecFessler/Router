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
        ip: IPv4,
        mac: Mac,
        timestamp: std.Io.Timestamp,
    };

    pub const Table = std.MultiArrayList(Entry);

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
        try table.setCapacity(alloc, capacity);
        return .{
            .io = io,
            .table = table,
            .ttl = ttl,
        };
    }

    pub fn deinit(self: *ArpTable, alloc: std.mem.Allocator) void {
        self.table.deinit(alloc);
    }

    fn FieldType(comptime field: std.meta.FieldEnum(Entry)) type {
        return @FieldType(Entry, @tagName(field));
    }

    // It's a little overcooked, considering we only search for IPs, but damn was it fun to write
    pub fn indexOfValue(
        self: *ArpTable,
        comptime field: Table.Field,
        value: FieldType(field),
    ) ?usize {
        const IntType = std.meta.Int(.unsigned, @bitSizeOf(FieldType(field)));
        const target: IntType = @bitCast(value);
        for (self.table.items(field), 0..) |item, i| {
            const key: IntType = @bitCast(item);
            if (target == key) return i;
        } else return null;
    }

    pub fn lookup(self: *ArpTable, ip: IPv4) ?Mac {
        const index = self.indexOfValue(.ip, ip) orelse return null;
        const timestamp = self.table.items(.timestamp)[index];
        const age = timestamp.untilNow(self.io, .boot);
        const is_expired = (self.ttl.toNanoseconds() - age.toNanoseconds()) <= 0;
        if (is_expired) {
            self.table.swapRemove(index);
            return null;
        }
        return self.table.items(.mac)[index];
    }

    pub fn cache(self: *ArpTable, ip: IPv4, mac: Mac) void {
        const entry: Entry = .{
            .ip = ip,
            .mac = mac,
            .timestamp = std.Io.Timestamp.now(self.io, .boot),
        };

        var index = self.indexOfValue(.ip, ip);
        if (index != null) {
            self.table.set(index.?, entry);
            return;
        }

        if (self.table.len == self.table.capacity) {
            var target_age = std.Io.Duration.fromMilliseconds(0);
            for (self.table.items(.timestamp), 0..) |timestamp, i| {
                const age = timestamp.untilNow(self.io, .boot);
                const found_new_oldest = age.toNanoseconds() >= target_age.toNanoseconds();
                if (!found_new_oldest) continue;
                index = i;
                target_age = age;
            }
            self.table.set(index.?, entry);
            return;
        }

        self.table.appendAssumeCapacity(entry);
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
    const index = table.indexOfValue(.ip, test_ip);
    const entry = table.table.get(index.?);
    try std.testing.expectEqual(test_mac, entry.mac);
}

test "ArpTable.cache() evicts one entry on full capacity" {
    var table = try ArpTable.init(
        std.testing.allocator,
        std.testing.io,
        1,
        std.Io.Duration.fromMilliseconds(10_000),
    );
    defer table.deinit(std.testing.allocator);
    const test_ip1: IPv4 = .{ 255, 255, 255, 255 };
    const test_ip2: IPv4 = .{ 1, 1, 1, 1 };
    const test_mac: Mac = .{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
    table.cache(test_ip1, test_mac);
    table.cache(test_ip2, test_mac);
    const expected_null = table.indexOfValue(.ip, test_ip1);
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
    const index = table.indexOfValue(.ip, test_ip);
    const timestamp_list = table.table.items(.timestamp);
    const entry_timestamp1 = timestamp_list[index.?];
    table.cache(test_ip, test_mac);
    const entry_timestamp2 = timestamp_list[index.?];
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
    const index = table.indexOfValue(.ip, test_ip);
    const entry = table.table.get(index.?);
    try std.testing.expectEqual(test_mac, entry.mac);
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
