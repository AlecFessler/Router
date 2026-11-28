const std = @import("std");
const Router = @import("router");
const Ethernet = Router.Protocols.Ethernet;
const IPv4 = Router.Protocols.IPv4;
const Key = Router.Tables.IPv4FragmentTable.IPv4FragmentTable.Key;

pub const ReassemblyTable = struct {
    const max_datagram = std.math.maxInt(u16);
    const prefix_space = 256; // Ethernet, VLAN stack and the first IPv4 header.
    const max_payload = max_datagram - 20;
    const Blocks = std.StaticBitSet((max_payload + 7) / 8);

    const Entry = struct {
        key: Key,
        deadline: std.Io.Timestamp,
        ethernet_len: usize,
        ip_header_len: usize = 0,
        blocks: Blocks = Blocks.initEmpty(),
        received: usize = 0,
        highest_end: usize = 0,
        saw_ce: bool = false,
        saw_not_ect: bool = false,
        final_len: ?usize = null,
        bytes: [prefix_space + max_payload]u8 = undefined,

        fn frame(self: *Entry, payload_len: usize) []u8 {
            return self.bytes[prefix_space - self.ethernet_len - self.ip_header_len .. prefix_space + payload_len];
        }
    };

    pub const Result = union(enum) { assembling: struct { has_first: bool }, complete: []u8 };

    entries: []Entry,
    io: std.Io,
    timeout: std.Io.Duration,

    pub fn init(alloc: std.mem.Allocator, io: std.Io, capacity: usize, timeout: std.Io.Duration) !ReassemblyTable {
        const entries = try alloc.alloc(Entry, capacity);
        for (entries) |*entry| entry.deadline = .zero;
        return .{ .entries = entries, .io = io, .timeout = timeout };
    }

    pub fn deinit(self: *ReassemblyTable, alloc: std.mem.Allocator) void {
        alloc.free(self.entries);
    }

    /// Copies a validated fragment. The completed Ethernet frame is borrowed until the next append.
    pub fn append(self: *ReassemblyTable, frame: []const u8, eth: Ethernet.EthernetFrameView, ip: IPv4.IPv4PacketView) !Result {
        const key = Key.from(ip);
        const tags = eth.get(.vlan_tags);
        const ethernet_len = 14 + tags.len;
        const header_len = @as(usize, ip.get(.ihl)) * 4;
        const data = ip.get(.payload);
        const start = @as(usize, ip.get(.fragment_offset)) * 8;
        const end = start + data.len;
        if (end > max_payload or ethernet_len + header_len > prefix_space) return error.DatagramTooLarge;

        const now = std.Io.Timestamp.now(self.io, .boot);
        var oldest: ?*Entry = null;
        const entry = for (self.entries) |*candidate| {
            if (candidate.deadline.toNanoseconds() > now.toNanoseconds() and std.meta.eql(candidate.key, key) and
                Ethernet.sameVlan(candidate.frame(0)[12 .. candidate.ethernet_len - 2], tags)) break candidate;
            if (oldest == null or candidate.deadline.toNanoseconds() < oldest.?.deadline.toNanoseconds())
                oldest = candidate;
        } else blk: {
            const slot = oldest orelse return error.ReassemblyTableFull;
            slot.* = .{ .key = key, .deadline = now.addDuration(self.timeout), .ethernet_len = ethernet_len };
            @memcpy(slot.frame(0), frame[0..ethernet_len]);
            break :blk slot;
        };
        errdefer entry.deadline = .zero;

        entry.saw_ce = entry.saw_ce or ip.get(.ecn) == 3;
        entry.saw_not_ect = entry.saw_not_ect or ip.get(.ecn) == 0;
        if (entry.saw_ce and entry.saw_not_ect) return error.ConflictingFragment;
        const more = ip.get(.more_fragments);
        if (entry.final_len) |last| {
            if (end > last or (more and end >= last) or (!more and end != last)) return error.ConflictingFragment;
        } else if (!more) {
            if (entry.highest_end >= end) return error.ConflictingFragment;
            entry.final_len = end;
        }

        const target = entry.bytes[prefix_space + start ..][0..data.len];
        var present: usize = 0;
        for (start / 8..(end + 7) / 8) |i| present += @intFromBool(entry.blocks.isSet(i));
        if (present != 0) {
            if (present == (data.len + 7) / 8 and std.mem.eql(u8, target, data)) return .{ .assembling = .{ .has_first = entry.ip_header_len != 0 } };
            return error.OverlappingFragment;
        }
        if (start == 0) {
            entry.ethernet_len = ethernet_len;
            entry.ip_header_len = header_len;
            @memcpy(entry.frame(0), frame[0 .. ethernet_len + header_len]);
        }
        entry.highest_end = @max(end, entry.highest_end);
        if (entry.highest_end + entry.ip_header_len > max_datagram)
            return error.DatagramTooLarge;
        @memcpy(target, data);
        entry.blocks.setRangeValue(.{ .start = start / 8, .end = (end + 7) / 8 }, true);
        entry.received += data.len;
        if (entry.final_len != entry.received) return .{ .assembling = .{ .has_first = entry.ip_header_len != 0 } };

        const assembled = entry.frame(entry.received);
        var header = try IPv4.parse(assembled[entry.ethernet_len..]);
        if (entry.saw_ce) header.set(.ecn, 3);
        header.set(.more_fragments, false);
        header.set(.total_length, @intCast(assembled.len - entry.ethernet_len));
        header.set(.header_checksum, 0);
        var checksum = header.checksum();
        checksum.addFields(.version, .options);
        header.set(.header_checksum, checksum.finish());
        entry.deadline = .zero;
        return .{ .complete = assembled };
    }
};
