const std = @import("std");
const Router = @import("router");
const f = @import("../requirements_tests/packets.zig");
const Table = Router.Tables.ReassemblyTable.ReassemblyTable;
const alloc = std.testing.allocator;
const eq = std.testing.expectEqual;
const bytesEqual = std.testing.expectEqualSlices;

fn append(table: *Table, id: u16, start: u13, more: bool, data: []const u8, vid: u12) !Table.Result {
    const ip = try f.P.ipv4(alloc, .{ .identification = id, .fragment_offset = start, .more_fragments = more, .payload = data });
    defer alloc.free(ip);
    const frame = try f.P.eth(alloc, .{ .src = f.cm, .dst = f.Nic.lan_mac, .ethertype = 0x0800, .payload = ip, .vlan_tags = &.{.{ .vid = vid }} });
    defer alloc.free(frame);
    const eth = try f.Eth.parse(frame);
    return table.append(frame, eth, try f.IP.parse(eth.get(.payload)));
}

test "reassembly keeps holes, IDs and VLANs separate and accepts identical retransmissions" {
    var table = try Table.init(alloc, std.testing.io, 3, .fromSeconds(60));
    defer table.deinit(alloc);
    _ = try append(&table, 1, 2, false, "tail!", 10);
    _ = try append(&table, 1, 2, false, "tail!", 10);
    _ = try append(&table, 2, 1, true, "other-id", 10);
    _ = try append(&table, 1, 1, true, "bad-vlan", 20);
    const pending = try append(&table, 1, 0, true, "12345678", 10);
    try std.testing.expect(pending.assembling.has_first);
    const complete = (try append(&table, 1, 1, true, "abcdefgh", 10)).complete;
    const eth = try f.Eth.parse(complete);
    const ip = try f.IP.parse(eth.get(.payload));
    try bytesEqual(u8, "12345678abcdefghtail!", ip.get(.payload));
    try eq(false, ip.get(.more_fragments));
    try eq(@as(u13, 0), ip.get(.fragment_offset));
    try eq(@as(u16, 41), ip.get(.total_length));
}

test "conflicting overlaps and inconsistent final lengths discard the partial datagram" {
    var table = try Table.init(alloc, std.testing.io, 1, .fromSeconds(60));
    defer table.deinit(alloc);
    _ = try append(&table, 1, 0, true, "0123456789abcdef", 1);
    try std.testing.expectError(error.OverlappingFragment, append(&table, 1, 1, true, "XXXXXXXX", 1));
    try eq(false, (try append(&table, 1, 2, false, "tail", 1)).assembling.has_first);
    try std.testing.expectError(error.ConflictingFragment, append(&table, 1, 3, false, "tail", 1));
    try eq(true, (try append(&table, 1, 0, true, "0123456789abcdef", 1)).assembling.has_first);
}

test "expiry runs on append and subsequent fragments do not extend the deadline" {
    const Clock = struct {
        var seconds: i64 = 0;
        fn now(_: ?*anyopaque, _: std.Io.Clock) std.Io.Timestamp {
            return .fromNanoseconds(@as(i96, seconds) * std.time.ns_per_s);
        }
    };
    var vtable = std.testing.io.vtable.*;
    vtable.now = Clock.now;
    var table = try Table.init(alloc, .{ .userdata = std.testing.io.userdata, .vtable = &vtable }, 1, .fromSeconds(10));
    defer table.deinit(alloc);
    Clock.seconds = 100;
    _ = try append(&table, 1, 0, true, "12345678", 1);
    Clock.seconds = 109;
    _ = try append(&table, 1, 1, true, "abcdefgh", 1);
    Clock.seconds = 110;
    try eq(false, (try append(&table, 1, 2, false, "last", 1)).assembling.has_first);
    _ = try append(&table, 2, 0, true, "new-slot", 1);
    const result = (try append(&table, 2, 1, false, "!", 1)).complete;
    const eth = try f.Eth.parse(result);
    try bytesEqual(u8, "new-slot!", (try f.IP.parse(eth.get(.payload))).get(.payload));
}

test "LAN and WAN echo reassemble out of order, verify the ICMP checksum and reply within MTU" {
    const data = [_]u8{0xa5} ** 3001;
    const request = try f.P.echo(alloc, .{ .data = &data });
    defer alloc.free(request);
    const expected = try f.P.echo(alloc, .{ .message_type = 0, .data = &data });
    defer alloc.free(expected);
    for ([_]f.Iface{ .lan, .wan }) |side| {
        var h = try f.warm();
        defer h.deinit();
        const src = if (side == .lan) f.client else f.peer;
        const dst = if (side == .lan) Router.State.lan_ip else f.public;
        var fragment: f.P.Ipv4Opts = .{ .src = src, .dst = dst, .protocol = 1, .ttl = if (side == .lan) 1 else 64, .identification = 37, .payload = &.{} };
        var end = request.len;
        while (end > 0) {
            const start = ((end - 1) / 128) * 128;
            fragment.fragment_offset = @intCast(start / 8);
            fragment.more_fragments = end < request.len;
            fragment.payload = request[start..end];
            fragment.ecn = if (start == 128) 3 else 2;
            if (start == 0) fragment.options = &.{ 0x44, 4, 5, 0 };
            try f.send(&h, side, fragment);
            if (start != 0) try eq(0, h.txCount());
            end = start;
        }
        var seen: usize = 0;
        try eq(3, h.txCount());
        for (0..h.txCount()) |i| {
            const ip = try f.emitted(&h, i, side);
            try eq(dst, ip.get(.src));
            try eq(src, ip.get(.dst));
            try eq(@as(usize, ip.get(.fragment_offset)) * 8, seen);
            try eq(i < 2, ip.get(.more_fragments));
            try eq(@as(u2, 3), ip.get(.ecn));
            try std.testing.expect(ip.get(.total_length) <= f.Eth.PAYLOAD_LEN_MAX);
            try bytesEqual(u8, if (i == 0) &.{ 0x44, 4, 5, 0 } else &.{ 1, 1, 1, 1 }, ip.get(.options));
            const payload = ip.get(.payload);
            try bytesEqual(u8, expected[seen..][0..payload.len], payload);
            seen += payload.len;
        }
        try eq(expected.len, seen);
        try eq(0, h.errorCount());
    }
}

test "local echo drops a bad whole-message checksum after receiving all fragments" {
    var h = try f.H.init(alloc, std.testing.io, .{});
    defer h.deinit();
    const request = try f.P.echo(alloc, .{ .data = "123456789" });
    defer alloc.free(request);
    request[request.len - 1] ^= 1;
    var fragment: f.P.Ipv4Opts = .{ .src = f.client, .dst = Router.State.lan_ip, .protocol = 1, .more_fragments = true, .payload = request[0..8] };
    try f.send(&h, .lan, fragment);
    try eq(0, h.errorCount());
    fragment.fragment_offset = 1;
    fragment.more_fragments = false;
    fragment.payload = request[8..];
    try f.send(&h, .lan, fragment);
    try eq(0, h.txCount());
    try eq(1, h.errorCount());
}

test "maximum IPv4 datagram reassembles without length wraparound" {
    var table = try Table.init(alloc, std.testing.io, 1, .fromSeconds(60));
    defer table.deinit(alloc);
    const data = [_]u8{0x5e} ** (65535 - 20);
    _ = try append(&table, 3, 8189, false, data[65512..], 1);
    var start: usize = 0;
    while (start < 65512) {
        const end = @min(start + 1480, 65512);
        const result = try append(&table, 3, @intCast(start / 8), true, data[start..end], 1);
        if (end == 65512) {
            const eth = try f.Eth.parse(result.complete);
            const ip = try f.IP.parse(eth.get(.payload));
            try eq(@as(u16, 65535), ip.get(.total_length));
            try bytesEqual(u8, &data, ip.get(.payload));
        } else try std.testing.expect(result == .assembling);
        start = end;
    }
}

test "early WAN ICMP tail still follows the NAT mapping when the head is an echo reply" {
    var h = try f.warm();
    defer h.deinit();
    const request = try f.P.echo(alloc, .{ .identifier = 777, .data = &(.{0} ** 8) });
    defer alloc.free(request);
    try f.send(&h, .lan, .{ .src = f.client, .dst = f.peer, .protocol = 1, .payload = request });
    const outbound = try f.emitted(&h, 0, .wan);
    const id = std.mem.readInt(u16, outbound.get(.payload)[4..6], .big);
    const reply = try f.P.echo(alloc, .{ .message_type = 0, .identifier = id, .data = request[8..] });
    defer alloc.free(reply);
    var opts: f.P.Ipv4Opts = .{ .src = f.peer, .dst = f.public, .protocol = 1, .fragment_offset = 1, .payload = reply[8..] };
    try f.send(&h, .wan, opts);
    try eq(1, h.txCount());
    opts.fragment_offset = 0;
    opts.more_fragments = true;
    opts.payload = reply[0..8];
    try f.send(&h, .wan, opts);
    try eq(3, h.txCount());
    const head = try f.emitted(&h, 1, .lan);
    const tail = try f.emitted(&h, 2, .lan);
    try eq(f.client, head.get(.dst));
    try eq(@as(u16, 777), std.mem.readInt(u16, head.get(.payload)[4..6], .big));
    try eq(f.client, tail.get(.dst));
    try eq(head.get(.identification), tail.get(.identification));
    try eq(@as(u13, 1), tail.get(.fragment_offset));
    try bytesEqual(u8, reply[8..], tail.get(.payload));
    try eq(0, h.errorCount());
}
