const std = @import("std");
const Router = @import("router");
const f = @import("../requirements_tests/packets.zig");
const alloc = std.testing.allocator;
const io = std.testing.io;
const expect = std.testing.expect;
const eq = std.testing.expectEqual;
const table = &Router.State.dhcp_table;

const tags = [_]f.P.VlanTag{.{ .vid = 37 }};
const broadcast: f.Eth.Mac = .{255} ** 6;
const zero_ip: [4]u8 = .{0} ** 4;
const next_mac: f.Eth.Mac = .{ 2, 0, 0, 0, 1, 43 };

fn dhcp(h: *f.H, mac: f.Eth.Mac, opts: f.fixtures.DhcpClient.Opts) !void {
    var tagged = opts;
    tagged.vlan_tags = &tags;
    const packet = try f.fixtures.DhcpClient.frame(alloc, mac, tagged);
    defer alloc.free(packet);
    try f.inject(h, .lan, packet);
}

fn startReclaim(h: *f.H) !void {
    const discover: f.fixtures.DhcpClient.Opts = .{ .message_type = 1, .broadcast_flag = true };
    try dhcp(h, f.cm, discover);
    try eq(f.client, (try f.message(h, .lan, .offer)).get(.your_ip));
    try dhcp(h, f.cm, .{ .message_type = 4, .requested_ip = f.client, .server_id = Router.State.lan_ip });
    h.nic.resetLogs();
    try eq(1, table.excluded_ips.items.len);

    try dhcp(h, next_mac, discover);
    try expect(table.reclaim == null);
    try eq(0, h.txCount());
    table.excluded_ips.items[0].deadline = .zero;
    try dhcp(h, next_mac, discover);
    try expect(table.reclaim != null);
    try dhcp(h, next_mac, discover);
    try eq(0, h.txCount());
    try eq(0, h.errorCount());
}

test "DHCP reclaim emits three spaced LAN probes and waits before offering the declined IP" {
    var h = try f.H.init(alloc, io, .{ .dhcp_pool = &.{f.client} });
    defer h.deinit();
    try startReclaim(&h);

    var last_dispatch = std.Io.Timestamp.now(io, .boot);
    for (0..4) |i| {
        // Wait for the actual timer worker; no more input frames arrive.
        try table.probe_due.wait(io);
        const now = std.Io.Timestamp.now(io, .boot);
        const min_ms: i64 = switch (i) {
            0 => 0,
            1, 2 => 1000,
            else => 2000,
        };
        try expect(last_dispatch.durationTo(now).toMilliseconds() >= min_ms);
        try eq(0, table.ip_pool.items.len);
        try eq(i, h.txCount());
        last_dispatch = now;
        try table.tickReclaim(h.nic.api());
        if (i == 3) break;
        const tx = h.txAt(i);
        try eq(f.Iface.lan, tx.iface);
        const eth = try f.Eth.parse(tx.bytes);
        try eq(broadcast, eth.get(.dst_mac));
        try eq(f.Nic.lan_mac, eth.get(.src_mac));
        try std.testing.expectEqualSlices(u8, &.{ 0x81, 0, 0, 37 }, eth.get(.vlan_tags));
        try eq(f.Eth.Ethertype.arp, eth.get(.ethertype));
        const arp = try Router.Protocols.Arp.parse(eth.get(.payload));
        try eq(Router.Protocols.Arp.OpCode.request, arp.get(.opcode));
        try eq(f.Nic.lan_mac, arp.get(.sender_mac));
        try eq(zero_ip, arp.get(.sender_ip));
        try eq([_]u8{0} ** 6, arp.get(.target_mac));
        try eq(f.client, arp.get(.target_ip));
    }

    try eq(3, h.txCount());
    try eq(0, table.excluded_ips.items.len);
    try expect(table.reclaim == null);
    try dhcp(&h, next_mac, .{ .message_type = 1, .broadcast_flag = true });
    try eq(f.client, (try f.message(&h, .lan, .offer)).get(.your_ip));
}

test "LAN ARP claims and competing probes cancel queued DHCP reclaim work" {
    // Deliver each timeout immediately so the conflict can be injected at a specific step.
    var vtable = io.vtable.*;
    vtable.sleep = std.Io.noSleep;
    const fast_io: std.Io = .{ .vtable = &vtable, .userdata = io.userdata };
    for ([_]f.P.ArpOpts{
        .{ .sender_mac = next_mac, .sender_ip = f.client, .target_ip = f.peer },
        .{ .opcode = 2, .sender_mac = next_mac, .sender_ip = f.client, .target_ip = zero_ip },
        .{ .sender_mac = next_mac, .sender_ip = zero_ip, .target_ip = f.client },
    }, [_]usize{ 0, 1, 3 }) |conflict, probes_sent| {
        var h = try f.H.init(alloc, fast_io, .{ .dhcp_pool = &.{f.client}, .wan_lease = f.activeLease() });
        defer h.deinit();
        try startReclaim(&h);
        try f.arpFrame(&h, .wan, tags[0], conflict);
        try f.arpFrame(&h, .lan, .{ .vid = 38 }, conflict);
        try f.arpFrame(&h, .lan, tags[0], .{ .sender_mac = f.Nic.lan_mac, .sender_ip = zero_ip, .target_ip = f.client });
        try f.arpFrame(&h, .lan, tags[0], .{ .sender_mac = next_mac, .sender_ip = f.peer, .target_ip = f.client });
        try expect(table.reclaim != null);

        // Inject the conflict before the first probe, between probes, or after the last.
        for (0..probes_sent) |_| {
            try table.probe_due.wait(io);
            try table.tickReclaim(h.nic.api());
        }
        try table.probe_due.wait(io);
        try f.arpFrame(&h, .lan, .{ .vid = 37, .pcp = 3 }, conflict);
        try expect(table.reclaim == null);
        try table.tickReclaim(h.nic.api());
        try eq(probes_sent, h.txCount());
        try eq(0, table.ip_pool.items.len);
        try eq(1200, table.excluded_ips.items[0].quarantine_seconds);
        try dhcp(&h, next_mac, .{ .message_type = 1, .broadcast_flag = true });
        try eq(probes_sent, h.txCount());
        try expect(table.reclaim == null);
        try eq(0, h.errorCount());
    }
}
