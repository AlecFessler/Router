const std = @import("std");
const Router = @import("router");
const f = @import("../requirements_tests/packets.zig");
const eq = std.testing.expectEqual;
const State = Router.State;
const vlan: f.P.VlanTag = .{ .vid = 37 };

const Clock = struct {
    var seconds: i64 = 0;

    fn now(_: ?*anyopaque, _: std.Io.Clock) std.Io.Timestamp {
        return .fromNanoseconds(@as(i96, seconds) * std.time.ns_per_s);
    }

    fn io(vtable: *std.Io.VTable) std.Io {
        seconds = 100;
        vtable.* = std.testing.io.vtable.*;
        vtable.now = now;
        return .{ .vtable = vtable, .userdata = std.testing.io.userdata };
    }
};

fn expectAnnouncement(h: *f.H, side: f.Iface, ip: [4]u8) !void {
    const tx = h.lastTx() orelse return error.MissingAnnouncement;
    try eq(side, tx.iface);
    const mac = h.nic.api().macAddress(side);
    const eth = try f.Eth.parse(tx.bytes);
    try eq([_]u8{255} ** 6, eth.get(.dst_mac));
    try eq(mac, eth.get(.src_mac));
    try std.testing.expectEqualSlices(u8, &.{ 0x81, 0, 0, 37 }, eth.get(.vlan_tags));
    const arp = try Router.Protocols.Arp.parse(eth.get(.payload));
    try eq(Router.Protocols.Arp.OpCode.request, arp.get(.opcode));
    try eq(mac, arp.get(.sender_mac));
    try eq(ip, arp.get(.sender_ip));
    try eq([_]u8{0} ** 6, arp.get(.target_mac));
    try eq(ip, arp.get(.target_ip));
}

test "LAN keeps its address and defends again after ten quiet seconds" {
    var vtable: std.Io.VTable = undefined;
    var h = try f.H.init(std.testing.allocator, Clock.io(&vtable), .{});
    defer h.deinit();
    const ip = State.lan_ip;
    for ([_]f.Eth.Mac{ f.Nic.lan_mac, f.Nic.wan_mac }) |mac|
        try f.arpFrame(&h, .lan, vlan, .{ .sender_mac = mac, .sender_ip = ip });
    try eq(0, h.txCount());

    const claim: f.P.ArpOpts = .{ .sender_mac = f.cm, .sender_ip = ip, .target_ip = f.client };
    try f.arpFrame(&h, .lan, vlan, claim);
    try eq(1, h.txCount());
    try expectAnnouncement(&h, .lan, ip);
    for ([_]i64{ 109, 111 }) |time| {
        Clock.seconds = time;
        try f.arpFrame(&h, .lan, vlan, claim);
        try eq(1, h.txCount());
    }
    Clock.seconds = 121;
    try f.arpFrame(&h, .lan, vlan, claim);
    try eq(2, h.txCount());
    try expectAnnouncement(&h, .lan, ip);
    try eq(null, State.lan_arp_table.lookup(ip));
    try eq(0, h.errorCount());
}

test "WAN defends once, declines a persistent conflict and rediscovers on the next tick" {
    var vtable: std.Io.VTable = undefined;
    const io = Clock.io(&vtable);
    var lease = f.activeLease();
    lease.server_id = f.dhcp_server;
    var h = try f.H.init(std.testing.allocator, io, .{ .wan_lease = lease });
    defer h.deinit();
    const claim: f.P.ArpOpts = .{ .opcode = 2, .sender_mac = f.gm, .sender_ip = lease.ip };
    try f.arpFrame(&h, .lan, vlan, .{ .sender_ip = State.lan_ip });
    try f.arpFrame(&h, .wan, vlan, claim);
    try expectAnnouncement(&h, .wan, lease.ip);
    try eq(lease.ip, State.wan_lease.?.ip);

    // Renewing the same IP must preserve its defense interval.
    h.cacheArp(.wan, f.gateway, f.gm);
    State.wan_lease.?.renewal_deadline = .zero;
    try f.D.tickWan(io, h.nic.api());
    const xid = (try f.message(&h, .wan, .request)).get(.xid);
    try f.server(&h, xid, 5);
    try eq(null, State.wan_transaction);
    h.nic.resetLogs();
    Clock.seconds += 9;
    try f.arpFrame(&h, .wan, vlan, claim);
    try eq(1, h.txCount());
    const decline = try f.message(&h, .wan, .decline);
    try eq(lease.ip, try f.option(decline, .requested_ip_address));
    try eq(lease.server_id, try f.option(decline, .server_id));
    try eq([_]u8{0} ** 4, decline.get(.client_ip));
    const ip = try f.emitted(&h, 0, .wan);
    try eq([_]u8{0} ** 4, ip.get(.src));
    try eq([_]u8{255} ** 4, ip.get(.dst));
    try eq(null, State.wan_lease);

    try f.arpFrame(&h, .wan, vlan, claim);
    try f.server(&h, xid, 5);
    try eq(null, State.wan_lease);
    try eq(1, h.txCount());
    try f.D.tickWan(io, h.nic.api());
    const discover = try f.message(&h, .wan, .discover);
    try eq(2, h.txCount());
    const new_xid = discover.get(.xid);
    try f.D.tickWan(io, h.nic.api());
    try eq(2, h.txCount());
    try f.server(&h, new_xid, 2);
    try f.D.tickWan(io, h.nic.api());
    _ = try f.message(&h, .wan, .request);
    try f.server(&h, new_xid, 5);
    try eq(f.public, State.wan_lease.?.ip);
    try eq(0, h.errorCount());
}
