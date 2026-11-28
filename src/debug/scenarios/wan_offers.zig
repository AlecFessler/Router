const std = @import("std");
const Router = @import("router");
const Sim = @import("../network_sim.zig");
const Fixtures = Router.TestFixtures.Synthetic;
const Dhcp = Router.Protocols.DHCPv4;
const IPv4 = Router.Protocols.IPv4.IPv4;
const Mac = Router.Protocols.Ethernet.Mac;

const Offer = struct {
    server: IPv4,
    server_mac: Mac,
    address: IPv4,
    mask: IPv4,
    gateway: IPv4,
    gateway_mac: Mac,
    seconds: u32,

    pub fn reply(self: Offer, peer: *Sim.Peer, alloc: std.mem.Allocator, xid: u32, kind: Dhcp.MessageType) !void {
        const base: []const u8 = if (kind == .nak) &(.{ 53, 1, 6, 54, 4 } ++ self.server) else try Fixtures.dhcpServerOptions(
            alloc,
            @intFromEnum(kind),
            self.server,
            self.mask,
            self.gateway,
            self.seconds,
        );
        var options: [59]u8 = @splat(0); // 300-byte BOOTP message including the end option.
        var writer: std.Io.Writer = .fixed(&options);
        try writer.writeAll(base);
        try writer.writeAll(&(.{ 61, 7, 1 } ++ Sim.wan_mac));
        const yiaddr: IPv4 = if (kind == .nak) @splat(0) else self.address;
        const frame = try Fixtures.dhcpFrame(alloc, 2, xid, Sim.wan_mac, @splat(0), yiaddr, self.server, @splat(255), &options);
        frame[6..12].* = self.server_mac;
        if (kind != .nak) frame[52] = 0x80; // The selecting client asked for broadcast delivery.
        try peer.inject(frame);
    }
};

candidates: [2]Offer,
first: u1,
sent: [2]bool = @splat(false),
selected: ?u1 = null,
late_offer_seen: bool = false,
requested_at: std.Io.Timestamp = .zero,
renewed_at: std.Io.Timestamp = .zero,
broadcast_at: std.Io.Timestamp = .zero,
next_renewal: std.Io.Timestamp = .zero,

pub fn init(first: u1, server: IPv4, random: std.Random) @This() {
    return .{
        .first = first,
        .candidates = .{ .{
            .server = server,
            .server_mac = Sim.gateway_mac,
            .address = .{ 198, 51, 100, random.intRangeAtMost(u8, 64, 125) },
            .mask = Sim.mask,
            .gateway = .{ 198, 51, 100, 249 },
            .gateway_mac = .{ 2, 0, 0, 0, 0, 9 },
            .seconds = 3600,
        }, .{
            .server = .{ 198, 51, 100, 253 },
            .server_mac = .{ 2, 0, 0, 0, 0, 4 },
            .address = .{ 198, 51, 100, random.intRangeAtMost(u8, 160, 190) },
            .mask = .{ 255, 255, 255, 128 },
            .gateway = .{ 198, 51, 100, 250 },
            .gateway_mac = .{ 2, 0, 0, 0, 0, 10 },
            .seconds = 7200,
        } },
    };
}

pub fn choice(self: *const @This()) Offer {
    return self.candidates[self.selected.?];
}

pub fn backup(self: *const @This()) Offer {
    var other = self.candidates[self.selected.? ^ 1];
    const original = self.choice();
    other.address = original.address;
    other.mask = original.mask;
    other.seconds = 14400;
    return other;
}

pub fn rebindTime(self: *const @This(), start: std.Io.Timestamp, phase: Sim.Scenarios.Lifecycle) u64 {
    const selected_ms: u64 = @intCast(start.durationTo(self.requested_at).toMilliseconds());
    const lifetime_ms = 1000 * @as(u64, self.choice().seconds);
    const t1 = selected_ms + lifetime_ms / 2;
    const t2 = selected_ms + 7 * lifetime_ms / 8;
    return switch (phase) {
        .rebind_server_neighbor => t1 - 25,
        .rebind_unicast => t1,
        .rebind_broadcast => t2,
        .rebind_ack => t2 + 25,
        .rebind_lookup => t2 + 60,
        .rebind_route => t2 + 65,
        .rebind_answer => t2 + 110,
        .rebind_backup_neighbor, .rebind_backup_renewal => @as(u64, @intCast(start.durationTo(self.next_renewal).toMilliseconds())) -
            @as(u64, if (phase == .rebind_backup_neighbor) 25 else 0),
        else => unreachable,
    };
}

pub fn rebindAck(self: *@This(), peer: *Sim.Peer, alloc: std.mem.Allocator, xid: u32) !void {
    const server = self.backup();
    const t1 = 6600;
    const t2 = 11400;
    var options: [59]u8 = @splat(0);
    var w: std.Io.Writer = .fixed(&options);
    try w.writeAll(try Fixtures.dhcpServerOptions(alloc, 5, server.server, server.mask, server.gateway, server.seconds));
    try w.writeAll(&(.{ 61, 7, 1 } ++ Sim.wan_mac ++ .{ 58, 4 }));
    try w.writeInt(u32, t1, .big);
    try w.writeAll(&.{ 59, 4 });
    try w.writeInt(u32, t2, .big);
    const frame = try Fixtures.dhcpFrame(alloc, 2, xid, Sim.wan_mac, server.address, server.address, server.server, server.address, &options);
    frame[0..6].* = Sim.wan_mac;
    frame[6..12].* = server.server_mac;
    try peer.inject(frame);
    try peer.count(0);
    const lease = Router.State.wanLease() orelse return error.MissingReboundLease;
    if (Router.State.wan_transaction != null or !std.meta.eql(lease.ip, server.address) or !std.meta.eql(lease.router, server.gateway) or
        !std.meta.eql(lease.subnet_mask, server.mask) or !std.meta.eql(lease.server_id, server.server)) return error.WrongReboundLease;
    // The unchanged transaction can conservatively use its first REQUEST; a new
    // transaction must date its timers from the broadcast the backup answered.
    for ([_]std.Io.Timestamp{ self.renewed_at, self.broadcast_at }) |sent_at| {
        const next_renewal = sent_at.addDuration(.fromSeconds(t1));
        if (std.meta.eql(lease.renewal_deadline, next_renewal) and
            std.meta.eql(lease.rebinding_deadline, sent_at.addDuration(.fromSeconds(t2))) and
            std.meta.eql(lease.expiration_deadline, sent_at.addDuration(.fromSeconds(server.seconds))))
        {
            self.next_renewal = next_renewal;
            return;
        }
    }
    return error.WrongReboundTimers;
}

pub fn exchange(self: *@This(), peer: *Sim.Peer, alloc: std.mem.Allocator, phase: Sim.Scenarios.Lifecycle, xid: u32, secs: u16) !void {
    if (phase != .nak_offer) {
        try peer.tickWan();
        try self.observeRequest(peer, xid, secs);
    }
    if (phase != .nak_bind or !self.late_offer_seen) {
        const index = switch (phase) {
            .nak_offer => self.first,
            .nak_second_offer => self.first ^ 1,
            // A client can wait for both offers. Deliver a delayed copy of the
            // other server's offer once its selection is known.
            .nak_bind => (self.selected orelse return error.MissingSelectingRequest) ^ 1,
            else => unreachable,
        };
        self.late_offer_seen = self.selected != null and index != self.selected.?;
        self.sent[index] = true;
        try self.candidates[index].reply(peer, alloc, xid, .offer);
        try self.observeRequest(peer, xid, secs);
    }
    if (Router.State.wanLease() != null) return error.UsedUnconfirmedAddress;
    if (self.selected != null) {
        const pending = Router.State.wan_transaction orelse return error.MissingSelectingRequest;
        const chosen = self.choice();
        if (pending.xid != xid or !std.meta.eql(pending.expected_server, @as(?IPv4, chosen.server)) or
            !std.meta.eql(pending.requested_ip, @as(?IPv4, chosen.address)) or
            !std.meta.eql(pending.request_sent_at, @as(?std.Io.Timestamp, self.requested_at))) return error.OfferDisplacedSelection;
    }
    if (phase != .nak_bind) return;
    const chosen = self.choice();
    try chosen.reply(peer, alloc, xid, .ack);
    try peer.count(0);
    const lease = Router.State.wanLease() orelse return error.MissingWanLease;
    if (Router.State.wan_transaction != null or !std.meta.eql(lease.ip, chosen.address) or !std.meta.eql(lease.subnet_mask, chosen.mask) or
        !std.meta.eql(lease.router, chosen.gateway) or !std.meta.eql(lease.server_id, chosen.server) or
        !std.meta.eql(lease.renewal_deadline, self.requested_at.addDuration(.fromSeconds(chosen.seconds / 2))) or
        !std.meta.eql(lease.rebinding_deadline, self.requested_at.addDuration(.fromSeconds(7 * chosen.seconds / 8))) or
        !std.meta.eql(lease.expiration_deadline, self.requested_at.addDuration(.fromSeconds(chosen.seconds)))) return error.WrongRecoveredLease;
}

fn observeRequest(self: *@This(), peer: *Sim.Peer, xid: u32, secs: u16) !void {
    if (peer.observation.count == 0) return peer.count(0);
    const frame = try peer.observation.take(0, .wan);
    if (frame.len < 282) return error.ShortDhcp;
    const index = try self.matchRequest(frame[42..]);
    const offer = self.candidates[index];
    _ = try peer.dhcp(.request, .{ .xid = xid, .seconds = secs, .server = offer.server, .requested = offer.address }, Sim.wan_mac, @splat(0));
    if (self.selected == null) self.requested_at = std.Io.Timestamp.now(peer.network.io, .boot);
    self.selected = index;
}

fn matchRequest(self: *const @This(), payload: []const u8) !u1 {
    const request = try Dhcp.parse(payload);
    var options = std.Io.Reader.fixed(request.get(.options));
    var server: ?IPv4 = null;
    var address: ?IPv4 = null;
    while (try Dhcp.parseOption(&options)) |o| switch (o) {
        .server_id => |ip| server = ip,
        .requested_ip_address => |ip| address = ip,
        else => {},
    };
    for (self.candidates, self.sent, 0..) |offer, seen, i| {
        if (!seen or !std.meta.eql(server, @as(?IPv4, offer.server)) or !std.meta.eql(address, @as(?IPv4, offer.address))) continue;
        const index: u1 = @intCast(i);
        if (self.selected != null and self.selected.? != index) return error.OfferDisplacedSelection;
        return index;
    }
    return error.RequestedUnadvertisedOffer;
}

test "a WAN client can select either delivered offer before its first REQUEST" {
    var prng = std.Random.DefaultPrng.init(700);
    var offers = init(0, .{ 198, 51, 100, 254 }, prng.random());
    offers.sent = @splat(true);
    for (offers.candidates, 0..) |offer, i| {
        const request = try Fixtures.DhcpClient.payload(std.testing.allocator, Sim.wan_mac, .{
            .message_type = 3,
            .server_id = offer.server,
            .requested_ip = offer.address,
            .broadcast_flag = true,
        });
        defer std.testing.allocator.free(request);
        offers.selected = null;
        const index: u1 = @intCast(i);
        try std.testing.expectEqual(index, try offers.matchRequest(request));
        offers.selected = index ^ 1;
        try std.testing.expectError(error.OfferDisplacedSelection, offers.matchRequest(request));
    }
}
