const std = @import("std");
const Router = @import("router");
const Sim = @import("../network_sim.zig");
const State = Router.State;
const Mac = Router.Protocols.Ethernet.Mac;
const IPv4 = Router.Protocols.IPv4.IPv4;
const Nat = Router.Tables.NatTable.NatTable;
const Dhcp = Router.TestFixtures.Synthetic.DhcpClient;
const Packets = Router.TestFixtures.Synthetic.Packets;
const LeaseState = Router.Tables.DhcpTable.DhcpTable.LeaseState;

const Guest = struct {
    mac: Mac,
    identifier: u16,
    remote: IPv4 = .{ 203, 0, 113, 8 },
    address: ?IPv4 = null,
    lease_state: LeaseState = .offered,
    deadline: std.Io.Timestamp = .zero,
    refreshed_hold: ?std.Io.Timestamp = null,
    generation: u64 = 0,
    public_identifier: u16 = 0,
    mapping_deadline: std.Io.Timestamp = .zero,
    neighbor_learned: std.Io.Timestamp = .zero,

    fn key(self: Guest, outside: bool) Nat.Key {
        return .{ .protocol = .icmp, .ip = if (outside) Sim.wan else self.address.?, .port = if (outside) self.public_identifier else self.identifier };
    }

    fn ping(self: Guest, alloc: std.mem.Allocator, reply: bool, outside: bool, ttl: u8, token: u64) ![]u8 {
        const host = self.key(outside).ip;
        const client_mac = if (outside) Sim.wan_mac else self.mac;
        const next_mac = if (outside) Sim.gateway_mac else Sim.lan_mac;
        var data: [8]u8 = undefined;
        std.mem.writeInt(u64, &data, token +% self.mac[5], .big);
        return Sim.wire(alloc, if (reply) next_mac else client_mac, if (reply) client_mac else next_mac, .{
            .src = if (reply) self.remote else host,
            .dst = if (reply) host else self.remote,
            .protocol = 1,
            .ttl = ttl,
            .payload = try Packets.echo(alloc, .{ .message_type = if (reply) 0 else 8, .identifier = self.key(outside).port, .sequence_number = 1, .data = &data }),
        });
    }

    fn checkMapping(self: Guest) !void {
        const table = &State.nat_table;
        const binding = table.inside.get(self.key(false)) orelse return error.MissingGuestMapping;
        if (!std.meta.eql(binding.outside, self.key(true)) or !std.meta.eql(table.outside.get(binding.outside), @as(?Nat.Key, self.key(false))) or
            !table.icmp_ports.used.isSet(self.public_identifier) or binding.generation != self.generation or !std.meta.eql(binding.deadline, self.mapping_deadline) or
            binding.peer_count != 1 or !std.meta.eql(binding.peers[0], Nat.Peer{ .ip = self.remote, .port = self.identifier })) return error.WrongGuestMapping;
    }

    fn checkNeighbor(self: Guest) !void {
        const index = State.lan_arp_table.indexOfValue(.ip, self.address.?) orelse return error.MissingGuestNeighbor;
        const entry = State.lan_arp_table.table.get(index);
        if (!std.meta.eql(entry.mac, self.mac) or !std.meta.eql(entry.timestamp, self.neighbor_learned)) return error.WrongGuestNeighbor;
    }
};

pub const JoiningClients = struct {
    guests: [2]Guest = .{
        .{ .mac = .{ 2, 7, 0, 0, 0, 75 }, .identifier = 34075 },
        .{ .mac = .{ 2, 7, 0, 0, 0, 76 }, .identifier = 34076 },
    },
    departed: ?Guest = null,
    missing_offer: ?struct {
        xid: u32,
        sent: std.Io.Timestamp,
        seconds: u16 = 0,
        received: ?IPv4 = null,
    } = null,
    missing_ack: ?struct { xid: u32, address: IPv4, sent: std.Io.Timestamp } = null,
    static_client: @import("static_client.zig") = undefined,

    pub fn selectOtherServer(self: *const JoiningClients, peer: *Sim.Peer, alloc: std.mem.Allocator) !void {
        // This router comes online during another server's exchange. Only the
        // client's broadcast selection reaches it; the other server can ACK by unicast.
        const guest = self.guests[0];
        const ip: IPv4 = .{ 192, 168, 86, 200 };
        const xid = @as(u32, @truncate(peer.network.seed)) +% guest.mac[5] -% 1;
        try peer.inject(try Dhcp.frame(alloc, guest.mac, .{
            .message_type = 3,
            .xid = xid,
            .requested_ip = ip,
            .server_id = .{ 192, 168, 86, 9 },
            .broadcast_flag = true,
        }));
        try peer.expectDrop();
        const table = &State.dhcp_table;
        if (table.table.len != 0 or table.ip_pool.items.len != 253 or table.excluded_ips.items.len != 0 or
            State.lan_arp_table.table.len != 0) return error.ForeignServerSelectionChangedState;
        var seen = std.StaticBitSet(256).initEmpty();
        for (table.ip_pool.items) |addr| {
            if (!std.mem.eql(u8, addr[0..3], Sim.lan[0..3]) or addr[3] < 2 or addr[3] == 255 or
                seen.isSet(addr[3])) return error.ForeignServerSelectionChangedState;
            seen.set(addr[3]);
        }
    }

    pub fn step(self: *JoiningClients, peer: *Sim.Peer, phase: Sim.Scenarios.Lifecycle) !void {
        switch (phase) {
            .static_inform, .static_dns_query, .static_dns_answer => {
                if ((phase == .static_dns_answer) != (peer.iface == .wan)) return;
                try self.static_client.step(peer, phase);
                return self.checkLeases(peer.network);
            },
            else => {},
        }
        const reply = phase == .guest_echo_replies or phase == .guest_replacement_reply;
        if ((peer.iface == .wan) != reply) return;
        var scratch = std.heap.FixedBufferAllocator.init(&peer.scratch);
        const alloc = scratch.allocator();
        const now = std.Io.Timestamp.now(peer.network.io, .boot);
        const handover = switch (phase) {
            .guest_first_release, .guest_replacement_discover, .guest_replacement_request, .guest_replacement_retry, .guest_replacement_connectivity, .guest_replacement_reply => true,
            else => false,
        };
        const participants: []Guest = if (handover) self.guests[0..1] else &self.guests;
        for (participants, 0..) |*guest, i| {
            if (phase == .guest_lost_offer and i != 1) continue;
            scratch.reset();
            const xid = @as(u32, @truncate(peer.network.seed)) +% guest.mac[5];
            switch (phase) {
                .guest_lost_offer, .guest_discovery, .guest_requests, .guest_replacement_discover, .guest_replacement_request, .guest_replacement_retry => {
                    const discover = phase == .guest_lost_offer or phase == .guest_discovery or phase == .guest_replacement_discover;
                    // The second arrival remembers an address already leased to another device.
                    const hint: ?IPv4 = if (handover) self.departed.?.address else if (i == 0) null else .{ 192, 168, 86, 4 };
                    var requested = if (discover) hint else guest.address;
                    var seconds: u16 = 0;
                    if (i == 1 and (phase == .guest_discovery or phase == .guest_requests)) {
                        const retry = if (self.missing_offer) |*r| r else return error.MissingDiscoverRetry;
                        if (xid != retry.xid) return error.WrongDiscoverRetry;
                        if (discover) {
                            const elapsed = retry.sent.durationTo(now);
                            if (elapsed.toMilliseconds() < 3000 or elapsed.toMilliseconds() > 5000 or retry.received != null) return error.WrongDiscoverRetry;
                            retry.seconds = @intCast(elapsed.toSeconds());
                        } else requested = retry.received orelse return error.RequestedUndeliveredOffer;
                        seconds = retry.seconds;
                    }
                    if (phase == .guest_replacement_retry) {
                        const missed = self.missing_ack orelse return error.UnexpectedSelectingRetry;
                        const delay = missed.sent.durationTo(now).toMilliseconds();
                        if (delay < 3000 or delay > 5000 or xid != missed.xid or !std.meta.eql(guest.address.?, missed.address)) return error.WrongSelectingRetry;
                        try self.checkLeases(peer.network);
                    }
                    try peer.inject(try Dhcp.frame(alloc, guest.mac, .{
                        .message_type = if (discover) 1 else 3,
                        .xid = xid,
                        .secs = seconds,
                        .requested_ip = requested,
                        .server_id = if (discover) null else Sim.lan,
                        .broadcast_flag = i == 0,
                    }));
                    if (discover) {
                        const tx = try peer.observation.take(0, .lan);
                        if (tx.len < 62) return error.ShortDhcp;
                        const offer = tx[58..62].*;
                        if (!self.canOffer(guest.address, offer)) return error.GuestOfferedUnavailableAddress;
                        if (handover and !std.meta.eql(offer, hint.?)) return error.ReleasedAddressNotReused;
                        const hold = now.addDuration(.fromSeconds(30));
                        if (std.meta.eql(guest.address, @as(?IPv4, offer))) guest.refreshed_hold = hold else guest.deadline = hold;
                        guest.address = offer;
                        if (phase == .guest_lost_offer) self.missing_offer = .{ .xid = xid, .sent = now };
                        if (phase == .guest_discovery and i == 1) self.missing_offer.?.received = offer;
                    } else {
                        guest.refreshed_hold = null;
                        guest.deadline = now.addDuration(.fromSeconds(86400));
                    }
                    _ = try peer.dhcp(if (discover) .offer else .ack, .{ .xid = xid, .unicast_yiaddr = i == 1 }, guest.mac, guest.address.?);
                    guest.lease_state = if (discover) .offered else .bound;
                    if (phase == .guest_requests and i == 1) self.missing_offer = null;
                    // The first ACK is visible at the router but is lost before reaching the client.
                    if (phase == .guest_replacement_request) self.missing_ack = .{ .xid = xid, .address = guest.address.?, .sent = now };
                    if (phase == .guest_replacement_retry) self.missing_ack = null;
                },
                .guest_connectivity, .guest_replacement_connectivity => {
                    if (self.missing_ack != null or self.missing_offer != null) return error.ClientUsedAddressBeforeAck;
                    const address = guest.address.?;
                    try peer.inject(try Sim.arp(alloc, guest.mac, address, address, null));
                    try peer.expectDrop();
                    try self.checkLeases(peer.network);
                    if (State.dhcp_table.reclaim != null or State.dhcp_table.excluded_ips.items.len != 0) return error.GuestAnnouncementTreatedAsConflict;
                    if (State.lan_arp_table.indexOfValue(.ip, address)) |index| {
                        if (!std.meta.eql(State.lan_arp_table.table.items(.mac)[index], guest.mac)) return error.WrongGuestNeighbor;
                    }
                    try peer.inject(try Sim.arp(alloc, guest.mac, address, Sim.lan, null));
                    try peer.count(1);
                    _ = try peer.expect(0, .lan, try Sim.arp(alloc, Sim.lan_mac, Sim.lan, address, guest.mac));
                    guest.neighbor_learned = now;
                    try guest.checkNeighbor();
                    guest.generation = peer.network.newConversationBinding();
                    guest.public_identifier = peer.network.reservePort(.icmp, guest.identifier);
                    if (handover and guest.generation <= self.departed.?.generation) return error.StaleGuestGeneration;
                    guest.mapping_deadline = now.addDuration(.fromSeconds(60));
                    try peer.inject(try guest.ping(alloc, false, false, 64, peer.network.seed));
                    try peer.count(1);
                    _ = try peer.expect(0, .wan, try guest.ping(alloc, false, true, 63, peer.network.seed));
                    try guest.checkMapping();
                },
                .guest_echo_replies, .guest_replacement_reply => {
                    try peer.inject(try guest.ping(alloc, true, true, 64, peer.network.seed));
                    try peer.count(1);
                    _ = try peer.expect(0, .lan, try guest.ping(alloc, true, false, 63, peer.network.seed));
                    try guest.checkMapping();
                },
                .guest_first_release, .guest_departures => {
                    const ip = guest.address.?;
                    const expected = try Sim.AfterLeaseRemoval.predict(peer.network, &State.nat_table, ip);
                    defer peer.network.mock.alloc.free(expected.survivors);
                    // DHCPRELEASE is unicast from the leased address to the selected server.
                    const payload = try Dhcp.payload(alloc, guest.mac, .{ .message_type = 7, .xid = xid, .ciaddr = ip, .server_id = Sim.lan });
                    try peer.inject(try Sim.wire(alloc, guest.mac, Sim.lan_mac, .{
                        .src = ip,
                        .dst = Sim.lan,
                        .payload = try Packets.udp(alloc, ip, Sim.lan, .{ .src_port = 68, .dst_port = 67, .payload = payload }),
                    }));
                    try peer.count(0);
                    const nat = &State.nat_table;
                    try expected.check(nat);
                    if (nat.inside.contains(guest.key(false)) or nat.outside.contains(guest.key(true)) or nat.icmp_ports.used.isSet(guest.public_identifier) or
                        State.lan_arp_table.indexOfValue(.ip, ip) != null or State.dhcp_table.lookupByClient(.{ .mac = guest.mac }) != null) return error.GuestStateAfterRelease;
                    peer.network.releasePort(.icmp, guest.public_identifier);
                    if (phase == .guest_first_release) {
                        self.departed = guest.*;
                        guest.* = .{ .mac = .{ 2, 7, 0, 0, 0, 77 }, .identifier = guest.identifier, .remote = .{ 203, 0, 113, 9 } };
                    } else guest.address = null;
                },
                else => unreachable,
            }
            try self.checkLeases(peer.network);
        }
        if (handover) {
            const old = self.departed.?;
            if (State.dhcp_table.lookupByClient(.{ .mac = old.mac }) != null) return error.StaleGuestLease;
            if (phase == .guest_replacement_discover or phase == .guest_replacement_request or phase == .guest_replacement_retry) {
                if (State.nat_table.inside.contains(old.key(false)) or State.nat_table.outside.contains(old.key(true)) or
                    State.lan_arp_table.indexOfValue(.ip, old.address.?) != null) return error.StaleGuestForwardingState;
            }
            try self.guests[1].checkMapping();
            try self.guests[1].checkNeighbor();
        }
    }

    fn available(self: *const JoiningClients, ip: IPv4) bool {
        if (!std.mem.eql(u8, ip[0..3], Sim.lan[0..3]) or ip[3] < 18 or ip[3] == 255) return false;
        for (self.guests) |guest| if (std.meta.eql(guest.address, @as(?IPv4, ip))) return false;
        return true;
    }

    fn canOffer(self: *const JoiningClients, reservation: ?IPv4, candidate: IPv4) bool {
        return std.meta.eql(reservation, @as(?IPv4, candidate)) or self.available(candidate);
    }

    fn checkLeases(self: *const JoiningClients, network: *const Sim.Network) !void {
        const table = &State.dhcp_table;
        var count: usize = 16;
        for (self.guests) |guest| if (guest.address) |ip| {
            count += 1;
            const index = table.lookupByIp(ip) orelse return error.MissingGuestLease;
            const entry = table.table.get(index);
            if (table.lookupByClient(.{ .mac = guest.mac }) != index or !std.meta.eql(guest.mac, entry.mac) or
                entry.state != guest.lease_state or (!std.meta.eql(entry.deadline, guest.deadline) and
                !std.meta.eql(guest.refreshed_hold, @as(?std.Io.Timestamp, entry.deadline)))) return error.WrongGuestLease;
            if (entry.state == .offered and (State.lan_arp_table.indexOfValue(.ip, ip) != null or
                State.nat_table.inside.contains(guest.key(false)))) return error.GuestUsedUnboundLease;
        };
        if (table.table.len != count or table.ip_pool.items.len != 253 - count) return error.WrongGuestLeasePool;
        var seen = std.StaticBitSet(256).initEmpty();
        for (table.ip_pool.items) |ip| {
            if (!self.available(ip) or seen.isSet(ip[3])) return error.WrongGuestLeasePool;
            seen.set(ip[3]);
        }
        for (network.clients, 0..) |client, i| {
            const last: u8 = @intCast(i + 2);
            const mac: Mac = .{ 2, 1, 0, 0, 0, last };
            const client_id = [1]u8{1} ++ mac;
            const owner: Router.Tables.DhcpTable.DhcpTable.Client = if (i == network.returning_client) .{ .id = &client_id } else .{ .mac = mac };
            const index = table.lookupByIp(.{ 192, 168, 86, last }) orelse return error.UnrelatedLeaseMissing;
            const entry = table.table.get(index);
            if (table.lookupByClient(owner) != index or entry.state != .bound or !std.meta.eql(entry.mac, mac) or
                !std.meta.eql(entry.deadline, client.lease_deadline)) return error.UnrelatedLeaseChanged;
        }
    }
};

test "guest DHCP offers accept any remaining free LAN address" {
    var clients: JoiningClients = .{};
    for ([_]u8{ 0, 1, 4, 17, 255 }) |host| try std.testing.expect(!clients.available(.{ 192, 168, 86, host }));
    try std.testing.expect(!clients.available(.{ 192, 168, 85, 18 }));
    clients.guests[0].address = .{ 192, 168, 86, 18 };
    try std.testing.expect(!clients.available(.{ 192, 168, 86, 18 }));
    try std.testing.expect(clients.available(.{ 192, 168, 86, 254 }));
    const first = clients.guests[0].address;
    clients.guests[1].address = .{ 192, 168, 86, 19 };
    try std.testing.expect(clients.canOffer(first, first.?));
    try std.testing.expect(clients.canOffer(first, .{ 192, 168, 86, 200 }));
    try std.testing.expect(!clients.canOffer(first, clients.guests[1].address.?));
    try std.testing.expect(!clients.canOffer(first, .{ 192, 168, 86, 4 }));
}

const Clock = Router.Debug.SimulationClock;
const Lifecycle = Sim.Scenarios.Lifecycle;

// Replay the LAN's known entropy input against the RFC 5227 PROBE_WAIT,
// PROBE_MIN/MAX and ANNOUNCE_WAIT intervals, independently of the router timer.
pub fn reclaimTimes(declined: u64) struct { start: u64, first: u64, second: u64, third: u64, finish: u64 } {
    var entropy: Clock.Entropy = .{};
    const random = std.Random.init(&entropy, Clock.Entropy.fill);
    const start = declined + 600_000;
    const first = start + random.intRangeAtMost(u32, 0, 1000);
    const second = first + random.intRangeAtMost(u32, 1000, 2000);
    const third = second + random.intRangeAtMost(u32, 1000, 2000);
    return .{ .start = start, .first = first, .second = second, .third = third, .finish = third + 2000 };
}

pub fn reclaim(peer: *Sim.Peer, alloc: std.mem.Allocator, step: Lifecycle, ip: IPv4, mac: Mac) !void {
    const table = &State.dhcp_table;
    try peer.beginObservation();
    try Clock.tickReclaim(peer.network.io, peer.network.mock.api());
    switch (step) {
        .first_probe, .second_probe, .third_probe => {
            try peer.count(1);
            _ = try peer.expect(0, .lan, try Sim.arp(alloc, Sim.lan_mac, @splat(0), ip, null));
        },
        else => try peer.count(0),
    }
    if (step == .reoffer) {
        if (table.reclaim != null or table.excluded_ips.items.len != 0 or table.ip_pool.items.len != 1 or
            !std.meta.eql(table.ip_pool.items[0], ip) or table.lookupByIp(ip) != null) return error.WrongReclaimState;
        const now = std.Io.Timestamp.now(peer.network.io, .boot);
        for ([2]bool{ false, true }) |request| {
            try peer.inject(try Dhcp.frame(alloc, mac, .{
                .message_type = if (request) 3 else 1,
                .requested_ip = ip,
                .server_id = if (request) Sim.lan else null,
                .xid = 741,
                .broadcast_flag = true,
            }));
            _ = try peer.dhcp(if (request) .ack else .offer, .{ .xid = 741 }, mac, ip);
            const index = table.lookupByIp(ip) orelse return error.MissingReclaimedLease;
            const entry = table.table.get(index);
            if (!std.meta.eql(entry.mac, mac) or table.lookupByClient(.{ .mac = mac }) != index or table.ip_pool.items.len != 0 or
                entry.state != @as(LeaseState, if (request) .bound else .offered) or
                !std.meta.eql(entry.deadline, now.addDuration(.fromSeconds(if (request) 86400 else 30)))) return error.WrongReclaimedLease;
        }
        return;
    }
    if (step == .decline or step == .before_reclaim or step == .reclaim_due or step == .before_reoffer) {
        // Two devices ask on opposite sides of the quarantine / final quiet intervals.
        const requester: Mac = if (step == .before_reclaim or step == .before_reoffer) .{ 2, 7, 0, 0, 0, 75 } else mac;
        try peer.inject(try Dhcp.frame(alloc, requester, .{ .message_type = 1, .requested_ip = ip, .xid = 741 + @as(u32, requester[5]), .broadcast_flag = true }));
    } else {
        // Other bound hosts' broadcast requests put silent timer ticks in the RX capture.
        const host: u8 = 18 + @intFromEnum(step) - @intFromEnum(Lifecycle.decline);
        try peer.inject(try Sim.arp(alloc, .{ 2, 1, 0, 0, 0, host }, .{ 192, 168, 86, host }, .{ 192, 168, 86, host + 1 }, null));
    }
    try peer.expectDrop();
    const sent: ?u2 = switch (step) {
        .decline, .before_reclaim => null,
        .reclaim_due, .before_first_probe => 0,
        .first_probe, .before_second_probe => 1,
        .second_probe, .before_third_probe => 2,
        .third_probe, .before_reoffer => 3,
        else => unreachable,
    };
    const actual: ?u2 = if (table.reclaim) |probe| probe.probes_sent else null;
    if (sent != actual or table.excluded_ips.items.len != 1 or !std.meta.eql(table.excluded_ips.items[0].ip, ip) or
        table.ip_pool.items.len != 0 or table.lookupByIp(ip) != null) return error.WrongReclaimState;
}
