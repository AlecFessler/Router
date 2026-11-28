const std = @import("std");
const Router = @import("router");
const Sim = @import("../network_sim.zig");
const State = Router.State;
const IPv4 = Router.Protocols.IPv4.IPv4;
const Mac = Router.Protocols.Ethernet.Mac;
const Offers = @import("wan_offers.zig");

job: Sim.Job,
old_answer: Sim.Job,
offers: Offers,
generation: u64,
deadline: std.Io.Timestamp,
lan_deadline: std.Io.Timestamp,
renewal_xid: u32 = 0,
discover_xid: ?u32 = null,
discover_seconds: u16 = 0,
refused_at: std.Io.Timestamp = .zero,

pub fn step(self: *@This(), peer: *Sim.Peer, phase: Sim.Scenarios.Lifecycle, old_ip: IPv4, server: IPv4) !void {
    const from_lan = phase == .nak_lookup or phase == .nak_retry or phase == .rebind_lookup;
    const both = phase == .nak_offline or phase == .rebind_unicast or phase == .rebind_broadcast or phase == .rebind_backup_renewal;
    if (!both and from_lan != (peer.iface == .lan)) return;
    const net = peer.network;
    const now = std.Io.Timestamp.now(net.io, .boot);
    var scratch = std.heap.FixedBufferAllocator.init(&peer.scratch);
    const alloc = scratch.allocator();
    const nat = &State.nat_table;
    if (phase == .nak_gateway) {
        const lease = State.wanLease() orelse return error.MissingWanLease;
        if (!std.meta.eql(lease.ip, old_ip) or !std.meta.eql(lease.server_id, server) or !std.meta.eql(lease.router, server)) return error.WrongWanLease;
        const slot = State.dhcp_table.lookupByIp(.{ 192, 168, 86, 18 }) orelse return error.MissingLanLease;
        var prng = std.Random.DefaultPrng.init(net.seed);
        const random = prng.random();
        self.* = .{
            .job = net.cold,
            .old_answer = undefined,
            .offers = .init(@truncate(net.seed), server, random),
            .generation = 0,
            .deadline = .zero,
            .lan_deadline = State.dhcp_table.table.get(slot).deadline,
        };
        self.job.choice.host = random.intRangeAtMost(u4, 1, 15);
        self.job.choice.kind = .dns_udp;
        self.job.choice.token = random.int(u32) | 1;
        self.job.source_port = random.intRangeAtMost(u16, 61000, 61499);
        self.job.remote = Sim.dns;
        self.job.wan_ip = old_ip;
    }
    const job = &self.job;
    switch (phase) {
        .nak_gateway => {
            try peer.inject(try Sim.arp(alloc, Sim.gateway_mac, server, old_ip, null));
            try peer.count(1);
            _ = try peer.expect(0, .wan, try Sim.arp(alloc, Sim.wan_mac, old_ip, server, Sim.gateway_mac));
        },
        .nak_lookup, .nak_retry, .rebind_lookup => {
            if (phase == .nak_lookup) {
                try peer.inject(try Sim.arp(alloc, job.mac(), job.host(), Sim.lan, null));
                try peer.count(1);
                _ = try peer.expect(0, .lan, try Sim.arp(alloc, Sim.lan_mac, Sim.lan, job.host(), job.mac()));
                job.makeDnsQuery(@truncate(job.choice.token), "www".*);
            } else if (phase == .nak_retry) {
                net.releasePort(.udp, self.old_answer.public_port);
                job.wan_ip = self.offers.choice().address;
            } else {
                // The LAN host reuses its DNS socket. Its five-minute NAT binding expired.
                net.releasePort(.udp, job.public_port);
                job.choice.token +%= 8;
                job.makeDnsQuery(@truncate(job.choice.token), "api".*);
            }
            self.generation = net.newConversationBinding();
            job.public_port = net.reservePort(.udp, job.source_port);
            self.deadline = now.addDuration(.fromSeconds(300));
            try peer.inject(try Sim.packet(alloc, job.*, false, false, 64));
            try peer.count(1);
            try job.checkUdpMapping(self.generation, self.deadline, &.{.{ .ip = Sim.dns, .port = 53 }});
            if (phase == .nak_lookup) {
                _ = try peer.expect(0, .wan, try Sim.packet(alloc, job.*, false, true, 63));
                self.old_answer = job.*;
                self.old_answer.makeResponse();
            } else {
                const offer = if (phase == .rebind_lookup) self.offers.backup() else self.offers.choice();
                _ = try peer.expect(0, .wan, try Sim.arp(alloc, Sim.wan_mac, offer.address, offer.gateway, null));
                const pending = State.arp_waiters_table.table.get(.{ .iface = .wan, .ip = offer.gateway }) orelse return error.MissingArpWaiter;
                if (pending.len != 1 or State.arp_waiters_table.table.count() != 1 or
                    nat.outside.contains(.{ .protocol = .udp, .ip = old_ip, .port = self.old_answer.public_port })) return error.StaleNatAfterNak;
            }
        },
        .nak_renew => {
            try peer.tickWan();
            self.renewal_xid = try peer.dhcp(.request, .{ .server = server }, Sim.wan_mac, old_ip);
            const pending = State.wan_transaction orelse return error.MissingWanTransaction;
            if (pending.xid != self.renewal_xid or !std.meta.eql(pending.requested_ip, @as(?IPv4, old_ip)) or
                !std.meta.eql(pending.expected_server, @as(?IPv4, server))) return error.WrongRenewalTransaction;
            try deliver(peer, alloc, self.old_answer, Sim.gateway_mac);
        },
        .nak_refusal => {
            self.refused_at = now;
            try self.offers.candidates[0].reply(peer, alloc, self.renewal_xid, .nak);
            try self.observeDiscover(peer, now);
            if (State.wanLease() != null) return error.RenewalNakKeptAddress;
        },
        .nak_offline => {
            if (State.wanLease() != null) return error.RenewalNakKeptAddress;
            if (peer.iface == .wan) {
                // The next poll follows a 12-second gap in this trace.
                try peer.tickWan();
                try self.observeDiscover(peer, now);
            } else {
                job.choice.token +%= 4;
                job.makeDnsQuery(@truncate(job.choice.token), "cdn".*);
                const before = nat.inside.get(job.insideKey());
                const generation = nat.next_generation;
                try peer.inject(try Sim.packet(alloc, job.*, false, false, 64));
                try peer.expectDrop();
                if (nat.next_generation != generation or !std.meta.eql(before, nat.inside.get(job.insideKey())) or
                    State.arp_waiters_table.table.count() != 0) return error.UsedRevokedAddress;
            }
        },
        .nak_offer, .nak_second_offer, .nak_bind => {
            const xid = self.discover_xid orelse return error.MissingRediscovery;
            try self.offers.exchange(peer, alloc, phase, xid, self.discover_seconds);
        },
        .nak_resolve_gateway, .rebind_route => {
            const offer = if (phase == .rebind_route) self.offers.backup() else self.offers.choice();
            try peer.inject(try Sim.arp(alloc, offer.gateway_mac, offer.gateway, offer.address, Sim.wan_mac));
            try peer.count(1);
            const queued = try Sim.packet(alloc, job.*, false, true, 63);
            queued[0..6].* = offer.gateway_mac;
            _ = try peer.expect(0, .wan, queued);
            if (State.arp_waiters_table.table.count() != 0 or !std.meta.eql(State.wan_arp_table.lookup(offer.gateway), @as(?Mac, offer.gateway_mac)))
                return error.WrongWanNeighbor;
        },
        .nak_answer, .rebind_answer => {
            const offer = if (phase == .rebind_answer) self.offers.backup() else self.offers.choice();
            if (phase == .nak_answer) {
                // A duplicate answer for the old public socket arrives ahead of the fresh answer.
                try peer.inject(try Sim.packet(alloc, self.old_answer, true, false, 64));
                try peer.expectDrop();
            }
            job.makeResponse();
            try deliver(peer, alloc, job.*, offer.gateway_mac);
            try job.checkUdpMapping(self.generation, self.deadline, &.{.{ .ip = Sim.dns, .port = 53 }});
        },
        .rebind_server_neighbor, .rebind_backup_neighbor => {
            const issuer = if (phase == .rebind_backup_neighbor) self.offers.backup() else self.offers.choice();
            try peer.tickWan();
            try peer.count(0);
            try peer.inject(try Sim.arp(alloc, issuer.server_mac, issuer.server, issuer.address, null));
            try peer.count(1);
            _ = try peer.expect(0, .wan, try Sim.arp(alloc, Sim.wan_mac, issuer.address, issuer.server, issuer.server_mac));
        },
        .rebind_unicast, .rebind_broadcast, .rebind_backup_renewal => {
            if (peer.iface == .lan) {
                // Record each timer instant in the input PCAP. This client will use the new gateway.
                try peer.inject(try Sim.arp(alloc, job.mac(), job.host(), Sim.lan, null));
                try peer.count(1);
                _ = try peer.expect(0, .lan, try Sim.arp(alloc, Sim.lan_mac, Sim.lan, job.host(), job.mac()));
            } else {
                const issuer = if (phase == .rebind_backup_renewal) self.offers.backup() else self.offers.choice();
                try peer.tickWan();
                if (phase != .rebind_broadcast) {
                    if (phase == .rebind_unicast) self.offers.renewed_at = now;
                    self.renewal_xid = try peer.dhcp(.request, .{ .server = issuer.server, .server_mac = issuer.server_mac }, Sim.wan_mac, issuer.address);
                } else {
                    self.offers.broadcast_at = now;
                    const frame = try peer.observation.take(0, .wan);
                    if (frame.len < 50) return error.ShortDhcp;
                    const xid = std.mem.readInt(u32, frame[46..50], .big);
                    const secs: u16 = if (xid == self.renewal_xid) @intCast(self.offers.renewed_at.durationTo(now).toSeconds()) else 0;
                    if (xid != self.renewal_xid) self.offers.renewed_at = now;
                    self.renewal_xid = try peer.dhcp(.request, .{ .rebind = true, .seconds = secs }, Sim.wan_mac, issuer.address);
                }
                const txn = State.wan_transaction orelse return error.MissingWanTransaction;
                const expected_server: ?IPv4 = if (phase == .rebind_broadcast) null else issuer.server;
                if (txn.xid != self.renewal_xid or !std.meta.eql(txn.expected_server, expected_server) or
                    !std.meta.eql(txn.requested_ip, @as(?IPv4, issuer.address))) return error.WrongRenewalTransaction;
            }
        },
        .rebind_ack => try self.offers.rebindAck(peer, alloc, self.renewal_xid),
        else => unreachable,
    }
    try self.checkLan(net);
}

fn observeDiscover(self: *@This(), peer: *Sim.Peer, now: std.Io.Timestamp) !void {
    if (peer.observation.count == 0) return peer.count(0);
    const frame = try peer.observation.take(0, .wan);
    if (frame.len < 52) return error.ShortDhcp;
    self.discover_seconds = std.mem.readInt(u16, frame[50..52], .big);
    if (self.discover_seconds > self.refused_at.durationTo(now).toSeconds()) return error.WrongRediscoveryAge;
    self.discover_xid = try peer.dhcp(.discover, .{ .seconds = self.discover_seconds }, Sim.wan_mac, @splat(0));
}

fn deliver(peer: *Sim.Peer, alloc: std.mem.Allocator, job: Sim.Job, gateway_mac: Mac) !void {
    const frame = try Sim.packet(alloc, job, true, false, 64);
    frame[6..12].* = gateway_mac;
    try peer.inject(frame);
    try peer.count(1);
    _ = try peer.expect(0, .lan, try Sim.packet(alloc, job, true, true, 63));
}

fn checkLan(self: *const @This(), net: *const Sim.Network) !void {
    const table = &State.dhcp_table;
    if (table.table.len != 252 or table.ip_pool.items.len != 1 or !std.meta.eql(table.ip_pool.items[0], IPv4{ 192, 168, 86, 2 })) return error.WanNakChangedLanPool;
    var seen = std.StaticBitSet(256).initEmpty();
    for (0..table.table.len) |i| {
        const e = table.table.get(i);
        const h = e.ip[3];
        const mac = [6]u8{ 2, 1, 0, 0, 0, h };
        if (h < 3 or h == 255 or seen.isSet(h) or !std.mem.eql(u8, e.ip[0..3], Sim.lan[0..3]) or !std.meta.eql(e.mac, mac) or
            e.state != .bound or !std.meta.eql(e.deadline, if (h < 18) net.clients[h - 2].lease_deadline else self.lan_deadline)) return error.WanNakChangedLanLease;
        if (h - 2 == @as(u8, net.returning_client)) {
            if (e.client != .id or e.client.id.len != 7 or !std.mem.eql(u8, e.client.id.bytes[0..7], &(.{1} ++ mac))) return error.WanNakChangedLanLease;
        } else if (e.client != .mac or !std.meta.eql(e.client.mac, mac)) return error.WanNakChangedLanLease;
        seen.set(h);
    }
}
