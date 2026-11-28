const std = @import("std");
const Router = @import("router");
const Sim = @import("../network_sim.zig");
const State = Router.State;
const Mac = Router.Protocols.Ethernet.Mac;

pub const Steps = enum { initial_query, initial_reply, announce, confirm, next_query, next_reply, restore, confirm_original, final_query, final_reply };

job: Sim.Job,
replacement: Mac,
gateway: Mac = Sim.gateway_mac,
awaiting_arp: bool = false,
generation: u64,
previous_count: usize,
deadline: std.Io.Timestamp = .zero,
lease: Router.Protocols.DHCPv4.DHCPv4Lease,

pub fn step(turn: *Sim.ConversationTurn) !void {
    const phase: Steps = @enumFromInt(turn.phase);
    const peer = turn.peer;
    const query = phase == .initial_query or phase == .next_query or phase == .final_query;
    if (query != (peer.iface == .lan)) return;
    const network = peer.network;
    const self = &network.episodes.gateway_failover;
    var fixed = std.heap.FixedBufferAllocator.init(&peer.scratch);
    const alloc = fixed.allocator();
    if (phase == .initial_query) {
        var prng = std.Random.DefaultPrng.init(network.seed +% turn.index);
        const random = prng.random();
        const lease = State.wanLease() orelse return error.MissingWanLease;
        if (!std.meta.eql(lease.ip, Sim.wan) or !std.meta.eql(lease.router, Sim.gateway)) return error.WrongWanLease;
        self.* = .{
            .job = network.cold,
            .replacement = .{ 2, 0x10, 0, 0, random.int(u8), random.int(u8) },
            .generation = network.newConversationBinding(),
            .previous_count = State.nat_table.inside.count(),
            .lease = lease,
        };
        self.job.choice.host = random.int(u4);
        self.job.choice.token = random.int(u16);
        self.job.choice.kind = .dns_udp;
        self.job.source_port = @intCast(46500 + turn.index);
        self.job.public_port = network.reservePort(.udp, self.job.source_port);
        self.job.remote = Sim.dns;
    }
    const job = &self.job;
    switch (phase) {
        .announce, .restore => {
            self.gateway = if (phase == .announce) self.replacement else Sim.gateway_mac;
            try peer.inject(try Sim.arp(alloc, self.gateway, Sim.gateway, Sim.gateway, null));
            if (peer.observation.count == 0) try peer.count(0) else try self.expectArp(peer, alloc);
        },
        .confirm, .confirm_original => if (self.awaiting_arp) {
            try peer.inject(try Sim.arp(alloc, self.gateway, Sim.gateway, Sim.wan, Sim.wan_mac));
            try peer.count(0);
            self.awaiting_arp = false;
        },
        .initial_query, .next_query, .final_query => {
            job.choice.token +%= 1;
            job.makeDnsQuery(@truncate(job.choice.token), switch (phase) {
                .initial_query => "www".*,
                .next_query => "cdn".*,
                .final_query => "api".*,
                else => unreachable,
            });
            self.deadline = std.Io.Timestamp.now(network.io, .boot).addDuration(.fromSeconds(300));
            try peer.inject(try Sim.packet(alloc, job.*, false, false, 64));
            // Revalidating the next hop before releasing this datagram is also legitimate.
            const first = peer.observation.take(0, .wan) catch &.{};
            if (phase != .initial_query and first.len >= 14 and std.mem.readInt(u16, first[12..14], .big) == 0x0806) {
                try self.expectArp(peer, alloc);
            } else try self.expectQuery(peer, alloc);
        },
        .initial_reply, .next_reply, .final_reply => {
            if (self.awaiting_arp) {
                try peer.inject(try Sim.arp(alloc, self.gateway, Sim.gateway, Sim.wan, Sim.wan_mac));
                try self.expectQuery(peer, alloc);
                self.awaiting_arp = false;
            }
            job.makeResponse();
            const input = try Sim.packet(alloc, job.*, true, false, 64);
            input[6..12].* = self.gateway;
            try peer.inject(input);
            try peer.count(1);
            _ = try peer.expect(0, .lan, try Sim.packet(alloc, job.*, true, true, 63));
            const index = State.wan_arp_table.indexOfValue(.ip, Sim.gateway) orelse return error.MissingWanNeighbor;
            const entry = State.wan_arp_table.table.get(index);
            if (!std.meta.eql(entry.mac, self.gateway) or State.wan_arp_table.table.len != 1) return error.WrongWanNeighbor;
        },
    }
    try job.checkUdpMapping(self.generation, self.deadline, &.{.{ .ip = Sim.dns, .port = 53 }});
    if (State.nat_table.next_generation != self.generation + 1 or State.nat_table.inside.count() != self.previous_count + 1 or
        State.nat_table.outside.count() != self.previous_count + 1) return error.WrongFailoverMappingCount;
    if (!std.meta.eql(State.wanLease(), @as(?@TypeOf(self.lease), self.lease)) or State.wan_transaction != null) return error.WrongWanLease;
    const index = State.lan_arp_table.indexOfValue(.ip, job.host()) orelse return error.MissingClientNeighbor;
    const entry = State.lan_arp_table.table.get(index);
    if (!std.meta.eql(entry.mac, job.mac()) or !std.meta.eql(entry.timestamp, network.lan_learned[job.choice.host])) return error.WrongClientNeighbor;
}

fn expectArp(self: *@This(), peer: *Sim.Peer, alloc: std.mem.Allocator) !void {
    const expected = try Sim.arp(alloc, Sim.wan_mac, Sim.wan, Sim.gateway, null);
    const actual = try peer.observation.take(0, .wan);
    // A unicast confirmation addressed to the announced MAC can also reach the new gateway.
    if (actual.len >= 42 and std.mem.eql(u8, actual[0..6], &self.gateway)) {
        expected[0..6].* = self.gateway;
        if (std.mem.eql(u8, actual[32..38], &self.gateway)) expected[32..38].* = self.gateway;
    }
    try peer.count(1);
    _ = try peer.expect(0, .wan, expected);
    self.awaiting_arp = true;
}

fn expectQuery(self: *const @This(), peer: *Sim.Peer, alloc: std.mem.Allocator) !void {
    const expected = try Sim.packet(alloc, self.job, false, true, 63);
    expected[0..6].* = self.gateway;
    try peer.count(1);
    _ = try peer.expect(0, .wan, expected);
}
