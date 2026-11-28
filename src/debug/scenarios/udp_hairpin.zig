const std = @import("std");
const Router = @import("router");
const Sim = @import("../network_sim.zig");
const Nat = Router.Tables.NatTable.NatTable;

pub const Steps = enum { join, candidates, send_moves, relay_moves, check_filter, direct_moves };
const rendezvous: Nat.Peer = .{ .ip = .{ 192, 0, 2, 187 }, .port = 45000 };
const Client = struct {
    job: Sim.Job,
    position: [4]u8,
    observed: [6]u8,
    candidate: Nat.Peer,
    generation: u64,
    deadline: std.Io.Timestamp,
};
clients: [2]Client,
room: [4]u8,
original_count: usize,

pub fn step(turn: *Sim.ConversationTurn) !void {
    const phase: Steps = @enumFromInt(turn.phase);
    const peer = turn.peer;
    const from_lan = phase == .join or phase == .send_moves or phase == .direct_moves;
    if (from_lan != (peer.iface == .lan)) return;
    const net = peer.network;
    const self = &net.episodes.udp_hairpin;
    const nat = &Router.State.nat_table;
    if (phase == .join) {
        var prng = std.Random.DefaultPrng.init(net.seed +% turn.index);
        const random = prng.random();
        self.original_count = nat.inside.count();
        random.bytes(&self.room);
        const first = random.int(u4);
        for (&self.clients, [2]u4{ first, first +% random.intRangeAtMost(u4, 1, 15) }) |*c, host| {
            random.bytes(&c.position);
            c.job = net.cold;
            c.job.choice.host = host;
            c.job.remote = rendezvous.ip;
            c.job.remote_port = rendezvous.port;
            // Two game clients use the same private port, so their advertised ports must differ.
            c.job.source_port = @intCast(47000 + turn.index);
            c.job.public_port = net.reservePort(.udp, c.job.source_port);
            c.generation = net.newConversationBinding();
        }
    }
    var scratch = std.heap.FixedBufferAllocator.init(&peer.scratch);
    const alloc = scratch.allocator();
    const refreshed = std.Io.Timestamp.now(net.io, .boot).addDuration(.fromSeconds(300));
    var missing: usize = 0;
    for (&self.clients, 0..) |*c, i| {
        scratch.reset();
        const other = &self.clients[1 - i];
        const job = &c.job;
        job.choice.token = @intCast(turn.index * 16 + turn.phase * 2 + i);
        switch (phase) {
            .join, .send_moves => {
                job.payload[0..4].* = if (phase == .join) "JOIN".* else "MOVE".*;
                job.payload[4..12].* = self.room ++ c.position;
                job.len = 12;
                _ = try peer.send(alloc, job, false);
                c.deadline = refreshed;
                if (phase == .join) {
                    const sent = try peer.observation.take(0, .wan);
                    c.observed = sent[26..30].* ++ sent[34..36].*;
                }
            },
            .candidates => {
                var reply = job.*;
                // The lobby tells each player its own observed socket, then the other player's.
                reply.payload[0..20].* = "PAIR".* ++ job.payload[4..8].* ++ c.observed ++ other.observed;
                reply.len = 20;
                try peer.inject(try Sim.packet(alloc, reply, true, false, 64));
                try peer.count(1);
                const delivered = try peer.expect(0, .lan, try Sim.packet(alloc, reply, true, true, 63));
                c.candidate = .{ .ip = delivered[56..60].*, .port = std.mem.readInt(u16, delivered[60..62], .big) };
                if (!std.mem.eql(u8, delivered[46..50], &self.room) or !std.mem.eql(u8, delivered[50..54], &Sim.wan) or
                    std.mem.readInt(u16, delivered[54..56], .big) != job.public_port or c.candidate.port != other.job.public_port or
                    c.candidate.port == job.public_port or !std.meta.eql(c.candidate.ip, Sim.wan)) return error.WrongRendezvousCandidate;
            },
            .relay_moves => {
                const moved = other.job.payload[0..12]; // Received by the server on the preceding turn.
                try peer.inject(try Sim.packetWithPayload(alloc, job.*, true, false, 64, moved));
                try peer.count(1);
                _ = try peer.expect(0, .lan, try Sim.packetWithPayload(alloc, job.*, true, true, 63, &("MOVE".* ++ self.room ++ other.position)));
            },
            .check_filter => {
                // A second WAN address checks reachability before either player contacts its peer.
                if (i != 0) continue;
                var check = job.*;
                check.remote[3] += 1;
                const data = "PATH".* ++ self.room;
                try peer.inject(try Sim.packetWithPayload(alloc, check, true, false, 64, &data));
                if (net.filtering_mode == .full_cone) {
                    try peer.count(1);
                    _ = try peer.expect(0, .lan, try Sim.packetWithPayload(alloc, check, true, true, 63, &data));
                } else try peer.expectDrop();
            },
            .direct_moves => {
                // Restricted-mode players use the verified relay; this direct assertion requires full-cone filtering.
                if (net.filtering_mode != .full_cone) continue;
                var outgoing = job.*;
                outgoing.remote = c.candidate.ip;
                outgoing.remote_port = c.candidate.port;
                const data = "NEXT".* ++ self.room ++ c.position;
                try peer.inject(try Sim.packetWithPayload(alloc, outgoing, false, false, 64, &data));
                // The receiving player sees its peer's external source socket at its own private destination.
                var inbound = other.job;
                inbound.remote = other.candidate.ip;
                inbound.remote_port = other.candidate.port;
                inbound.choice.token = outgoing.choice.token;
                const expected = try Sim.packetWithPayload(alloc, inbound, true, true, 63, &data);
                peer.expectDelivery(.lan, expected) catch |err| switch (err) {
                    error.MissingDelivery => missing += 1,
                    else => return err,
                };
            },
        }
    }
    for (&self.clients) |*c| {
        if (phase == .direct_moves and net.filtering_mode == .full_cone) {
            const entry = nat.inside.get(c.job.insideKey()) orelse return error.MissingNatState;
            if (entry.peer_count < 1 or entry.peer_count > 2 or
                (!std.meta.eql(entry.deadline, c.deadline) and !std.meta.eql(entry.deadline, refreshed))) return error.WrongHairpinState;
            const peers = [_]Nat.Peer{ rendezvous, c.candidate };
            try c.job.checkUdpMapping(c.generation, entry.deadline, peers[0..entry.peer_count]);
        } else try c.job.checkUdpMapping(c.generation, c.deadline, &.{rendezvous});
    }
    if (nat.inside.count() != self.original_count + 2 or nat.outside.count() != self.original_count + 2 or
        nat.next_generation != self.clients[1].generation + 1 or Router.State.nat_filtering_mode != net.filtering_mode) return error.WrongHairpinState;
    if (missing != 0) {
        std.log.err("UDP hairpin: {d}/2 direct LAN deliveries missing in full_cone, verified public ports {d} and {d}", .{
            missing, self.clients[0].job.public_port, self.clients[1].job.public_port,
        });
        return error.MissingHairpinDelivery;
    }
}
