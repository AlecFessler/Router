const std = @import("std");
const Router = @import("router");
const Sim = @import("../network_sim.zig");
const Nat = Router.Tables.NatTable.NatTable;
const Lifecycle = Sim.Scenarios.Lifecycle;
const relay = Nat.Peer{ .ip = .{ 203, 0, 113, 228 }, .port = 5683 };

jobs: [2]Sim.Job,
tokens: [2]u8,
generation: u64,
previous_count: usize,
original_deadline: std.Io.Timestamp,
active_deadline: std.Io.Timestamp,

pub fn step(self: *@This(), peer: *Sim.Peer, phase: Lifecycle) !void {
    const ping = phase == .udp_first_ping or phase == .udp_second_ping;
    const pong = phase == .udp_first_pong or phase == .udp_second_pong;
    const outbound = phase == .udp_subscribe or ping;
    if (outbound != (peer.iface == .lan)) return;
    const network = peer.network;
    const nat = &Router.State.nat_table;
    const now = std.Io.Timestamp.now(network.io, .boot);
    var fixed = std.heap.FixedBufferAllocator.init(&peer.scratch);
    const alloc = fixed.allocator();
    if (phase == .udp_subscribe) {
        self.previous_count = nat.inside.count();
        self.original_deadline = now.addDuration(.fromSeconds(300));
        self.active_deadline = self.original_deadline;
        for (&self.jobs, 0..) |*job, i| {
            job.* = network.cold;
            job.choice.host = @intCast(1 + network.seed % 14 + i);
            job.remote = relay.ip;
            job.remote_port = relay.port;
            job.source_port = 47422;
            job.public_port = network.reservePort(.udp, job.source_port);
            const generation = network.newConversationBinding();
            if (i == 0) self.generation = generation;
        }
    }
    if (phase == .udp_second_ping) {
        // Refresh only link-layer neighbors, so delivery can test NAT past the 300-second ARP lifetime.
        for (&self.jobs) |*job| {
            var client = Sim.ClientTurn{ .peer = peer, .alloc = alloc, .id = job.choice.host };
            try client.learnGateway();
        }
    }
    const elapsed = self.original_deadline.durationTo(now).toNanoseconds();
    switch (phase) {
        .udp_last_live => if (elapsed != -std.time.ns_per_ms) return error.WrongIdleDeadline,
        .udp_idle_deadline => if (elapsed != 0) return error.WrongIdleDeadline,
        .udp_after_idle => if (elapsed != std.time.ns_per_ms) return error.WrongIdleDeadline,
        else => {},
    }
    for (&self.jobs, 0..) |*job, i| {
        fixed.reset();
        const token: u8 = @intCast(i + 1);
        if (phase == .udp_subscribe) {
            // NON GET /state with Observe=0 and a client-chosen observation token.
            job.payload[0..12].* = .{ 0x51, 1, 0, token, token, 0x60, 0x55, 's', 't', 'a', 't', 'e' };
            job.len = 12;
            job.choice.token = token;
            _ = try peer.send(alloc, job, false);
            self.tokens[i] = job.payload[4];
        } else if (ping or pong) {
            if (i != 0) continue;
            const id: u8 = if (phase == .udp_first_ping or phase == .udp_first_pong) 11 else 12;
            job.choice.token = id;
            if (ping) {
                job.payload[0..4].* = .{ 0x40, 0, 0, id }; // Empty Confirmable CoAP ping.
                job.len = 4;
                _ = try peer.send(alloc, job, false);
                self.active_deadline = now.addDuration(.fromSeconds(300));
            } else {
                job.payload[0] = 0x70; // Empty Reset echoes the received Message ID.
                try peer.inject(try Sim.packet(alloc, job.*, true, false, 64));
                try peer.count(1);
                _ = try peer.expect(0, .lan, try Sim.packet(alloc, job.*, true, true, 63));
            }
        } else {
            const sequence: u8 = switch (phase) {
                .udp_initial_reading => 1,
                .udp_last_live => 2,
                .udp_idle_deadline => 3,
                .udp_after_idle => if (i == 1) 3 else 4,
                else => unreachable,
            };
            // 2.05 Content, Observe sequence, Max-Age=900 seconds and the reported value.
            job.payload[0..12].* = .{ 0x51, 69, token, sequence, self.tokens[i], 0x61, sequence, 0x82, 3, 132, 0xff, '0' + sequence };
            job.len = 12;
            job.choice.token = 256 * @as(u32, token) + sequence;
            try peer.inject(try Sim.packet(alloc, job.*, true, false, 64));
            if (i == 1 and elapsed >= 0) {
                try peer.expectDrop();
                if (phase == .udp_idle_deadline) network.releasePort(.udp, job.public_port);
            } else {
                job.payload[4] = token;
                try peer.count(1);
                _ = try peer.expect(0, .lan, try Sim.packet(alloc, job.*, true, true, 63));
            }
        }
    }
    const live: usize = if (elapsed < 0) 2 else 1;
    if (nat.inside.count() != self.previous_count + live or nat.outside.count() != self.previous_count + live or
        nat.next_generation != self.generation + 2) return error.WrongKeepaliveMappingCount;
    for (self.jobs[0..live], 0..) |*job, i| try job.checkUdpMapping(self.generation + i, if (i == 0) self.active_deadline else self.original_deadline, &.{relay});
    if (live == 1) {
        const idle = &self.jobs[1];
        if (nat.inside.contains(idle.insideKey()) or nat.outside.contains(.{ .protocol = .udp, .ip = Sim.wan, .port = idle.public_port }) or
            nat.udp_ports.used.isSet(idle.public_port)) return error.IdleMappingSurvived;
    }
}
