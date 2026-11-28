const std = @import("std");
const Router = @import("router");
const Sim = @import("../network_sim.zig");
const IPv4 = Router.Protocols.IPv4.IPv4;

pub const Steps = enum { first_poll, second_poll, second_reply, first_reply };
const server: IPv4 = .{ 203, 0, 113, 123 };
const Client = struct {
    job: Sim.Job,
    transmit: u64,
    deadline: std.Io.Timestamp,
};

clients: [2]Client,
first_generation: u64,
previous_count: usize,
rate_limited: bool,

pub fn step(turn: *Sim.ConversationTurn) !void {
    const phase: Steps = @enumFromInt(turn.phase);
    const reply = phase == .second_reply or phase == .first_reply;
    const peer = turn.peer;
    if (reply != (peer.iface == .wan)) return;
    const index: usize = if (phase == .first_poll or phase == .first_reply) 0 else 1;
    const version: u8 = if (index == 0) 3 else 4;
    const network = peer.network;
    const self = &network.episodes.ntp;
    if (phase == .first_poll) {
        var prng = std.Random.DefaultPrng.init(network.seed +% turn.index);
        const random = prng.random();
        const host = random.int(u4);
        for (&self.clients, [2]u4{ host, host +% random.intRangeAtMost(u4, 1, 15) }) |*c, h| {
            c.job = network.cold;
            c.job.choice.host = h;
            c.job.remote = server;
            c.job.remote_port = 123;
            c.job.source_port = @intCast(45835 + turn.index);
            c.job.len = 48;
        }
        self.previous_count = Router.State.nat_table.inside.count();
        self.rate_limited = random.boolean();
    }
    const client = &self.clients[index];
    var fixed = std.heap.FixedBufferAllocator.init(&peer.scratch);
    const alloc = fixed.allocator();
    const job = &client.job;
    job.choice.token = @intCast(turn.index * 4 + turn.phase);
    const now = (@as(u64, 4_000_000_000) << 32) + (Router.Nic.Simulation.phase << 32) / 1000;
    if (!reply) {
        const generation = network.newConversationBinding();
        if (index == 0) self.first_generation = generation;
        job.public_port = network.reservePort(.udp, job.source_port);
        client.transmit = now;
        client.deadline = std.Io.Timestamp.now(network.io, .boot).addDuration(.fromSeconds(300));
        @memset(job.payload[0..job.len], 0);
        job.payload[0] = version << 3 | 3;
        if (version == 4) job.payload[2] = 6;
        std.mem.writeInt(u64, job.payload[40..48], client.transmit, .big);
        _ = try peer.send(alloc, job, false);
    } else {
        // A server may rate-limit the second request from the shared WAN address.
        const limited = self.rate_limited and index == 1;
        const received_transmit = std.mem.readInt(u64, job.payload[40..48], .big);
        job.payload[0..48].* = response(version, received_transmit, now, limited);
        try peer.inject(try Sim.packet(alloc, job.*, true, false, 64));
        try peer.count(1);
        job.payload[0..48].* = response(version, client.transmit, now, limited);
        _ = try peer.expect(0, .lan, try Sim.packet(alloc, job.*, true, true, 63));
    }

    const live: usize = if (phase == .first_poll) 1 else 2;
    const nat = &Router.State.nat_table;
    if (nat.inside.count() != self.previous_count + live or nat.outside.count() != self.previous_count + live or
        nat.next_generation != self.first_generation + live) return error.WrongNtpMappingCount;
    for (self.clients[0..live], 0..) |*c, i| try c.job.checkUdpMapping(self.first_generation + i, c.deadline, &.{.{ .ip = server, .port = 123 }});
}

fn response(version: u8, origin: u64, sent: u64, limited: bool) [48]u8 {
    var msg: [48]u8 = @splat(0);
    msg[0] = version << 3 | 4;
    msg[2] = 6;
    std.mem.writeInt(u64, msg[24..32], origin, .big);
    if (limited) {
        msg[0] |= 0xc0;
        msg[12..16].* = "RATE".*;
    } else {
        msg[1] = 2;
        msg[3] = @bitCast(@as(i8, -20));
        std.mem.writeInt(u32, msg[4..8], 128, .big);
        std.mem.writeInt(u32, msg[8..12], 64, .big);
        msg[12..16].* = .{ 192, 0, 2, 9 };
        std.mem.writeInt(u64, msg[16..24], sent - (@as(u64, 4) << 32), .big);
        std.mem.writeInt(u64, msg[32..40], origin + (1 << 20), .big);
        std.mem.writeInt(u64, msg[40..48], sent, .big);
    }
    return msg;
}
