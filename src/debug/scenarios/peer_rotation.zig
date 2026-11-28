const std = @import("std");
const Router = @import("router");
const Sim = @import("../network_sim.zig");
const Nat = Router.Tables.NatTable.NatTable;
const State = Router.State;
pub const Steps = enum { contact, reply };

jobs: [10]Sim.Job = undefined,
peers: [4]Nat.Peer = undefined,
len: usize = 0,
generation: u64 = 0,
deadline: std.Io.Timestamp = .zero,

fn check(self: *const @This(), job: Sim.Job) !void {
    const table = &State.nat_table;
    const key = job.insideKey();
    const outside: Nat.Key = .{ .protocol = .udp, .ip = Sim.wan, .port = job.public_port };
    const entry = table.inside.get(key) orelse return error.MissingNatState;
    if (entry.peer_count != self.len or entry.generation != self.generation or !std.meta.eql(entry.deadline, self.deadline) or
        !std.meta.eql(entry.outside, outside) or !std.meta.eql(table.outside.get(outside), @as(?Nat.Key, key)) or
        !table.udp_ports.used.isSet(job.public_port)) return error.WrongNatState;
    for (entry.peers[0..self.len], self.peers[0..self.len]) |actual, expected| {
        if (!std.meta.eql(actual, expected)) return error.WrongNatPeer;
    }
}

pub fn step(self: *Sim.ConversationTurn) !void {
    const step_name: Steps = @enumFromInt(self.phase);
    if ((step_name == .contact) == (self.peer.iface == .lan)) {
        var scratch = std.heap.FixedBufferAllocator.init(&self.peer.scratch);
        try exchange(self.peer, &scratch, self.index);
    }
}
pub fn exchange(self: *Sim.Peer, scratch: *std.heap.FixedBufferAllocator, episode: usize) !void {
    const network = self.network;
    const sequence = &network.episodes.peer_rotation;
    const alloc = scratch.allocator();
    var prng = std.Random.DefaultPrng.init(network.seed +% episode);
    const random = prng.random();
    const distinct = random.intRangeAtMost(usize, 5, 8);
    if (self.iface == .lan) {
        const host = random.int(u4);
        const port: u16 = @intCast(40000 + episode);
        const public_port = network.reservePort(.udp, port);
        sequence.len = 0;
        var addresses = [_]u8{ 41, 42, 43, 44, 45, 46, 47, 48 };
        random.shuffle(u8, &addresses);
        sequence.generation = network.newConversationBinding();
        sequence.deadline = std.Io.Timestamp.now(network.io, .boot).addDuration(.fromSeconds(300));
        for (0..distinct + 2) |i| {
            scratch.reset();
            const job = &sequence.jobs[i];
            job.* = network.cold;
            job.choice.host = host;
            job.choice.token = random.int(u32);
            job.source_port = port;
            job.public_port = public_port;
            job.remote = .{ 203, 0, 113, if (i < distinct) addresses[i] else addresses[random.uintLessThan(usize, distinct)] };
            random.bytes(job.payload[0..job.len]);
            _ = try self.send(alloc, job, false);
            for (sequence.peers[0..sequence.len]) |known| {
                if (std.meta.eql(known.ip, job.remote)) break;
            } else {
                if (sequence.len == sequence.peers.len) {
                    std.mem.copyForwards(Nat.Peer, sequence.peers[0..3], sequence.peers[1..4]);
                    sequence.len -= 1;
                }
                sequence.peers[sequence.len] = .{ .ip = job.remote, .port = job.service() };
                sequence.len += 1;
            }
            try sequence.check(job.*);
        }
    } else {
        var indices: [10]usize = undefined;
        const order = indices[0 .. distinct + 2];
        for (order, 0..) |*index, i| index.* = i;
        random.shuffle(usize, order);
        for (order) |index| {
            scratch.reset();
            const job = sequence.jobs[index];
            for (sequence.peers[0..sequence.len]) |known| {
                if (std.meta.eql(known.ip, job.remote)) {
                    try self.answer(alloc, job);
                    break;
                }
            } else {
                if (network.filtering_mode == .full_cone) {
                    try self.answer(alloc, job);
                } else {
                    try self.inject(try Sim.packet(alloc, job, true, false, 64));
                    try self.expectDrop();
                }
            }
            try sequence.check(job);
        }
    }
}
