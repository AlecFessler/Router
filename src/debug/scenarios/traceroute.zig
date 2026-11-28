const std = @import("std");
const Router = @import("router");
const Sim = @import("../network_sim.zig");
const Packets = Router.TestFixtures.Synthetic.Packets;
const Nat = Router.Tables.NatTable.NatTable;

pub const Steps = enum { first_hop, second_probe, hop_reply, third_probe, destination_reply };
const base_port = 33434;
const max_payload = 56;

job: Sim.Job,
wan_probe: [28 + max_payload]u8,
generation: u64,
previous_count: usize,
deadline: std.Io.Timestamp = .zero,

pub fn step(turn: *Sim.ConversationTurn) !void {
    const phase: Steps = @enumFromInt(turn.phase);
    const outbound = phase != .hop_reply and phase != .destination_reply;
    const peer = turn.peer;
    if (outbound != (peer.iface == .lan)) return;
    const network = peer.network;
    const self = &network.episodes.traceroute;
    const nat = &Router.State.nat_table;
    const job = &self.job;
    if (phase == .first_hop) {
        var prng = std.Random.DefaultPrng.init(network.seed +% turn.index);
        const random = prng.random();
        job.* = network.cold;
        job.choice.host = random.int(u4);
        job.remote = .{ 203, 0, 113, random.intRangeAtMost(u8, 32, 223) };
        job.choice.token = random.int(u32);
        job.len = random.intRangeAtMost(usize, 24, max_payload);
        random.bytes(job.payload[0..job.len]);
        // A source port already visible on WAN forces the errors to restore the client's port.
        const cursor = network.next[2];
        job.source_port = if (cursor == 1024) 65535 else cursor - 1;
        self.previous_count = nat.inside.count();
        self.generation = nat.next_generation;
    }
    const hop: u8 = switch (phase) {
        .first_hop => 1,
        .second_probe, .hop_reply => 2,
        .third_probe, .destination_reply => 3,
    };
    var fixed = std.heap.FixedBufferAllocator.init(&peer.scratch);
    const alloc = fixed.allocator();
    const len = 28 + job.len;
    if (outbound) {
        job.choice.ttl = hop;
        job.choice.outcome = if (hop == 1) .ttl else .reply;
        job.choice.token +%= 1;
        job.remote_port = base_port + @as(u16, hop) - 1;
        job.payload[0] = hop;
        std.mem.writeInt(u32, job.payload[4..8], @intCast(Router.Nic.Simulation.phase), .big);
        if (hop == 2) {
            self.generation = network.newConversationBinding();
            job.public_port = network.reservePort(.udp, job.source_port);
            if (job.source_port == job.public_port) return error.ExpectedTraceroutePortCollision;
        }
        const forwarded = try peer.send(alloc, job, false);
        if (hop == 1) {
            if (forwarded or nat.inside.contains(job.insideKey()) or nat.inside.count() != self.previous_count or
                nat.outside.count() != self.previous_count or nat.next_generation != self.generation) return error.TtlProbeCreatedMapping;
            return;
        }
        if (!forwarded) return error.MissingTracerouteProbe;
        const transmitted = try peer.observation.take(0, .wan);
        @memcpy(self.wan_probe[0..len], transmitted[14..]);
        self.deadline = std.Io.Timestamp.now(network.io, .boot).addDuration(.fromSeconds(300));
    } else {
        const destination = phase == .destination_reply;
        const probe = self.wan_probe[0..len];
        // The destination sees the packet after the upstream router decrements its TTL.
        const original = if (destination) try Packets.ipv4(alloc, .{
            .src = probe[12..16].*,
            .dst = probe[16..20].*,
            .ttl = probe[8] - 1,
            .identification = std.mem.readInt(u16, probe[4..6], .big),
            .payload = probe[20..],
        }) else probe;
        const restored = try Sim.packet(alloc, job.*, false, false, 1);
        // The gateway includes the minimum UDP quote. The final host includes the probe payload.
        const quoted_len = if (destination) len else 28;
        try peer.inject(try feedback(alloc, job, destination, false, original[0..quoted_len]));
        try peer.count(1);
        _ = try peer.expect(0, .lan, try feedback(alloc, job, destination, true, restored[14..][0..quoted_len]));
    }
    const contacts = [_]Nat.Peer{ .{ .ip = job.remote, .port = base_port + 1 }, .{ .ip = job.remote, .port = base_port + 2 } };
    try job.checkUdpMapping(self.generation, self.deadline, contacts[0 .. hop - 1]);
    if (nat.inside.count() != self.previous_count + 1 or nat.outside.count() != self.previous_count + 1 or
        nat.next_generation != self.generation + 1) return error.WrongTracerouteMappingCount;
}

fn feedback(alloc: std.mem.Allocator, job: *const Sim.Job, destination: bool, translated: bool, quote: []const u8) ![]u8 {
    const ttl: u8 = if (destination) 63 else 64;
    return Sim.wire(alloc, if (translated) Sim.lan_mac else Sim.gateway_mac, if (translated) job.mac() else Sim.wan_mac, .{
        .src = if (destination) job.remote else Sim.gateway,
        .dst = if (translated) job.host() else Sim.wan,
        .ttl = ttl - @intFromBool(translated),
        .protocol = 1,
        .payload = try Packets.icmp(alloc, .{
            .message_type = if (destination) 3 else 11,
            .code = if (destination) 3 else 0,
            .body = try std.mem.concat(alloc, u8, &.{ &([_]u8{0} ** 4), quote }),
        }),
    });
}
