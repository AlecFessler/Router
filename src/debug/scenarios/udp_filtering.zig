const std = @import("std");
const Router = @import("router");
const Sim = @import("../network_sim.zig");
const Nat = Router.Tables.NatTable.NatTable;

pub const Steps = enum { send_audio, exact_peer, same_address, other_address, contact_second, second_reply };

job: Sim.Job,
sources: [2]Nat.Peer,
ssrc: u32,
generation: u64,
deadline: std.Io.Timestamp = .zero,
previous_count: usize,

pub fn step(turn: *Sim.ConversationTurn) !void {
    const phase: Steps = @enumFromInt(turn.phase);
    const outbound = phase == .send_audio or phase == .contact_second;
    const peer = turn.peer;
    if (outbound != (peer.iface == .lan)) return;
    const network = peer.network;
    const self = &network.episodes.udp_filtering;
    const nat = &Router.State.nat_table;
    if (phase == .send_audio) {
        var prng = std.Random.DefaultPrng.init(network.seed +% turn.index);
        const random = prng.random();
        const port: u16 = @intCast(42500 + turn.index);
        self.* = .{
            .job = network.cold,
            .sources = .{
                .{ .ip = .{ 203, 0, 113, random.intRangeAtMost(u8, 80, 111) }, .port = 5004 },
                .{ .ip = .{ 203, 0, 113, random.intRangeAtMost(u8, 160, 191) }, .port = 5004 },
            },
            .ssrc = random.int(u32),
            .generation = network.newConversationBinding(),
            .previous_count = nat.inside.count(),
        };
        self.job.choice.host = random.int(u4);
        self.job.source_port = port;
        self.job.public_port = network.reservePort(.udp, port);
    }
    const second_source = phase == .other_address or phase == .contact_second or phase == .second_reply;
    const source = self.sources[@intFromBool(second_source)];
    const job = &self.job;
    job.remote = source.ip;
    job.remote_port = source.port + @as(u16, if (phase == .same_address) 2 else 0);
    job.choice.token = self.ssrc +% @as(u32, @intCast(turn.phase));

    // Three RTP sources in a call. The first remote can send its next packet from
    // a new port; the second starts sending before this client has sent it audio.
    const stream = self.ssrc +% @as(u32, if (outbound) 0 else if (second_source) 2 else 1);
    const later: u16 = @intFromBool(phase == .same_address or phase == .contact_second or phase == .second_reply);
    @memset(audioFrame(job, stream, @as(u16, @truncate(stream)) +% later, stream +% (160 * @as(u32, later))), 0xff);

    var fixed = std.heap.FixedBufferAllocator.init(&peer.scratch);
    const alloc = fixed.allocator();
    if (outbound) {
        self.deadline = std.Io.Timestamp.now(network.io, .boot).addDuration(.fromSeconds(300));
        _ = try peer.send(alloc, job, false);
    } else {
        try peer.inject(try Sim.packet(alloc, job.*, true, false, 64));
        // RFC 4787 section 5: changing only the port distinguishes the two
        // restricted policies. Changing the IP distinguishes full-cone filtering.
        const allowed = switch (phase) {
            .exact_peer, .second_reply => true,
            .same_address => network.filtering_mode != .endpoint_dependent,
            .other_address => network.filtering_mode == .full_cone,
            else => unreachable,
        };
        if (allowed) {
            try peer.count(1);
            _ = try peer.expect(0, .lan, try Sim.packet(alloc, job.*, true, true, 63));
        } else try peer.expectDrop();
    }
    const contacted: usize = if (phase == .contact_second or phase == .second_reply) 2 else 1;
    try job.checkUdpMapping(self.generation, self.deadline, self.sources[0..contacted]);
    if (nat.inside.count() != self.previous_count + 1 or nat.outside.count() != self.previous_count + 1 or
        nat.next_generation != self.generation + 1) return error.WrongMediaMappingCount;
}

pub fn audioFrame(job: *Sim.Job, ssrc: u32, sequence: u16, timestamp: u32) []u8 {
    job.len = 12 + 160;
    job.payload[0..2].* = .{ 0x80, 0 }; // RTP v2, G.711 mu-law
    std.mem.writeInt(u16, job.payload[2..4], sequence, .big);
    std.mem.writeInt(u32, job.payload[4..8], timestamp, .big);
    std.mem.writeInt(u32, job.payload[8..12], ssrc, .big);
    return job.payload[12..job.len];
}

pub const EchoCall = struct {
    pub const Steps = enum { send_first, echo_first, send_second, echo_second, send_third, echo_third };
    const Stream = struct { ssrc: u32, sequence: u16, timestamp: u32 };

    job: Sim.Job,
    streams: [2]Stream,
    client_starts_omitted: bool,
    generation: u64,
    previous_count: usize,
    deadline: std.Io.Timestamp = .zero,

    pub fn step(turn: *Sim.ConversationTurn) !void {
        const reply = turn.phase % 2 != 0;
        const peer = turn.peer;
        if (reply != (peer.iface == .wan)) return;
        const network = peer.network;
        const self = &network.episodes.rtp_checksums;
        const nat = &Router.State.nat_table;
        const job = &self.job;
        if (turn.phase == 0) {
            var prng = std.Random.DefaultPrng.init(network.seed +% turn.index);
            const random = prng.random();
            job.* = network.cold;
            job.choice.host = random.int(u4);
            job.remote = .{ 203, 0, 113, 230 };
            job.remote_port = 5004;
            // Request a source port already occupied by a different binding on WAN.
            const cursor = network.next[2];
            job.source_port = if (cursor == 1024) 65535 else cursor - 1;
            job.public_port = network.reservePort(.udp, job.source_port);
            if (job.public_port == job.source_port) return error.ExpectedMediaPortCollision;
            self.generation = network.newConversationBinding();
            self.previous_count = nat.inside.count();
            self.client_starts_omitted = random.boolean();
            for (&self.streams) |*s| s.* = .{ .ssrc = random.int(u32), .sequence = random.int(u16), .timestamp = random.int(u32) };
            if (self.streams[0].ssrc == self.streams[1].ssrc) self.streams[1].ssrc +%= 1;
        }
        const index: u16 = @intCast(turn.phase / 2);
        const s = self.streams[@intFromBool(reply)];
        const client_omits = if (index % 2 == 0) self.client_starts_omitted else !self.client_starts_omitted;
        job.omit_udp_checksum = client_omits != reply;
        job.choice.token = s.timestamp +% index;
        const samples = audioFrame(job, s.ssrc, s.sequence +% index, s.timestamp +% (160 * @as(u32, index)));
        if (index == 0) job.payload[1] |= 0x80;
        var fixed = std.heap.FixedBufferAllocator.init(&peer.scratch);
        const alloc = fixed.allocator();
        if (!reply) {
            writeTone(samples, index);
            self.deadline = std.Io.Timestamp.now(network.io, .boot).addDuration(.fromSeconds(300));
            _ = try peer.send(alloc, job, false);
        } else {
            // The echo peer returns the samples delivered by WAN. The phone expects what it sent.
            try peer.inject(try Sim.packet(alloc, job.*, true, false, 64));
            try peer.count(1);
            writeTone(samples, index);
            _ = try peer.expect(0, .lan, try Sim.packet(alloc, job.*, true, true, 63));
        }
        try job.checkUdpMapping(self.generation, self.deadline, &.{.{ .ip = job.remote, .port = 5004 }});
        if (nat.inside.count() != self.previous_count + 1 or nat.outside.count() != self.previous_count + 1 or
            nat.next_generation != self.generation + 1) return error.WrongMediaMappingCount;
    }
};

pub fn writeTone(samples: []u8, index: u16) void {
    // One 18-sample cycle of a mu-law encoded test tone at 8 kHz.
    const cycle = [_]u8{ 0xff, 0xb4, 0xa6, 0x9e, 0x9c, 0x9c, 0x9e, 0xa6, 0xb4, 0xff, 0x34, 0x26, 0x1e, 0x1c, 0x1c, 0x1e, 0x26, 0x34 };
    for (samples, 0..) |*b, i| b.* = cycle[(@as(usize, index) * samples.len + i) % cycle.len];
}
