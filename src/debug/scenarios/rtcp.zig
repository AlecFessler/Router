const std = @import("std");
const Router = @import("router");
const Sim = @import("../network_sim.zig");
const Audio = @import("udp_filtering.zig");
const Phase = Sim.Scenarios.Lifecycle;

sockets: [2]Sim.Job,
deadlines: [2]std.Io.Timestamp = undefined,
opened: usize = 0,
generation: u64 = 0,
original_count: usize,
sender: u32,
listener: u32,
first_sequence: u16,
first_timestamp: u32,
start: u64,
received_ssrc: u32 = 0,
highest_sequence: u32 = 0,
packets: u32 = 0,
octets: u32 = 0,
last_sample: u32 = 0,
last_audio_at: u64 = 0,
lsr: u32 = 0,
sr_at: u64 = 0,

pub fn at(start: u64, seed: u64, phase: Phase) u64 {
    var random = std.Random.DefaultPrng.init(seed +% @intFromEnum(phase));
    const jitter = random.random().intRangeAtMost(u64, 0, 450);
    return start + switch (phase) {
        .audio_start => @as(u64, 0),
        .audio_second => 20,
        .audio_third => 40,
        .audio_first_sr => 1750 + jitter,
        .audio_first_rr => 2400 + jitter,
        .audio_resume => 3600,
        .audio_fifth => 3620,
        .audio_sixth => 3640,
        .audio_second_sr => 6000 + jitter,
        .audio_second_rr => 6900 + jitter,
        else => unreachable,
    };
}

pub fn step(self: *@This(), peer: *Sim.Peer, phase: Phase) !void {
    const rr = phase == .audio_first_rr or phase == .audio_second_rr;
    const sr = phase == .audio_first_sr or phase == .audio_second_sr;
    if (rr != (peer.iface == .wan)) return;
    const net = peer.network;
    const nat = &Router.State.nat_table;
    const now = Router.Nic.Simulation.phase;
    if (phase == .audio_start) {
        var prng = std.Random.DefaultPrng.init(net.seed);
        const random = prng.random();
        self.* = .{
            .sockets = @splat(net.cold),
            .original_count = nat.inside.count(),
            .sender = random.int(u32),
            .listener = random.int(u32),
            .first_sequence = if (random.boolean()) random.intRangeAtMost(u16, 65532, 65535) else random.int(u16),
            .first_timestamp = random.int(u32),
            .start = now,
        };
        if (self.listener == self.sender) self.listener +%= 1;
        const host = random.intRangeAtMost(u4, 1, 15); // Client zero has declined its lease.
        const addr = random.intRangeAtMost(u8, 128, 220);
        for (&self.sockets, 0..) |*s, i| {
            s.choice.host = host;
            s.remote = .{ 192, 0, 2, addr };
            s.remote_port = @intCast(5004 + i);
        }
        // The phone binds an available even/odd pair. One of those port numbers is occupied on WAN.
        var occupied = net.used[2].iterator(.{ .direction = .reverse });
        while (occupied.next()) |p| {
            if (p < 1024 or net.used[2].isSet(p ^ 1)) continue;
            self.sockets[0].source_port = @intCast(p & ~@as(usize, 1));
            self.sockets[1].source_port = self.sockets[0].source_port + 1;
            if (!nat.inside.contains(self.sockets[0].insideKey()) and !nat.inside.contains(self.sockets[1].insideKey())) break;
        } else return error.NoAudioPortPair;
    }
    const i = @intFromBool(rr or sr);
    const job = &self.sockets[i];
    if (phase == .audio_start or phase == .audio_first_sr) {
        const generation = net.newConversationBinding();
        if (i == 0) self.generation = generation;
        job.public_port = net.reservePort(.udp, job.source_port);
        self.opened += 1;
        if (i == 1 and self.sockets[0].public_port == job.public_port) return error.SharedMediaSocket;
    }
    job.choice.token = self.sender +% @intFromEnum(phase);
    const timestamp = self.first_timestamp +% @as(u32, @intCast((now - self.start) * 8));
    var fixed = std.heap.FixedBufferAllocator.init(&peer.scratch);
    const alloc = fixed.allocator();
    if (sr) {
        const count: u32 = if (phase == .audio_first_sr) 3 else 6;
        var out: std.Io.Writer = .fixed(&job.payload);
        try out.writeAll(&.{ 0x80, 200, 0, 6 }); // SR with no reception blocks: only the phone sends audio.
        try out.writeInt(u32, self.sender, .big);
        try out.writeInt(u64, ntp(now), .big);
        for ([_]u32{ timestamp, count, count * 160 }) |word| try out.writeInt(u32, word, .big);
        try sdes(&out, self.sender, "mic@home.example");
        job.len = out.buffered().len;
        _ = try peer.send(alloc, job, false);
        const heard = job.payload[0..job.len];
        if (std.mem.readInt(u32, heard[4..8], .big) != self.received_ssrc or
            std.mem.readInt(u32, heard[16..20], .big) != self.last_sample +% @as(u32, @intCast((now - self.last_audio_at) * 8)) or
            std.mem.readInt(u32, heard[20..24], .big) != self.packets or std.mem.readInt(u32, heard[24..28], .big) != self.octets) return error.WrongRtcpSenderReport;
        self.lsr = std.mem.readInt(u32, heard[10..14], .big);
        self.sr_at = now;
    } else if (rr) {
        // Regular 20 ms delivery within each talkspurt: no missing sequences or arrival jitter.
        const delay: u32 = @intCast((now - self.sr_at) * 65536 / 1000);
        job.len = try receiverReport(&job.payload, self.listener, self.received_ssrc, self.highest_sequence, self.lsr, delay);
        try peer.inject(try Sim.packet(alloc, job.*, true, false, 64));
        try peer.count(1);
        const last: u32 = if (phase == .audio_first_rr) 2 else 5;
        job.len = try receiverReport(&job.payload, self.listener, self.sender, @as(u32, self.first_sequence) + last, @truncate(ntp(self.sr_at) >> 16), delay);
        _ = try peer.expect(0, .lan, try Sim.packet(alloc, job.*, true, true, 63));
    } else {
        const index: u16 = switch (phase) {
            .audio_start => 0,
            .audio_second => 1,
            .audio_third => 2,
            .audio_resume => 3,
            .audio_fifth => 4,
            .audio_sixth => 5,
            else => unreachable,
        };
        const samples = Audio.audioFrame(job, self.sender, self.first_sequence +% index, timestamp);
        Audio.writeTone(samples, index);
        if (phase == .audio_start or phase == .audio_resume) job.payload[1] |= 0x80;
        _ = try peer.send(alloc, job, false);
        const seq = std.mem.readInt(u16, job.payload[2..4], .big);
        const ssrc = std.mem.readInt(u32, job.payload[8..12], .big);
        if (self.packets == 0) {
            self.received_ssrc = ssrc;
            self.highest_sequence = seq;
        } else {
            self.highest_sequence += 1;
            if (seq != @as(u16, @truncate(self.highest_sequence)) or ssrc != self.received_ssrc) return error.InvalidAudioStream;
        }
        self.last_sample = std.mem.readInt(u32, job.payload[4..8], .big);
        self.last_audio_at = now;
        self.packets += 1;
        self.octets += @intCast(job.len - 12);
    }
    if (!rr) self.deadlines[i] = std.Io.Timestamp.now(net.io, .boot).addDuration(.fromSeconds(300));
    for (self.sockets[0..self.opened], 0..) |*s, index| {
        try s.checkUdpMapping(self.generation + index, self.deadlines[index], &.{.{ .ip = s.remote, .port = s.remote_port }});
    }
    if (nat.inside.count() != self.original_count + self.opened or nat.outside.count() != self.original_count + self.opened or
        nat.next_generation != self.generation + self.opened) return error.WrongMediaMappingCount;
}

fn ntp(ms: u64) u64 {
    return (@as(u64, 4_000_000_000) << 32) + (ms << 32) / 1000;
}

fn sdes(out: *std.Io.Writer, ssrc: u32, name: []const u8) !void {
    const len = std.mem.alignForward(usize, 11 + name.len, 4);
    try out.writeAll(&.{ 0x81, 202, 0, @intCast(len / 4 - 1) });
    try out.writeInt(u32, ssrc, .big);
    try out.writeAll(&.{ 1, @intCast(name.len) }); // SDES CNAME item
    try out.writeAll(name);
    try out.splatByteAll(0, len - (10 + name.len)); // END and alignment
}

fn receiverReport(buffer: []u8, reporter: u32, source: u32, highest: u32, lsr: u32, delay: u32) !usize {
    var out: std.Io.Writer = .fixed(buffer);
    try out.writeAll(&.{ 0x81, 201, 0, 7 });
    for ([_]u32{ reporter, source, 0, highest, 0, lsr, delay }) |word| try out.writeInt(u32, word, .big);
    try sdes(&out, reporter, "listener@peer.example");
    return out.buffered().len;
}
