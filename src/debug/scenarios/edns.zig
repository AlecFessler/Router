const std = @import("std");
const Router = @import("router");
const Sim = @import("../network_sim.zig");
const addressResponse = @import("dns.zig").addressResponse;
const Edns = @This();

socket: Sim.Job,
id: u16,
large_limit: u16,
large_records: u8,
answer: [1232]u8 = undefined,
answer_len: usize = 0,
generation: usize,
deadline: std.Io.Timestamp,
mapping_count: usize,

pub const Steps = enum { small_query, small_answer, large_query, large_answer };

fn opt(limit: u16) [11]u8 {
    // Root owner, type OPT, requestor/responder UDP capacity, EDNS version 0 and no options.
    var rr = [_]u8{ 0, 0, 41, 0, 0, 0, 0, 0, 0, 0, 0 };
    std.mem.writeInt(u16, rr[3..5], limit, .big);
    return rr;
}

pub fn step(turn: *Sim.ConversationTurn) !void {
    const phase: Steps = @enumFromInt(turn.phase);
    const querying = phase == .small_query or phase == .large_query;
    const peer = turn.peer;
    if (querying != (peer.iface == .lan)) return;
    const net = peer.network;
    const self = &net.episodes.edns_udp;
    const nat = &Router.State.nat_table;
    if (phase == .small_query) {
        var prng = std.Random.DefaultPrng.init(net.seed +% turn.index);
        const random = prng.random();
        self.* = .{
            .socket = net.cold,
            .id = random.int(u16),
            .large_limit = if (random.boolean()) 1232 else 1400,
            .large_records = random.intRangeAtMost(u8, 17, 41),
            .generation = net.newConversationBinding(),
            .deadline = undefined,
            .mapping_count = nat.inside.count() + 1,
        };
        self.socket.choice.host = random.int(u4);
        self.socket.choice.kind = .dns_udp;
        self.socket.choice.token = random.int(u32) | 3; // AAAA
        self.socket.remote = Sim.dns;
        self.socket.source_port = @intCast(net.used[2].findLastSet() orelse return error.MissingNatState);
        self.socket.public_port = net.reservePort(.udp, self.socket.source_port);
        if (self.socket.public_port == self.socket.source_port) return error.ExpectedUdpPortCollision;
    }
    var scratch = std.heap.FixedBufferAllocator.init(&peer.scratch);
    const alloc = scratch.allocator();
    const small = phase == .small_query or phase == .small_answer;
    const limit = if (small) 512 else self.large_limit;
    const socket = &self.socket;
    if (querying) {
        socket.choice.token +%= 4;
        socket.makeDnsQuery(if (small) self.id else self.id +% 1, if (small) "api".* else "cdn".*);
        socket.payload[11] = 1;
        socket.payload[socket.len..][0..11].* = opt(limit);
        socket.len += 11;
        var received = socket.*;
        _ = try peer.send(alloc, &received, false);
        try self.resolve(received.payload[0..received.len]);
        self.deadline = std.Io.Timestamp.now(net.io, .boot).addDuration(.fromSeconds(300));
    } else {
        const message = self.answer[0..self.answer_len];
        try peer.inject(try Sim.packetWithPayload(alloc, socket.*, true, false, 64, message));
        try peer.count(1);
        const lan = try peer.expect(0, .lan, try Sim.packetWithPayload(alloc, socket.*, true, true, 63, message));
        const arrived = lan[42..];
        const records: u16 = if (small) 1 else self.large_records;
        const question_end = socket.len - 11;
        if (arrived.len != question_end + 28 * records + 11 or arrived.len > limit or (arrived.len <= 512) != small or
            !std.mem.eql(u8, arrived[0..2], socket.payload[0..2]) or std.mem.readInt(u16, arrived[2..4], .big) != 0x8180 or
            !std.mem.eql(u8, arrived[4..6], &.{ 0, 1 }) or std.mem.readInt(u16, arrived[6..8], .big) != records or
            !std.mem.eql(u8, arrived[8..question_end], socket.payload[8..question_end]) or
            !std.mem.eql(u8, arrived[arrived.len - 11 ..], &opt(1232))) return error.WrongEdnsAnswer;
        for (0..records) |i| {
            const rr = arrived[question_end + 28 * i ..][0..28];
            // Every AAAA belongs to the original name, in class IN, TTL 60, in 2001:db8::/96.
            if (!std.mem.eql(u8, rr[0..16], &.{ 0xc0, 12, 0, 28, 0, 1, 0, 0, 0, 60, 0, 16, 0x20, 1, 0xd, 0xb8 }) or
                !std.mem.allEqual(u8, rr[16..27], 0) or rr[27] != 80 + i) return error.WrongEdnsAddress;
        }
    }
    try socket.checkUdpMapping(self.generation, self.deadline, &.{.{ .ip = Sim.dns, .port = 53 }});
    if (nat.inside.count() != self.mapping_count or nat.outside.count() != self.mapping_count or
        nat.next_generation != self.generation + 1) return error.WrongDnsMappings;
}

fn resolve(self: *Edns, request: []const u8) !void {
    const question_end = request.len - 11;
    const additional = request[question_end..];
    const limit = std.mem.readInt(u16, additional[3..5], .big);
    if (!std.mem.eql(u8, request[2..12], &.{ 1, 0, 0, 1, 0, 0, 0, 0, 0, 1 }) or
        !std.mem.eql(u8, additional, &opt(limit)) or
        !std.mem.eql(u8, request[16..question_end], "\x07example\x03net\x00\x00\x1c\x00\x01")) return error.WrongEdnsQuestion;
    const records: u8 = if (std.mem.eql(u8, request[12..16], "\x03api")) 1 else if (std.mem.eql(u8, request[12..16], "\x03cdn")) self.large_records else return error.UnknownEdnsName;
    @memcpy(self.answer[0..question_end], request[0..question_end]);
    const end = addressResponse(&self.answer, question_end, 16, records, false);
    self.answer[end..][0..11].* = opt(1232);
    self.answer_len = end + 11;
    if (self.answer_len > limit) return error.EdnsAnswerExceedsOffer;
}
