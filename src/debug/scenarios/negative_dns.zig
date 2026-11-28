const std = @import("std");
const Router = @import("router");
const Sim = @import("../network_sim.zig");
const addressResponse = @import("dns.zig").addressResponse;
const NegativeDns = @This();

query: Sim.Job,
answer: Sim.Job,
first_id: u16,
id_stride: u16,
zone_ttl: u32,
minimum: u32,
generation: u64,
deadline: std.Io.Timestamp,
mapping_count: usize,
result: ?Result = null,

const Result = enum { nxdomain, nodata, address };
pub const Steps = enum { missing_query, missing_answer, aaaa_query, aaaa_answer, a_query, a_answer };

pub fn step(turn: *Sim.ConversationTurn) !void {
    const phase: Steps = @enumFromInt(turn.phase);
    const querying = phase == .missing_query or phase == .aaaa_query or phase == .a_query;
    const peer = turn.peer;
    if (querying != (peer.iface == .lan)) return;
    const net = peer.network;
    const nat = &Router.State.nat_table;
    const self = &net.episodes.negative_dns;
    if (phase == .missing_query) {
        var prng = std.Random.DefaultPrng.init(net.seed +% turn.index);
        const random = prng.random();
        self.* = .{
            .query = net.cold,
            .answer = undefined,
            .first_id = random.int(u16),
            .id_stride = random.int(u16) | 1,
            .zone_ttl = if (random.boolean()) 300 else 7200,
            .minimum = if (random.boolean()) 1800 else 86400,
            .generation = net.newConversationBinding(),
            .deadline = undefined,
            .mapping_count = nat.inside.count() + 1,
        };
        self.query.choice.host = random.int(u4);
        self.query.choice.kind = .dns_udp;
        self.query.remote = Sim.dns;
        self.query.source_port = @intCast(35500 + turn.index);
        self.query.public_port = net.reservePort(.udp, self.query.source_port);
    }
    var scratch = std.heap.FixedBufferAllocator.init(&peer.scratch);
    const alloc = scratch.allocator();
    const query = &self.query;
    if (querying) {
        if ((phase == .aaaa_query and self.result != .nxdomain) or
            (phase == .a_query and self.result != .nodata)) return error.WrongDnsLookupResult;
        query.choice.token = if (phase == .a_query) 1 else 3;
        const index: u16 = @intCast(turn.phase / 2);
        query.makeDnsQuery(self.first_id +% index *% self.id_stride, if (phase == .missing_query) "old".* else "cam".*);
        self.answer = query.*;
        _ = try peer.send(alloc, &self.answer, false);
        try self.resolve();
        self.deadline = std.Io.Timestamp.now(net.io, .boot).addDuration(.fromSeconds(300));
    } else {
        try peer.inject(try Sim.packet(alloc, self.answer, true, false, 64));
        try peer.count(1);
        const lan = try peer.expect(0, .lan, try Sim.packet(alloc, self.answer, true, true, 63));
        self.result = try self.accept(lan[42..]);
        const expected: Result = switch (phase) {
            .missing_answer => .nxdomain,
            .aaaa_answer => .nodata,
            .a_answer => .address,
            else => unreachable,
        };
        if (self.result != expected) return error.WrongDnsLookupResult;
    }
    try query.checkUdpMapping(self.generation, self.deadline, &.{.{ .ip = Sim.dns, .port = 53 }});
    if (nat.inside.count() != self.mapping_count or nat.outside.count() != self.mapping_count or
        nat.next_generation != self.generation + 1) return error.WrongDnsMappings;
}

// Each name has a three-octet first label, so example.net starts at offset 16.
const soa_names = "\x03ns1\xc0\x10\x0ahostmaster\xc0\x10";

fn resolve(self: *NegativeDns) !void {
    const answer = &self.answer;
    const message = &answer.payload;
    const question = message[0..answer.len];
    if (!std.mem.eql(u8, question[2..13], &.{ 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 3 }) or
        !std.mem.eql(u8, question[16 .. question.len - 4], "\x07example\x03net\x00") or
        !std.mem.eql(u8, question[question.len - 2 ..], &.{ 0, 1 })) return error.WrongDnsQuestion;
    const exists = std.mem.eql(u8, question[13..16], "cam");
    if (!exists and !std.mem.eql(u8, question[13..16], "old")) return error.WrongDnsQuestion;
    const qtype = std.mem.readInt(u16, question[question.len - 4 ..][0..2], .big);
    if (exists and qtype == 1) {
        answer.len = addressResponse(message, question.len, 4, 1, false);
        return;
    }
    if (qtype != 28) return error.WrongDnsQuestion;
    message[2..4].* = .{ 0x81, if (exists) 0x80 else 0x83 };
    message[9] = 1;
    var rr: std.Io.Writer = .fixed(message[question.len..]);
    try rr.writeAll("\xc0\x10\x00\x06\x00\x01");
    try rr.writeInt(u32, @min(self.zone_ttl, self.minimum), .big);
    try rr.writeInt(u16, soa_names.len + 20, .big);
    try rr.writeAll(soa_names);
    for ([_]u32{ 2026112801, 3600, 600, 86400, self.minimum }) |value| try rr.writeInt(u32, value, .big);
    answer.len += rr.buffered().len;
}

fn accept(self: *const NegativeDns, message: []const u8) !Result {
    const q = self.query.payload[0..self.query.len];
    if (message.len < q.len or !std.mem.eql(u8, message[0..2], q[0..2]) or
        !std.mem.eql(u8, message[12..q.len], q[12..]) or !std.mem.eql(u8, message[4..6], &.{ 0, 1 }) or
        !std.mem.eql(u8, message[10..12], &.{ 0, 0 })) return error.WrongDnsQuestion;
    const flags = std.mem.readInt(u16, message[2..4], .big);
    const rr = message[q.len..];
    if (std.mem.eql(u8, message[6..10], &.{ 0, 1, 0, 0 })) {
        if (flags != 0x8180 or !std.mem.eql(u8, rr, &.{ 0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 203, 0, 113, 80 })) return error.WrongDnsAddress;
        return .address;
    }
    if (!std.mem.eql(u8, message[6..10], &.{ 0, 0, 0, 1 }) or rr.len != 12 + soa_names.len + 20 or
        !std.mem.eql(u8, rr[0..6], "\xc0\x10\x00\x06\x00\x01") or std.mem.readInt(u16, rr[10..12], .big) != rr.len - 12 or
        !std.mem.eql(u8, rr[12 .. rr.len - 20], soa_names) or
        std.mem.readInt(u32, rr[6..10], .big) != @min(self.zone_ttl, self.minimum)) return error.WrongDnsAuthority;
    var timers: std.Io.Reader = .fixed(rr[rr.len - 20 ..]);
    for ([_]u32{ 2026112801, 3600, 600, 86400, self.minimum }) |value| {
        if (try timers.takeInt(u32, .big) != value) return error.WrongDnsAuthority;
    }
    return switch (flags) {
        0x8183 => .nxdomain,
        0x8180 => .nodata,
        else => error.WrongDnsLookupResult,
    };
}
