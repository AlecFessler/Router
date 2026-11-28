const std = @import("std");
const Router = @import("router");
const Sim = @import("../network_sim.zig");
const Tcp = @import("tcp.zig").TcpConnection;
const Pipeline = @This();

connection: Tcp,
queries: [2]Sim.Job,
answers: [544]u8 = undefined,
received: [544]u8 = undefined,
answered: [2]bool = .{ false, false },
answer_len: usize = 0,
consumed: usize = 0,
window: u16,
mapping_count: usize,

pub const Steps = enum { syn, syn_ack, queries, first_answers, open_window, remaining_answer, client_close, server_close, final_ack };

pub fn step(turn: *Sim.ConversationTurn) !void {
    const phase: Steps = @enumFromInt(turn.phase);
    const peer = turn.peer;
    const from_lan = switch (phase) {
        .syn, .queries, .open_window, .client_close, .final_ack => true,
        else => false,
    };
    if (from_lan != (peer.iface == .lan)) return;
    const net = peer.network;
    const self = &net.episodes.pipelined_dns;
    const tcp = &self.connection;
    const nat = &Router.State.nat_table;
    switch (phase) {
        .syn => {
            var prng = std.Random.DefaultPrng.init(net.seed +% turn.index);
            const random = prng.random();
            const port: u16 = @intCast(net.used[1].findLastSet() orelse return error.MissingNatState);
            self.* = .{
                .connection = Tcp.open(peer, random, random.int(u4), Sim.dns, port),
                .queries = @splat(net.cold),
                .mapping_count = nat.inside.count() + 1,
                // A 52-byte receive window fits the A response and one byte of the next length field.
                .window = if (random.boolean()) 52 else random.intRangeAtMost(u16, 96, 144),
            };
            tcp.service_peer = .{ .ip = Sim.dns, .port = 53 };
            if (tcp.public_port == tcp.port) return error.ExpectedTcpPortCollision;
            const id = random.int(u16);
            for (&self.queries, [_][3]u8{ "cdn".*, "api".* }, 0..) |*query, label, i| {
                query.choice.kind = .dns_tcp;
                query.syn = false;
                query.choice.token = if (i == 0) 3 else 1;
                query.dns_records = if (i == 0) random.intRangeAtMost(u4, 5, 7) else 1;
                query.makeDnsQuery(if (i == 0) id else id +% (random.int(u16) | 1), label);
            }
            try tcp.exchange(peer, .{ .syn = true, .ack = false }, null, .{ .window = self.window });
        },
        .syn_ack => try tcp.segment(peer, .{ .syn = true }, null),
        .queries => {
            try tcp.exchange(peer, .{}, null, .{ .window = self.window });
            var server_queries: [2]Sim.Job = self.queries;
            for (&server_queries) |*query| {
                try tcp.exchange(peer, .{ .psh = true, .payload = query.payload[0..query.len] }, null, .{ .window = self.window });
                const payload = try delivered(peer, .wan);
                var reader: std.Io.Reader = .fixed(payload);
                const q = try reader.take(try reader.takeInt(u16, .big));
                if (reader.bufferedLen() != 0 or q.len < 4) return error.WrongDnsTcpQuestion;
                // Build the resolver's record type, question and ID from the frame that actually arrived.
                query.choice.token = switch (std.mem.readInt(u16, q[q.len - 4 ..][0..2], .big)) {
                    1 => 1,
                    28 => 3,
                    else => return error.WrongDnsTcpQuestion,
                };
                @memcpy(query.payload[0..payload.len], payload);
                query.len = payload.len;
            }
            var stream: std.Io.Writer = .fixed(&self.answers);
            // The cached A lookup completes while the earlier AAAA lookup is still outstanding.
            for ([_]usize{ 1, 0 }) |i| {
                server_queries[i].makeResponse();
                try stream.writeAll(server_queries[i].payload[0..server_queries[i].len]);
            }
            self.answer_len = stream.buffered().len;
        },
        .first_answers, .remaining_answer => {
            const first = phase == .first_answers;
            const start: usize = if (first) 0 else self.window;
            const end = if (first) self.window else self.answer_len;
            try tcp.segment(peer, .{ .psh = true, .payload = self.answers[start..end] }, null);
            @memcpy(self.received[start..end], try delivered(peer, .lan));
            const completed = try self.accept(self.received[self.consumed..end]);
            if (first) {
                if (completed != 1 or self.consumed >= end or end >= self.answer_len) return error.WrongDnsTcpBoundary;
            } else if (completed != 0 or self.consumed != end) return error.WrongDnsTcpBoundary;
        },
        .open_window => try tcp.exchange(peer, .{}, null, .{ .window = 4096 }),
        .client_close => try tcp.exchange(peer, .{ .fin = true }, null, .{ .window = 4096 }),
        .server_close => try tcp.segment(peer, .{ .fin = true }, null),
        .final_ack => try tcp.exchange(peer, .{}, null, .{ .window = 4096 }),
    }
    if (nat.inside.count() != self.mapping_count or nat.outside.count() != self.mapping_count or
        nat.next_generation != tcp.generation + 1) return error.WrongDnsMappings;
}

fn delivered(peer: *Sim.Peer, iface: Router.Nic.Api.IFace) ![]const u8 {
    const frame = try peer.observation.take(0, iface);
    return frame[34 + @as(usize, frame[46] >> 4) * 4 ..];
}

fn accept(self: *Pipeline, bytes: []const u8) !usize {
    var reader: std.Io.Reader = .fixed(bytes);
    const length = try reader.takeInt(u16, .big);
    const msg = try reader.take(length);
    if (msg.len < 12) return error.WrongDnsTcpAnswer;
    for (self.queries, 0..) |query, i| {
        if (!std.mem.eql(u8, msg[0..2], query.payload[2..4])) continue;
        if (self.answered[i]) return error.DuplicateDnsTcpAnswer;
        var expected = query;
        expected.makeResponse();
        if (!std.mem.eql(u8, msg, expected.payload[2..expected.len])) return error.WrongDnsTcpAnswer;
        self.answered[i] = true;
        self.consumed += 2 + @as(usize, length);
        return i;
    }
    return error.UnknownDnsTransaction;
}
