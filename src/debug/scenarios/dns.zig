const std = @import("std");
const Router = @import("router");
const Sim = @import("../network_sim.zig");
const Job = Sim.Job;
const State = Router.State;
const Nat = Router.Tables.NatTable.NatTable;
const dns = Sim.dns;
const resolver = Nat.Peer{ .ip = dns, .port = 53 };
const packet = Sim.packet;

pub fn addressResponse(message: []u8, question_len: usize, address_len: usize, records: u8, alias: bool) usize {
    message[2..4].* = .{ 0x81, if (address_len == 0) 0x83 else 0x80 };
    if (address_len == 0) return question_len;
    std.mem.writeInt(u16, message[6..8], @as(u16, records) + @intFromBool(alias), .big);
    var offset = question_len;
    var owner: u16 = 0xc00c;
    if (alias) {
        // The CNAME target "edge" shares the question's domain suffix.
        const cname = message[offset..][0..19];
        cname[0..12].* = .{ 0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, 7 };
        cname[12..17].* = "\x04edge".*;
        std.mem.writeInt(u16, cname[17..19], 0xc000 | (13 + @as(u16, message[12])), .big);
        owner = 0xc000 | @as(u16, @intCast(offset + 12));
        offset += cname.len;
    }
    for (0..records) |i| {
        const answer = message[offset..];
        std.mem.writeInt(u16, answer[0..2], owner, .big);
        answer[2..12].* = .{ 0, if (address_len == 4) 1 else 28, 0, 1, 0, 0, 0, 60, 0, @intCast(address_len) };
        const last: u8 = @intCast(80 + i);
        if (address_len == 4) {
            answer[12..16].* = .{ 203, 0, 113, last };
        } else {
            answer[12..28].* = .{ 0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, last };
        }
        offset += 12 + address_len;
    }
    return offset;
}

pub const ParallelDns = struct {
    requests: [6]Job,
    answers: [6]Job,
    first_generation: u64,
    previous_mappings: usize,
    deadline: std.Io.Timestamp,

    pub const Steps = enum { queries, answers };

    pub fn step(turn: *Sim.ConversationTurn) !void {
        const self = &turn.peer.network.episodes.parallel_dns;
        const phase: Steps = @enumFromInt(turn.phase);
        const peer = turn.peer;
        if ((phase == .queries) != (peer.iface == .lan)) return;
        const network = peer.network;
        var prng = std.Random.DefaultPrng.init(network.seed +% turn.index);
        const random = prng.random();
        var scratch = std.heap.FixedBufferAllocator.init(&peer.scratch);
        const alloc = scratch.allocator();
        switch (phase) {
            .queries => {
                const first_host = random.int(u4);
                const first_id = random.int(u16);
                const id_step = random.int(u16) | 1;
                const labels = [3][3]u8{ "www".*, "api".*, "cdn".* };
                self.previous_mappings = State.nat_table.inside.count();
                self.deadline = std.Io.Timestamp.now(network.io, .boot).addDuration(.fromSeconds(300));
                for (&self.requests, &self.answers, 0..) |*request, *answer, i| {
                    scratch.reset();
                    const generation = network.newConversationBinding();
                    if (i == 0) self.first_generation = generation;
                    request.* = network.cold;
                    request.choice.host = first_host +% @as(u4, @intCast(i / 2));
                    request.choice.kind = .dns_udp;
                    const is_aaaa = i % 2 != 0;
                    request.choice.token = (random.int(u32) & ~@as(u32, 3)) | @as(u32, if (is_aaaa) 3 else 1);
                    request.remote = dns;
                    // Each client uses the same pair of private ports.
                    request.source_port = @intCast(34000 + 2 * turn.index + i % 2);
                    request.public_port = network.reservePort(.udp, request.source_port);
                    request.dns_alias = i >= 4;
                    request.dns_records = if (i == 0) 8 else if (request.dns_alias) random.intRangeAtMost(u4, 1, 2) else if (is_aaaa) 1 else random.intRangeAtMost(u4, 2, 4);
                    request.makeDnsQuery(first_id +% id_step *% @as(u16, @intCast(i)), labels[i / 2]);
                    // Save the client's complete expected answer before the resolver sees any router output.
                    answer.* = request.*;
                    answer.makeResponse();
                    _ = try peer.send(alloc, request, false);
                    try self.checkMappings(network, i + 1);
                }
            },
            .answers => {
                var order = [_]usize{ 0, 1, 2, 3, 4, 5 };
                random.shuffle(usize, &order);
                if (order[0] == 0) std.mem.swap(usize, &order[0], &order[1]);
                for (order) |i| {
                    scratch.reset();
                    var delivered = self.requests[i];
                    delivered.makeResponse();
                    try peer.inject(try packet(alloc, delivered, true, false, 64));
                    try peer.count(1);
                    _ = try peer.expect(0, .lan, try packet(alloc, self.answers[i], true, true, 63));
                    try self.checkMappings(network, self.requests.len);
                }
            },
        }
    }

    fn checkMappings(self: *const ParallelDns, network: *const Sim.Network, count: usize) !void {
        const nat = &State.nat_table;
        if (nat.inside.count() != self.previous_mappings + count or nat.outside.count() != self.previous_mappings + count or
            nat.next_generation != self.first_generation + count or nat.udp_ports.next != network.next[2]) return error.WrongDnsMappings;
        for (self.answers[0..count], 0..) |*expected, i| try expected.checkUdpMapping(self.first_generation + i, self.deadline, &.{resolver});
    }
};

pub const Retry = struct {
    query: Job,
    response: Job,
    first_sent: std.Io.Timestamp,
    deadline: std.Io.Timestamp,
    mappings: usize,
    generation: u64,
    completed_id: ?u16 = null,

    pub fn step(self: *Retry, peer: *Sim.Peer, phase: Sim.Scenarios.Lifecycle) !void {
        const querying = phase == .dns_initial_query or phase == .dns_retransmit;
        if (querying != (peer.iface == .lan)) return;
        const net = peer.network;
        const nat = &State.nat_table;
        var scratch = std.heap.FixedBufferAllocator.init(&peer.scratch);
        const alloc = scratch.allocator();
        const now = std.Io.Timestamp.now(net.io, .boot);
        if (querying) {
            if (phase == .dns_initial_query) {
                var prng = std.Random.DefaultPrng.init(net.seed);
                const random = prng.random();
                self.* = .{
                    .query = net.cold,
                    .response = undefined,
                    .first_sent = now,
                    .deadline = undefined,
                    .mappings = nat.inside.count() + 1,
                    .generation = net.newConversationBinding(),
                };
                self.query.choice.kind = .dns_udp;
                self.query.choice.host = random.intRangeAtMost(u4, 1, 15);
                self.query.choice.token = random.int(u32) | 1;
                self.query.remote = dns;
                // Choose a socket number held on WAN so both replies must restore the client's port.
                self.query.source_port = @intCast(net.used[2].findLastSet() orelse return error.MissingNatState);
                self.query.public_port = net.reservePort(.udp, self.query.source_port);
                if (self.query.public_port == self.query.source_port) return error.ExpectedUdpPortCollision;
                self.query.dns_records = random.intRangeAtMost(u4, 1, 3);
                self.query.makeDnsQuery(random.int(u16), "upd".*);
            } else {
                const elapsed = self.first_sent.durationTo(now).toMilliseconds();
                if (elapsed < 2000 or elapsed > 5000) return error.WrongDnsRetryTime;
            }
            self.deadline = now.addDuration(.fromSeconds(300));
            var sent = self.query;
            if (phase == .dns_retransmit) sent.choice.token +%= 4;
            _ = try peer.send(alloc, &sent, false);
            const tx = try peer.observation.take(0, .wan);
            if (phase == .dns_initial_query) {
                // The resolver builds its answer from the query and source socket it received.
                self.response = sent;
                self.response.wan_ip = tx[26..30].*;
                self.response.remote = tx[30..34].*;
                self.response.makeResponse();
                self.response.choice.token ^= 0x4000;
            } else if (!std.mem.eql(u8, sent.payload[0..sent.len], self.query.payload[0..self.query.len]) or
                sent.public_port != self.response.public_port) return error.WrongDnsRetryQuestion;
        } else {
            // A delayed resolver answer arrives after the retry, then a byte-identical copy arrives.
            try peer.inject(try packet(alloc, self.response, true, false, 64));
            try peer.count(1);
            var expected = self.query;
            expected.makeResponse();
            expected.choice.token ^= 0x4000;
            const tx = try peer.expect(0, .lan, try packet(alloc, expected, true, true, 63));
            const id = std.mem.readInt(u16, tx[42..44], .big);
            if (phase == .dns_delayed_answer) {
                if (self.completed_id != null) return error.UnexpectedDnsCompletion;
                self.completed_id = id;
            } else if (self.completed_id != id) return error.UnexpectedDnsCompletion;
        }
        try self.query.checkUdpMapping(self.generation, self.deadline, &.{resolver});
        if (nat.inside.count() != self.mappings or nat.outside.count() != self.mappings or
            nat.next_generation != self.generation + 1) return error.WrongDnsMappings;
    }
};

pub const Fallback = struct {
    query: Job,
    tcp: @import("tcp.zig").TcpConnection,
    retry: [64]u8,
    answer: [1024]u8,
    answer_len: usize,
    records: u8,
    previous_mappings: usize,
    udp_generation: u64,
    udp_deadline: std.Io.Timestamp,

    pub const Steps = enum { udp_query, truncated, syn, syn_ack, tcp_query, tcp_answer, client_close, server_close, final_ack };

    pub fn step(turn: *Sim.ConversationTurn) !void {
        const phase: Steps = @enumFromInt(turn.phase);
        const peer = turn.peer;
        const from_lan = switch (phase) {
            .udp_query, .syn, .tcp_query, .client_close, .final_ack => true,
            .truncated, .syn_ack, .tcp_answer, .server_close => false,
        };
        if (from_lan != (peer.iface == .lan)) return;
        const network = peer.network;
        const self = &network.episodes.dns_fallback;
        var scratch = std.heap.FixedBufferAllocator.init(&peer.scratch);
        const alloc = scratch.allocator();
        const query = &self.query;
        switch (phase) {
            .udp_query => {
                var prng = std.Random.DefaultPrng.init(network.seed +% turn.index);
                const random = prng.random();
                const port: u16 = @intCast(38000 + turn.index);
                query.* = network.cold;
                query.choice.host = random.int(u4);
                query.choice.kind = .dns_udp;
                query.choice.token = random.int(u32) | 1;
                query.remote = dns;
                query.source_port = port;
                query.public_port = network.reservePort(.udp, port);
                query.makeDnsQuery(random.int(u16), "img".*);
                const aaaa = query.payload[query.len - 3] == 28;
                self.records = if (aaaa) random.intRangeAtMost(u8, 17, 21) else random.intRangeAtMost(u8, 30, 34);
                self.tcp = .{
                    .host = query.host(),
                    .mac = query.mac(),
                    .port = port,
                    .public_port = undefined,
                    .remote = dns,
                    .service_peer = resolver,
                    .client_next = random.int(u32),
                    .server_next = random.int(u32),
                    .generation = undefined,
                };
                self.previous_mappings = State.nat_table.inside.count();
                self.udp_generation = network.newConversationBinding();
                self.udp_deadline = std.Io.Timestamp.now(network.io, .boot).addDuration(.fromSeconds(300));
                _ = try peer.send(alloc, query, false);
            },
            .truncated => {
                var short = query.*;
                short.payload[2..4].* = .{ 0x83, 0x80 }; // QR, TC, RD, RA; no partial RRset.
                try peer.inject(try packet(alloc, short, true, false, 64));
                try peer.count(1);
                const tx = try peer.expect(0, .lan, try packet(alloc, short, true, true, 63));
                std.mem.writeInt(u16, self.retry[0..2], @intCast(query.len), .big);
                @memcpy(self.retry[2..][0..query.len], tx[tx.len - query.len ..]);
                self.retry[4..6].* = .{ 1, 0 };
                if (!std.mem.eql(u8, self.retry[2..][0..query.len], query.payload[0..query.len])) return error.WrongDnsRetryQuestion;
            },
            .syn => {
                self.tcp.generation = network.newConversationBinding();
                self.tcp.public_port = network.reservePort(.tcp, self.tcp.port);
                try self.tcp.segment(peer, .{ .syn = true, .ack = false }, null);
            },
            .syn_ack => try self.tcp.segment(peer, .{ .syn = true }, null),
            .tcp_query => {
                try self.tcp.segment(peer, .{}, null);
                const framed = self.retry[0 .. 2 + query.len];
                try self.tcp.segment(peer, .{ .psh = true, .payload = framed }, null);
                const tx = try peer.observation.take(0, .wan);
                const received = tx[tx.len - framed.len ..];
                self.answer_len = self.fullAnswer(&self.answer, received[2..]);
            },
            .tcp_answer => {
                try self.tcp.segment(peer, .{ .psh = true, .payload = self.answer[0..self.answer_len] }, null);
                const tx = try peer.observation.take(0, .lan);
                var expected: [1024]u8 = undefined;
                const n = self.fullAnswer(&expected, query.payload[0..query.len]);
                if (n <= 514 or !std.mem.endsWith(u8, tx, expected[0..n])) return error.WrongDnsTcpAnswer;
            },
            .client_close => try self.tcp.segment(peer, .{ .fin = true }, null),
            .server_close => try self.tcp.segment(peer, .{ .fin = true }, null),
            .final_ack => try self.tcp.segment(peer, .{}, null),
        }
        // Opening TCP on the same numeric port must preserve the UDP mapping and its expiry.
        const n: usize = if (@intFromEnum(phase) < @intFromEnum(Steps.syn)) 1 else 2;
        const nat = &State.nat_table;
        if (nat.inside.count() != self.previous_mappings + n or nat.outside.count() != self.previous_mappings + n or
            nat.next_generation != self.udp_generation + n) return error.WrongDnsMappings;
        try query.checkUdpMapping(self.udp_generation, self.udp_deadline, &.{resolver});
    }

    fn fullAnswer(self: *const Fallback, buffer: []u8, question: []const u8) usize {
        const message = buffer[2..];
        @memcpy(message[0..question.len], question);
        const address_len: usize = if (question[question.len - 3] == 28) 16 else 4;
        const len = addressResponse(message, question.len, address_len, self.records, true);
        std.mem.writeInt(u16, buffer[0..2], @intCast(len), .big);
        return len + 2;
    }
};

test "parallel DNS answers preserve the original question and encode each address record" {
    var job: Job = undefined;
    job.choice.kind = .dns_udp;
    job.syn = false;
    job.dns_alias = false;
    for ([_]bool{ false, true }) |aaaa| {
        job.choice.token = if (aaaa) 3 else 1;
        job.dns_records = if (aaaa) 1 else 8;
        job.makeDnsQuery(0x1324, "cdn".*);
        job.makeResponse();
        const header = [_]u8{ 0x13, 0x24, 0x81, 0x80, 0, 1, 0, job.dns_records, 0, 0, 0, 0 };
        try std.testing.expectEqualSlices(u8, &header, job.payload[0..12]);
        const qtype: u8 = if (aaaa) 28 else 1;
        const name = "\x03cdn\x07example\x03net\x00";
        try std.testing.expectEqualSlices(u8, name, job.payload[12..][0..name.len]);
        const type_offset = 12 + name.len;
        try std.testing.expectEqualSlices(u8, &.{ 0, qtype, 0, 1 }, job.payload[type_offset..][0..4]);
        var offset: usize = type_offset + 4;
        for (0..job.dns_records) |i| {
            const size: u8 = if (aaaa) 16 else 4;
            try std.testing.expectEqualSlices(u8, &.{ 0xc0, 12, 0, qtype, 0, 1, 0, 0, 0, 60, 0, size }, job.payload[offset..][0..12]);
            offset += 12;
            const address: []const u8 = if (aaaa) &[_]u8{ 0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 80 } else &[_]u8{ 203, 0, 113, @intCast(80 + i) };
            try std.testing.expectEqualSlices(u8, address, job.payload[offset..][0..size]);
            offset += size;
        }
        try std.testing.expectEqual(offset, job.len);
    }
}

test "a framed DNS answer compresses its CNAME and address owners within the DNS message" {
    var job: Job = undefined;
    job.choice.kind = .dns_tcp;
    job.choice.token = 1;
    job.syn = false;
    job.dns_alias = true;
    job.dns_records = 1;
    job.makeDnsQuery(0x273a, "cdn".*);
    const end_of_question = job.len;
    job.makeResponse();
    try std.testing.expectEqual(job.len - 2, std.mem.readInt(u16, job.payload[0..2], .big));
    try std.testing.expectEqual(@as(u16, 2), std.mem.readInt(u16, job.payload[8..10], .big));
    const records = "\xc0\x0c\x00\x05\x00\x01\x00\x00\x00\x3c\x00\x07\x04edge\xc0\x10" ++
        "\xc0\x2d\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\xcb\x00\x71\x50";
    try std.testing.expectEqualSlices(u8, records, job.payload[end_of_question..job.len]);
}
