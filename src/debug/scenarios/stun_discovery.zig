const std = @import("std");
const Router = @import("router");
const Sim = @import("../network_sim.zig");
const IPv4 = Router.Protocols.IPv4.IPv4;
const Nat = Router.Tables.NatTable.NatTable;
const Discovery = @This();

pub const Steps = enum { requests, fastest_reply, other_replies, delayed_reply };
const cookie = [4]u8{ 0x21, 0x12, 0xa4, 0x42 };
const Contact = struct {
    server: IPv4,
    transaction: [12]u8,
    observed_transaction: [12]u8,
    observed_address: IPv4,
    observed_port: u16,
};

socket: Sim.Job,
contacts: [14]Contact = undefined,
count: usize,
missing: usize,
mapping_count: usize,
generation: u64,
deadline: std.Io.Timestamp,

pub fn step(turn: *Sim.ConversationTurn) !void {
    const peer = turn.peer;
    const phase: Steps = @enumFromInt(turn.phase);
    if ((phase == .requests) != (peer.iface == .lan)) return;
    const net = peer.network;
    const self = &net.episodes.stun_discovery;
    var scratch = std.heap.FixedBufferAllocator.init(&peer.scratch);
    const alloc = scratch.allocator();
    const discovery = net.conversations.get(.stun_discovery);
    var prng = std.Random.DefaultPrng.init(net.seed +% (discovery - 1));
    const random = prng.random();
    if (phase == .requests) {
        self.socket = net.cold;
        self.socket.choice.host = random.int(u4);
        self.socket.remote_port = 3478;
        self.socket.source_port = @intCast(41641 + discovery - 1);
        self.socket.public_port = net.reservePort(.udp, self.socket.source_port);
        // Most discovery batches are small. The larger cases exercise delayed replies across more peers.
        self.count = switch (random.int(u5)) {
            0 => self.contacts.len,
            1 => 5,
            else => random.intRangeAtMost(usize, 2, 4),
        };
        self.mapping_count = Router.State.nat_table.inside.count() + 1;
        self.missing = 0;
        self.generation = net.newConversationBinding();
        self.deadline = std.Io.Timestamp.now(net.io, .boot).addDuration(.fromSeconds(300));
        const first_server = random.intRangeAtMost(u8, 1, 240);
        var ids = transactionGenerator(random);
        for (self.contacts[0..self.count], 0..) |*contact, i| {
            scratch.reset();
            var transaction: [12]u8 = undefined;
            ids.random().bytes(&transaction);
            for (self.contacts[0..i]) |previous| {
                if (std.mem.eql(u8, &previous.transaction, &transaction)) return error.DuplicateStunTransaction;
            }
            const server: IPv4 = .{ 192, 0, 2, first_server + @as(u8, @intCast(i)) };
            self.socket.remote = server;
            self.socket.choice.token = random.int(u32);
            self.socket.payload[0..20].* = bindingRequest(transaction);
            self.socket.len = 20;
            _ = try peer.send(alloc, &self.socket, false);
            const sent = try peer.observation.take(0, .wan);
            contact.* = .{
                .server = server,
                .transaction = transaction,
                .observed_transaction = sent[50..62].*,
                .observed_address = sent[26..30].*,
                .observed_port = std.mem.readInt(u16, sent[34..36], .big),
            };
            try self.checkMapping();
        }
    } else {
        var order: [14]usize = undefined;
        for (order[0..self.count], 0..) |*slot, i| slot.* = i;
        // Let both the most recently contacted server and the earliest one answer after the entire fan-out.
        std.mem.swap(usize, &order[0], &order[self.count - 1]);
        random.shuffle(usize, order[1 .. self.count - 1]);
        const arrived = switch (phase) {
            .fastest_reply => order[0..1],
            .other_replies => order[1 .. self.count - 1],
            .delayed_reply => order[self.count - 1 .. self.count],
            .requests => unreachable,
        };
        for (arrived) |i| {
            scratch.reset();
            const contact = self.contacts[i];
            var reply = self.socket;
            reply.remote = contact.server;
            reply.choice.token = random.int(u32);
            reply.len = 32;
            reply.payload[0..32].* = success(contact.observed_transaction, contact.observed_address, contact.observed_port);
            try peer.inject(try Sim.packet(alloc, reply, true, false, 64));
            reply.payload[0..32].* = success(contact.transaction, Sim.wan, self.socket.public_port);
            const expected = try Sim.packet(alloc, reply, true, true, 63);
            peer.expectDelivery(.lan, expected) catch |err| switch (err) {
                error.MissingDelivery => self.missing += 1,
                else => return err,
            };
            try self.checkMapping();
        }
        if (phase == .delayed_reply and self.missing != 0) {
            std.log.err("STUN discovery: {d}/{d} contacted servers' Binding Success replies were missing on LAN, public UDP port {d}", .{ self.missing, self.count, self.socket.public_port });
            return error.MissingStunReplies;
        }
    }
}

fn transactionGenerator(random: std.Random) std.Random.DefaultCsprng {
    var key: [std.Random.DefaultCsprng.secret_seed_length]u8 = undefined;
    random.bytes(&key);
    return .init(key);
}

fn bindingRequest(transaction: [12]u8) [20]u8 {
    return .{ 0, 1, 0, 0 } ++ cookie ++ transaction;
}

fn success(transaction: [12]u8, address: IPv4, port: u16) [32]u8 {
    var msg = [4]u8{ 1, 1, 0, 12 } ++ cookie ++ transaction ++ [6]u8{ 0, 0x20, 0, 8, 0, 1 } ++ [_]u8{0} ** 6;
    std.mem.writeInt(u16, msg[26..28], port ^ 0x2112, .big);
    for (address, cookie, msg[28..32]) |byte, mask, *result| result.* = byte ^ mask;
    return msg;
}

pub const Retry = struct {
    job: Sim.Job,
    transaction: [12]u8,
    cached_reply: [32]u8,
    first_sent: std.Io.Timestamp,
    deadline: std.Io.Timestamp,
    generation: u64,

    pub fn step(self: *Retry, peer: *Sim.Peer, phase: Sim.Scenarios.Lifecycle) !void {
        const initial = phase == .stun_initial_request;
        const response = phase == .stun_success;
        if (response != (peer.iface == .wan)) return;
        const net = peer.network;
        const now = std.Io.Timestamp.now(net.io, .boot);
        const nat = &Router.State.nat_table;
        const count = nat.inside.count();
        const next = nat.next_generation;
        const job = &self.job;
        if (initial) {
            var prng = std.Random.DefaultPrng.init(net.seed);
            const random = prng.random();
            var ids = transactionGenerator(random);
            ids.random().bytes(&self.transaction);
            self.first_sent = now;
            self.generation = net.newConversationBinding();
            job.* = net.cold;
            // Client zero just declined its lease.
            job.choice.host = random.intRangeAtMost(u4, 1, 15);
            job.choice.token = random.int(u32);
            job.remote = .{ 203, 0, 113, random.intRangeAtMost(u8, 1, 220) };
            job.remote_port = 3478;
            // The client's socket is free locally, but its port number is already occupied on WAN.
            var occupied = net.used[2].iterator(.{ .direction = .reverse });
            while (occupied.next()) |port| {
                job.source_port = @intCast(port);
                if (!nat.inside.contains(job.insideKey())) break;
            } else return error.NoStunClientSocket;
            job.public_port = net.reservePort(.udp, job.source_port);
            if (job.public_port == job.source_port) return error.ExpectedUdpPortCollision;
            job.payload[0..20].* = bindingRequest(self.transaction);
            job.len = 20;
        }
        const leases = &Router.State.dhcp_table;
        const lease = leases.table.get(leases.lookupByIp(job.host()) orelse return error.MissingLanLease);
        if (lease.state != .bound or !std.meta.eql(lease.mac, job.mac()) or
            !std.meta.eql(lease.deadline, net.clients[job.choice.host].lease_deadline)) return error.WrongLeaseState;
        const elapsed = self.first_sent.durationTo(now).toMilliseconds();
        var scratch = std.heap.FixedBufferAllocator.init(&peer.scratch);
        const alloc = scratch.allocator();
        if (!response) {
            if (!initial) {
                if (elapsed != 500) return error.WrongStunRetryTimer;
                job.choice.token +%= 1;
            }
            _ = try peer.send(alloc, job, false);
            const sent = try peer.observation.take(0, .wan);
            const reply = success(sent[50..62].*, sent[26..30].*, std.mem.readInt(u16, sent[34..36], .big));
            // The server answers the first request, but that response is lost before reaching WAN RX.
            if (initial) self.cached_reply = reply else if (!std.mem.eql(u8, &self.cached_reply, &reply)) return error.ChangedStunTransaction;
            self.deadline = now.addDuration(.fromSeconds(300));
        } else {
            if (elapsed < 515 or elapsed > 590) return error.WrongStunResponseTime;
            const expected = success(self.transaction, Sim.wan, job.public_port);
            try peer.inject(try Sim.packetWithPayload(alloc, job.*, true, false, 64, &self.cached_reply));
            try peer.count(1);
            _ = try peer.expect(0, .lan, try Sim.packetWithPayload(alloc, job.*, true, true, 63, &expected));
        }
        try job.checkUdpMapping(self.generation, self.deadline, &.{.{ .ip = job.remote, .port = 3478 }});
        const added = @intFromBool(initial);
        if (nat.inside.count() != count + added or nat.outside.count() != count + added or
            nat.next_generation != next + added) return error.WrongStunMapping;
    }
};

test "STUN Binding Success echoes the transaction and XORs the public IPv4 socket" {
    const transaction = "twelve-bytes".*;
    const msg = success(transaction, .{ 198, 51, 100, 2 }, 41641);
    const expected = "\x01\x01\x00\x0c\x21\x12\xa4\x42" ++ "twelve-bytes" ++ "\x00\x20\x00\x08\x00\x01\x83\xbb\xe7\x21\xc0\x40";
    try std.testing.expectEqualSlices(u8, expected, &msg);
}

fn checkMapping(self: *const Discovery) !void {
    const nat = &Router.State.nat_table;
    const inside = self.socket.insideKey();
    const outside: Nat.Key = .{ .protocol = .udp, .ip = Sim.wan, .port = self.socket.public_port };
    const entry = nat.inside.get(inside) orelse return error.MissingNatState;
    if (nat.inside.count() != self.mapping_count or nat.outside.count() != self.mapping_count or
        nat.next_generation != self.generation + 1 or entry.generation != self.generation or !std.meta.eql(entry.deadline, self.deadline) or
        !std.meta.eql(entry.outside, outside) or !std.meta.eql(nat.outside.get(outside), @as(?Nat.Key, inside)) or
        !nat.udp_ports.used.isSet(outside.port)) return error.WrongStunMapping;
}
