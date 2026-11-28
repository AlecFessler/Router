const std = @import("std");
const Router = @import("router");
const Sim = @import("../network_sim.zig");
const State = Router.State;
const Packets = Router.TestFixtures.Synthetic.Packets;
const Nat = Router.Tables.NatTable.NatTable;
const IPv4 = Router.Protocols.IPv4.IPv4;
const Mac = Router.Protocols.Ethernet.Mac;

host: IPv4,
mac: Mac,
remote: IPv4,
port: u16,
public_port: u16,
id: u16,
payload: [original_len - 28]u8 = undefined,
quote: [quote_len]u8 = undefined,
mtu: u16 = 0,
response: [32]u8 = undefined,
generation: u64,
deadline: std.Io.Timestamp = .zero,

const PathMtu = @This();

pub const Steps = enum { initial_datagram, fragmentation_needed, retry, response };

const original_len = 1472;
const advertised_mtu = 1464;
const quote_len = 548;

pub fn step(turn: *Sim.ConversationTurn) !void {
    try turn.peer.network.episodes.path_mtu.advance(turn, @enumFromInt(turn.phase));
}

pub fn advance(self: *PathMtu, turn: *Sim.ConversationTurn, phase: Steps) !void {
    const from_lan = phase == .initial_datagram or phase == .retry;
    const peer = turn.peer;
    if (from_lan != (peer.iface == .lan)) return;
    var scratch = std.heap.FixedBufferAllocator.init(&peer.scratch);
    const alloc = scratch.allocator();
    switch (phase) {
        .initial_datagram, .retry => {
            if (phase == .initial_datagram) {
                var prng = std.Random.DefaultPrng.init(peer.network.seed +% turn.index);
                const random = prng.random();
                const host = random.intRangeAtMost(u8, 2, 17);
                // Use an ephemeral source port already occupied on WAN by another socket.
                const cursor = peer.network.next[2];
                const port: u16 = if (cursor == 1024) 65535 else cursor - 1;
                const public_port = peer.network.reservePort(.udp, port);
                if (public_port == port) return error.ExpectedUdpPortCollision;
                self.* = .{
                    .host = .{ 192, 168, 86, host },
                    .mac = .{ 2, 1, 0, 0, 0, host },
                    .remote = .{ 203, 0, 113, random.intRangeAtMost(u8, 32, 200) },
                    .port = port,
                    .public_port = public_port,
                    .id = random.int(u16),
                    .generation = peer.network.newConversationBinding(),
                };
                random.bytes(&self.payload);
            }
            const data = if (phase == .retry) self.payload[0 .. self.mtu - 28] else &self.payload;
            const id = if (phase == .retry) self.id +% 1 else self.id;
            try peer.inject(try self.datagram(alloc, false, false, id, 64, data));
            try peer.count(1);
            const actual = try peer.expect(0, .wan, try self.datagram(alloc, true, false, id, 63, data));
            if (phase == .initial_datagram) {
                self.quote = actual[14..][0..quote_len].*;
            } else {
                self.response = actual[actual.len - self.response.len ..][0..32].*;
            }
            self.deadline = std.Io.Timestamp.now(peer.network.io, .boot).addDuration(.fromSeconds(300));
        },
        .fragmentation_needed => {
            try peer.inject(try self.feedback(alloc, false));
            try peer.count(1);
            const actual = try peer.expect(0, .lan, try self.feedback(alloc, true));
            self.mtu = std.mem.readInt(u16, actual[40..42], .big);
        },
        .response => {
            try peer.inject(try self.datagram(alloc, true, true, self.id +% 2, 55, &self.response));
            try peer.count(1);
            _ = try peer.expect(0, .lan, try self.datagram(alloc, false, true, self.id +% 2, 54, &self.response));
        },
    }
    try self.checkMapping();
}

pub fn checkMapping(self: *const PathMtu) !void {
    const table = &State.nat_table;
    const inside: Nat.Key = .{ .protocol = .udp, .ip = self.host, .port = self.port };
    const outside: Nat.Key = .{ .protocol = .udp, .ip = Sim.wan, .port = self.public_port };
    const e = table.inside.get(inside) orelse return error.MissingNatState;
    if (!std.meta.eql(e.outside, outside) or !std.meta.eql(table.outside.get(outside), @as(?Nat.Key, inside)) or
        !table.udp_ports.used.isSet(self.public_port) or table.next_generation != self.generation + 1 or
        e.generation != self.generation or !std.meta.eql(e.deadline, self.deadline) or e.peer_count != 1 or
        !std.meta.eql(e.peers[0], Nat.Peer{ .ip = self.remote, .port = 443 })) return error.WrongPathMtuMapping;
}

fn datagram(self: *const PathMtu, alloc: std.mem.Allocator, outside: bool, reply: bool, id: u16, ttl: u8, data: []const u8) ![]u8 {
    const client = if (outside) Sim.wan else self.host;
    const port = if (outside) self.public_port else self.port;
    const src = if (reply) self.remote else client;
    const dst = if (reply) client else self.remote;
    const near = if (outside) Sim.wan_mac else self.mac;
    const far = if (outside) Sim.gateway_mac else Sim.lan_mac;
    return Sim.wire(alloc, if (reply) far else near, if (reply) near else far, .{
        .src = src,
        .dst = dst,
        .ttl = ttl,
        .identification = id,
        .dont_fragment = true,
        .payload = try Packets.udp(alloc, src, dst, .{
            .src_port = if (reply) 443 else port,
            .dst_port = if (reply) port else 443,
            .payload = data,
        }),
    });
}

pub fn feedback(self: *const PathMtu, alloc: std.mem.Allocator, translated: bool) ![]u8 {
    var body: [4 + quote_len]u8 = undefined;
    body[0..2].* = .{ 0, 0 };
    std.mem.writeInt(u16, body[2..4], advertised_mtu, .big);
    // The partial quote retains the original full datagram's lengths and UDP checksum.
    const quote = if (translated) (try self.datagram(alloc, false, false, self.id, 63, &self.payload))[14..][0..quote_len] else &self.quote;
    @memcpy(body[4..], quote);
    return Sim.wire(alloc, if (translated) Sim.lan_mac else Sim.gateway_mac, if (translated) self.mac else Sim.wan_mac, .{
        .src = Sim.gateway,
        .dst = if (translated) self.host else Sim.wan,
        .protocol = 1,
        .ttl = if (translated) 54 else 55,
        .payload = try Packets.icmp(alloc, .{ .message_type = 3, .code = 4, .body = &body }),
    });
}
