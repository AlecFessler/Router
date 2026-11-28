const std = @import("std");
const Router = @import("router");
const Sim = @import("../network_sim.zig");
const Tcp = @import("tcp.zig").TcpConnection;
const Lifecycle = Sim.Scenarios.Lifecycle;

connection: Tcp,
previous_mappings: usize,
timer_started: u64,
token: [8]u8,
received: [8]u8,
http_client_end: u32,
http_server_end: u32,

pub fn open(self: *@This(), peer: *Sim.Peer, phase: Lifecycle) !void {
    const from_server = phase == .opening_syn_ack or phase == .opening_retry_syn_ack or phase == .opening_response;
    if (from_server != (peer.iface == .wan)) return;
    const network = peer.network;
    const nat = &Router.State.nat_table;
    const tcp = &self.connection;
    const now = Router.Nic.Simulation.phase;
    if (phase == .opening_syn) {
        var prng = std.Random.DefaultPrng.init(network.seed);
        const random = prng.random();
        const cursor = network.next[1];
        const port: u16 = if (cursor == 1024) 65535 else cursor - 1;
        // Client 0 declines its lease while this HTTP connection is idle.
        const client = random.intRangeAtMost(u4, 1, 15);
        tcp.* = Tcp.open(peer, random, client, .{ 203, 0, 113, 232 }, port);
        if (tcp.public_port == port) return error.ExpectedTcpPortCollision;
        self.previous_mappings = nat.inside.count();
        var nonce: [4]u8 = undefined;
        random.bytes(&nonce);
        self.token = std.fmt.bytesToHex(nonce, .lower);
    }
    const retry = phase == .opening_retry_syn or phase == .opening_retry_syn_ack;
    if (retry and now - self.timer_started != 1000) return error.WrongHandshakeTimer;
    switch (phase) {
        .opening_syn, .opening_retry_syn => {
            const lost = phase == .opening_syn;
            if (lost) self.timer_started = now;
            try tcp.exchange(peer, .{ .syn = true, .ack = false, .options = &.{ 1, 3, 3, 7 } }, if (retry) tcp.client_next -% 1 else null, .{ .accepted_by_peer = !lost });
        },
        .opening_syn_ack, .opening_retry_syn_ack => {
            if (!retry) self.timer_started = now;
            try tcp.segment(peer, .{ .syn = true, .options = &.{ 1, 3, 3, 8 } }, if (retry) tcp.server_next -% 1 else null);
        },
        // The client preconnects. Its pure ACK is lost beyond WAN before it has a request to send.
        .opening_lost_ack => try tcp.exchange(peer, .{}, null, .{ .accepted_by_peer = false }),
        .opening_ack => try tcp.segment(peer, .{}, null),
        .opening_request => {
            var buf: [96]u8 = undefined;
            const path = "GET /echo/";
            const request = try std.fmt.bufPrint(&buf, path ++ "{s} HTTP/1.1\r\nHost: example.net\r\n\r\n", .{self.token});
            try tcp.segment(peer, .{ .psh = true, .payload = request }, null);
            const wire = try peer.observation.take(0, .wan);
            self.received = wire[wire.len - request.len + path.len ..][0..8].*;
        },
        .opening_response => {
            const header = "HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\n";
            try tcp.segment(peer, .{ .psh = true, .payload = &(header.* ++ self.received) }, null);
            const wire = try peer.observation.take(0, .lan);
            if (!std.mem.endsWith(u8, wire, &(header.* ++ self.token))) return error.WrongHandshakeResponse;
        },
        .opening_response_ack => {
            try tcp.segment(peer, .{}, null);
            self.http_client_end = tcp.client_next;
            self.http_server_end = tcp.server_next;
        },
        else => unreachable,
    }
    if (nat.inside.count() != self.previous_mappings + 1 or nat.outside.count() != self.previous_mappings + 1 or
        nat.next_generation != tcp.generation + 1) return error.WrongHandshakeMappingCount;
}

pub fn close(self: *@This(), peer: *Sim.Peer, phase: Lifecycle) !void {
    const from_server = phase == .closing_server_fin or phase == .closing_lost_ack or phase == .closing_ack;
    if (from_server != (peer.iface == .wan)) return;
    const nat = &Router.State.nat_table;
    const count = nat.inside.count();
    const generation = nat.next_generation;
    const retry = phase == .closing_retry_fin;
    const fin = phase == .closing_server_fin or phase == .closing_client_fin or retry;
    const now = Router.Nic.Simulation.phase;
    if (phase == .closing_client_fin) self.timer_started = now;
    if (retry and now - self.timer_started != 1000) return error.WrongFinRetryTimer;

    // The server closes the idle HTTP connection. Its final ACK is lost after LAN egress.
    try self.connection.exchange(peer, .{ .fin = fin }, if (retry) self.http_client_end else null, .{ .accepted_by_peer = phase != .closing_lost_ack });
    const wire = try peer.observation.take(0, if (from_server) .lan else .wan);
    const server_seq = self.http_server_end +% @intFromBool(phase != .closing_server_fin);
    const client_seq = self.http_client_end +% @intFromBool(phase == .closing_lost_ack or phase == .closing_ack);
    if (std.mem.readInt(u32, wire[38..42], .big) != (if (from_server) server_seq else client_seq) or
        std.mem.readInt(u32, wire[42..46], .big) != (if (from_server) client_seq else server_seq) or
        wire.len != 34 + @as(usize, wire[46] >> 4) * 4) return error.WrongFinRetrySequence;
    if (nat.inside.count() != count or nat.outside.count() != count or nat.next_generation != generation) return error.WrongFinRetryMapping;
}
