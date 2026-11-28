const std = @import("std");
const Router = @import("router");
const Sim = @import("../network_sim.zig");
const Tcp = @import("tcp.zig").TcpConnection;
const Lifecycle = Sim.Scenarios.Lifecycle;
const Persist = @This();

tcp: Tcp,
response: [3200]u8,
length: usize,
received: usize,
first_seq: u32,
first_window: u16,
closed_at: u64,
mapping_count: usize,

const open_window = 4096;

pub fn step(self: *Persist, peer: *Sim.Peer, phase: Lifecycle) !void {
    const from_server = switch (phase) {
        .persist_syn_ack, .persist_fill, .persist_probe, .persist_retry, .persist_resume => true,
        else => false,
    };
    if (from_server != (peer.iface == .wan)) return;
    const tcp = &self.tcp;
    const nat = &Router.State.nat_table;
    const now = Router.Nic.Simulation.phase;
    switch (phase) {
        .persist_syn => {
            var prng = std.Random.DefaultPrng.init(peer.network.seed);
            const random = prng.random();
            // Client 0 has already declined its lease by the time this download begins.
            tcp.* = Tcp.open(peer, random, random.intRangeAtMost(u4, 1, 15), .{ 203, 0, 113, 239 }, 47919);
            self.mapping_count = nat.inside.count() + 1;
            self.first_window = random.intRangeAtMost(u16, 1024, 1388);
            self.received = 0;
            const size = random.intRangeAtMost(usize, 2400, 3100);
            const header = try std.fmt.bufPrint(&self.response, "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {d}\r\n\r\n", .{size});
            self.length = header.len + size;
            random.bytes(self.response[header.len..self.length]);
            try tcp.exchange(peer, .{ .syn = true, .ack = false }, null, .{ .window = self.first_window });
        },
        .persist_syn_ack => {
            try tcp.segment(peer, .{ .syn = true }, null);
            self.first_seq = tcp.server_next;
        },
        .persist_request => try tcp.exchange(peer, .{ .psh = true, .payload = "GET /firmware.bin HTTP/1.1\r\nHost: example.net\r\n\r\n" }, null, .{ .window = self.first_window }),
        .persist_fill => try self.send(peer, self.first_window, true),
        .persist_probe, .persist_retry => {
            const first = phase == .persist_probe;
            if (now - self.closed_at != @as(u64, if (first) 1000 else 3000) or self.received != self.first_window) return error.WrongPersistProbe;
            // The first octet is outside the closed window. Only its retry can enter the stream.
            try self.send(peer, 1, !first);
        },
        .persist_resume => while (self.received < self.length) {
            try self.send(peer, @min(1388, self.length - self.received), true);
        },
        .persist_zero, .persist_zero_ack, .persist_lost_update, .persist_open_ack, .persist_done => {
            const window: u16 = switch (phase) {
                .persist_zero, .persist_zero_ack => 0,
                .persist_lost_update => open_window,
                .persist_open_ack, .persist_done => @intCast(open_window - (self.received - self.first_window)),
                else => unreachable,
            };
            if (phase == .persist_zero) self.closed_at = now;
            try tcp.exchange(peer, .{}, null, .{ .window = window, .accepted_by_peer = phase != .persist_lost_update });
            const ack = try peer.observation.take(0, .wan);
            if (std.mem.readInt(u32, ack[42..46], .big) != self.first_seq +% @as(u32, @intCast(self.received)) or
                std.mem.readInt(u16, ack[48..50], .big) != window) return error.WrongPersistAck;
            if (phase == .persist_done and self.received != self.length) return error.IncompleteDownload;
        },
        else => unreachable,
    }
    if (nat.inside.count() != self.mapping_count or nat.outside.count() != self.mapping_count or
        nat.next_generation != tcp.generation + 1) return error.WrongPersistMapping;
}

fn send(self: *Persist, peer: *Sim.Peer, length: usize, accepted: bool) !void {
    const payload = self.response[self.received..][0..length];
    const seq = self.first_seq +% @as(u32, @intCast(self.received));
    try self.tcp.exchange(peer, .{ .payload = payload }, if (accepted) null else seq, .{ .accepted_by_peer = accepted });
    const frame = try peer.observation.take(0, .lan);
    const data = frame[34 + @as(usize, frame[46] >> 4) * 4 ..];
    if (std.mem.readInt(u32, frame[38..42], .big) != seq or !std.mem.eql(u8, data, payload)) return error.WrongPersistData;
    if (accepted) self.received += data.len;
}
