const std = @import("std");
const Router = @import("router");
const Sim = @import("../network_sim.zig");
const Tcp = @import("tcp.zig").TcpConnection;
const Upload = @This();

connection: Tcp,
body: [4096]u8 = undefined,
length: usize,
received: usize = 0,
received_crc: std.hash.Crc32 = .init(),
fin_with_data: bool,
early_response_ack: bool,
client_fin_end: u32 = undefined,
server_fin_end: u32 = undefined,
mapping_count: usize,

pub const Steps = enum { connect, accept, start_upload, ack_prefix, finish_upload, ack_eof, respond, read_response, server_close, final_ack };

pub fn step(turn: *Sim.ConversationTurn) !void {
    const phase: Steps = @enumFromInt(turn.phase);
    const peer = turn.peer;
    const from_lan = switch (phase) {
        .connect, .start_upload, .finish_upload, .read_response, .final_ack => true,
        .accept, .ack_prefix, .ack_eof, .respond, .server_close => false,
    };
    if (from_lan != (peer.iface == .lan)) return;
    const network = peer.network;
    const self = &network.episodes.half_closed_upload;
    const nat = &Router.State.nat_table;
    var prng = std.Random.DefaultPrng.init((network.seed +% turn.index) ^ (@as(u64, turn.phase) << 48));
    const random = prng.random();
    const c = &self.connection;
    switch (phase) {
        .connect => {
            self.* = .{
                .connection = Tcp.open(peer, random, random.int(u4), .{ 203, 0, 113, 92 }, @intCast(42000 + turn.index)),
                .length = random.intRangeAtMost(usize, 1500, self.body.len),
                .fin_with_data = random.boolean(),
                .early_response_ack = random.boolean(),
                .mapping_count = nat.inside.count() + 1,
            };
            random.bytes(self.body[0..self.length]);
            try c.segment(peer, .{ .syn = true, .ack = false }, null);
        },
        .accept => try c.segment(peer, .{ .syn = true }, null),
        .start_upload => {
            try c.segment(peer, .{}, null);
            var header: [160]u8 = undefined;
            const http = try std.fmt.bufPrint(&header, "POST /checksum HTTP/1.1\r\nHost: example.net\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n", .{self.length});
            try c.segment(peer, .{ .psh = true, .payload = http }, null);
            try self.sendData(peer, random.intRangeAtMost(usize, 250, 1200), false);
        },
        .ack_prefix => try c.segment(peer, .{}, null),
        .finish_upload => {
            while (self.received < self.length) {
                const end = @min(self.length, self.received + random.intRangeAtMost(usize, 400, 1448));
                try self.sendData(peer, end, end == self.length and self.fin_with_data);
            }
            if (!self.fin_with_data) try c.segment(peer, .{ .fin = true }, null);
            self.client_fin_end = try finEnd(try peer.observation.take(0, .wan));
        },
        .ack_eof => {
            try c.segment(peer, .{}, null);
            const ack = try peer.observation.take(0, .lan);
            if (std.mem.readInt(u32, ack[42..46], .big) != self.client_fin_end) return error.WrongUploadFinAck;
        },
        .respond => {
            var response: [128]u8 = undefined;
            const http = try std.fmt.bufPrint(&response, "HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\n{x:0>8}\n", .{self.received_crc.final()});
            try c.segment(peer, .{ .psh = true, .payload = http }, null);
            const tx = try peer.observation.take(0, .lan);
            const checksum = try std.fmt.parseInt(u32, tx[tx.len - 9 .. tx.len - 1], 16);
            if (checksum != std.hash.Crc32.hash(self.body[0..self.length]) or
                std.mem.readInt(u32, tx[42..46], .big) != self.client_fin_end) return error.WrongUploadResponse;
        },
        .read_response => if (self.early_response_ack) try c.segment(peer, .{}, null),
        .server_close => {
            try c.segment(peer, .{ .fin = true }, null);
            self.server_fin_end = try finEnd(try peer.observation.take(0, .lan));
        },
        .final_ack => {
            try c.segment(peer, .{}, null);
            const ack = try peer.observation.take(0, .wan);
            if (std.mem.readInt(u32, ack[38..42], .big) != self.client_fin_end or
                std.mem.readInt(u32, ack[42..46], .big) != self.server_fin_end) return error.WrongUploadFinAck;
        },
    }
    if (nat.inside.count() != self.mapping_count or nat.outside.count() != self.mapping_count or
        nat.next_generation != c.generation + 1) return error.WrongUploadMapping;
}

fn sendData(self: *Upload, peer: *Sim.Peer, end: usize, fin: bool) !void {
    try self.connection.segment(peer, .{ .psh = true, .fin = fin, .payload = self.body[self.received..end] }, null);
    const tx = try peer.observation.take(0, .wan);
    const payload = tx[34 + @as(usize, tx[46] >> 4) * 4 ..];
    self.received_crc.update(payload);
    self.received += payload.len;
    if (self.received != end) return error.WrongUploadLength;
}

fn finEnd(frame: []const u8) !u32 {
    if (frame[47] & 1 == 0) return error.MissingUploadFin;
    const payload_len = frame.len - 34 - @as(usize, frame[46] >> 4) * 4;
    return std.mem.readInt(u32, frame[38..42], .big) +% @as(u32, @intCast(payload_len)) +% 1;
}
