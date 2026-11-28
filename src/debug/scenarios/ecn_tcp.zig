const std = @import("std");
const Router = @import("router");
const Sim = @import("../network_sim.zig");
const Tcp = @import("tcp.zig").TcpConnection;

connection: Tcp,
upload: [2400]u8 = undefined,
received: [2400]u8 = undefined,
length: usize,
upload_split: usize,
download_split: usize,
ack_expected: u32 = undefined,
echo_due: bool = false,
cwr_due: bool = false,

pub const Steps = enum {
    connect,
    accept,
    request,
    marked_upload,
    echo_upload,
    finish_upload,
    response,
    marked_download,
    echo_download,
    finish_download,
    acknowledge,
    server_close,
    client_close,
    final_ack,
};

pub fn step(turn: *Sim.ConversationTurn) !void {
    const phase: Steps = @enumFromInt(turn.phase);
    const peer = turn.peer;
    const from_lan = switch (phase) {
        .connect, .request, .marked_upload, .finish_upload, .echo_download, .acknowledge, .client_close => true,
        else => false,
    };
    if (from_lan != (peer.iface == .lan)) return;
    const egress: Router.Nic.Api.IFace = if (from_lan) .wan else .lan;
    const self = &peer.network.episodes.ecn_tcp;
    const c = &self.connection;
    switch (phase) {
        .connect => {
            var prng = std.Random.DefaultPrng.init(peer.network.seed +% turn.index);
            const random = prng.random();
            const length = random.intRangeAtMost(usize, 900, self.upload.len);
            const min = @max(256, length -| 1428);
            const max = @min(1428, length - 256);
            self.* = .{
                .connection = Tcp.open(peer, random, random.int(u4), .{ 203, 0, 113, 88 }, @intCast(43400 + turn.index)),
                .length = length,
                .upload_split = random.intRangeAtMost(usize, min, max),
                .download_split = random.intRangeAtMost(usize, min, max),
            };
            random.bytes(self.upload[0..length]);
            try c.segment(peer, .{ .syn = true, .ack = false, .ece = true, .cwr = true }, null);
        },
        .accept => try c.segment(peer, .{ .syn = true, .ece = true }, null),
        .request, .response => {
            // Negotiation, pure ACKs, and the final close use Not-ECT. Original data uses ECT(0).
            try c.segment(peer, .{}, null);
            if (phase == .response) try self.checkAck(try peer.observation.take(0, egress));
            var buf: [160]u8 = undefined;
            const message = if (from_lan)
                try std.fmt.bufPrint(&buf, "POST /echo HTTP/1.1\r\nHost: example.net\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n", .{self.length})
            else
                try std.fmt.bufPrint(&buf, "HTTP/1.1 200 OK\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n", .{self.length});
            try c.exchange(peer, .{ .psh = true, .payload = message }, null, .{ .ecn = 2 });
        },
        .marked_upload, .marked_download, .finish_upload, .finish_download => {
            const marked = phase == .marked_upload or phase == .marked_download;
            const split = if (from_lan) self.upload_split else self.download_split;
            const start = if (marked) 0 else split;
            const end = if (marked) split else self.length;
            if (!marked and !self.cwr_due) return error.MissingEcnEcho;
            const data = if (from_lan) self.upload[start..end] else self.received[start..end];
            // CE is already on the ingress frame. CWR belongs on the sender's first new segment after ECE.
            try c.exchange(peer, .{ .psh = true, .cwr = self.cwr_due, .payload = data }, null, .{ .ecn = if (marked) 3 else 2 });
            const tx = try peer.observation.take(0, egress);
            const payload = tx[34 + @as(usize, tx[46] >> 4) * 4 ..];
            if (!std.mem.eql(u8, payload, self.upload[start..end])) return error.WrongEcnPayload;
            if (from_lan) @memcpy(self.received[start..end], payload);
            self.ack_expected = std.mem.readInt(u32, tx[38..42], .big) +% @as(u32, @intCast(payload.len));
            if (tx[15] & 3 == 3) self.echo_due = true;
            if (tx[47] & 0x80 != 0) {
                self.echo_due = false;
                self.cwr_due = false;
            }
        },
        .echo_upload, .echo_download, .acknowledge => {
            if (self.echo_due != (phase != .acknowledge)) return error.WrongEcnFeedback;
            try c.segment(peer, .{ .ece = self.echo_due }, null);
            const ack = try peer.observation.take(0, egress);
            try self.checkAck(ack);
            self.cwr_due = ack[47] & 0x40 != 0;
        },
        .server_close, .client_close => try c.segment(peer, .{ .fin = true }, null),
        .final_ack => try c.segment(peer, .{}, null),
    }
}

fn checkAck(self: *const @This(), frame: []const u8) !void {
    if (std.mem.readInt(u32, frame[42..46], .big) != self.ack_expected or
        frame[15] & 3 != 0 or frame[47] != (@as(u8, if (self.echo_due) 0x40 else 0) | 0x10)) return error.WrongEcnAck;
}
