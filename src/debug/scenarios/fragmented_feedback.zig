const std = @import("std");
const Router = @import("router");
const Sim = @import("../network_sim.zig");
const PathMtu = @import("path_mtu.zig");

flow: PathMtu,

pub const Steps = enum { datagram, error_tail, error_head, retry, response };
const Piece = enum { head, tail, whole };

pub fn step(turn: *Sim.ConversationTurn) !void {
    const peer = turn.peer;
    const self = &peer.network.episodes.fragmented_feedback;
    const phase: Steps = @enumFromInt(turn.phase);
    switch (phase) {
        .datagram => return self.flow.advance(turn, .initial_datagram),
        .retry => return self.flow.advance(turn, .retry),
        .response => return self.flow.advance(turn, .response),
        .error_tail, .error_head => if (peer.iface != .wan) return,
    }
    var scratch = std.heap.FixedBufferAllocator.init(&peer.scratch);
    const alloc = scratch.allocator();
    const id = self.flow.id +% 1;
    // On a return path with a 320- or 508-byte MTU, a 576-byte error arrives in two pieces.
    const split: usize = if (id & 1 == 0) 296 else 488;
    const reported = try self.flow.feedback(alloc, false);
    if (phase == .error_tail) {
        try peer.inject(try piece(alloc, reported, split, .tail, id));
        try peer.count(0);
    } else {
        const restored = try self.flow.feedback(alloc, true);
        const whole = try piece(alloc, restored, split, .whole, id);
        const head = try piece(alloc, reported, split, .head, id);
        peer.inject(head) catch |err| {
            // Retain the expected client-visible message even when dispatch itself fails.
            if (peer.expected) |out| out[@intFromEnum(Router.Nic.Api.IFace.lan)].frame(peer.network.mock.io, whole);
            try self.flow.checkMapping();
            return err;
        };

        // Either egress representation must deliver the complete translated feedback.
        const n: usize = if (peer.observation.count == 2) 2 else 1;
        try peer.count(n);
        var output_id = id;
        var tail_first = false;
        if (peer.observation.count != 0) {
            const first = try peer.observation.take(0, .lan);
            if (first.len < 22) return error.ShortFeedbackHeader;
            output_id = std.mem.readInt(u16, first[18..20], .big);
            tail_first = std.mem.readInt(u16, first[20..22], .big) & 0x1fff != 0;
        }
        for (0..n) |i| {
            const part: Piece = if (n == 1) .whole else if ((i == 0) == tail_first) .tail else .head;
            const actual = try peer.expect(i, .lan, try piece(alloc, restored, split, part, output_id));
            if (part != .tail) self.flow.mtu = std.mem.readInt(u16, actual[40..42], .big);
        }
        if (peer.network.mock.outstanding.load(.monotonic) != 0) return error.RetainedFeedbackBuffer;
    }
    try self.flow.checkMapping();
}

fn piece(alloc: std.mem.Allocator, frame: []const u8, split: usize, part: Piece, id: u16) ![]u8 {
    const msg = frame[34..];
    return Sim.wire(alloc, frame[6..12].*, frame[0..6].*, .{
        .src = frame[26..30].*,
        .dst = frame[30..34].*,
        .ttl = frame[22],
        .protocol = 1,
        .identification = id,
        .more_fragments = part == .head,
        .fragment_offset = if (part == .tail) @intCast(split / 8) else 0,
        .payload = switch (part) {
            .head => msg[0..split],
            .tail => msg[split..],
            .whole => msg,
        },
    });
}
