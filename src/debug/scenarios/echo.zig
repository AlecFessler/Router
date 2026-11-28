const std = @import("std");
const Router = @import("router");
const Sim = @import("../network_sim.zig");
const Packets = Router.TestFixtures.Synthetic.Packets;
const State = Router.State;
const chunk = 1480;

pub const Steps = enum { first_head, second_tail, first_completion, second_completion };

pub fn step(turn: *Sim.ConversationTurn) !void {
    const peer = turn.peer;
    if (peer.iface != .lan) return;
    const phase: Steps = @enumFromInt(turn.phase);
    var prng = std.Random.DefaultPrng.init(peer.network.seed +% turn.index);
    const random = prng.random();
    const id = random.int(u16);
    const identifier = random.int(u16);
    const first = random.int(u1);
    var clients = [2]Sim.Job{ peer.network.cold, peer.network.cold };
    clients[0].choice.host = random.int(u4);
    clients[1].choice.host = clients[0].choice.host +% random.intRangeAtMost(u4, 1, 15);
    const lengths = [2]usize{ random.intRangeAtMost(usize, 1600, 1900), random.intRangeAtMost(usize, 2000, 2300) };
    var data: [2][2300]u8 = undefined;
    for (&data) |*bytes| random.bytes(bytes);
    const sender: u1 = switch (phase) {
        .first_head => 0,
        .second_tail => 1,
        .first_completion => first,
        .second_completion => 1 - first,
    };
    const complete = phase == .first_completion or phase == .second_completion;
    const head = if (sender == 0) !complete else complete;
    var scratch = std.heap.FixedBufferAllocator.init(&peer.scratch);
    const alloc = scratch.allocator();
    const data_sent = data[sender][0..lengths[sender]];
    const request = try Packets.echo(alloc, .{ .identifier = identifier, .data = data_sent });
    const nat_generation = State.nat_table.next_generation;
    try peer.inject(try frame(alloc, clients[sender], id, request, head, false));
    if (complete) {
        const reply = try Packets.echo(alloc, .{ .message_type = 0, .identifier = identifier, .data = data_sent });
        try peer.count(2);
        _ = try peer.expect(0, .lan, try frame(alloc, clients[sender], id, reply, true, true));
        _ = try peer.expect(1, .lan, try frame(alloc, clients[sender], id, reply, false, true));
    } else try peer.count(0);

    const entries = State.reassembly_tables[@intFromEnum(peer.iface)].entries;
    const now = std.Io.Timestamp.now(peer.network.io, .boot);
    var expected_count: usize = 0;
    for (clients, lengths, 0..) |client, length, i| {
        if (turn.phase < i or phase == .second_completion or (phase == .first_completion and first == i)) continue;
        expected_count += 1;
        // Only the source IPv4 address differs between these two reassembly keys.
        const key: Router.Tables.IPv4FragmentTable.IPv4FragmentTable.Key = .{ .src = client.host(), .dst = Sim.lan, .protocol = .icmp, .identification = id };
        const entry = for (entries) |*candidate| {
            if (candidate.deadline.toNanoseconds() != 0 and std.meta.eql(candidate.key, key)) break candidate;
        } else return error.MissingPendingEcho;
        const final: ?usize = if (i == 0) null else length + 8;
        const received = if (i == 0) chunk else length + 8 - chunk;
        const remaining: i64 = 60_000 - @as(i64, @intCast(turn.phase - i));
        if (entry.received != received or entry.final_len != final or entry.highest_end != (final orelse chunk) or
            entry.ip_header_len != @as(usize, if (i == 0) 20 else 0) or
            !std.meta.eql(entry.deadline, now.addDuration(.fromMilliseconds(remaining)))) return error.WrongReassemblyState;
    }
    var actual_count: usize = 0;
    for (entries) |*entry| actual_count += @intFromBool(entry.deadline.toNanoseconds() != 0);
    if (actual_count != expected_count or State.nat_table.next_generation != nat_generation or
        peer.network.mock.outstanding.load(.monotonic) != 0) return error.WrongReassemblyState;
}

fn frame(alloc: std.mem.Allocator, client: Sim.Job, id: u16, msg: []const u8, head: bool, reply: bool) ![]u8 {
    return Sim.wire(alloc, if (reply) Sim.lan_mac else client.mac(), if (reply) client.mac() else Sim.lan_mac, .{
        .src = if (reply) Sim.lan else client.host(),
        .dst = if (reply) client.host() else Sim.lan,
        .protocol = 1,
        .identification = id,
        .more_fragments = head,
        .fragment_offset = if (head) 0 else chunk / 8,
        .payload = if (head) msg[0..chunk] else msg[chunk..],
    });
}
