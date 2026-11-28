const std = @import("std");
const Router = @import("router");
const Sim = @import("../network_sim.zig");
const Scenarios = Sim.Scenarios;
const Peer = Sim.Peer;
const ConversationTurn = Sim.ConversationTurn;
const Packets = Router.TestFixtures.Synthetic.Packets;
const IFace = Router.Nic.Api.IFace;
const Nat = Router.Tables.NatTable.NatTable;
const IPv4 = Router.Protocols.IPv4.IPv4;
const Mac = Router.Protocols.Ethernet.Mac;
const State = Router.State;
const wan = Sim.wan;
const wan_mac = Sim.wan_mac;
const lan_mac = Sim.lan_mac;
const gateway_mac = Sim.gateway_mac;
const wire = Sim.wire;

pub const DuplexTransfer = struct {
    pub const Steps = enum { syn, syn_ack, requests, streaming, ack_prefix, reorder, sack, fill_gap, cumulative_ack, server_close, client_close, final_ack };
    upload: TcpConnection,
    download: TcpConnection,
    segment_len: u16,
    gap: u32 = 0,
    sack_left: u32 = 0,
    sack_middle: u32 = 0,
    sack_right: u32 = 0,

    pub fn step(turn: *ConversationTurn) !void {
        const self = &turn.peer.network.episodes.duplex_tcp;
        const peer = turn.peer;
        const network = peer.network;
        const phase: Steps = @enumFromInt(turn.phase);
        const from_lan = peer.iface == .lan;
        var prng = std.Random.DefaultPrng.init((network.seed +% turn.index) ^ (@as(u64, @intFromEnum(phase)) << 48));
        const random = prng.random();
        switch (phase) {
            .syn => if (from_lan) {
                const first = random.int(u4);
                const port: u16 = @intCast(36000 + turn.index);
                self.segment_len = if (random.boolean()) 1388 else 1448;
                for ([_]*TcpConnection{ &self.upload, &self.download }, 0..) |connection, i| {
                    const id = first +% @as(u4, @intCast(i));
                    const host = 2 + @as(u8, id);
                    connection.* = .{
                        .host = .{ 192, 168, 86, host },
                        .mac = .{ 2, 1, 0, 0, 0, host },
                        .remote = .{ 203, 0, 113, @intCast(70 + i) },
                        .port = port,
                        .public_port = network.reservePort(.tcp, port),
                        // Some transfers cross TCP sequence wrap inside the selectively acknowledged range.
                        .client_next = if (i == 0 and random.boolean()) 0 -% (3 * @as(u32, self.segment_len)) else random.int(u32),
                        .server_next = random.int(u32),
                        .generation = network.newConversationBinding(),
                    };
                    try connection.segment(peer, .{ .syn = true, .ack = false, .options = &.{ 4, 2, 1, 1 } }, null);
                }
            },
            .syn_ack => if (!from_lan) {
                for ([_]*TcpConnection{ &self.upload, &self.download }) |connection| {
                    try connection.segment(peer, .{ .syn = true, .options = &.{ 4, 2, 1, 1 } }, null);
                }
            },
            .requests => if (from_lan) {
                var buf: [128]u8 = undefined;
                const post = try std.fmt.bufPrint(&buf, "POST /upload HTTP/1.1\r\nHost: example.net\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n", .{4 * self.segment_len});
                try self.upload.segment(peer, .{ .psh = true, .payload = post }, null);
                try self.download.segment(peer, .{ .psh = true, .payload = "GET /file HTTP/1.1\r\nHost: example.net\r\nConnection: close\r\n\r\n" }, null);
            },
            .streaming => {
                if (from_lan) {
                    try self.upload.data(peer, random, self.segment_len, null);
                    self.gap = self.upload.client_next;
                } else {
                    try self.download.segment(peer, .{ .psh = true, .payload = "HTTP/1.1 200 OK\r\nContent-Length: 5712\r\nConnection: close\r\n\r\n" }, null);
                    for (0..2) |_| try self.download.data(peer, random, 1428, null);
                }
            },
            .ack_prefix, .cumulative_ack => if (from_lan) {
                try self.download.segment(peer, .{}, null);
            } else {
                try self.upload.segment(peer, .{}, null);
                const ack = try peer.observation.take(0, .lan);
                const end = if (phase == .ack_prefix) self.gap else self.sack_right;
                if (std.mem.readInt(u32, ack[42..46], .big) != end) return error.WrongCumulativeAck;
            },
            .reorder => if (from_lan) {
                var seq = self.gap +% self.segment_len;
                for (0..2) |i| {
                    try self.upload.data(peer, random, self.segment_len, seq);
                    const tx = try peer.observation.take(0, .wan);
                    const start = std.mem.readInt(u32, tx[38..42], .big);
                    const header = @as(usize, tx[46] >> 4) * 4;
                    seq = start +% @as(u32, @intCast(tx.len - 34 - header));
                    if (i == 0) {
                        self.sack_left = start;
                        self.sack_middle = seq;
                    } else self.sack_right = seq;
                }
            } else try self.download.data(peer, random, 1428, null),
            .sack => if (from_lan) {
                try self.download.segment(peer, .{}, null);
            } else {
                for ([_]u32{ self.sack_middle, self.sack_right }) |right| {
                    var opt = [_]u8{ 1, 1, 5, 10 } ++ [_]u8{0} ** 8;
                    std.mem.writeInt(u32, opt[4..8], self.sack_left, .big);
                    std.mem.writeInt(u32, opt[8..12], right, .big);
                    try self.upload.segment(peer, .{ .options = &opt }, null);
                    const ack = try peer.observation.take(0, .lan);
                    if (std.mem.readInt(u32, ack[42..46], .big) != self.gap or !std.mem.eql(u8, ack[54..66], &opt)) return error.WrongSack;
                }
            },
            .fill_gap => if (from_lan) {
                try self.upload.data(peer, random, self.segment_len, null);
                if (self.upload.client_next != self.sack_left) return error.TcpSequenceGap;
                // The receiver can now acknowledge the contiguous bytes it previously SACKed.
                self.upload.client_next = self.sack_right;
            } else try self.download.data(peer, random, 1428, null),
            .server_close => if (!from_lan) {
                try self.upload.segment(peer, .{ .psh = true, .fin = true, .payload = "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n" }, null);
                try self.download.segment(peer, .{ .fin = true }, null);
            },
            .client_close, .final_ack => if ((phase == .client_close) == from_lan) {
                for ([_]*TcpConnection{ &self.upload, &self.download }) |connection| {
                    try connection.segment(peer, .{ .fin = from_lan }, null);
                }
            },
        }
    }
};

pub const Download = struct {
    pub const Steps = enum { syn, syn_ack, request, response, cumulative_ack, server_close, client_close, final_ack };
    connection: TcpConnection,
    segments: usize,
    retransmit: bool,
    reset: bool,

    pub fn step(turn: *ConversationTurn) !void {
        const peer = turn.peer;
        const index = turn.index;
        const step_name: Steps = @enumFromInt(turn.phase);
        const from_lan = switch (step_name) {
            .syn, .request, .cumulative_ack, .client_close => true,
            .syn_ack, .response, .server_close, .final_ack => false,
        };
        if (from_lan != (peer.iface == .lan)) return;
        const network = peer.network;
        const download = &network.episodes.download;
        var prng = std.Random.DefaultPrng.init(network.seed +% index);
        const random = prng.random();
        if (step_name == .syn) {
            const settings = network.workload.download orelse Scenarios.Download.init(random);
            const host = 2 + @as(u8, settings.client);
            const port: u16 = @intCast(32000 + index);
            download.* = .{
                .connection = .{
                    .host = .{ 192, 168, 86, host },
                    .mac = .{ 2, 1, 0, 0, 0, host },
                    .remote = .{ 203, 0, 113, random.intRangeAtMost(u8, 32, 220) },
                    .port = port,
                    .public_port = network.reservePort(.tcp, port),
                    .client_next = settings.client_seq,
                    .server_next = settings.server_seq,
                    .generation = network.newConversationBinding(),
                },
                .segments = settings.segments,
                .retransmit = settings.retransmit,
                .reset = settings.reset,
            };
        }
        switch (step_name) {
            .syn, .syn_ack => try download.connection.segment(peer, .{ .syn = true, .ack = step_name == .syn_ack }, null),
            .request => {
                try download.connection.segment(peer, .{}, null);
                try download.connection.segment(peer, .{ .psh = true, .payload = "GET /download HTTP/1.0\r\nHost: example.net\r\n\r\n" }, null);
            },
            .response => {
                var data: [1428]u8 = undefined;
                for (0..download.segments) |i| {
                    random.bytes(&data);
                    if (i == 0) {
                        const header = "HTTP/1.0 200 OK\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n";
                        @memcpy(data[0..header.len], header);
                    }
                    const sequence = download.connection.server_next;
                    try download.connection.segment(peer, .{ .payload = &data }, null);
                    if (i == 1 and download.retransmit) try download.connection.segment(peer, .{ .payload = &data }, sequence);
                }
            },
            .cumulative_ack => try download.connection.segment(peer, .{}, null),
            .server_close => try download.connection.segment(peer, .{ .fin = !download.reset, .rst = download.reset }, null),
            .client_close => if (!download.reset) {
                try download.connection.segment(peer, .{}, null);
                try download.connection.segment(peer, .{ .fin = true }, null);
            },
            .final_ack => if (!download.reset) try download.connection.segment(peer, .{}, null),
        }
    }
};

pub const CancelledDownload = struct {
    pub const Steps = enum { connect, accept, request, partial_response, cancel, reconnect, accept_again, late_data, closed_reset, request_again, complete_response, close, finish };
    original: TcpConnection,
    replacement: TcpConnection,
    closed_reset_seq: u32,

    pub fn step(turn: *ConversationTurn) !void {
        const phase: Steps = @enumFromInt(turn.phase);
        const from_lan = switch (phase) {
            .connect, .request, .cancel, .reconnect, .closed_reset, .request_again, .close => true,
            else => false,
        };
        const peer = turn.peer;
        if (from_lan != (peer.iface == .lan)) return;
        const self = &peer.network.episodes.cancelled_download;
        var prng = std.Random.DefaultPrng.init((peer.network.seed +% turn.index) ^ (@as(u64, @intFromEnum(phase)) << 48));
        const random = prng.random();
        switch (phase) {
            .connect => {
                self.original = TcpConnection.open(peer, random, random.int(u4), .{ 203, 0, 113, 85 }, @intCast(38000 + 2 * turn.index));
                try self.original.segment(peer, .{ .syn = true, .ack = false }, null);
            },
            .accept => try self.original.segment(peer, .{ .syn = true }, null),
            .request => try self.original.segment(peer, .{ .psh = true, .payload = "GET /large HTTP/1.1\r\nHost: example.net\r\n\r\n" }, null),
            .partial_response => {
                try self.original.segment(peer, .{ .psh = true, .payload = "HTTP/1.1 200 OK\r\nContent-Length: 8192\r\n\r\n" }, null);
                try self.original.data(peer, random, 1428, null);
            },
            .cancel => try self.original.segment(peer, .{ .rst = true }, null),
            .reconnect => {
                self.replacement = TcpConnection.open(peer, random, @intCast(self.original.host[3] - 2), self.original.remote, self.original.port + 1);
                try self.replacement.segment(peer, .{ .syn = true, .ack = false }, null);
            },
            .accept_again => try self.replacement.segment(peer, .{ .syn = true }, null),
            .late_data => {
                // A segment already in flight reaches the old socket after its application closed.
                try self.original.data(peer, random, 1388, null);
                const late = try peer.observation.take(0, .lan);
                self.closed_reset_seq = std.mem.readInt(u32, late[42..46], .big);
            },
            .closed_reset => try self.original.segment(peer, .{ .rst = true, .ack = false }, self.closed_reset_seq),
            .request_again => try self.replacement.segment(peer, .{ .psh = true, .payload = "GET /small HTTP/1.1\r\nHost: example.net\r\nConnection: close\r\n\r\n" }, null),
            .complete_response => try self.replacement.segment(peer, .{ .fin = true, .psh = true, .payload = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok" }, null),
            .close => try self.replacement.segment(peer, .{ .fin = true }, null),
            .finish => try self.replacement.segment(peer, .{}, null),
        }
        if (@intFromEnum(phase) >= @intFromEnum(Steps.reconnect)) {
            try self.original.checkMapping();
            try self.replacement.checkMapping();
        }
    }
};

pub const WindowUpdate = struct {
    pub const Steps = enum { syn, syn_ack, request, first_data, acknowledge, reopen_window, resume_data, acknowledge_burst, server_close, client_close, final_ack };
    connection: TcpConnection,
    window_ack: u32,
    window_seq: u32,
    available: u16,
    const first_window = 2048;
    const chunk_len = 1388;

    pub fn step(turn: *ConversationTurn) !void {
        const phase: Steps = @enumFromInt(turn.phase);
        const peer = turn.peer;
        const from_lan = switch (phase) {
            .syn, .request, .acknowledge, .reopen_window, .acknowledge_burst, .client_close => true,
            else => false,
        };
        if (from_lan != (peer.iface == .lan)) return;
        const self = &peer.network.episodes.receive_window_update;
        var prng = std.Random.DefaultPrng.init((peer.network.seed +% turn.index) ^ (@as(u64, @intFromEnum(phase)) << 48));
        const random = prng.random();
        const c = &self.connection;
        switch (phase) {
            .syn => {
                c.* = TcpConnection.open(peer, random, random.int(u4), .{ 203, 0, 113, 86 }, @intCast(39000 + turn.index));
                try c.exchange(peer, .{ .syn = true, .ack = false }, null, first_window, .forward);
            },
            .syn_ack => try c.segment(peer, .{ .syn = true }, null),
            .request => try c.exchange(peer, .{ .psh = true, .payload = "GET /file HTTP/1.0\r\n\r\n" }, null, first_window, .forward),
            .first_data => {
                var first: [chunk_len]u8 = undefined;
                random.bytes(&first);
                const headers = "HTTP/1.0 200 OK\r\nConnection: close\r\n\r\n";
                @memcpy(first[0..headers.len], headers);
                try c.segment(peer, .{ .psh = true, .payload = &first }, null);
            },
            .acknowledge, .reopen_window => {
                const small = phase == .acknowledge;
                const window: u16 = if (small) first_window - chunk_len else random.intRangeAtMost(u16, 8192, 32768);
                try c.exchange(peer, .{}, null, window, .forward);
                const ack = try peer.observation.take(0, .wan);
                const seq = std.mem.readInt(u32, ack[38..42], .big);
                const cumulative = std.mem.readInt(u32, ack[42..46], .big);
                const advertised = std.mem.readInt(u16, ack[48..50], .big);
                if (small) {
                    self.window_seq = seq;
                    self.window_ack = cumulative;
                } else if (cumulative != self.window_ack or seq != self.window_seq or advertised <= self.available) return error.WrongWindowUpdate;
                self.available = advertised;
            },
            .resume_data => {
                if (self.available < 3 * chunk_len) return error.WrongWindowUpdate;
                for (0..3) |_| try c.data(peer, random, chunk_len, null);
            },
            .acknowledge_burst => {
                if (c.server_next != self.window_ack +% (3 * chunk_len)) return error.WrongCumulativeAck;
                try c.exchange(peer, .{}, null, self.available, .forward);
            },
            .server_close => try c.segment(peer, .{ .fin = true }, null),
            .client_close => try c.exchange(peer, .{ .fin = true }, null, self.available, .forward),
            .final_ack => try c.segment(peer, .{}, null),
        }
    }
};

pub const WanChange = struct {
    original: TcpConnection,
    retry: TcpConnection,
    lan_lease_deadline: std.Io.Timestamp,

    const request = "GET /status HTTP/1.1\r\nHost: example.net\r\n\r\n";
    const late = "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nold";
    const fresh = "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nnew";

    pub fn step(self: *WanChange, peer: *Peer, phase: Scenarios.Lifecycle, replacement: IPv4, gateway: IPv4) !void {
        const from_lan = switch (phase) {
            .wan_change_syn, .wan_change_request, .wan_change_reconnect, .wan_change_retry, .wan_change_ack => true,
            else => false,
        };
        if (from_lan != (peer.iface == .lan)) return;
        const net = peer.network;
        var prng = std.Random.DefaultPrng.init(net.seed ^ Router.Nic.Simulation.phase);
        const after_change = @intFromEnum(phase) >= @intFromEnum(Scenarios.Lifecycle.wan_change_reconnect);
        const lease = State.wanLease() orelse return error.MissingWanLease;
        if (!std.meta.eql(lease.ip, if (after_change) replacement else wan) or
            !std.meta.eql(lease.router, if (after_change) gateway else Sim.gateway)) return error.WrongWanLease;
        if (phase == .wan_change_syn) {
            self.original = TcpConnection.open(peer, prng.random(), 13, .{ 203, 0, 113, 90 }, 41861);
            var scratch = std.heap.FixedBufferAllocator.init(&peer.scratch);
            const alloc = scratch.allocator();
            const c = &self.original;
            try peer.inject(try Sim.arp(alloc, c.mac, c.host, Sim.lan, null));
            try peer.count(1);
            _ = try peer.expect(0, .lan, try Sim.arp(alloc, lan_mac, Sim.lan, c.host, c.mac));
        }
        const c = if (after_change) &self.retry else &self.original;
        const slot = State.dhcp_table.lookupByIp(self.original.host) orelse return error.MissingLanLease;
        const client = State.dhcp_table.table.get(slot);
        if (phase == .wan_change_syn) self.lan_lease_deadline = client.deadline;
        if (client.state != .bound or !std.meta.eql(client.mac, self.original.mac) or !std.meta.eql(client.deadline, self.lan_lease_deadline) or
            !std.meta.eql(State.lan_arp_table.lookup(self.original.host), @as(?Mac, self.original.mac)) or
            !std.meta.eql(State.wan_arp_table.lookup(lease.router), @as(?Mac, gateway_mac)) or
            State.arp_waiters_table.table.count() != 0) return error.WrongWanChangeNeighbor;
        switch (phase) {
            .wan_change_reconnect => {
                try self.original.checkMapping();
                net.releasePort(.tcp, self.original.public_port);
                self.retry = TcpConnection.open(peer, prng.random(), 13, self.original.remote, self.original.port);
                self.retry.public_ip = replacement;
                try c.segment(peer, .{ .syn = true, .ack = false }, null);
                if (State.nat_table.outside.contains(.{ .protocol = .tcp, .ip = wan, .port = self.original.public_port }) or
                    c.generation == self.original.generation) return error.StaleNatAfterWanChange;
            },
            .wan_change_syn => try c.segment(peer, .{ .syn = true, .ack = false }, null),
            .wan_change_accept, .wan_change_accept_again => {
                if (after_change) try self.drop(peer, phase);
                try c.segment(peer, .{ .syn = true }, null);
            },
            .wan_change_request, .wan_change_retry => try c.segment(peer, .{ .psh = true, .payload = request }, null),
            .wan_change_response => try c.segment(peer, .{ .psh = true, .payload = fresh }, null),
            .wan_change_ack => try c.segment(peer, .{}, null),
            else => unreachable,
        }
    }

    pub fn drop(self: *WanChange, peer: *Peer, phase: Scenarios.Lifecycle) !void {
        const nat = &State.nat_table;
        const other = peer.network.opened[@intFromEnum(Scenarios.Flow.tcp)].?.insideKey();
        const untouched = nat.inside.get(other) orelse return error.MissingNatState;
        const count = nat.inside.count();
        const generation = nat.next_generation;
        const cursor = nat.tcp_ports.next;
        if (phase == .after_expiry) {
            // The client times out and aborts its socket while the router has no WAN address.
            try self.original.exchange(peer, .{ .rst = true }, null, 0, .drop);
        } else {
            // The server acknowledges the verified old GET, even after the same client socket reopens.
            try self.original.exchange(peer, .{ .psh = true, .payload = late }, null, 32768, .drop);
        }
        if (nat.inside.count() != count or nat.outside.count() != count or nat.next_generation != generation or
            nat.tcp_ports.next != cursor or !std.meta.eql(nat.inside.get(other), @as(?Nat.Entry, untouched)) or
            State.arp_waiters_table.table.count() != 0) return error.StaleReplyChangedState;
        try (if (phase == .wan_change_accept_again) &self.retry else &self.original).checkMapping();
    }
};

pub const TcpConnection = struct {
    host: IPv4,
    mac: Mac,
    remote: IPv4,
    port: u16,
    public_port: u16,
    client_next: u32,
    server_next: u32,
    last_timestamp: [2]u32 = .{ 0, 0 },
    generation: u64,
    deadline: std.Io.Timestamp = .zero,
    service_peer: ?Nat.Peer = null,
    public_ip: IPv4 = wan,

    fn open(peer: *Peer, random: std.Random, client: u4, remote: IPv4, port: u16) TcpConnection {
        const network = peer.network;
        const host = 2 + @as(u8, client);
        return .{
            .host = .{ 192, 168, 86, host },
            .mac = .{ 2, 1, 0, 0, 0, host },
            .remote = remote,
            .port = port,
            .public_port = network.reservePort(.tcp, port),
            .client_next = random.int(u32),
            .server_next = random.int(u32),
            .generation = network.newConversationBinding(),
        };
    }

    fn data(self: *TcpConnection, peer: *Peer, random: std.Random, length: u16, seq: ?u32) !void {
        var bytes: [1448]u8 = undefined;
        random.bytes(bytes[0..length]);
        try self.segment(peer, .{ .psh = true, .payload = bytes[0..length] }, seq);
    }

    pub fn segment(self: *TcpConnection, peer: *Peer, options: Packets.TcpOpts, retransmit_seq: ?u32) !void {
        try self.exchange(peer, options, retransmit_seq, if (options.rst) 0 else 32768, .forward);
    }

    fn exchange(self: *TcpConnection, peer: *Peer, options: Packets.TcpOpts, retransmit_seq: ?u32, window: u16, expected: enum { forward, drop }) !void {
        var scratch = std.heap.FixedBufferAllocator.init(&peer.scratch);
        const alloc = scratch.allocator();
        const from_lan = peer.iface == .lan;
        const egress: IFace = if (from_lan) .wan else .lan;
        const next = if (from_lan) &self.client_next else &self.server_next;
        var tcp = options;
        tcp.seq_number = retransmit_seq orelse next.*;
        tcp.ack_number = if (!tcp.ack) 0 else if (from_lan) self.server_next else self.client_next;
        tcp.window = window;
        var timestamps: [16]u8 = .{ 2, 4, 5, 180, 1, 1, 8, 10 } ++ .{0} ** 8;
        std.mem.writeInt(u32, timestamps[8..12], @intCast(Router.Nic.Simulation.phase + 1), .big);
        std.mem.writeInt(u32, timestamps[12..16], self.last_timestamp[@intFromEnum(egress)], .big);
        var combined: [40]u8 = undefined;
        var opts: std.Io.Writer = .fixed(&combined);
        if (tcp.syn) try opts.writeAll(timestamps[0..4]);
        try opts.writeAll(options.options);
        try opts.writeAll(timestamps[4..]);
        tcp.options = if (tcp.rst) &.{} else opts.buffered();
        var tx: []const u8 = undefined;
        for ([_]bool{ false, true }) |translated| {
            const outside = from_lan == translated;
            const local_ip = if (outside) self.public_ip else self.host;
            const port = if (outside) self.public_port else self.port;
            const remote_ip = if (!outside and self.service_peer != null) Sim.lan else self.remote;
            const server_port = if (self.service_peer) |resolver| resolver.port else 80;
            const src = if (from_lan) local_ip else remote_ip;
            const dst = if (from_lan) remote_ip else local_ip;
            const client_mac = if (outside) wan_mac else self.mac;
            const server_mac = if (outside) gateway_mac else lan_mac;
            tcp.src_port = if (from_lan) port else server_port;
            tcp.dst_port = if (from_lan) server_port else port;
            const frame = try wire(alloc, if (from_lan) client_mac else server_mac, if (from_lan) server_mac else client_mac, .{
                .src = src,
                .dst = dst,
                .protocol = 6,
                .identification = @truncate(tcp.seq_number),
                .dont_fragment = true,
                .ttl = if (translated) 63 else 64,
                .payload = try Packets.tcp(alloc, src, dst, tcp),
            });
            if (translated) {
                tx = try peer.expect(0, egress, frame);
            } else {
                try peer.inject(frame);
                if (expected == .drop) return peer.expectDrop();
                try peer.count(1);
            }
        }
        // Subsequent ACKs consume the verified segment delivered to the other endpoint.
        const header_len = @as(usize, tx[46] >> 4) * 4;
        const consumed = tx.len - 34 - header_len + @intFromBool(tcp.syn or tcp.fin);
        if (retransmit_seq == null) next.* = std.mem.readInt(u32, tx[38..42], .big) +% @as(u32, @intCast(consumed));
        if (!tcp.rst) self.last_timestamp[@intFromEnum(peer.iface)] = std.mem.readInt(u32, tx[34 + header_len - 8 ..][0..4], .big);
        if (from_lan) {
            self.public_port = std.mem.readInt(u16, tx[34..36], .big);
            self.deadline = std.Io.Timestamp.now(peer.network.io, .boot).addDuration(.fromSeconds(7440));
        }
        try self.checkMapping();
    }

    pub fn checkMapping(self: *const TcpConnection) !void {
        const table = &State.nat_table;
        table.mutex.lockUncancelable(table.io);
        defer table.mutex.unlock(table.io);
        const key: Nat.Key = .{ .protocol = .tcp, .ip = self.host, .port = self.port, .service_peer = self.service_peer };
        const outside: Nat.Key = .{ .protocol = .tcp, .ip = self.public_ip, .port = self.public_port };
        const entry = table.inside.get(key) orelse return error.MissingNatState;
        if (!std.meta.eql(entry.outside, outside) or !std.meta.eql(table.outside.get(outside), @as(?Nat.Key, key)) or
            entry.generation != self.generation or !std.meta.eql(entry.deadline, self.deadline) or
            !table.tcp_ports.used.isSet(self.public_port) or entry.peer_count != 1 or
            !std.meta.eql(entry.peers[0], self.service_peer orelse Nat.Peer{ .ip = self.remote, .port = 80 })) return error.WrongTcpMapping;
    }
};
