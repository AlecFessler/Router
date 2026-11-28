//! The two peers build wire expectations independently, then answer verified router transmissions.
const std = @import("std");
const Router = @import("router");

pub const Scenarios = @import("scenarios/catalog.zig");
const Fixtures = Router.TestFixtures.Synthetic;
const Packets = Fixtures.Packets;
const Runtime = Router.Debug.Runtime;
const Clock = Router.Debug.SimulationClock;
const State = Router.State;
const Sim = Router.Nic.Simulation;
const IFace = Router.Nic.Api.IFace;
const Nat = Router.Tables.NatTable.NatTable;
const IPv4 = Router.Protocols.IPv4.IPv4;
const Mac = Router.Protocols.Ethernet.Mac;
pub const lan: IPv4 = .{ 192, 168, 86, 1 };
pub const wan: IPv4 = .{ 198, 51, 100, 2 };
pub const gateway: IPv4 = .{ 198, 51, 100, 1 };
pub const dns: IPv4 = .{ 8, 8, 8, 8 };
pub const mask: IPv4 = .{ 255, 255, 255, 0 };
pub const lan_mac: Mac = .{ 2, 0, 0, 0, 0, 1 };
pub const wan_mac: Mac = .{ 2, 0, 0, 0, 0, 2 };
pub const gateway_mac: Mac = .{ 2, 0, 0, 0, 0, 3 };
const broadcast: Mac = @splat(255);
const batch = 256;
pub const max_reply_lag = 3;
const Startup = Scenarios.Startup;
const Lifecycle = Scenarios.Lifecycle;
const first_burst = std.meta.fields(Startup).len;

pub const FilteringMode = Nat.FilteringMode;

pub const Workload = struct {
    filtering_mode: FilteringMode = .address_restricted,
    choices: []const Choice = &.{},
    conversations: []const Scenarios.Conversation = &.{},
    download: ?Scenarios.Download = null,
    burst_width: usize = batch,
    reply_lag: ?u8 = null,
};

pub const Choice = struct {
    host: u4,
    socket: u5,
    kind: Scenarios.Flow,
    scenario: ?Scenarios.ClientScenario = null,
    outcome: Scenarios.Outcome,
    token: u32,
    size: u8,
    payload_prefix: ?[8]u8 = null,
    ttl: u8 = 64,
};

pub const Job = struct {
    choice: Choice,
    lan_address: ?IPv4 = null,
    public_port: u16,
    source_port: u16,
    remote: IPv4,
    remote_port: u16 = 443,
    omit_udp_checksum: bool = false,
    wan_ip: IPv4 = wan,
    reply_source_port: ?u16 = null,
    dns_records: u4 = 1,
    dns_alias: bool = false,
    // Obtained from the verified wire request; echoed by the simulated peer.
    payload: [272]u8,
    len: usize,
    request_len: usize,
    syn: bool,
    seq: u32,
    ack: u32,
    reply_ack: ?u32 = null,

    fn requestEnd(self: Job) u32 {
        return self.seq +% @as(u32, @intCast(if (self.syn) 1 else self.request_len));
    }

    pub fn host(self: Job) IPv4 {
        return self.lan_address orelse .{ 192, 168, 86, 2 + @as(u8, self.choice.host) };
    }

    pub fn mac(self: Job) Mac {
        return .{ 2, 1, 0, 0, 0, self.host()[3] };
    }

    fn protocol(self: Job) u8 {
        return switch (self.choice.kind) {
            .udp, .dns_udp => 17,
            .tcp, .dns_tcp => 6,
            .ping => 1,
        };
    }

    fn isDns(self: Job) bool {
        return self.choice.kind == .dns_udp or self.choice.kind == .dns_tcp;
    }

    pub fn service(self: Job) u16 {
        return if (self.isDns()) 53 else self.remote_port;
    }

    pub fn insideKey(self: Job) Nat.Key {
        return .{
            .ip = self.host(),
            .port = self.source_port,
            .protocol = @enumFromInt(self.protocol()),
            .service_peer = if (self.isDns()) .{ .ip = dns, .port = 53 } else null,
        };
    }

    // Conversation turns inspect shared state while the opposite interface is idle.
    pub fn checkUdpMapping(self: *const Job, generation: u64, deadline: std.Io.Timestamp, peers: []const Nat.Peer) !void {
        const nat = &State.nat_table;
        const inside = self.insideKey();
        const outside: Nat.Key = .{ .protocol = .udp, .ip = self.wan_ip, .port = self.public_port };
        const entry = nat.inside.get(inside) orelse return error.MissingNatState;
        if (!std.meta.eql(entry.outside, outside) or !std.meta.eql(nat.outside.get(outside), @as(?Nat.Key, inside)) or
            entry.generation != generation or !std.meta.eql(entry.deadline, deadline) or
            !nat.udp_ports.used.isSet(outside.port) or entry.peer_count != peers.len) return error.WrongUdpMapping;
        for (entry.peers[0..entry.peer_count], peers) |actual, expected| {
            if (!std.meta.eql(actual, expected)) return error.WrongNatPeer;
        }
    }

    pub fn makeDnsQuery(self: *Job, id: u16, label: [3]u8) void {
        const query = "\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x07example\x03net\x00\x00\x01\x00\x01";
        const offset: usize = if (self.protocol() == 6) 2 else 0;
        self.len = offset + 2 + query.len;
        std.mem.writeInt(u16, self.payload[offset..][0..2], id, .big);
        @memcpy(self.payload[offset + 2 .. self.len], query);
        self.payload[offset + 13 ..][0..3].* = label;
        self.payload[self.len - 3] = if (self.choice.token & 2 == 0) 1 else 28;
        if (offset != 0) std.mem.writeInt(u16, self.payload[0..2], @intCast(self.len - 2), .big);
    }

    pub fn makeResponse(self: *Job) void {
        if (self.isDns() and self.len > 0) {
            const offset: usize = if (self.protocol() == 6) 2 else 0;
            const answer_len = self.dnsAddressLen();
            self.len = offset + @import("scenarios/dns.zig").addressResponse(self.payload[offset..], self.len - offset, answer_len, self.dns_records, self.dns_alias);
            if (offset != 0) std.mem.writeInt(u16, self.payload[0..2], @intCast(self.len - 2), .big);
        }
    }

    fn dnsAddressLen(self: Job) usize {
        if (!self.isDns() or self.syn or self.choice.token & 1 == 0) return 0;
        return if (self.choice.token & 2 == 0) 4 else 16;
    }
};

pub fn wire(alloc: std.mem.Allocator, src_mac: Mac, dst_mac: Mac, opts: Packets.Ipv4Opts) ![]u8 {
    return Packets.eth(alloc, .{ .src = src_mac, .dst = dst_mac, .payload = try Packets.ipv4(alloc, opts) });
}

pub fn arp(alloc: std.mem.Allocator, mac: Mac, addr: IPv4, target: IPv4, peer: ?Mac) ![]u8 {
    const msg = try Packets.arp(alloc, .{
        .opcode = if (peer != null) 2 else 1,
        .sender_mac = mac,
        .sender_ip = addr,
        .target_ip = target,
        .target_mac = peer orelse @splat(0),
    });
    return Packets.eth(alloc, .{
        .ethertype = 0x806,
        .src = mac,
        .dst = peer orelse broadcast,
        .payload = msg,
    });
}

pub fn packet(alloc: std.mem.Allocator, job: Job, reply: bool, translated: bool, ttl: u8) ![]u8 {
    return packetWithPayload(alloc, job, reply, translated, ttl, job.payload[0..job.len]);
}

pub fn packetWithPayload(alloc: std.mem.Allocator, job: Job, reply: bool, translated: bool, ttl: u8, data: []const u8) ![]u8 {
    const outside = reply != translated;
    const remote = if (outside or !job.isDns()) job.remote else lan;
    const local = if (outside) job.wan_ip else job.host();
    const src = if (reply) remote else local;
    const dst = if (reply) local else remote;
    const port = if (outside) job.public_port else job.source_port;
    const src_port = if (reply) job.reply_source_port orelse job.service() else port;
    const dst_port = if (reply) port else job.service();
    const msg = switch (job.protocol()) {
        17 => try Packets.udp(alloc, src, dst, .{
            .src_port = src_port,
            .dst_port = dst_port,
            .payload = data,
            .checksum = if (job.omit_udp_checksum) 0 else null,
        }),
        6 => try Packets.tcp(alloc, src, dst, .{
            .src_port = src_port,
            .dst_port = dst_port,
            .seq_number = if (reply) job.ack else job.seq,
            .ack_number = if (reply) job.reply_ack orelse job.requestEnd() else if (job.syn) 0 else job.ack,
            .syn = job.syn,
            .ack = reply or !job.syn,
            .psh = !job.syn,
            .payload = data,
        }),
        else => try Packets.echo(alloc, .{
            .message_type = if (reply) 0 else 8,
            .identifier = port,
            .sequence_number = @truncate(job.choice.token),
            .data = data,
        }),
    };
    const src_mac = if (outside) (if (reply) gateway_mac else wan_mac) else (if (reply) lan_mac else job.mac());
    const dst_mac = if (outside) (if (reply) wan_mac else gateway_mac) else (if (reply) job.mac() else lan_mac);
    return wire(alloc, src_mac, dst_mac, .{
        .src = src,
        .dst = dst,
        .protocol = job.protocol(),
        .ttl = ttl,
        .identification = @truncate(job.choice.token),
        .payload = msg,
    });
}

pub const Barrier = struct {
    io: std.Io,
    mutex: std.Io.Mutex = .init,
    changed: std.Io.Condition = .init,
    arrived: usize = 0,
    pub fn wait(self: *Barrier) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        self.arrived += 1;
        if (self.arrived % 2 == 0) return self.changed.signal(self.io);
        const n = self.arrived;
        while (n == self.arrived) self.changed.waitUncancelable(self.io, &self.mutex);
    }
};

const FragmentTable = Router.Tables.IPv4FragmentTable.IPv4FragmentTable;

const FragmentModel = struct {
    const Entry = struct { key: FragmentTable.Key, translation: FragmentTable.Translation, deadline: std.Io.Timestamp };
    entries: std.ArrayList(Entry) = .empty,
    next_id: u16 = 0,

    fn lookup(self: *const FragmentModel, key: FragmentTable.Key, now: std.Io.Timestamp) ?FragmentTable.Translation {
        for (self.entries.items) |e| {
            if (e.deadline.toNanoseconds() > now.toNanoseconds() and std.meta.eql(e.key, key)) return e.translation;
        }
        return null;
    }

    fn inserted(self: *FragmentModel, table: *const FragmentTable, now: std.Io.Timestamp) !void {
        var i: usize = 0;
        while (i < self.entries.items.len) {
            if (self.entries.items[i].deadline.toNanoseconds() <= now.toNanoseconds()) {
                _ = self.entries.swapRemove(i);
            } else i += 1;
        }
        if (self.entries.items.len < table.capacity) return;
        // Equally old entries are interchangeable. Require eviction of exactly one oldest mapping.
        var earliest = self.entries.items[0].deadline.toNanoseconds();
        for (self.entries.items) |e| earliest = @min(earliest, e.deadline.toNanoseconds());
        for (self.entries.items, 0..) |e, index| {
            if (e.deadline.toNanoseconds() == earliest and !table.table.contains(e.key)) {
                _ = self.entries.swapRemove(index);
                return;
            }
        }
        return error.WrongFragmentEviction;
    }

    fn check(self: *const FragmentModel, table: *const FragmentTable) !void {
        if (table.table.count() != self.entries.items.len or table.next_identification != self.next_id) return error.WrongFragmentState;
        for (self.entries.items) |expected| {
            const entry = table.table.get(expected.key) orelse return error.WrongFragmentState;
            if (entry.state != .resolved or !std.meta.eql(entry.deadline, expected.deadline) or
                !std.meta.eql(entry.state.resolved, expected.translation)) return error.WrongFragmentState;
        }
    }
};

// A DHCP eviction may change only this client's NAT mappings.
pub const AfterLeaseRemoval = struct {
    const Mapping = struct { key: Nat.Key, entry: Nat.Entry };
    survivors: []Mapping,
    used: [3]std.StaticBitSet(65536),
    next: [3]u16,
    generation: u64,

    pub fn predict(network: *const Network, nat: *const Nat, host: IPv4) !AfterLeaseRemoval {
        try network.checkAllocatedPorts();
        var count: usize = 0;
        for (nat.inside.keys()) |key| if (!std.meta.eql(key.ip, host)) {
            count += 1;
        };
        var model: AfterLeaseRemoval = .{
            .survivors = try network.mock.alloc.alloc(Mapping, count),
            .used = network.used,
            .next = network.next,
            .generation = nat.next_generation,
        };
        var i: usize = 0;
        for (nat.inside.keys(), nat.inside.values()) |key, entry| {
            if (std.meta.eql(key.ip, host)) {
                const bucket: usize = switch (key.protocol) {
                    .icmp => 0,
                    .tcp => 1,
                    .udp => 2,
                    else => unreachable,
                };
                model.used[bucket].unset(entry.outside.port);
            } else {
                model.survivors[i] = .{ .key = key, .entry = entry };
                i += 1;
            }
        }
        return model;
    }

    pub fn check(self: *const AfterLeaseRemoval, nat: *const Nat) !void {
        if (nat.inside.count() != self.survivors.len or nat.outside.count() != self.survivors.len or nat.next_generation != self.generation) return error.WrongBindingsAfterLeaseRemoval;
        for (self.survivors) |mapping| {
            const actual = nat.inside.get(mapping.key) orelse return error.UnrelatedMappingRemoved;
            if (!std.meta.eql(mapping.entry, actual) or !std.meta.eql(nat.outside.get(mapping.entry.outside), @as(?Nat.Key, mapping.key))) return error.UnrelatedMappingChanged;
        }
        for ([_]*const @TypeOf(nat.icmp_ports){ &nat.icmp_ports, &nat.tcp_ports, &nat.udp_ports }, &self.used, self.next) |pool, *used, next| {
            if (!pool.used.eql(used.*) or pool.next != next) return error.WrongPortsAfterLeaseRemoval;
        }
    }
};

pub const Peer = struct {
    network: *Network,
    iface: IFace,
    observation: Sim.Observation = .{},
    seen: std.EnumSet(Router.Debug.Cli.EntryPoint) = .empty,
    transaction_id: u32 = 0,
    initial_xid: u32 = 0,
    expected_count: ?usize = null,
    verified: usize = 0,
    pending: bool = false,
    drops: usize = 0,
    rx: usize = 0,
    tx: usize = 0,
    scratch: [32768]u8 = undefined,
    expected: ?*[2]Sim.Output,

    pub fn inject(self: *Peer, bytes: []const u8) !void {
        if (try self.dispatch(bytes)) return error.UnexpectedUnhandled;
    }

    pub fn beginObservation(self: *Peer) !void {
        try self.finishObservation();
        self.expected_count = null;
        self.observation.count = 0;
        self.verified = 0;
        self.pending = true;
    }

    fn finishObservation(self: *Peer) !void {
        if (self.pending) return error.UncheckedObservation;
    }

    pub fn tickWan(self: *Peer) !void {
        try self.beginObservation();
        try Router.Protocols.DHCPv4.tickWan(self.network.io, self.network.mock.api());
    }

    fn dispatch(self: *Peer, bytes: []const u8) !bool {
        try self.beginObservation();
        self.rx += 1;
        const nic = self.network.mock.api();
        const input = self.network.mock.inject(self.iface, bytes);
        var views: Router.Protocols.ViewStack = .{};
        Router.Debug.Unhandled.seen = false;
        Router.Protocols.Ethernet.handle(input, nic, self.iface, &views) catch |err| {
            nic.release(input);
            return err;
        };
        return Router.Debug.Unhandled.seen;
    }

    pub fn expect(self: *Peer, index: usize, iface: IFace, bytes: []const u8) ![]u8 {
        const wanted = self.expected_count orelse return error.MissingOutputCount;
        if (!self.pending or index != self.verified or index >= wanted) return error.UnexpectedOutputAssertion;
        if (self.expected) |out| out[@intFromEnum(iface)].frame(self.network.mock.io, bytes);
        const actual = self.observation.take(index, iface) catch |err| {
            std.log.err("expected {d} TX, observed {d}, missing or wrong {t} output {d}", .{ wanted, self.observation.count, iface, index });
            return err;
        };
        if (!std.mem.eql(u8, actual, bytes)) {
            const pos = std.mem.indexOfDiff(u8, actual, bytes).?;
            std.log.err("{t} TX {d}: first difference at byte {d}, expected {d} bytes, got {d}", .{ iface, index, pos, bytes.len, actual.len });
            return error.WrongTxBytes;
        }
        self.tx += 1;
        self.verified += 1;
        if (self.verified == wanted) {
            if (self.observation.count != wanted) return error.WrongTxCount;
            self.pending = false;
        }
        return actual;
    }

    pub fn count(self: *Peer, n: usize) !void {
        if (self.expected_count != null or !self.pending) return error.DuplicateOutputCount;
        self.expected_count = n;
        // Record a positive wire expectation before reporting a missing transmission.
        if (n == 0) {
            if (self.observation.count != 0) return error.WrongTxCount;
            self.pending = false;
        }
    }

    pub fn expectDrop(self: *Peer) !void {
        try self.count(0);
        self.drops += 1;
    }

    pub fn expectDelivery(self: *Peer, iface: IFace, bytes: []const u8) !void {
        if (self.observation.count == 0) {
            // Keep the missing packet in the oracle PCAP when a conversation checks further deliveries.
            if (self.expected) |out| out[@intFromEnum(iface)].frame(self.network.mock.io, bytes);
            try self.count(0);
            return error.MissingDelivery;
        }
        try self.count(1);
        _ = try self.expect(0, iface, bytes);
    }

    pub const DhcpExpectation = struct {
        xid: ?u32 = null,
        rebind: bool = false,
        seconds: u16 = 0,
        client_ip: ?IPv4 = null,
        client_id: ?[]const u8 = null,
        unicast_yiaddr: bool = false,
        requested: IPv4 = wan,
        server: IPv4 = gateway,
        server_mac: Mac = gateway_mac,
    };
    pub fn dhcp(
        self: *Peer,
        kind: Router.Protocols.DHCPv4.MessageType,
        expected: DhcpExpectation,
        mac: Mac,
        address: IPv4,
    ) !u32 {
        try self.count(1);
        const xid = expected.xid orelse blk: {
            const actual = self.observation.take(0, self.iface) catch |err| {
                std.log.err("expected {t} DHCP {t} for MAC {x}, observed {d} TX", .{ self.iface, kind, &mac, self.observation.count });
                return err;
            };
            if (actual.len < 50) return error.ShortDhcp;
            break :blk std.mem.readInt(u32, actual[46..50], .big);
        };
        const client = self.iface == .wan;
        var boot: [300]u8 = @splat(0);
        boot[0..4].* = .{ if (client) 1 else 2, 1, 6, 0 };
        std.mem.writeInt(u32, boot[4..8], xid, .big);
        const renewal = client and kind == .request and !std.meta.eql(address, IPv4{ 0, 0, 0, 0 });
        std.mem.writeInt(u16, boot[8..10], expected.seconds, .big);
        const unicast = (renewal and !expected.rebind) or expected.client_ip != null or expected.unicast_yiaddr;
        if (!unicast and kind != .decline) boot[10] = 0x80;
        if (renewal) boot[12..16].* = address else boot[16..20].* = address;
        if (expected.client_ip) |ip| boot[12..16].* = ip;
        boot[28..34].* = mac;
        boot[236..240].* = .{ 99, 130, 83, 99 };
        var options = std.Io.Writer.fixed(boot[240..]);
        try options.writeAll(&.{ 53, 1, @intFromEnum(kind) });
        if (client) {
            if ((kind == .request and !renewal) or kind == .decline) {
                try options.writeAll(&(.{ 54, 4 } ++ expected.server ++ .{ 50, 4 } ++ expected.requested));
            }
            try options.writeAll(&(.{ 61, 7, 1 } ++ mac));
            if (kind != .decline) try options.writeAll(&.{ 55, 7, 1, 3, 6, 51, 54, 58, 59 });
        } else {
            try options.writeAll(&(.{ 54, 4 } ++ lan));
            if (expected.client_id) |id| {
                try options.writeAll(&.{ 61, @intCast(id.len) });
                try options.writeAll(id);
            }
            if (!std.meta.eql(address, IPv4{ 0, 0, 0, 0 })) try options.writeAll(&.{ 51, 4, 0, 1, 0x51, 0x80 });
            if (kind != .nak) try options.writeAll(&(.{ 1, 4 } ++ mask ++ .{ 3, 4 } ++ lan ++ .{ 6, 8 } ++ dns ++ .{ 8, 8, 4, 4 }));
        }
        try options.writeByte(255);
        var buf: [2048]u8 = undefined;
        var fixed = std.heap.FixedBufferAllocator.init(&buf);
        const alloc = fixed.allocator();
        const src: IPv4 = if (renewal) address else if (client) @splat(0) else lan;
        const dst: IPv4 = if (!unicast) @splat(255) else if (client) expected.server else expected.client_ip orelse address;
        const udp = try Packets.udp(alloc, src, dst, .{
            .src_port = if (client) 68 else 67,
            .dst_port = if (client) 67 else 68,
            .payload = &boot,
        });
        const dst_mac = if (!unicast) broadcast else if (client) expected.server_mac else mac;
        _ = try self.expect(0, self.iface, try wire(alloc, if (client) wan_mac else lan_mac, dst_mac, .{
            .src = src,
            .dst = dst,
            .dont_fragment = true,
            .payload = udp,
        }));
        return xid;
    }

    fn setup(self: *Peer, alloc: std.mem.Allocator, random: std.Random) !void {
        const network = self.network;
        if (self.iface == .wan) {
            try self.tickWan();
            const xid = try self.dhcp(.discover, .{}, wan_mac, @splat(0));
            self.initial_xid = xid;
            var turn: GatewayTurn = .{ .peer = self, .alloc = alloc, .random = random, .xid = xid };
            while (network.upstream != .bound) {
                const input: Scenarios.GatewayInput = if (network.upstream == .unconfigured) .discover else .request;
                const scenario = Scenarios.gatewayScenario(network.upstream, input, network.weights, random) orelse return error.InvalidGatewayTransition;
                network.gateway_counts.getPtr(scenario).* += 1;
                try Scenarios.generate(Scenarios.gateways, scenario, &turn);
            }
            return;
        }

        try network.guests.selectOtherServer(self, alloc);
        var returning: ClientTurn = .{ .peer = self, .alloc = alloc, .id = network.returning_client };
        try returning.requestRememberedLease();
        // A different client already knows the gateway MAC at startup.
        network.clients[0].knows_gateway = true;
        var hosts: [15]u4 = undefined;
        for (&hosts, 0..) |*host, i| host.* = @intCast(if (i < network.returning_client) i else i + 1);
        try self.acquireClients(&hosts, random);
    }

    fn acquireClients(self: *Peer, hosts: []u4, random: std.Random) !void {
        const network = self.network;
        var remaining: usize = hosts.len;
        while (remaining != 0) {
            const index = random.uintLessThan(usize, remaining);
            const id = hosts[index];
            const client = &network.clients[id];
            const scenario = Scenarios.choose(client.available(.unconfigured, false, false), network.weights, random) orelse return error.NoClientScenario;
            var scratch = std.heap.FixedBufferAllocator.init(&self.scratch);
            var turn: ClientTurn = .{ .peer = self, .alloc = scratch.allocator(), .id = id };
            try Scenarios.generate(Scenarios.clients, scenario, &turn);
            network.scenario_counts.getPtr(scenario).* += 1;
            if (client.lease == .bound and client.knows_gateway) {
                remaining -= 1;
                hosts[index] = hosts[remaining];
            }
        }
    }

    fn learnGateway(self: *Peer, alloc: std.mem.Allocator, id: u4) !void {
        const host: IPv4 = .{ 192, 168, 86, 2 + @as(u8, id) };
        const mac: Mac = .{ 2, 1, 0, 0, 0, host[3] };
        try self.inject(try arp(alloc, mac, host, lan, null));
        try self.count(1);
        _ = try self.expect(0, .lan, try arp(alloc, lan_mac, lan, host, mac));
        if (!std.meta.eql(State.lan_arp_table.lookup(host), @as(?Mac, mac))) return error.WrongArpState;
        self.network.lan_learned[id] = std.Io.Timestamp.now(self.network.io, .boot);
    }

    fn multicastDns(self: *Peer, alloc: std.mem.Allocator, host: IPv4, mac: Mac) !void {
        const mdns: IPv4 = .{ 224, 0, 0, 251 };
        const query = "\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x09_services\x07_dns-sd\x04_udp\x05local\x00\x00\x0c\x00\x01";
        try self.inject(try wire(alloc, mac, .{ 1, 0, 0x5e, 0, 0, 251 }, .{
            .src = host,
            .dst = mdns,
            .ttl = 255,
            .payload = try Packets.udp(alloc, host, mdns, .{ .src_port = 5353, .dst_port = 5353, .payload = query }),
        }));
    }

    fn ipv6MulticastDns(self: *Peer, alloc: std.mem.Allocator, mac: Mac, announcement: bool) !void {
        // The LAN capture has AirPlay PTR questions with cached answers. An unsolicited
        // announcement advertises the same kind of record without a question.
        const service = "\x08_airplay\x04_tcp\x05local\x00";
        const record = "\x00\x0c\x00\x01\x00\x00\x11\x94\x00\x07\x04TV00\xc0\x0c";
        const message: []const u8 = if (announcement)
            "\x00\x00\x84\x00\x00\x00\x00\x01\x00\x00\x00\x00" ++ service ++ record
        else
            "\x00\x00\x00\x00\x00\x01\x00\x01\x00\x00\x00\x00" ++ service ++ "\x00\x0c\x00\x01\xc0\x0c" ++ record;
        const ip = try alloc.alloc(u8, 48 + message.len);
        @memset(ip[0..48], 0);
        ip[0] = 0x60;
        std.mem.writeInt(u16, ip[4..6], @intCast(ip.len - 40), .big);
        ip[6..8].* = .{ 17, 255 };
        ip[8..10].* = .{ 0xfe, 0x80 };
        ip[16..24].* = .{ mac[0] ^ 2, mac[1], mac[2], 0xff, 0xfe, mac[3], mac[4], mac[5] };
        ip[24..26].* = .{ 0xff, 2 };
        ip[39] = 0xfb;
        std.mem.writeInt(u16, ip[40..42], 5353, .big);
        std.mem.writeInt(u16, ip[42..44], 5353, .big);
        ip[44..46].* = ip[4..6].*;
        @memcpy(ip[48..], message);
        const tv = if (announcement) mac[5] else mac[5] ^ 1;
        const hex = "0123456789abcdef";
        ip[ip.len - 4 ..][0..2].* = .{ hex[tv >> 4], hex[tv & 15] };
        var sum = Router.Meta.Checksum.checksumContribution(ip[8..40]) + 17 + (ip.len - 40) + Router.Meta.Checksum.checksumContribution(ip[40..]);
        while (sum >> 16 != 0) sum = (sum & 0xffff) + (sum >> 16);
        const checksum = ~@as(u16, @intCast(sum));
        std.mem.writeInt(u16, ip[46..48], if (checksum == 0) 0xffff else checksum, .big);
        const frame = try Packets.eth(alloc, .{ .src = mac, .dst = .{ 0x33, 0x33, 0, 0, 0, 0xfb }, .ethertype = 0x86dd, .payload = ip });

        const previous = self.seen;
        self.seen = .empty;
        defer self.seen.setUnion(previous);
        var report: Router.Debug.Unhandled.Observation = .{};
        Router.Debug.Unhandled.observation = &report;
        defer Router.Debug.Unhandled.observation = null;
        const suffix = " Ethernet: packet with ethertype 34525 unhandled";
        const expected: []const u8 = if (self.iface == .lan) "ingress=lan" ++ suffix else "ingress=wan" ++ suffix;
        if (!try self.dispatch(frame) or !self.seen.eql(.initOne(.ethernet))) return error.WrongIpv6Dispatch;
        if (report.count != 1 or !std.mem.eql(u8, expected, report.line[0..report.len])) return error.WrongIpv6Report;
        try self.expectDrop();
    }

    pub fn send(self: *Peer, alloc: std.mem.Allocator, job: *Job, cold: bool) !bool {
        const ttl: u8 = if (job.choice.outcome == .ttl) 1 else job.choice.ttl;
        const input = try packet(alloc, job.*, false, false, ttl);
        try self.inject(input);
        try self.count(1);
        if (cold) {
            _ = try self.expect(0, .wan, try arp(alloc, wan_mac, wan, gateway, null));
            return false;
        }
        if (ttl == 1) {
            const body = try std.mem.concat(alloc, u8, &.{ &(@as([4]u8, @splat(0))), input[14..] });
            const msg = try Packets.icmp(alloc, .{ .message_type = 11, .body = body });
            _ = try self.expect(0, .lan, try wire(alloc, lan_mac, job.mac(), .{
                .src = lan,
                .dst = job.host(),
                .protocol = 1,
                .dont_fragment = true,
                .payload = msg,
            }));
            return false;
        }
        const actual = try self.expect(0, .wan, try packet(alloc, job.*, false, true, ttl - 1));
        // The server receives the translated source socket and application bytes from the actual TX.
        job.public_port = std.mem.readInt(u16, if (job.protocol() == 1) actual[38..40] else actual[34..36], .big);
        @memcpy(job.payload[0..job.len], actual[actual.len - job.len ..]);
        const table = &State.nat_table;
        table.mutex.lockUncancelable(table.io);
        defer table.mutex.unlock(table.io);
        const key = job.insideKey();
        const entry = table.inside.get(key) orelse return error.MissingNatState;
        if (!std.meta.eql(entry.outside.ip, wan) or entry.outside.port != job.public_port or
            !std.meta.eql(table.outside.get(entry.outside), @as(?@TypeOf(key), key)) or
            !entry.acceptsPeerIp(job.remote)) return error.WrongNatState;
        return true;
    }

    pub fn answer(self: *Peer, alloc: std.mem.Allocator, request: Job) !void {
        var job = request;
        const stream = self.network.tcpStream(job.choice);
        if (job.choice.outcome == .reply or job.choice.outcome == .wan_ttl) {
            if (stream) |tcp| try tcp.receiveRequest(&job);
        }
        if (job.choice.outcome == .unknown_peer or job.choice.outcome == .unmapped) {
            job.makeResponse();
            if (job.choice.outcome == .unknown_peer) job.remote = .{ 203, 0, 113, 250 } else job.public_port = 44000;
            try self.inject(try packet(alloc, job, true, false, 64));
            if (job.choice.outcome == .unmapped or job.isDns() or self.network.filtering_mode != .full_cone) return self.expectDrop();
            try self.count(1);
            _ = try self.expect(0, .lan, try packet(alloc, job, true, true, 63));
            return;
        }
        if (job.choice.outcome == .wan_ttl) {
            job.makeResponse();
            const input = try packet(alloc, job, true, false, 1);
            try self.inject(input);
            const msg = try Packets.icmp(alloc, .{
                .message_type = 11,
                .body = try std.mem.concat(alloc, u8, &.{ &([_]u8{0} ** 4), input[14..] }),
            });
            try self.count(1);
            _ = try self.expect(0, .wan, try wire(alloc, wan_mac, gateway_mac, .{
                .src = wan,
                .dst = job.remote,
                .protocol = 1,
                .dont_fragment = true,
                .payload = msg,
            }));
            return;
        }
        if (job.choice.outcome == .port_unreachable or job.choice.outcome == .time_exceeded) {
            const kind: u8 = if (job.choice.outcome == .port_unreachable) 3 else 11;
            const original = try packet(alloc, job, false, true, job.choice.ttl - 1);
            const restored = try packet(alloc, job, false, false, job.choice.ttl - 1);
            const reporter = if (kind == 11) gateway else job.remote;
            const source = if (job.isDns() and std.meta.eql(reporter, dns)) lan else reporter;
            const end = if (job.choice.token & 1 == 0) 42 else original.len;
            const msg = try Packets.icmp(alloc, .{
                .message_type = kind,
                .code = if (kind == 3) 3 else 0,
                .body = try std.mem.concat(alloc, u8, &.{ &(@as([4]u8, @splat(0))), original[14..end] }),
            });
            try self.inject(try wire(alloc, gateway_mac, wan_mac, .{ .src = reporter, .dst = wan, .protocol = 1, .payload = msg }));
            const out = try Packets.icmp(alloc, .{
                .message_type = kind,
                .code = if (kind == 3) 3 else 0,
                .body = try std.mem.concat(alloc, u8, &.{ &(@as([4]u8, @splat(0))), restored[14..end] }),
            });
            try self.count(1);
            _ = try self.expect(0, .lan, try wire(alloc, lan_mac, job.mac(), .{
                .src = source,
                .dst = job.host(),
                .ttl = 63,
                .protocol = 1,
                .payload = out,
            }));
            return;
        }
        job.makeResponse();
        try self.inject(try packet(alloc, job, true, false, 64));
        try self.count(1);
        _ = try self.expect(0, .lan, try packet(alloc, job, true, true, 63));
        if (stream) |tcp| try tcp.receiveReply(job);
    }

    fn lifecycle(self: *Peer, step: Lifecycle) !void {
        const replacement_ip: IPv4 = .{ 198, 51, 100, 33 };
        const replacement_gateway: IPv4 = .{ 198, 51, 100, 254 };
        switch (step) {
            .nak_gateway, .nak_lookup, .nak_renew, .nak_refusal, .nak_offline, .nak_offer, .nak_second_offer, .nak_bind, .nak_retry, .nak_resolve_gateway, .nak_answer => return self.network.renewal_nak.step(self, step, replacement_ip, replacement_gateway),
            .rebind_server_neighbor, .rebind_unicast, .rebind_broadcast, .rebind_ack, .rebind_lookup, .rebind_route, .rebind_answer, .rebind_backup_neighbor, .rebind_backup_renewal => return self.network.renewal_nak.step(self, step, replacement_ip, replacement_gateway),
            .opening_syn,
            .opening_retry_syn,
            .opening_syn_ack,
            .opening_lost_ack,
            .opening_retry_syn_ack,
            .opening_ack,
            .opening_request,
            .opening_response,
            .opening_response_ack,
            => return self.network.tcp_retries.open(self, step),
            .closing_server_fin,
            .closing_client_ack,
            .closing_client_fin,
            .closing_lost_ack,
            .closing_retry_fin,
            .closing_ack,
            => return self.network.tcp_retries.close(self, step),
            .persist_syn,
            .persist_syn_ack,
            .persist_request,
            .persist_fill,
            .persist_zero,
            .persist_probe,
            .persist_zero_ack,
            .persist_lost_update,
            .persist_retry,
            .persist_open_ack,
            .persist_resume,
            .persist_done,
            => return self.network.persist.step(self, step),
            .udp_subscribe,
            .udp_initial_reading,
            .udp_first_ping,
            .udp_first_pong,
            .udp_second_ping,
            .udp_second_pong,
            .udp_last_live,
            .udp_idle_deadline,
            .udp_after_idle,
            => return self.network.subscriptions.step(self, step),
            .dns_initial_query, .dns_retransmit, .dns_delayed_answer, .dns_duplicate_answer => return self.network.dns_retry.step(self, step),
            .stun_initial_request, .stun_retry_request, .stun_success => return self.network.stun_retry.step(self, step),
            .audio_start, .audio_second, .audio_third, .audio_first_sr, .audio_first_rr, .audio_resume, .audio_fifth, .audio_sixth, .audio_second_sr, .audio_second_rr => return self.network.audio_call.step(self, step),
            .wan_change_syn,
            .wan_change_accept,
            .wan_change_request,
            .wan_change_reconnect,
            .wan_change_accept_again,
            .wan_change_retry,
            .wan_change_response,
            .wan_change_ack,
            => return self.network.wan_change.step(self, step, replacement_ip, replacement_gateway),
            .guest_lost_offer,
            .guest_discovery,
            .guest_requests,
            .guest_connectivity,
            .guest_echo_replies,
            .guest_first_release,
            .guest_replacement_discover,
            .guest_replacement_request,
            .guest_replacement_retry,
            .guest_replacement_connectivity,
            .guest_replacement_reply,
            .guest_departures,
            .static_inform,
            .static_dns_query,
            .static_dns_answer,
            => return self.network.guests.step(self, step),
            .sleeping_client_queries,
            .sleeping_client_replies,
            .sleeping_client_still_waiting,
            .sleeping_client_timeout,
            .sleeping_client_late_arp,
            .sleeping_client_retries,
            .sleeping_client_recovers,
            => return self.network.sleeping_client.step(self, step),
            else => {},
        }
        var scratch = std.heap.FixedBufferAllocator.init(&self.scratch);
        const alloc = scratch.allocator();
        const host: IPv4 = .{ 192, 168, 86, 2 };
        const mac: Mac = .{ 2, 1, 0, 0, 0, 2 };
        const table = &State.dhcp_table;
        if (step == .use_new_lease or step == .resolve_new_gateway or step == .resolve_return_host) {
            const job = &self.network.opened[@intFromEnum(Scenarios.Flow.tcp)].?;
            const nat = &State.nat_table;
            if (step == .use_new_lease and self.iface == .lan) {
                const old = nat.inside.get(job.insideKey()) orelse return error.MissingNatState;
                const generation = self.network.newConversationBinding();
                self.network.releasePort(.tcp, job.public_port);
                job.public_port = self.network.reservePort(.tcp, job.source_port);
                job.wan_ip = replacement_ip;
                try self.inject(try packet(alloc, job.*, false, false, 64));
                try self.count(1);
                _ = try self.expect(0, .wan, try arp(alloc, wan_mac, replacement_ip, replacement_gateway, null));
                const renewed = nat.inside.get(job.insideKey()) orelse return error.MissingNatState;
                if (nat.outside.contains(old.outside) or renewed.generation != generation or renewed.generation == old.generation or !std.meta.eql(renewed.outside.ip, replacement_ip) or
                    renewed.outside.port != job.public_port or !std.meta.eql(nat.outside.get(renewed.outside), @as(?Nat.Key, job.insideKey()))) return error.StaleNatAfterWanChange;
            }
            if (step == .resolve_new_gateway and self.iface == .wan) {
                try self.inject(try arp(alloc, gateway_mac, replacement_gateway, replacement_ip, wan_mac));
                try self.count(1);
                const request = try self.expect(0, .wan, try packet(alloc, job.*, false, true, 63));
                if (State.arp_waiters_table.table.count() != 0) return error.WrongArpState;
                job.public_port = std.mem.readInt(u16, request[34..36], .big);
                try self.inject(try packet(alloc, job.*, true, false, 64));
                try self.count(1);
                _ = try self.expect(0, .lan, try arp(alloc, lan_mac, lan, job.host(), null));
                const pending = State.arp_waiters_table.table.get(.{ .iface = .lan, .ip = job.host() }) orelse return error.MissingArpWaiter;
                if (pending.len != 1 or State.lan_arp_table.indexOfValue(.ip, job.host()) != null) return error.WrongArpState;
            }
            if (step == .resolve_return_host and self.iface == .lan) {
                try self.inject(try arp(alloc, job.mac(), job.host(), lan, lan_mac));
                try self.count(1);
                _ = try self.expect(0, .lan, try packet(alloc, job.*, true, true, 63));
                if (State.arp_waiters_table.table.count() != 0 or
                    !std.meta.eql(State.lan_arp_table.lookup(job.host()), @as(?Mac, job.mac()))) return error.WrongArpState;
            }
            return;
        }
        if (step == .contact_peers or step == .delayed_replies) {
            if ((step == .contact_peers) == (self.iface == .lan)) try @import("scenarios/peer_rotation.zig").exchange(self, &scratch, 128);
            if (step == .delayed_replies and self.iface == .lan) {
                // A bound device asks for its configuration, then renews by unicast.
                const index = table.lookupByIp(host) orelse return error.MissingLanLease;
                const before = table.table.get(index);
                for ([_]u8{ 8, 3 }) |kind| {
                    scratch.reset();
                    const payload = try Fixtures.DhcpClient.payload(alloc, mac, .{ .message_type = kind, .xid = 901, .ciaddr = host });
                    try self.inject(try wire(alloc, mac, lan_mac, .{
                        .src = host,
                        .dst = lan,
                        .payload = try Packets.udp(alloc, host, lan, .{ .src_port = 68, .dst_port = 67, .payload = payload }),
                    }));
                    _ = try self.dhcp(.ack, .{ .xid = 901, .client_ip = host }, mac, if (kind == 8) @splat(0) else host);
                    const current = table.table.get(index);
                    const deadline = if (kind == 8) before.deadline else std.Io.Timestamp.now(self.network.io, .boot).addDuration(.fromSeconds(86400));
                    if (!std.meta.eql(current.deadline, deadline) or !std.meta.eql(current.mac, mac) or current.state != .bound) return error.WrongLeaseState;
                    if (kind == 3) self.network.clients[0].lease_deadline = deadline;
                }
                try self.inject(try Fixtures.DhcpClient.frame(alloc, mac, .{ .message_type = 3, .server_id = .{ 192, 168, 86, 253 }, .requested_ip = host }));
                try self.expectDrop();
            }
            return;
        }
        if (step == .address_conflict) {
            const outside = self.iface == .wan;
            const address = if (outside) wan else lan;
            const claimant = if (outside) gateway_mac else mac;
            const claim = try arp(alloc, claimant, address, address, null);
            try self.inject(claim);
            try self.count(1);
            _ = try self.expect(0, self.iface, try arp(alloc, if (outside) wan_mac else lan_mac, address, address, null));
            if (outside) {
                try self.inject(claim);
                _ = try self.dhcp(.decline, .{}, wan_mac, @splat(0));
                if (State.wanLease() != null) return error.ConflictingWanLease;
            }
            return;
        }
        if (step == .restart or step == .after_expiry) {
            if (self.iface == .wan) {
                if (step == .restart) {
                    try self.tickWan();
                    self.transaction_id = try self.dhcp(.discover, .{}, wan_mac, @splat(0));
                }
            } else {
                const job = self.network.expiry_probe;
                const nat = &State.nat_table;
                const generation = nat.next_generation;
                const bindings = nat.inside.count();
                try self.inject(try packet(alloc, job, false, false, 64));
                try self.expectDrop();
                if (nat.inside.count() != bindings or nat.outside.count() != bindings or nat.next_generation != generation or
                    nat.inside.contains(job.insideKey()) or State.arp_waiters_table.table.count() != 0) return error.StateChangedWithoutWanLease;
                if (step == .after_expiry) return self.network.wan_change.drop(self, .after_expiry);
                const bound = table.lookupByIp(host) orelse return error.MissingLanLease;
                if (table.table.get(bound).state != .bound) return error.WrongLeaseState;
                const pool_before = table.ip_pool.items.len;
                const expected_nat = try AfterLeaseRemoval.predict(self.network, &State.nat_table, host);
                defer self.network.mock.alloc.free(expected_nat.survivors);
                try self.inject(try Fixtures.DhcpClient.frame(alloc, mac, .{ .message_type = 7, .ciaddr = host }));
                try self.count(0);
                for (table.table.items(.ip)) |ip| if (std.meta.eql(ip, host)) return error.StaleReleasedAddress;
                if (table.ip_pool.items.len != pool_before + 1 or State.lan_arp_table.indexOfValue(.ip, host) != null) return error.StaleReleasedAddress;
                for (table.ip_pool.items) |ip| {
                    if (std.meta.eql(ip, host)) break;
                } else return error.AddressNotReturned;
                try expected_nat.check(nat);
                self.network.used = expected_nat.used;
            }
            return;
        }
        if (self.iface == .wan) {
            if (step == .rejected_offer or step == .new_wan_address) {
                const succeed = step == .new_wan_address;
                const address = replacement_ip;
                const server = replacement_gateway;
                if (succeed) {
                    try self.tickWan();
                    self.transaction_id = try self.dhcp(.discover, .{}, wan_mac, @splat(0));
                }
                const xid = self.transaction_id;
                for ([_]u8{ 2, if (succeed) 5 else 6 }) |kind| {
                    const options = try Fixtures.dhcpServerOptions(alloc, kind, server, mask, server, 3600);
                    const offered = if (kind == 6) IPv4{ 0, 0, 0, 0 } else address;
                    // A delayed OFFER or ACK from the actual first exchange arrives on the old subnet.
                    const pending = State.wan_transaction orelse return error.MissingWanTransaction;
                    if (pending.xid == self.initial_xid) return error.IndistinguishableTransactions;
                    const old = try Fixtures.dhcpServerOptions(alloc, if (kind == 2) 2 else 5, gateway, mask, gateway, 3600);
                    try self.inject(try Fixtures.dhcpFrame(alloc, 2, self.initial_xid, wan_mac, @splat(0), wan, gateway, @splat(255), old));
                    try self.expectDrop();
                    if (State.wanLease() != null or !std.meta.eql(pending, State.wan_transaction orelse return error.AcceptedStaleTransaction)) return error.AcceptedStaleTransaction;
                    try self.inject(try Fixtures.dhcpFrame(alloc, 2, xid, wan_mac, @splat(0), offered, server, @splat(255), options));
                    try self.count(0);
                    if (kind == 2) {
                        try self.tickWan();
                        _ = try self.dhcp(.request, .{ .xid = xid, .server = server, .requested = address }, wan_mac, @splat(0));
                    }
                }
                if (State.wan_transaction != null) return error.WrongLeaseState;
                if (succeed) {
                    const lease = State.wanLease() orelse return error.MissingWanLease;
                    if (!std.meta.eql(lease.ip, address) or !std.meta.eql(lease.router, server) or !std.meta.eql(lease.server_id, server)) return error.WrongWanLease;
                    try self.inject(try packet(alloc, self.network.opened[@intFromEnum(Scenarios.Flow.tcp)].?, true, false, 64));
                    try self.expectDrop();
                    try self.network.wan_change.drop(self, .new_wan_address);
                } else if (State.wanLease() != null) return error.LeaseAfterNak;
            } else if (step == .bind_again) {
                const xid = self.transaction_id;
                for ([_]u8{ 2, 5 }) |kind| {
                    const options = try Fixtures.dhcpServerOptions(alloc, kind, gateway, mask, gateway, 16);
                    try self.inject(try Fixtures.dhcpFrame(alloc, 2, xid, wan_mac, @splat(0), wan, gateway, wan, options));
                    try self.count(0);
                    if (kind == 2) {
                        try self.tickWan();
                        _ = try self.dhcp(.request, .{ .xid = xid }, wan_mac, @splat(0));
                    }
                }
                const lease = State.wanLease() orelse return error.MissingWanLease;
                if (lease.expiration_deadline.untilNow(self.network.io, .boot).toSeconds() != -16) return error.WrongWanLease;
            } else if (step == .retry_renewal or step == .rebind or step == .expire) {
                try self.tickWan();
                switch (step) {
                    .retry_renewal => self.transaction_id = try self.dhcp(.request, .{}, wan_mac, wan),
                    .rebind => _ = try self.dhcp(.request, .{ .xid = self.transaction_id, .seconds = 6, .rebind = true }, wan_mac, wan),
                    .expire => {
                        self.transaction_id = try self.dhcp(.discover, .{}, wan_mac, @splat(0));
                        if (State.wanLease() != null) return error.ExpiredWanLease;
                    },
                    else => unreachable,
                }
            } else if (step == .reclaim_due) {
                const job = self.network.expiry_probe;
                const nat = &State.nat_table;
                const before = nat.inside.count();
                const entry = nat.inside.get(job.insideKey()) orelse return error.MissingNatState;
                if (entry.deadline.untilNow(self.network.io, .boot).toNanoseconds() < 0 or
                    !nat.outside.contains(entry.outside) or !nat.udp_ports.used.isSet(job.public_port)) return error.ExpectedExpiredBinding;
                const reply = try packet(alloc, job, true, false, 64);
                for (0..2) |_| {
                    try self.inject(reply);
                    try self.expectDrop();
                    if (nat.inside.contains(job.insideKey()) or nat.outside.contains(entry.outside) or nat.udp_ports.used.isSet(job.public_port) or
                        nat.inside.count() != before - 1 or nat.outside.count() != before - 1) return error.ExpiredBindingNotRemoved;
                }
                self.network.releasePort(.udp, job.public_port);
            } else if (step == .cache_gateway) {
                try self.inject(try arp(alloc, gateway_mac, gateway, wan, null));
                try self.count(1);
                _ = try self.expect(0, .wan, try arp(alloc, wan_mac, wan, gateway, gateway_mac));
            } else if (step == .renew) {
                try self.tickWan();
                const xid = try self.dhcp(.request, .{}, wan_mac, wan);
                const opts = try Fixtures.dhcpServerOptions(alloc, 5, gateway, mask, gateway, 3600);
                try self.inject(try Fixtures.dhcpFrame(alloc, 2, xid, wan_mac, @splat(0), wan, gateway, wan, opts));
                try self.count(0);
                const lease = State.wanLease() orelse return error.MissingWanLease;
                if (lease.renewal_deadline.durationTo(lease.expiration_deadline).toSeconds() != 1800 or
                    lease.renewal_deadline.untilNow(self.network.io, .boot).toSeconds() != -1800) return error.RenewalFailed;
            }
            return;
        }
        if (step == .retry_renewal or step == .rebind or step == .expire) {
            // A neighbor asks for another host. Also records this timer instant for PCAP replay.
            const neighbor: IPv4 = .{ 192, 168, 86, 220 };
            try self.inject(try arp(alloc, .{ 2, 1, 0, 0, 0, 220 }, neighbor, .{ 192, 168, 86, 221 }, null));
            try self.expectDrop();
            if (State.lan_arp_table.indexOfValue(.ip, neighbor) != null) return error.UnrelatedArpLearned;
        }
        if (step == .decline) {
            const expected_nat = try AfterLeaseRemoval.predict(self.network, &State.nat_table, host);
            defer self.network.mock.alloc.free(expected_nat.survivors);
            try self.inject(try Fixtures.DhcpClient.frame(alloc, mac, .{ .message_type = 4, .requested_ip = host, .server_id = lan }));
            try self.count(0);
            if (table.lookupByIp(host) != null or table.excluded_ips.items.len != 1 or
                State.lan_arp_table.lookup(host) != null) return error.DeclineDidNotQuarantine;
            try expected_nat.check(&State.nat_table);
            self.network.used = expected_nat.used;
            for (18..255) |i| {
                scratch.reset();
                const addr: IPv4 = .{ 192, 168, 86, @intCast(i) };
                const hw: Mac = .{ 2, 1, 0, 0, 0, @intCast(i) };
                try self.inject(try Fixtures.DhcpClient.frame(alloc, hw, .{
                    .message_type = 3,
                    .requested_ip = addr,
                    .server_id = lan,
                    .xid = @intCast(i),
                    .broadcast_flag = true,
                }));
                _ = try self.dhcp(.ack, .{ .xid = @intCast(i) }, hw, addr);
            }
        }
        if (@intFromEnum(step) >= @intFromEnum(Lifecycle.decline) and @intFromEnum(step) <= @intFromEnum(Lifecycle.reoffer))
            return @import("scenarios/lease.zig").reclaim(self, alloc, step, host, mac);
        if (step == .renew) {
            // A read of the WAN lease and a fresh NAT insertion can overlap the renewal ACK.
            var job = self.network.cold;
            job.source_port = 101;
            job.public_port = self.network.reservePort(.udp, job.source_port);
            const nat = &State.nat_table;
            const expected = try RenewalAllocation.predict(self.network.mock.alloc, nat, job, self.network.newConversationBinding(), self.network.io);
            defer self.network.mock.alloc.free(expected.prior);
            _ = try self.send(alloc, &job, false);
            try expected.check(nat, job.insideKey());
        }
    }

    const RenewalAllocation = struct {
        prior: []AfterLeaseRemoval.Mapping,
        entry: Nat.Entry,
        used: std.StaticBitSet(65536),

        fn predict(alloc: std.mem.Allocator, nat: *Nat, job: Job, generation: u64, io: std.Io) !RenewalAllocation {
            const port = job.public_port;
            if (nat.inside.contains(job.insideKey()) or nat.next_generation != generation or
                nat.udp_ports.used.isSet(port)) return error.UnexpectedRenewalBaseline;
            const prior = try alloc.alloc(AfterLeaseRemoval.Mapping, nat.inside.count());
            for (prior, nat.inside.keys(), nat.inside.values()) |*mapping, key, entry| mapping.* = .{ .key = key, .entry = entry };
            var expected: RenewalAllocation = .{
                .prior = prior,
                .entry = .{
                    .outside = .{ .protocol = .udp, .ip = job.wan_ip, .port = port },
                    .generation = generation,
                    .deadline = std.Io.Timestamp.now(io, .boot).addDuration(.fromSeconds(300)),
                    .port_allocator = &nat.udp_ports,
                    .peer_count = 1,
                },
                .used = nat.udp_ports.used,
            };
            expected.entry.peers[0] = .{ .ip = job.remote, .port = job.service() };
            expected.used.set(port);
            return expected;
        }

        fn check(self: *const RenewalAllocation, nat: *const Nat, key: Nat.Key) !void {
            const mappings = self.prior.len + 1;
            const outside = self.entry.outside;
            const next: u16 = if (outside.port == 65535) 1024 else outside.port + 1;
            if (nat.inside.count() != mappings or nat.outside.count() != mappings or nat.next_generation != self.entry.generation + 1 or
                !std.meta.eql(nat.inside.get(key), @as(?Nat.Entry, self.entry)) or !std.meta.eql(nat.outside.get(outside), @as(?Nat.Key, key)) or
                !nat.udp_ports.used.eql(self.used) or nat.udp_ports.next != next) return error.WrongRenewalAllocation;
            for (self.prior) |mapping| {
                if (!std.meta.eql(nat.inside.get(mapping.key), @as(?Nat.Entry, mapping.entry)) or
                    !std.meta.eql(nat.outside.get(mapping.entry.outside), @as(?Nat.Key, mapping.key))) return error.UnrelatedMappingChanged;
            }
        }
    };

    fn transitFragments(self: *Peer, alloc: std.mem.Allocator, job: *Job, id: u16, head_first: bool) !void {
        const inbound = self.iface == .wan;
        const egress: IFace = if (inbound) .lan else .wan;
        const input = try packet(alloc, job.*, inbound, false, 64);
        const output = try packet(alloc, job.*, inbound, true, 63);
        const key: FragmentTable.Key = .{
            .src = input[26..30].*,
            .dst = input[30..34].*,
            .identification = id,
            .protocol = @enumFromInt(job.protocol()),
        };
        const fragment_table = if (inbound) &State.wan_fragment_table else &State.lan_fragment_table;
        const model = &self.network.fragments[@intFromEnum(self.iface)];
        const now = std.Io.Timestamp.now(self.network.io, .boot);
        const existing = model.lookup(key, now);
        const translated_id = if (existing) |t| t.identification else model.next_id;
        var first_payload_len: usize = 0;
        for ([_]bool{ head_first, !head_first }, 0..) |head, n| {
            const frame = try fragment(alloc, input, head, id);
            if (head) first_payload_len = frame.len - 34;
            try self.inject(frame);
            if (n == 0 and existing == null) try model.inserted(fragment_table, now);
            if (!head and n == 0 and existing == null) {
                try self.count(0);
                const entry = fragment_table.table.get(key) orelse return error.MissingPendingFragment;
                if (entry.state != .waiting or entry.state.waiting.len != 1) return error.WrongFragmentState;
                continue;
            }
            const emitted: usize = if (head and n == 1 and existing == null) 2 else 1;
            try self.count(emitted);
            for (0..emitted) |i| {
                const is_head = head and i == 0;
                const tx = try self.expect(i, egress, try fragment(alloc, output, is_head, translated_id));
                if (!inbound) {
                    const header: usize = if (job.protocol() == 6) 20 else 8;
                    if (is_head) {
                        job.public_port = std.mem.readInt(u16, tx[34..36], .big);
                        @memcpy(job.payload[0 .. tx.len - 34 - header], tx[34 + header ..]);
                    } else @memcpy(job.payload[job.len - (tx.len - 34) .. job.len], tx[34..]);
                }
            }
        }
        if (existing == null) {
            const binding = self.network.bindings[@intFromEnum(job.choice.kind)][job.choice.host][job.choice.socket].?;
            model.entries.appendAssumeCapacity(.{
                .key = key,
                .deadline = now.addDuration(.fromSeconds(30)),
                .translation = .{
                    .nat_key = if (inbound) .{ .protocol = key.protocol, .ip = job.wan_ip, .port = job.public_port } else job.insideKey(),
                    .nat_generation = binding.generation,
                    .identification = translated_id,
                    .first_payload_len = first_payload_len,
                },
            });
            model.next_id +%= 1;
        }
        try model.check(fragment_table);
    }

    fn localEcho(self: *Peer, alloc: std.mem.Allocator, host: IPv4, mac: Mac, token: u32, split: bool) !void {
        const iface = self.iface;
        const destination = if (iface == .lan) lan else wan;
        const local_mac = if (iface == .lan) lan_mac else wan_mac;
        const id: u16 = @truncate(token);
        var bytes: [3400]u8 = undefined;
        var prng = std.Random.DefaultPrng.init(token);
        const random = prng.random();
        const large = split and token & 12 == 8;
        const length = if (large) switch ((token >> 6) & 3) {
            0 => @as(usize, 1472), // Fits precisely in a 1500-byte IPv4 datagram without options.
            1 => @as(usize, 1473),
            2 => @as(usize, 2953),
            else => random.intRangeAtMost(usize, 3000, bytes.len),
        } else random.intRangeAtMost(usize, 20, 96);
        random.bytes(bytes[0..length]);
        const echo = try Packets.echo(alloc, .{ .data = bytes[0..length], .identifier = id });
        defer alloc.free(echo);
        const options: []const u8 = if (large and token & 16 != 0) &.{ 0x44, 4, 5, 0 } else &.{};
        const mark_ce = large and token & 32 != 0;
        const chunk = if (large) random.intRangeAtMost(usize, 96, 160) * 8 else 16;
        const parts = if (large) try std.math.divCeil(usize, echo.len, chunk) else if (split) @as(usize, 2) else 1;
        var storage: [8192]u8 = undefined;
        var frames = std.heap.FixedBufferAllocator.init(&storage);
        var received: usize = 0;
        var has_first = false;
        var final_len: ?usize = null;
        const entries = State.reassembly_tables[@intFromEnum(iface)].entries;
        const key: FragmentTable.Key = .{ .src = host, .dst = destination, .identification = id, .protocol = .icmp };
        for (0..parts) |i| {
            frames.reset();
            const part = if (token & 1 == 0) i else parts - 1 - i;
            const start = part * chunk;
            const end = if (part + 1 == parts) echo.len else start + chunk;
            try self.inject(try wire(frames.allocator(), mac, local_mac, .{
                .src = host,
                .dst = destination,
                .protocol = 1,
                .identification = id,
                .more_fragments = end < echo.len,
                .fragment_offset = @intCast(start / 8),
                .options = if (part == 0) options else &.{},
                .ecn = if (mark_ce) (if (part == 1) 3 else 2) else 0,
                .payload = echo[start..end],
            }));
            if (iface == .wan and i == 0 and start != 0) {
                try self.network.fragments[@intFromEnum(iface)].inserted(&State.wan_fragment_table, std.Io.Timestamp.now(self.network.io, .boot));
            }
            if (i + 1 == parts) break;
            try self.count(0);
            has_first = has_first or start == 0;
            if (end == echo.len) final_len = end;
            received += end - start;
            for (entries) |*entry| {
                if (entry.deadline.toNanoseconds() != 0 and std.meta.eql(entry.key, key) and
                    entry.received == received and entry.final_len == final_len and (entry.ip_header_len != 0) == has_first) break;
            } else return error.MissingPendingEcho;
        }
        for (entries) |*entry| if (entry.deadline.toNanoseconds() != 0 and std.meta.eql(entry.key, key)) return error.IncompleteEcho;
        const reply = try Packets.echo(alloc, .{ .message_type = 0, .data = bytes[0..length], .identifier = id });
        defer alloc.free(reply);
        const capacity = 1500 - 20 - options.len;
        const reply_chunk = if (reply.len <= capacity) reply.len else std.mem.alignBackward(usize, capacity, 8);
        const replies = try std.math.divCeil(usize, reply.len, reply_chunk);
        try self.count(replies);
        for (0..replies) |i| {
            frames.reset();
            const start = i * reply_chunk;
            const end = @min(start + reply_chunk, reply.len);
            _ = try self.expect(i, iface, try wire(frames.allocator(), local_mac, mac, .{
                .src = destination,
                .dst = host,
                .protocol = 1,
                .identification = id,
                .more_fragments = end < reply.len,
                .fragment_offset = @intCast(start / 8),
                .options = if (i == 0 or options.len == 0) options else &.{ 1, 1, 1, 1 },
                .ecn = if (mark_ce) 3 else 0,
                .payload = reply[start..end],
            }));
        }
    }

    fn fragments(self: *Peer, alloc: std.mem.Allocator, request: Job) !void {
        var job = request;
        const iface = self.iface;
        const host = if (iface == .lan) job.host() else gateway;
        const src_mac = if (iface == .lan) job.mac() else gateway_mac;
        const dst_mac = if (iface == .lan) lan_mac else wan_mac;
        try self.localEcho(alloc, host, src_mac, 122, false);
        try self.localEcho(alloc, host, src_mac, 123, true);
        try self.localEcho(alloc, host, src_mac, 202, true);
        const inbound = iface == .wan;
        const egress: IFace = if (inbound) .lan else .wan;
        const original_id: u16 = @truncate(self.network.seed);
        try self.transitFragments(alloc, &job, original_id, false);
        // A repeated train reuses the live translation, including when its tail arrives first.
        try self.transitFragments(alloc, &job, original_id, false);
        // Each sender can also originate an ICMP error quoting a translated packet it received.
        for ([_][2]u8{ .{ 3, 1 }, .{ 3, 3 }, .{ 3, 4 }, .{ 11, 0 }, .{ 11, 1 } }) |message| {
            const kind, const code = message;
            const rest = if (kind == 3 and code == 4) [4]u8{ 0, 0, 5, 220 } else [4]u8{ 0, 0, 0, 0 };
            const quoted = try packet(alloc, job, !inbound, true, 63);
            const restored = try packet(alloc, job, !inbound, false, 63);
            const msg = try Packets.icmp(alloc, .{
                .message_type = kind,
                .code = code,
                .body = try std.mem.concat(alloc, u8, &.{ &rest, quoted[14..42] }),
            });
            try self.inject(try wire(alloc, src_mac, dst_mac, .{
                .src = quoted[30..34].*,
                .dst = quoted[26..30].*,
                .protocol = 1,
                .payload = msg,
            }));
            const result = try Packets.icmp(alloc, .{
                .message_type = kind,
                .code = code,
                .body = try std.mem.concat(alloc, u8, &.{ &rest, restored[14..42] }),
            });
            try self.count(1);
            _ = try self.expect(0, egress, try wire(alloc, if (inbound) lan_mac else wan_mac, if (inbound) job.mac() else gateway_mac, .{
                .src = restored[30..34].*,
                .dst = restored[26..30].*,
                .ttl = 63,
                .protocol = 1,
                .payload = result,
            }));
        }
        for (State.reassembly_tables[@intFromEnum(iface)].entries) |*entry| if (entry.deadline.toNanoseconds() != 0) return error.IncompleteEcho;
    }
};

fn fragment(alloc: std.mem.Allocator, frame: []const u8, head: bool, id: u16) ![]u8 {
    const split: usize = if (frame[23] == 6) 24 else 16;
    return wire(alloc, frame[6..12].*, frame[0..6].*, .{
        .src = frame[26..30].*,
        .dst = frame[30..34].*,
        .protocol = frame[23],
        .ttl = frame[22],
        .identification = id,
        .more_fragments = head,
        .fragment_offset = if (head) 0 else @intCast(split / 8),
        .payload = if (head) frame[34..][0..split] else frame[34 + split ..],
    });
}

pub const ClientTurn = struct {
    peer: *Peer,
    alloc: std.mem.Allocator,
    id: u4,
    choice: ?Choice = null,
    burst: usize = 0,
    index: usize = 0,
    sent: ?Job = null,

    fn host(self: *const ClientTurn) IPv4 {
        return .{ 192, 168, 86, 2 + @as(u8, self.id) };
    }

    fn mac(self: *const ClientTurn) Mac {
        return .{ 2, 1, 0, 0, 0, self.host()[3] };
    }

    pub fn discover(self: *ClientTurn) !void {
        try self.lease(false);
    }

    pub fn requestLease(self: *ClientTurn) !void {
        try self.lease(true);
    }

    fn lease(self: *ClientTurn, request: bool) !void {
        const xid = 42 + @as(u32, self.id);
        const ethernet_id = [1]u8{1} ++ self.mac();
        const client_id: ?[]const u8 = if (self.id == self.peer.network.returning_client) &ethernet_id else null;
        try self.peer.inject(try Fixtures.DhcpClient.frame(self.alloc, self.mac(), .{
            .message_type = if (request) 3 else 1,
            .requested_ip = self.host(),
            .server_id = if (request) lan else null,
            .client_id = client_id,
            .xid = xid,
            .broadcast_flag = true,
        }));
        _ = try self.peer.dhcp(if (request) .ack else .offer, .{ .xid = xid, .client_id = client_id }, self.mac(), self.host());
        const address = (try self.peer.observation.take(0, .lan))[58..62].*;
        const index = State.dhcp_table.lookupByIp(address) orelse return error.MissingLanLease;
        const entry = State.dhcp_table.table.get(index);
        if (!std.meta.eql(entry.mac, self.mac()) or entry.state != @as(@TypeOf(entry.state), if (request) .bound else .offered)) return error.WrongLeaseState;
        if (client_id) |id| {
            if (State.dhcp_table.lookupByClient(.{ .id = id }) != index) return error.WrongLeaseState;
        }
        const client = &self.peer.network.clients[self.id];
        client.lease = if (request) .bound else .offered;
        if (request) client.lease_deadline = std.Io.Timestamp.now(self.peer.network.io, .boot).addDuration(.fromSeconds(86400));
    }

    fn requestRememberedLease(self: *ClientTurn) !void {
        const client = &self.peer.network.clients[self.id];
        const table = &State.dhcp_table;
        const client_id = [1]u8{1} ++ self.mac();
        const xid = @as(u32, if (client.lease == .bound) 0x20000 else 0x10000) + self.id;
        const count = table.table.len;
        const available = table.ip_pool.items.len;
        const neighbor = State.lan_arp_table.lookup(self.host());
        try self.peer.inject(try Fixtures.DhcpClient.frame(self.alloc, self.mac(), .{
            .message_type = 3,
            .client_id = &client_id,
            .requested_ip = self.host(),
            .xid = xid,
        }));
        if (client.lease == .bound) {
            _ = try self.peer.dhcp(.ack, .{ .xid = xid, .client_id = &client_id, .unicast_yiaddr = true }, self.mac(), self.host());
            const index = table.lookupByClient(.{ .id = &client_id }) orelse return error.MissingLanLease;
            const entry = table.table.get(index);
            const deadline = std.Io.Timestamp.now(self.peer.network.io, .boot).addDuration(.fromSeconds(86400));
            if (entry.client != .id or !std.mem.eql(u8, entry.client.id.bytes[0..entry.client.id.len], &client_id) or
                entry.state != .bound or !std.meta.eql(entry.ip, self.host()) or !std.meta.eql(entry.mac, self.mac()) or
                !std.meta.eql(entry.deadline, deadline) or deadline.toNanoseconds() <= client.lease_deadline.toNanoseconds()) return error.WrongLeaseState;
            client.lease_deadline = deadline;
        } else {
            try self.peer.expectDrop();
            if (table.lookupByIp(self.host()) != null or table.lookupByClient(.{ .id = &client_id }) != null) return error.UnexpectedRememberedLease;
        }
        if (table.table.len != count or table.ip_pool.items.len != available or
            !std.meta.eql(neighbor, State.lan_arp_table.lookup(self.host()))) return error.WrongLeaseState;
    }

    pub fn learnGateway(self: *ClientTurn) !void {
        try self.peer.learnGateway(self.alloc, self.id);
        self.peer.network.clients[self.id].knows_gateway = true;
    }

    pub fn fragmentedEcho(self: *ClientTurn) !void {
        try self.peer.localEcho(self.alloc, self.host(), self.mac(), self.choice.?.token, true);
    }

    pub fn multicastDns(self: *ClientTurn) !void {
        try self.peer.multicastDns(self.alloc, self.host(), self.mac());
        try self.peer.expectDrop();
    }

    pub fn ipv6MulticastDns(self: *ClientTurn) !void {
        try self.peer.ipv6MulticastDns(self.alloc, self.mac(), self.choice.?.token & 1 == 0);
    }

    pub fn transport(comptime flow: Scenarios.Flow) *const fn (*ClientTurn) anyerror!void {
        return struct {
            fn generate(self: *ClientTurn) !void {
                const network = self.peer.network;
                var choice = self.choice.?;
                choice.kind = flow;
                if ((flow == .tcp or flow == .dns_tcp) and choice.outcome != .ttl) {
                    const kind = @intFromEnum(flow);
                    if (network.bindings[kind][self.id][choice.socket] == null) choice.outcome = .reply;
                    network.ready_after[kind][self.id][choice.socket] = self.burst + network.reply_lag + 1;
                }
                if (self.index < forced_count and !std.meta.eql(choice, forced(self.index))) return error.MissingForcedConversation;
                var job = network.makeJob(choice);
                if (try self.peer.send(self.alloc, &job, false)) self.sent = job;
                if (self.index < forced_count and flow == .udp and choice.outcome == .unknown_peer) network.expiry_probe = job;
            }
        }.generate;
    }
};

pub const GatewayTurn = struct {
    peer: *Peer,
    alloc: std.mem.Allocator,
    random: std.Random,
    xid: u32 = 0,
    request: ?Job = null,

    fn lease(self: *GatewayTurn, kind: u8) !void {
        const options = try Fixtures.dhcpServerOptions(self.alloc, kind, gateway, mask, gateway, 3600);
        try self.peer.inject(try Fixtures.dhcpFrame(self.alloc, 2, self.xid, wan_mac, @splat(0), wan, gateway, @splat(255), options));
        try self.peer.count(0);
    }

    pub fn offerLease(self: *GatewayTurn) !void {
        try self.lease(2);
        const network = self.peer.network;
        try self.peer.tickWan();
        _ = try self.peer.dhcp(.request, .{ .xid = self.xid }, wan_mac, @splat(0));
        network.upstream = .offered;
    }

    pub fn acknowledgeLease(self: *GatewayTurn) !void {
        try self.lease(5);
        const bound = State.wanLease() orelse return error.MissingWanLease;
        if (!std.meta.eql(bound.ip, wan) or !std.meta.eql(bound.router, gateway) or !std.meta.eql(bound.subnet_mask, mask)) return error.WrongWanLease;
        self.peer.network.upstream = .bound;
    }

    pub fn answerFlow(self: *GatewayTurn) !void {
        try self.peer.answer(self.alloc, self.request.?);
    }

    pub fn refreshArp(self: *GatewayTurn) !void {
        try self.peer.inject(try arp(self.alloc, gateway_mac, gateway, wan, null));
        self.peer.network.gateway_learned = std.Io.Timestamp.now(self.peer.network.io, .boot);
        try self.peer.count(1);
        _ = try self.peer.expect(0, .wan, try arp(self.alloc, wan_mac, wan, gateway, gateway_mac));
    }

    pub fn fragmentedEcho(self: *GatewayTurn) !void {
        try self.peer.localEcho(self.alloc, gateway, gateway_mac, self.random.int(u32), true);
    }
};

pub const ConversationTurn = struct {
    peer: *Peer,
    index: usize,
    phase: usize,
};

const TcpStream = struct {
    client_acked: u32 = 0,
    server_received: u32 = 0,
    client_received: u32 = 0,
    connected: bool = false,
    unacknowledged: ?Choice = null,

    fn nextRequest(self: *TcpStream, choice: Choice) Choice {
        if (self.unacknowledged) |original| {
            var retry = choice;
            retry.token = original.token;
            retry.size = original.size;
            retry.payload_prefix = original.payload_prefix;
            return retry;
        }
        self.unacknowledged = choice;
        return choice;
    }

    fn receiveRequest(self: *TcpStream, request: *Job) !void {
        const end = request.requestEnd();
        if (request.seq != self.client_acked) return error.TcpSequenceGap;
        // A returning reply can be lost after the server has already received these bytes.
        if (request.seq == self.server_received) self.server_received = end else if (end != self.server_received) return error.TcpSequenceGap;
        request.reply_ack = self.server_received;
    }

    fn receiveReply(self: *TcpStream, reply: Job) !void {
        if (self.unacknowledged == null or reply.seq != self.client_acked or
            reply.reply_ack != self.server_received or reply.ack != self.client_received) return error.UnexpectedTcpReply;
        self.client_acked = self.server_received;
        self.client_received +%= @intCast(if (reply.syn) 1 else reply.len);
        self.connected = true;
        self.unacknowledged = null;
    }
};

test "bulk TCP retries the missing bytes after ICMP time exceeded before advancing the cumulative ACK" {
    const io = std.testing.io;
    var mock = Sim.Mock{ .io = io, .alloc = std.testing.allocator };
    var network = Network{ .io = io, .started = .zero, .mock = &mock, .barrier = .{ .io = io }, .width = 1, .seed = 42, .budget = 1 };
    var choice: Choice = .{ .host = 5, .socket = 21, .kind = .tcp, .outcome = .reply, .token = 21, .size = 32 };
    const stream = network.tcpStream(choice).?;
    var handshake = network.makeJob(choice);
    try stream.receiveRequest(&handshake);
    try stream.receiveReply(handshake);

    // Seed 42 sent bytes [1, 41) to port 443. The upstream gateway reported that they expired.
    choice.outcome = .time_exceeded;
    const lost = network.makeJob(choice);
    try std.testing.expectEqual(@as(u32, 1), lost.seq);
    try std.testing.expectEqual(@as(u32, 41), lost.requestEnd());
    var gap = lost;
    gap.seq = 41;
    try std.testing.expectError(error.TcpSequenceGap, stream.receiveRequest(&gap));

    // The first retransmission reaches the server, but its reply expires on the return leg.
    choice.token = 9000;
    choice.size = 203;
    choice.payload_prefix = "new data".*;
    var storage: [2048]u8 = undefined;
    for ([_]Scenarios.Outcome{ .wan_ttl, .reply }) |outcome| {
        choice.outcome = outcome;
        var retry = network.makeJob(choice);
        try std.testing.expectEqual(lost.seq, retry.seq);
        try std.testing.expectEqualSlices(u8, lost.payload[0..lost.len], retry.payload[0..retry.len]);
        try stream.receiveRequest(&retry);
        var scratch = std.heap.FixedBufferAllocator.init(&storage);
        const reply = try packet(scratch.allocator(), retry, true, false, 64);
        try std.testing.expectEqual(@as(u32, 41), std.mem.readInt(u32, reply[42..46], .big));
        if (outcome == .reply) try stream.receiveReply(retry);
    }
    const next = network.makeJob(choice);
    try std.testing.expectEqual(@as(u32, 41), next.seq);
    try std.testing.expectEqual(@as(u32, 41), next.ack);
    try std.testing.expectEqualSlices(u8, "new data", next.payload[0..8]);
}

pub const Network = struct {
    const PortSpace = enum { icmp, tcp, udp };
    const Binding = struct { port: u16, generation: u64, deadline: std.Io.Timestamp };
    mock: *Sim.Mock,
    io: std.Io,
    started: std.Io.Timestamp,
    barrier: Barrier,
    width: usize,
    reply_lag: usize = 1,
    seed: u64,
    budget: usize,
    workload: Workload = .{},
    filtering_mode: FilteringMode = .address_restricted,
    jobs: [max_reply_lag + 1][batch]?Job = undefined,
    cold: Job = undefined,
    returning_client: u4 = 1,
    returning_flow: Job = undefined,
    queued: [5]Job = undefined,
    gateway_learned: std.Io.Timestamp = .zero,
    lan_learned: [16]std.Io.Timestamp = @splat(.zero),
    clients: [16]Scenarios.Client = @splat(.{}),
    upstream: Scenarios.Lease = .unconfigured,
    weights: Scenarios.Weights = .{},
    scenario_counts: std.EnumArray(Scenarios.ClientScenario, usize) = .initFill(0),
    episodes: Scenarios.ConversationState = undefined,
    gateway_counts: std.EnumArray(Scenarios.WanScenario, usize) = .initFill(0),
    conversations: std.EnumArray(Scenarios.Conversation, usize) = .initFill(0),
    fragment_jobs: [3]Job = undefined,
    wan_change: @import("scenarios/tcp.zig").WanChange = undefined,
    renewal_nak: @import("scenarios/renewal_nak.zig") = undefined,
    sleeping_client: @import("scenarios/neighbor.zig").SleepingClient = .{},
    dns_retry: @import("scenarios/dns.zig").Retry = undefined,
    stun_retry: @import("scenarios/stun_discovery.zig").Retry = undefined,
    audio_call: @import("scenarios/rtcp.zig") = undefined,
    subscriptions: @import("scenarios/coap.zig") = undefined,
    tcp_retries: @import("scenarios/tcp_retries.zig") = undefined,
    persist: @import("scenarios/tcp_persist.zig") = undefined,
    guests: @import("scenarios/lease.zig").JoiningClients = .{},
    fragments: [2]FragmentModel = @splat(.{}),
    opened: [forced_count]?Job = @splat(null),
    expiry_probe: Job = undefined,
    // Only LAN creates bindings. The model independently predicts port preservation and collisions.
    bindings: [flow_count][16][32]?Binding = @splat(@splat(@splat(null))),
    binding_count: usize = 0,
    conversation_bindings: usize = 0,
    used: [3]std.StaticBitSet(65536) = @splat(.initEmpty()),
    next: [3]u16 = @splat(49152),
    ready_after: [flow_count][16][32]usize = @splat(@splat(@splat(0))),
    tcp_streams: [2][16][32]TcpStream = @splat(@splat(@splat(.{}))),
    failure: [2]?anyerror = .{ null, null },

    pub fn newConversationBinding(self: *Network) usize {
        const generation = self.binding_count + self.conversation_bindings;
        self.conversation_bindings += 1;
        return generation;
    }

    pub fn reservePort(self: *Network, space: PortSpace, preferred: u16) u16 {
        const index = @intFromEnum(space);
        const used = &self.used[index];
        const port = if (preferred >= 1024 and !used.isSet(preferred)) preferred else find: {
            for (1024..65536) |_| {
                const candidate = self.next[index];
                self.next[index] = if (candidate == 65535) 1024 else candidate + 1;
                if (!used.isSet(candidate)) break :find candidate;
            }
            // A run has fewer NAT slots than public ports in a single transport.
            unreachable;
        };
        used.set(port);
        return port;
    }

    pub fn releasePort(self: *Network, space: PortSpace, port: u16) void {
        const used = &self.used[@intFromEnum(space)];
        std.debug.assert(used.isSet(port));
        used.unset(port);
    }

    fn tcpStream(self: *Network, choice: Choice) ?*TcpStream {
        return switch (choice.kind) {
            .tcp, .dns_tcp => &self.tcp_streams[@intFromBool(choice.kind == .dns_tcp)][choice.host][choice.socket],
            else => null,
        };
    }

    fn makeJob(self: *Network, selected: Choice) Job {
        const stream = self.tcpStream(selected);
        const choice = if (stream) |tcp| tcp.nextRequest(selected) else selected;
        const kind = @intFromEnum(choice.kind);
        const port: u16 = 20000 + @as(u16, choice.socket);
        const slot = &self.bindings[kind][choice.host][choice.socket];
        const protocol: PortSpace = switch (choice.kind) {
            .ping => .icmp,
            .tcp, .dns_tcp => .tcp,
            else => .udp,
        };
        const is_new = slot.* == null;
        var public = if (slot.*) |b| b.port else port;
        if (is_new and choice.outcome != .ttl) {
            public = self.reservePort(protocol, port);
            slot.* = .{ .port = public, .generation = self.binding_count, .deadline = .zero };
            self.binding_count += 1;
        }
        if (choice.outcome != .ttl) {
            const lifetime = ([_]i64{ 60, 7440, 300 })[@intFromEnum(protocol)];
            slot.*.?.deadline = std.Io.Timestamp.now(self.io, .boot).addDuration(.fromSeconds(lifetime));
        }
        var job = Job{
            .choice = choice,
            .public_port = public,
            .source_port = port,
            .remote = if (choice.kind == .dns_udp or choice.kind == .dns_tcp) dns else .{ 203, 0, 113, 1 + @as(u8, choice.socket) },
            .payload = undefined,
            .len = 8 + @as(usize, choice.size),
            .request_len = undefined,
            .syn = if (stream) |tcp| !tcp.connected else false,
            .seq = if (stream) |tcp| tcp.client_acked else 0,
            .ack = if (stream) |tcp| tcp.client_received else 0,
        };
        for (job.payload[0..job.len], 0..) |*b, i| b.* = @truncate((choice.token >> @intCast(8 * (i % 4))) +% @as(u32, @intCast(i)));
        if (choice.payload_prefix) |bytes| job.payload[0..bytes.len].* = bytes;
        if (job.isDns()) job.makeDnsQuery(@truncate(job.choice.token), "www".*);
        if (job.syn) job.len = 0;
        job.request_len = job.len;
        return job;
    }

    fn checkAllocatedPorts(self: *const Network) !void {
        const nat = &State.nat_table;
        for ([_]*const Router.Tables.NatTable.PortAllocator{ &nat.icmp_ports, &nat.tcp_ports, &nat.udp_ports }, &self.used, self.next) |allocator, *used, next| {
            if (!allocator.used.eql(used.*) or allocator.next != next) return error.WrongAllocatedPorts;
        }
    }

    // At the barrier both workers have finished their inputs for this millisecond.
    fn checkNat(self: *const Network) !void {
        const nat = &State.nat_table;
        if (nat.inside.count() != self.binding_count or nat.outside.count() != self.binding_count or
            nat.next_generation != self.binding_count) return error.WrongBindingCount;
        try self.checkAllocatedPorts();
        for (&self.bindings, 0..) |*hosts, kind_index| for (hosts, 0..) |*sockets, host| for (sockets, 0..) |maybe, socket| {
            const binding = maybe orelse continue;
            const kind: @FieldType(Choice, "kind") = @enumFromInt(kind_index);
            const key: Nat.Key = .{
                .ip = .{ 192, 168, 86, @intCast(2 + host) },
                .port = @intCast(20000 + socket),
                .protocol = switch (kind) {
                    .tcp, .dns_tcp => .tcp,
                    .udp, .dns_udp => .udp,
                    .ping => .icmp,
                },
                .service_peer = if (kind == .dns_tcp or kind == .dns_udp) .{ .ip = dns, .port = 53 } else null,
            };
            const outside: Nat.Key = .{ .ip = wan, .port = binding.port, .protocol = key.protocol };
            const peer = key.service_peer orelse Nat.Peer{
                .ip = .{ 203, 0, 113, @intCast(1 + socket) },
                .port = if (kind == .ping) key.port else 443,
            };
            const entry = nat.inside.get(key) orelse return error.MissingNatState;
            if (!std.meta.eql(entry.outside, outside) or !std.meta.eql(nat.outside.get(outside), @as(?Nat.Key, key)) or
                entry.generation != binding.generation or entry.deadline.toNanoseconds() != binding.deadline.toNanoseconds() or
                entry.peer_count != 1 or !std.meta.eql(entry.peers[0], peer))
            {
                std.log.debug("unexpected NAT state for {t} {any}:{d}, public port {d}", .{ key.protocol, key.ip, key.port, binding.port });
                return error.WrongNatState;
            }
        };
    }

    fn checkLeasesAndArp(self: *const Network) !void {
        const lease = State.wanLease() orelse return error.MissingWanLease;
        if (!std.meta.eql(lease.ip, wan) or !std.meta.eql(lease.router, gateway) or
            !std.meta.eql(lease.server_id, gateway) or !std.meta.eql(lease.subnet_mask, mask) or
            !std.meta.eql(lease.renewal_deadline, self.started.addDuration(.fromSeconds(1800))) or
            !std.meta.eql(lease.rebinding_deadline, self.started.addDuration(.fromSeconds(3150))) or
            !std.meta.eql(lease.expiration_deadline, self.started.addDuration(.fromSeconds(3600)))) return error.WrongWanLease;
        const dhcp = &State.dhcp_table;
        if (State.wan_transaction != null or dhcp.reclaim != null or dhcp.table.len != 16 or
            dhcp.ip_pool.items.len != 237 or dhcp.excluded_ips.items.len != 0) return error.WrongLeaseState;
        var available = std.StaticBitSet(256).initEmpty();
        for (dhcp.ip_pool.items) |ip| {
            if (!std.mem.eql(u8, ip[0..3], lan[0..3]) or ip[3] < 18 or ip[3] == 255 or available.isSet(ip[3])) return error.WrongLeasePool;
            available.set(ip[3]);
        }
        if (State.lan_arp_table.table.len != 16 or State.wan_arp_table.table.len != 1 or
            State.arp_waiters_table.table.count() != 0) return error.WrongArpState;
        const gateway_index = State.wan_arp_table.indexOfValue(.ip, gateway) orelse return error.WrongArpState;
        const upstream = State.wan_arp_table.table.get(gateway_index);
        if (!std.meta.eql(upstream.mac, gateway_mac) or !std.meta.eql(upstream.timestamp, self.gateway_learned)) return error.WrongArpState;
        var seen = std.StaticBitSet(16).initEmpty();
        for (0..dhcp.table.len) |i| {
            const entry = dhcp.table.get(i);
            if (!std.mem.eql(u8, entry.ip[0..3], lan[0..3]) or entry.ip[3] < 2 or entry.ip[3] > 17 or
                entry.state != .bound or !std.meta.eql(entry.deadline, self.clients[entry.ip[3] - 2].lease_deadline)) return error.WrongLeaseState;
            const mac: Mac = .{ 2, 1, 0, 0, 0, entry.ip[3] };
            if (!std.meta.eql(entry.mac, mac) or seen.isSet(entry.ip[3] - 2)) return error.WrongLeaseState;
            seen.set(entry.ip[3] - 2);
            const index = State.lan_arp_table.indexOfValue(.ip, entry.ip) orelse return error.WrongArpState;
            const neighbor = State.lan_arp_table.table.get(index);
            const learned = self.lan_learned[entry.ip[3] - 2];
            if (!std.meta.eql(neighbor.mac, mac) or !std.meta.eql(neighbor.timestamp, learned)) return error.WrongArpState;
        }
    }

    fn checkFragments(self: *const Network) !void {
        if (self.mock.outstanding.load(.monotonic) != 0) return error.UnexpectedPendingBuffers;
        for (&self.fragments, &State.reassembly_tables, [_]*const FragmentTable{ &State.lan_fragment_table, &State.wan_fragment_table }) |*model, *reassembly, table| {
            for (reassembly.entries) |*entry| if (!std.meta.eql(entry.deadline, std.Io.Timestamp.zero)) return error.IncompleteEcho;
            try model.check(table);
        }
    }

    fn startup(self: *Network, peer: *Peer, phase: Startup, rng: std.Random) !void {
        var stack = std.heap.FixedBufferAllocator.init(&peer.scratch);
        const alloc = stack.allocator();
        const cold_choice: Choice = .{
            .host = 0,
            .socket = 0,
            .kind = .udp,
            .outcome = .reply,
            .token = 123,
            .size = 32,
        };
        switch (phase) {
            .acquire_leases => return peer.setup(alloc, rng),
            .queue_for_gateway => if (peer.iface == .lan) {
                var job = self.makeJob(cold_choice);
                _ = try peer.send(alloc, &job, true);
                self.cold = job;
                for (&self.queued, 0..) |*queued, i| {
                    stack.reset();
                    var next = cold_choice;
                    next.token += @intCast(i + 1);
                    queued.* = self.makeJob(next);
                    try peer.inject(try packet(alloc, queued.*, false, false, 64));
                    try peer.count(0);
                }
                const pending = State.arp_waiters_table.table.get(.{ .iface = .wan, .ip = gateway }) orelse return error.MissingArpWaiter;
                if (pending.len != self.queued.len + 1 or self.mock.outstanding.load(.monotonic) != pending.len) return error.WrongArpState;
            },
            .resolve_gateway => if (peer.iface == .wan) {
                try peer.inject(try arp(alloc, gateway_mac, gateway, wan, wan_mac));
                try peer.count(1 + self.queued.len);
                const tx = try peer.expect(0, .wan, try packet(alloc, self.cold, false, true, 63));
                self.cold.public_port = std.mem.readInt(u16, tx[34..36], .big);
                @memcpy(self.cold.payload[0..self.cold.len], tx[tx.len - self.cold.len ..]);
                for (self.queued, 1..) |queued, index| {
                    stack.reset();
                    _ = try peer.expect(index, .wan, try packet(alloc, queued, false, true, 63));
                }
                self.gateway_learned = std.Io.Timestamp.now(self.io, .boot);
                if (State.arp_waiters_table.table.count() != 0 or !std.meta.eql(State.wan_arp_table.lookup(gateway), @as(?Mac, gateway_mac))) return error.WrongArpState;
            },
            .queue_for_client => if (peer.iface == .wan) {
                const host = self.cold.host();
                try peer.inject(try packet(alloc, self.cold, true, false, 64));
                try peer.count(1);
                _ = try peer.expect(0, .lan, try arp(alloc, lan_mac, lan, host, null));
                const pending = State.arp_waiters_table.table.get(.{ .iface = .lan, .ip = host }) orelse return error.MissingArpWaiter;
                if (pending.len != 1 or State.lan_arp_table.lookup(host) != null) return error.WrongArpState;
            },
            .resolve_client => if (peer.iface == .lan) {
                const host = self.cold.host();
                try peer.inject(try arp(alloc, self.cold.mac(), host, lan, lan_mac));
                self.lan_learned[0] = std.Io.Timestamp.now(self.io, .boot);
                try peer.count(1);
                _ = try peer.expect(0, .lan, try packet(alloc, self.cold, true, true, 63));
                if (State.arp_waiters_table.table.count() != 0 or !std.meta.eql(State.lan_arp_table.lookup(host), @as(?Mac, self.cold.mac()))) return error.WrongArpState;
            },
            .returning_client_dora => if (peer.iface == .lan) {
                var host = [1]u4{self.returning_client};
                try peer.acquireClients(&host, rng);
            },
            .confirm_remembered_lease => if (peer.iface == .lan) {
                var client: ClientTurn = .{ .peer = peer, .alloc = alloc, .id = self.returning_client };
                try client.requestRememberedLease();
                stack.reset();
                self.returning_flow = self.makeJob(.{
                    .host = self.returning_client,
                    .socket = 1,
                    .kind = .udp,
                    .outcome = .reply,
                    .token = rng.int(u32),
                    .size = 32,
                });
                _ = try peer.send(alloc, &self.returning_flow, false);
            },
            .returning_client_reply => if (peer.iface == .wan) {
                try peer.answer(alloc, self.returning_flow);
            },
            .echo_and_fragments => return peer.fragments(alloc, self.cold),
            .open_fragment_flows, .accept_fragment_flows, .fragmented_requests, .fragmented_responses => {
                if ((phase == .open_fragment_flows or phase == .fragmented_requests) != (peer.iface == .lan)) return;
                for ([_]@FieldType(Choice, "kind"){ .tcp, .dns_udp, .dns_tcp }, &self.fragment_jobs, 0..) |kind, *job, i| {
                    stack.reset();
                    if (peer.iface == .lan) {
                        var choice = forced(i);
                        choice.kind = kind;
                        job.* = self.makeJob(choice);
                    }
                    if (phase == .open_fragment_flows) {
                        _ = try peer.send(alloc, job, false);
                    } else if (phase == .accept_fragment_flows) {
                        if (job.isDns()) {
                            const key = job.insideKey();
                            const nat = &State.nat_table;
                            const before = nat.inside.get(key) orelse return error.MissingNatState;
                            var wrong_port = job.*;
                            wrong_port.reply_source_port = 5300;
                            wrong_port.makeResponse();
                            try peer.inject(try packet(alloc, wrong_port, true, false, 64));
                            try peer.expectDrop();
                            if (!std.meta.eql(nat.inside.get(key), @as(?Nat.Entry, before)) or
                                !std.meta.eql(nat.outside.get(before.outside), @as(?Nat.Key, key))) return error.WrongNatState;
                        }
                        try peer.answer(alloc, job.*);
                        var other = job.*;
                        other.choice.outcome = .unknown_peer;
                        try peer.answer(alloc, other);
                    } else {
                        const stream = self.tcpStream(job.choice);
                        if (peer.iface == .wan) {
                            if (stream) |tcp| try tcp.receiveRequest(job);
                            job.makeResponse();
                        }
                        const head_first = ((self.seed ^ i) & 1 == 0) == (peer.iface == .lan);
                        try peer.transitFragments(alloc, job, @intCast(i + 124), head_first);
                        if (peer.iface == .wan) {
                            if (stream) |tcp| try tcp.receiveReply(job.*);
                        }
                    }
                }
            },
            .open_tcp => if (peer.iface == .lan) {
                for (&self.opened, 0..) |*slot, i| {
                    var choice = forced(i);
                    if ((choice.kind != .tcp and choice.kind != .dns_tcp) or choice.outcome == .ttl) continue;
                    stack.reset();
                    choice.outcome = .reply;
                    var job = self.makeJob(choice);
                    _ = try peer.send(alloc, &job, false);
                    slot.* = job;
                }
            },
            .accept_tcp => if (peer.iface == .wan) {
                for (self.opened) |slot| {
                    stack.reset();
                    if (slot) |job| try peer.answer(alloc, job);
                }
            },
            .ipv6_multicast_dns => {
                try peer.ipv6MulticastDns(alloc, if (peer.iface == .lan) self.cold.mac() else gateway_mac, peer.iface == .lan);
            },
            .link_discovery => {
                if (peer.iface == .lan) {
                    try peer.multicastDns(alloc, self.cold.host(), self.cold.mac());
                    try peer.expectDrop();
                } else {
                    // Two 802.1Q tags and protocol 112 occur together in isp_to_router.pcap.
                    const tags = [_]Packets.VlanTag{ .{ .vid = 4090 }, .{ .vid = 999 } };
                    var advertisement = [_]u8{ 0x21, 90, 100, 1, 0, 1, 0, 0 } ++ wan ++ [_]u8{0} ** 8;
                    const sum = Router.Meta.Checksum.checksumContribution(&advertisement);
                    std.mem.writeInt(u16, advertisement[6..8], ~@as(u16, @truncate((sum & 0xffff) + (sum >> 16))), .big);
                    const frame = try Packets.eth(alloc, .{
                        .src = gateway_mac,
                        .dst = .{ 1, 0, 0x5e, 0, 0, 18 },
                        .vlan_tags = &tags,
                        .payload = try Packets.ipv4(alloc, .{
                            .src = gateway,
                            .dst = .{ 224, 0, 0, 18 },
                            .ttl = 255,
                            .protocol = 112,
                            .payload = &advertisement,
                        }),
                    });
                    const previous = peer.seen;
                    peer.seen = .empty;
                    defer peer.seen.setUnion(previous);
                    if (!try peer.dispatch(frame) or !peer.seen.contains(.ipv4)) return error.WrongTaggedDispatch;
                    try peer.expectDrop();

                    // A local response uses the request's VLAN stack on the same link.
                    for ([2]bool{ false, true }) |reply| {
                        const bytes = try Packets.eth(alloc, .{
                            .src = if (reply) wan_mac else gateway_mac,
                            .dst = if (reply) gateway_mac else wan_mac,
                            .vlan_tags = &tags,
                            .payload = try Packets.ipv4(alloc, .{
                                .src = if (reply) wan else gateway,
                                .dst = if (reply) gateway else wan,
                                .protocol = 1,
                                .payload = try Packets.echo(alloc, .{ .message_type = if (reply) 0 else 8, .identifier = 90, .data = "uplink" }),
                            }),
                        });
                        if (reply) {
                            try peer.count(1);
                            _ = try peer.expect(0, .wan, bytes);
                        } else try peer.inject(bytes);
                    }
                }
            },
        }
    }

    fn conversationKind(self: *Network, index: usize) Scenarios.Conversation {
        var random = std.Random.DefaultPrng.init(self.seed +% index);
        const required = Scenarios.mandatory_conversations;
        return if (index < required.len)
            required[index]
        else if (index - required.len < self.workload.conversations.len)
            self.workload.conversations[index - required.len]
        else
            Scenarios.chooseConversation(.bound, self.weights, random.random()).?;
    }

    fn conversation(self: *Network, peer: *Peer, kind: Scenarios.Conversation, index: usize, phase: usize) !void {
        if (self.upstream != .bound) return error.InvalidGatewayTransition;
        if (phase == 0 and peer.iface == .lan) self.conversations.getPtr(kind).* += 1;
        var turn: ConversationTurn = .{ .peer = peer, .index = index, .phase = phase };
        try Scenarios.generate(Scenarios.conversations, kind, &turn);
    }

    fn selectClientScenario(self: *const Network, choice: *Choice, required: bool, burst: usize, random: std.Random) !Scenarios.ClientScenario {
        const preferred = if (required) Scenarios.flowScenario(choice.kind) else choice.scenario;
        // A TCP-only workload may pick a socket still waiting for its SYN-ACK.
        // Cycle through bound clients' sockets until the selected profile can run.
        for (0..self.clients.len * 32) |_| {
            const available = self.clients[choice.host].available(
                self.upstream,
                burst >= self.ready_after[@intFromEnum(Scenarios.Flow.tcp)][choice.host][choice.socket],
                burst >= self.ready_after[@intFromEnum(Scenarios.Flow.dns_tcp)][choice.host][choice.socket],
            );
            if (preferred) |scenario| if (available.contains(scenario)) return scenario;
            if (required) return error.MissingForcedConversation;
            if (Scenarios.choose(available, self.weights, random)) |scenario| return scenario;
            choice.socket +%= 1;
            if (choice.socket == 0) choice.host +%= 1;
        }
        return error.NoClientScenario;
    }

    fn bulk(self: *Network, peer: *Peer, burst: usize, rng: std.Random) !void {
        var stack = std.heap.FixedBufferAllocator.init(&peer.scratch);
        const alloc = stack.allocator();
        if (peer.iface == .lan) {
            const start = @min(burst * self.width, self.budget);
            const stop = @min(start + self.width, self.budget);
            for (start..stop) |packet_index| {
                stack.reset();
                var choice = if (packet_index < forced_count) forced(packet_index) else if (packet_index < forced_count + self.workload.choices.len) self.workload.choices[packet_index - forced_count] else Choice{
                    .host = rng.int(u4),
                    .socket = rng.int(u5),
                    .kind = rng.enumValue(@FieldType(Choice, "kind")),
                    .outcome = if (rng.int(u4) != 0) .reply else rng.enumValue(@FieldType(Choice, "outcome")),
                    .token = rng.int(u32),
                    .size = rng.int(u8),
                };
                const required = packet_index < forced_count;
                const scenario = try self.selectClientScenario(&choice, required, burst, rng);
                self.scenario_counts.getPtr(scenario).* += 1;
                var turn: ClientTurn = .{ .peer = peer, .alloc = alloc, .id = choice.host, .choice = choice, .burst = burst, .index = packet_index };
                try Scenarios.generate(Scenarios.clients, scenario, &turn);
                self.jobs[burst % self.jobs.len][packet_index % self.width] = turn.sent;
            }
        } else if (burst >= self.reply_lag) {
            const sent_burst = burst - self.reply_lag;
            const start = sent_burst * self.width;
            var indices: [batch]usize = undefined;
            const order = indices[0..@min(self.width, self.budget - start)];
            for (order, 0..) |*index, i| index.* = start + i;
            rng.shuffle(usize, order);
            for (order) |packet_index| {
                stack.reset();
                const request = self.jobs[sent_burst % self.jobs.len][packet_index % self.width];
                const scenario = Scenarios.gatewayScenario(self.upstream, if (request != null) .flow else .idle, self.weights, rng) orelse return error.InvalidGatewayTransition;
                self.gateway_counts.getPtr(scenario).* += 1;
                var turn: GatewayTurn = .{ .peer = peer, .alloc = alloc, .random = rng, .request = request };
                try Scenarios.generate(Scenarios.gateways, scenario, &turn);
            }
        }
    }
};

const flow_count = std.meta.fields(Scenarios.Flow).len;
const forced_count = flow_count * std.meta.fields(Scenarios.Outcome).len;

fn forced(i: usize) Choice {
    return .{
        .host = @truncate(i),
        .socket = @truncate(i),
        .kind = @enumFromInt(i % flow_count),
        .outcome = @enumFromInt(i / flow_count),
        .token = @intCast(i),
        .size = 32,
    };
}

test "fragment model checks every registered train and detects a changed translation" {
    const alloc = std.testing.allocator;
    var table = try FragmentTable.init(alloc, std.testing.io, 3, .fromSeconds(30));
    defer table.table.deinit(alloc);
    var model: FragmentModel = .{};
    defer model.entries.deinit(alloc);
    const now = std.Io.Timestamp.now(std.testing.io, .boot);
    const deadline = now.addDuration(.fromSeconds(30));
    for ([_]u16{ 30000, 19, 6110 }, 0..) |id, i| {
        const key: FragmentTable.Key = .{ .src = lan, .dst = gateway, .protocol = .udp, .identification = id };
        const value: FragmentTable.Translation = .{
            .nat_key = .{ .ip = lan, .port = 55000, .protocol = .udp },
            .nat_generation = 12,
            .first_payload_len = 24,
            .identification = @intCast(i),
        };
        table.table.putAssumeCapacity(key, .{ .deadline = deadline, .state = .{ .resolved = value } });
        table.next_identification += 1;
        try model.entries.append(alloc, .{ .key = key, .deadline = deadline, .translation = value });
        model.next_id += 1;
    }
    try model.check(&table);
    const key = model.entries.items[2].key;
    table.table.getPtr(key).?.state.resolved.identification += 1;
    try std.testing.expectError(error.WrongFragmentState, model.check(&table));
}

test "UDP allocation during WAN renewal preserves existing sockets and consumes one public port" {
    const alloc = std.testing.allocator;
    const clock = Clock.vtable(std.testing.io);
    const io: std.Io = .{ .vtable = &clock, .userdata = std.testing.io.userdata };
    var nat = try Nat.init(alloc, io, 3);
    defer nat.deinit(alloc);
    const job: Job = .{
        .choice = forced(0),
        .public_port = 49152,
        .source_port = 101,
        .remote = .{ 203, 0, 113, 1 },
        .payload = undefined,
        .len = 0,
        .request_len = 0,
        .syn = false,
        .seq = 0,
        .ack = 0,
    };
    const remote: Nat.Peer = .{ .ip = job.remote, .port = job.service() };
    var original = job.insideKey();
    original.port = 20000;
    _ = try nat.mapOutbound(&nat.udp_ports, original, wan, .fromSeconds(300), remote);
    const expected = try Peer.RenewalAllocation.predict(alloc, &nat, job, 1, io);
    defer alloc.free(expected.prior);
    _ = try nat.mapOutbound(&nat.udp_ports, job.insideKey(), wan, .fromSeconds(300), remote);
    try expected.check(&nat, job.insideKey());
    nat.inside.getPtr(original).?.deadline = .zero;
    try std.testing.expectError(error.UnrelatedMappingChanged, expected.check(&nat, job.insideKey()));
    nat.inside.getPtr(original).?.deadline = expected.prior[0].entry.deadline;
    nat.udp_ports.used.set(job.public_port + 1);
    try std.testing.expectError(error.WrongRenewalAllocation, expected.check(&nat, job.insideKey()));
}

test "wire assertions must account for each input and every declared output" {
    var peer: Peer = .{ .network = undefined, .iface = .lan, .expected = null };
    try peer.beginObservation();
    try std.testing.expectError(error.UncheckedObservation, peer.beginObservation());
    try peer.count(0);
    try peer.finishObservation();
    try peer.beginObservation();
    try peer.count(2);
    try std.testing.expectError(error.UncheckedObservation, peer.finishObservation());
    try std.testing.expectError(error.UnexpectedOutputAssertion, peer.expect(1, .lan, "skipped first output"));
}

test "port oracle keeps transport pools separate and skips reserved ports across cursor wrap" {
    var network: Network = undefined;
    network.used = @splat(.initEmpty());
    network.next = .{ 49152, 65535, 49152 };
    const equal = std.testing.expectEqual;
    try equal(@as(u16, 38010), network.reservePort(.tcp, 38010));
    try equal(@as(u16, 38010), network.reservePort(.udp, 38010));
    try equal(@as(u16, 65535), network.reservePort(.tcp, 65535));
    try equal(@as(u16, 1024), network.reservePort(.tcp, 1024));
    try equal(@as(u16, 1025), network.reservePort(.tcp, 38010));
    network.releasePort(.tcp, 38010);
    try equal(@as(u16, 38010), network.reservePort(.tcp, 38010));
    try equal(@as(u16, 1026), network.reservePort(.tcp, 101));
    try equal(@as(u16, 49152), network.reservePort(.udp, 38010));
}

test "NAT oracle detects changes to a live mapping even when no frame was transmitted" {
    var clock = Clock.vtable(std.testing.io);
    const io: std.Io = .{ .vtable = &clock, .userdata = std.testing.io.userdata };
    var mock = Sim.Mock{ .io = io, .alloc = std.testing.allocator };
    var network = Network{
        .io = io,
        .started = std.Io.Timestamp.now(io, .boot),
        .mock = &mock,
        .barrier = .{ .io = io },
        .width = 1,
        .seed = 0,
        .budget = 1,
    };
    const table = &State.nat_table;
    table.* = try Nat.init(std.testing.allocator, io, 1);
    defer table.deinit(std.testing.allocator);
    const job = network.makeJob(forced(0));
    const key = job.insideKey();
    _ = try table.mapOutbound(&table.udp_ports, key, wan, .fromSeconds(300), .{
        .ip = job.remote,
        .port = job.service(),
    });
    try network.checkNat();
    const entry = table.inside.getPtr(key).?;
    const deadline = entry.deadline;
    entry.deadline = deadline.addDuration(.fromMilliseconds(1));
    try std.testing.expectError(error.WrongNatState, network.checkNat());
    entry.deadline = deadline;
    entry.peer_count = 0;
    try std.testing.expectError(error.WrongNatState, network.checkNat());
    entry.peer_count = 1;
    table.udp_ports.used.set(44000);
    try std.testing.expectError(error.WrongAllocatedPorts, network.checkNat());
    table.udp_ports.used.unset(44000);
    try network.checkNat();
}

pub fn run(
    io: std.Io,
    mock: *Sim.Mock,
    seed: u64,
    budget: usize,
    workload: Workload,
    expected: ?*[2]Sim.Output,
    weights: Scenarios.Weights,
) !void {
    try Scenarios.validate(weights);
    Sim.phase = 0;
    var schedule = std.Random.DefaultPrng.init(seed);
    const lag = workload.reply_lag orelse schedule.random().intRangeAtMost(u8, 1, max_reply_lag);
    if (lag < 1 or lag > max_reply_lag or workload.burst_width == 0 or workload.burst_width > batch) return error.InvalidWorkload;
    // Even a TCP-only profile must have a free socket until the earliest replies arrive.
    const sockets = 16 * 32;
    var network = Network{
        .width = @min(workload.burst_width, sockets / (1 + @as(usize, lag))),
        .reply_lag = lag,
        .io = io,
        .started = std.Io.Timestamp.now(io, .boot),
        .mock = mock,
        .barrier = .{ .io = io },
        .seed = seed,
        .returning_client = @intCast(1 + seed % 15),
        .budget = @max(budget, workload.choices.len + forced_count),
        .workload = workload,
        .filtering_mode = workload.filtering_mode,
        .weights = weights,
    };
    var lan_peer = Peer{ .network = &network, .iface = .lan, .expected = expected };
    var wan_peer = Peer{ .network = &network, .iface = .wan, .expected = expected };
    defer lan_peer.observation.deinit(mock.alloc);
    defer wan_peer.observation.deinit(mock.alloc);
    Router.Debug.Cli.enabled = false;
    const previous_mode = State.nat_filtering_mode;
    State.nat_filtering_mode = workload.filtering_mode;
    defer State.nat_filtering_mode = previous_mode;
    try Runtime.setup(mock.alloc, io, mock.api(), lan, mask);
    {
        defer Runtime.teardown(mock.alloc, mock.api());
        defer for (&network.fragments) |*model| model.entries.deinit(mock.alloc);
        for (&network.fragments, [_]*const FragmentTable{ &State.lan_fragment_table, &State.wan_fragment_table }) |*model, table| {
            try model.entries.ensureTotalCapacity(mock.alloc, table.capacity);
        }
        const t = try std.Thread.spawn(.{}, worker, .{&wan_peer});
        worker(&lan_peer);
        t.join();
        for (network.failure) |err| if (err) |e| return e;
        if (mock.outstanding.load(.monotonic) != 0) return error.UnexpectedPendingBuffers;
    }
    if (mock.outstanding.load(.monotonic) != 0) return error.UnreleasedNicBuffers;
    var required = std.EnumSet(Router.Debug.Cli.EntryPoint).initFull();
    for ([_]Router.Debug.Cli.EntryPoint{ .rx, .tx, .release }) |event| required.remove(event);
    for ([_]*Peer{ &lan_peer, &wan_peer }) |peer| {
        if (peer.iface == .wan) required.remove(.dns);
        var missing = required.differenceWith(peer.seen).iterator();
        if (missing.next()) |entry| {
            std.log.err("{t} never reached {t}", .{ peer.iface, entry });
            return error.MissingHandlerCoverage;
        }
    }
    if (!@import("builtin").is_test) std.debug.print("seed {d}: LAN RX {d}, WAN RX {d}, verified TX {d}, verified silent drops {d}; all required protocol handlers reached\n", .{
        seed,
        lan_peer.rx,
        wan_peer.rx,
        lan_peer.tx + wan_peer.tx,
        lan_peer.drops + wan_peer.drops,
    });
    if (!@import("builtin").is_test) {
        std.debug.print("LAN catalog dispatches", .{});
        inline for (std.meta.tags(Scenarios.ClientScenario)) |scenario| std.debug.print(" {t}={d}", .{ scenario, network.scenario_counts.get(scenario) });
        std.debug.print("\nWAN catalog dispatches", .{});
        inline for (std.meta.tags(Scenarios.WanScenario)) |scenario| std.debug.print(" {t}={d}", .{ scenario, network.gateway_counts.get(scenario) });
        std.debug.print("\nconversation catalog dispatches", .{});
        inline for (std.meta.tags(Scenarios.Conversation)) |kind| std.debug.print(" {t}={d}", .{ kind, network.conversations.get(kind) });
        std.debug.print("\n", .{});
    }
}

fn worker(peer: *Peer) void {
    Clock.resetWorker();
    const network = peer.network;
    Sim.observation = &peer.observation;
    defer Sim.observation = null;
    Router.Debug.Cli.visited = &peer.seen;
    defer Router.Debug.Cli.visited = null;
    var prng = std.Random.DefaultPrng.init(network.seed);
    const traffic_end = first_burst + network.reply_lag + (std.math.divCeil(usize, network.budget, network.width) catch unreachable);
    const conversation_count = @max(Scenarios.mandatory_conversations.len + network.workload.conversations.len, std.math.clamp(network.budget / 512, 1, 128));
    var episode: usize = 0;
    var phase: usize = 0;
    var lifecycle_index: usize = 0;
    var round: usize = 0;
    while (lifecycle_index < std.meta.fields(Lifecycle).len) : (round += 1) {
        network.barrier.wait();
        const traffic = round < traffic_end;
        const kind = if (!traffic and episode < conversation_count) network.conversationKind(episode) else null;
        const step: Lifecycle = @enumFromInt(lifecycle_index);
        Sim.phase = if (traffic or kind != null) Startup.elapsed(round) else step.at(Startup.elapsed(round - lifecycle_index), network);
        const result = if (round < first_burst)
            network.startup(peer, @enumFromInt(round), prng.random())
        else if (traffic)
            network.bulk(peer, round - first_burst, prng.random())
        else if (kind) |conversation|
            network.conversation(peer, conversation, episode, phase)
        else
            peer.lifecycle(step);
        if (kind) |conversation| {
            phase += 1;
            if (phase == Scenarios.steps(conversation)) {
                phase = 0;
                episode += 1;
            }
        } else if (!traffic) lifecycle_index += 1;
        const verified = if (result) |_| peer.finishObservation() else |err| err;
        verified catch |err| {
            network.failure[@intFromEnum(peer.iface)] = err;
            const scenario = if (round < first_burst) @tagName(@as(Startup, @enumFromInt(round))) else if (traffic) "bulk" else if (kind) |k| @tagName(k) else @tagName(step);
            std.log.err("scenario {s} on {t}: {t} (round {d}, RX {d})", .{ scenario, peer.iface, err, round, peer.rx });
        };
        // A failed producer must never publish a partially filled batch.
        network.barrier.wait();
        if (round >= @intFromEnum(Startup.echo_and_fragments)) {
            if (peer.iface == .lan and network.failure[0] == null and network.failure[1] == null) {
                if (traffic) {
                    if (round == @intFromEnum(Startup.echo_and_fragments)) _ = network.makeJob(network.cold.choice);
                    network.checkNat() catch |err| {
                        network.failure[@intFromEnum(peer.iface)] = err;
                        std.log.err("NAT state after round {d}: {t}", .{ round, err });
                    };
                    network.checkLeasesAndArp() catch |err| {
                        network.failure[@intFromEnum(peer.iface)] = err;
                        std.log.err("lease or ARP state after round {d}: {t}", .{ round, err });
                    };
                    network.checkFragments() catch |err| {
                        network.failure[@intFromEnum(peer.iface)] = err;
                        std.log.err("fragment state after round {d}: {t}", .{ round, err });
                    };
                } else network.checkAllocatedPorts() catch |err| {
                    network.failure[@intFromEnum(peer.iface)] = err;
                    std.log.err("NAT port allocation after round {d}: {t}", .{ round, err });
                };
            }
            network.barrier.wait();
        }
        if (network.failure[0] != null or network.failure[1] != null) break;
    }
}
