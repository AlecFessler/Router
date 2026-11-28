//! The scenario catalog drives selection, dispatch, configuration and coverage counts.
const std = @import("std");
const Sim = @import("../network_sim.zig");
const Tcp = @import("tcp.zig");

pub const Lease = enum { unconfigured, offered, bound };
pub const Flow = enum { udp, tcp, dns_udp, dns_tcp, ping };
pub const Outcome = enum { reply, ttl, unknown_peer, port_unreachable, time_exceeded, unmapped, wan_ttl };
pub const GatewayInput = enum { discover, request, flow, idle };
const ClientState = enum { unconfigured, offered, needs_arp, local, online, tcp_ready, dns_tcp_ready };

fn Entry(comptime Context: type, comptime Condition: type) type {
    return struct {
        when: Condition,
        weight: ?u16,
        generate: *const fn (*Context) anyerror!void,

        fn scenario(when: Condition, weight: ?u16, callback: *const fn (*Context) anyerror!void) @This() {
            return .{ .when = when, .weight = weight, .generate = callback };
        }
    };
}

const client = Entry(Sim.ClientTurn, ClientState).scenario;
pub const clients = .{
    .discover = client(.unconfigured, null, Sim.ClientTurn.discover),
    .request_lease = client(.offered, null, Sim.ClientTurn.requestLease),
    .resolve_gateway = client(.needs_arp, null, Sim.ClientTurn.learnGateway),
    .tcp = client(.tcp_ready, 54, Sim.ClientTurn.transport(.tcp)),
    .udp = client(.online, 27, Sim.ClientTurn.transport(.udp)),
    .dns_udp = client(.online, 9, Sim.ClientTurn.transport(.dns_udp)),
    .dns_tcp = client(.dns_tcp_ready, 2, Sim.ClientTurn.transport(.dns_tcp)),
    .ping = client(.online, 3, Sim.ClientTurn.transport(.ping)),
    .arp_refresh = client(.local, 1, Sim.ClientTurn.learnGateway),
    .fragmented_echo = client(.local, 2, Sim.ClientTurn.fragmentedEcho),
    .multicast_dns = client(.local, 2, Sim.ClientTurn.multicastDns),
    .ipv6_multicast_dns = client(.local, 1, Sim.ClientTurn.ipv6MulticastDns),
};

const gateway = Entry(Sim.GatewayTurn, GatewayInput).scenario;
pub const gateways = .{
    .offer_lease = gateway(.discover, null, Sim.GatewayTurn.offerLease),
    .acknowledge_lease = gateway(.request, null, Sim.GatewayTurn.acknowledgeLease),
    .answer_flow = gateway(.flow, null, Sim.GatewayTurn.answerFlow),
    .arp_refresh = gateway(.idle, 3, Sim.GatewayTurn.refreshArp),
    .fragmented_echo = gateway(.idle, 1, Sim.GatewayTurn.fragmentedEcho),
};

const PeerRotation = @import("peer_rotation.zig");
const PathMtu = @import("path_mtu.zig");
const Dns = @import("dns.zig");
const Echo = @import("echo.zig");

fn episode(when: Lease, weight: u16, comptime Program: type, mandatory: bool) struct {
    when: Lease,
    weight: ?u16,
    Program: type,
    steps: usize,
    mandatory: bool,
    generate: *const fn (*Sim.ConversationTurn) anyerror!void,
} {
    return .{ .when = when, .weight = weight, .steps = std.meta.fields(Program.Steps).len, .Program = Program, .generate = Program.step, .mandatory = mandatory };
}
pub const conversations = .{
    .download = episode(.bound, 5, Tcp.Download, true),
    .peer_rotation = episode(.bound, 1, PeerRotation, false),
    .path_mtu = episode(.bound, 1, PathMtu, true),
    .parallel_dns = episode(.bound, 2, Dns.ParallelDns, true),
    .duplex_tcp = episode(.bound, 2, Tcp.DuplexTransfer, true),
    .cancelled_download = episode(.bound, 1, Tcp.CancelledDownload, true),
    .receive_window_update = episode(.bound, 1, Tcp.WindowUpdate, true),
    .dns_fallback = episode(.bound, 1, Dns.Fallback, true),
    .interleaved_echo = episode(.bound, 1, Echo, true),
    .fragmented_feedback = episode(.bound, 1, @import("fragmented_feedback.zig"), false),
};

pub const ClientScenario = std.meta.FieldEnum(@TypeOf(clients));
pub const WanScenario = std.meta.FieldEnum(@TypeOf(gateways));
pub const Conversation = std.meta.FieldEnum(@TypeOf(conversations));

// A catalog row owns the state its callback keeps between packets.
pub const ConversationState = blk: {
    const fields = std.meta.fields(@TypeOf(conversations));
    var names: [fields.len][]const u8 = undefined;
    var types: [fields.len]type = undefined;
    for (fields, 0..) |field, i| {
        names[i] = field.name;
        types[i] = @field(conversations, field.name).Program;
    }
    break :blk @Struct(.auto, null, &names, &types, &@as([fields.len]std.builtin.Type.StructField.Attributes, @splat(.{})));
};

pub const mandatory_conversations = blk: {
    var tags: []const Conversation = &.{};
    for (std.meta.tags(Conversation)) |kind| {
        if (@field(conversations, @tagName(kind)).mandatory) tags = tags ++ .{kind};
    }
    break :blk tags;
};

pub fn steps(kind: Conversation) usize {
    return switch (kind) {
        inline else => |k| @field(conversations, @tagName(k)).steps,
    };
}

pub fn generate(comptime table: anytype, id: std.meta.FieldEnum(@TypeOf(table)), turn: anytype) !void {
    const received = turn.peer.rx;
    switch (id) {
        inline else => |tag| try @field(table, @tagName(tag)).generate(turn),
    }
    // A multi-turn conversation can wait while the other interface acts.
    if (@TypeOf(turn.*) != Sim.ConversationTurn and turn.peer.rx == received) return error.EmptyScenario;
}

// Only selectable frequencies are configurable. The names and defaults come from the catalog.
pub const Weights = blk: {
    var names: []const []const u8 = &.{};
    var attrs: []const std.builtin.Type.StructField.Attributes = &.{};
    for (.{ clients, conversations, gateways }, .{ "", "", "wan_" }) |table, prefix| {
        for (std.meta.fields(@TypeOf(table))) |field| {
            const weight = @field(table, field.name).weight orelse continue;
            names = names ++ .{prefix ++ field.name};
            attrs = attrs ++ .{std.builtin.Type.StructField.Attributes{ .default_value_ptr = &weight }};
        }
    }
    break :blk @Struct(.auto, null, names, &@as([names.len]type, @splat(u16)), attrs[0..names.len]);
};

fn chooseWeighted(comptime table: anytype, comptime prefix: []const u8, available: std.EnumSet(std.meta.FieldEnum(@TypeOf(table))), weights: Weights, random: std.Random) ?std.meta.FieldEnum(@TypeOf(table)) {
    const Tag = std.meta.FieldEnum(@TypeOf(table));
    var total: u32 = 0;
    inline for (comptime std.meta.tags(Tag)) |s| if (available.contains(s)) {
        total += if (@field(table, @tagName(s)).weight == null) 1 else @field(weights, prefix ++ @tagName(s));
    };
    if (total == 0) return null;
    var ticket = random.uintLessThan(u32, total);
    inline for (comptime std.meta.tags(Tag)) |s| if (available.contains(s)) {
        const weight: u32 = if (@field(table, @tagName(s)).weight == null) 1 else @field(weights, prefix ++ @tagName(s));
        if (ticket < weight) return s;
        ticket -= weight;
    };
    unreachable;
}

pub fn validate(weights: Weights) !void {
    inline for (.{ clients, conversations, gateways }, .{ "", "", "wan_" }, .{ error.EmptyScenarioWeights, error.EmptyConversationWeights, error.EmptyGatewayWeights }) |table, prefix, err| {
        var total: u32 = 0;
        inline for (std.meta.fields(@TypeOf(table))) |field| {
            if (@field(table, field.name).weight != null) total += @field(weights, prefix ++ field.name);
        }
        if (total == 0) return err;
    }
}

pub const Client = struct {
    lease: Lease = .unconfigured,
    lease_deadline: std.Io.Timestamp = .zero,
    knows_gateway: bool = false,

    pub fn available(self: Client, upstream: Lease, tcp_ready: bool, dns_tcp_ready: bool) std.EnumSet(ClientScenario) {
        const local = self.lease == .bound and self.knows_gateway;
        const online = local and upstream == .bound;
        var set: std.EnumSet(ClientScenario) = .empty;
        inline for (comptime std.meta.tags(ClientScenario)) |s| {
            const when = comptime @field(clients, @tagName(s)).when;
            const ready = switch (when) {
                .unconfigured => self.lease == .unconfigured,
                .offered => self.lease == .offered,
                .needs_arp => self.lease == .bound and !self.knows_gateway,
                .local => local,
                .online => online,
                .tcp_ready => online and tcp_ready,
                .dns_tcp_ready => online and dns_tcp_ready,
            };
            if (ready) set.insert(s);
        }
        return set;
    }
};

pub fn choose(available: std.EnumSet(ClientScenario), weights: Weights, random: std.Random) ?ClientScenario {
    return chooseWeighted(clients, "", available, weights, random);
}

pub fn flowScenario(kind: Flow) ClientScenario {
    return switch (kind) {
        inline else => |flow| @field(ClientScenario, @tagName(flow)),
    };
}

pub fn gatewayScenario(lease: Lease, input: GatewayInput, weights: Weights, random: std.Random) ?WanScenario {
    const ready = switch (input) {
        .discover => lease == .unconfigured,
        .request => lease == .offered,
        .flow, .idle => lease == .bound,
    };
    if (!ready) return null;
    var available: std.EnumSet(WanScenario) = .empty;
    inline for (comptime std.meta.tags(WanScenario)) |s| if (@field(gateways, @tagName(s)).when == input) {
        available.insert(s);
    };
    return chooseWeighted(gateways, "wan_", available, weights, random);
}

pub fn chooseConversation(lease: Lease, weights: Weights, random: std.Random) ?Conversation {
    var available: std.EnumSet(Conversation) = .empty;
    inline for (comptime std.meta.tags(Conversation)) |s| if (@field(conversations, @tagName(s)).when == lease) {
        available.insert(s);
    };
    return chooseWeighted(conversations, "", available, weights, random);
}

pub const Download = struct {
    client: u4,
    client_seq: u32,
    server_seq: u32,
    segments: u8,
    retransmit: bool,
    reset: bool,

    pub fn init(random: std.Random) Download {
        return .{
            .client = random.int(u4),
            .client_seq = random.int(u32),
            .server_seq = random.int(u32),
            .segments = random.intRangeAtMost(u8, 2, 6),
            .retransmit = random.boolean(),
            .reset = random.boolean(),
        };
    }
};

pub const Startup = enum {
    acquire_leases,
    queue_for_gateway,
    resolve_gateway,
    queue_for_client,
    resolve_client,
    returning_client_dora,
    confirm_remembered_lease,
    returning_client_reply,
    echo_and_fragments,
    open_fragment_flows,
    accept_fragment_flows,
    fragmented_requests,
    fragmented_responses,
    open_tcp,
    accept_tcp,
    link_discovery,
    ipv6_multicast_dns,

    pub fn elapsed(round: usize) usize {
        // The returning client waits for a reply before discovery, then reconnects later.
        if (round >= @intFromEnum(Startup.confirm_remembered_lease)) return round + 34_000;
        if (round >= @intFromEnum(Startup.returning_client_dora)) return round + 4_000;
        return round;
    }
};

pub const Lifecycle = enum {
    contact_peers,
    delayed_replies,
    guest_discovery,
    guest_requests,
    guest_connectivity,
    guest_echo_replies,
    guest_departures,
    decline,
    before_reclaim,
    reclaim_due,
    before_first_probe,
    first_probe,
    before_second_probe,
    second_probe,
    before_third_probe,
    third_probe,
    before_reoffer,
    reoffer,
    cache_gateway,
    renew,
    address_conflict,
    restart,
    bind_again,
    retry_renewal,
    rebind,
    wan_change_syn,
    wan_change_accept,
    wan_change_request,
    expire,
    after_expiry,
    rejected_offer,
    new_wan_address,
    use_new_lease,
    resolve_new_gateway,
    resolve_return_host,
    sleeping_client_queries,
    sleeping_client_replies,
    sleeping_client_still_waiting,
    sleeping_client_timeout,
    sleeping_client_late_arp,
    sleeping_client_retries,
    sleeping_client_recovers,
    wan_change_reconnect,
    wan_change_accept_again,
    wan_change_retry,
    wan_change_response,
    wan_change_ack,

    pub fn at(step: Lifecycle, traffic_end: usize) u64 {
        const probes = @import("lease.zig").reclaimTimes(traffic_end + 1000);
        return switch (step) {
            .contact_peers => traffic_end + 1,
            .delayed_replies => traffic_end + 2,
            .guest_discovery => traffic_end + 10,
            .guest_requests => traffic_end + 30,
            .guest_connectivity => traffic_end + 80,
            .guest_echo_replies => traffic_end + 110,
            .guest_departures => traffic_end + 950,
            .decline => traffic_end + 1000,
            .before_reclaim => probes.start - 1,
            .reclaim_due => probes.start,
            .before_first_probe => probes.first - 1,
            .first_probe => probes.first,
            .before_second_probe => probes.second - 1,
            .second_probe => probes.second,
            .before_third_probe => probes.third - 1,
            .third_probe => probes.third,
            .before_reoffer => probes.finish - 1,
            .reoffer => probes.finish,
            .cache_gateway => 1799000,
            .renew => 1800000,
            .address_conflict => 1800001,
            .restart => 1800002,
            .bind_again => 1800003,
            .retry_renewal => 1808003,
            .rebind => 1814003,
            .wan_change_syn => 1814100,
            .wan_change_accept => 1814125,
            .wan_change_request => 1814150,
            .expire => 1816003,
            .after_expiry => 1816004,
            .rejected_offer => 1816005,
            .new_wan_address => 1816006,
            .use_new_lease => 1816007,
            .resolve_new_gateway => 1816008,
            .resolve_return_host => 1816009,
            .sleeping_client_queries => 1816010,
            .sleeping_client_replies => 1816011,
            .sleeping_client_still_waiting => 1818010,
            .sleeping_client_timeout => 1818011,
            .sleeping_client_late_arp => 1818012,
            .sleeping_client_retries => 1818013,
            .sleeping_client_recovers => 1818014,
            .wan_change_reconnect => 1819000,
            .wan_change_accept_again => 1819025,
            .wan_change_retry => 1819050,
            .wan_change_response => 1819075,
            .wan_change_ack => 1819100,
        };
    }
};
