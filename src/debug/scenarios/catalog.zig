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
    .ntp = episode(.bound, 1, @import("ntp.zig"), true),
    .half_closed_upload = episode(.bound, 1, @import("half_closed_upload.zig"), true),
    .udp_filtering = episode(.bound, 1, @import("udp_filtering.zig"), true),
    .stun_discovery = episode(.bound, 1, @import("stun_discovery.zig"), false),
    .traceroute = episode(.bound, 1, @import("traceroute.zig"), true),
    .ecn_tcp = episode(.bound, 1, @import("ecn_tcp.zig"), true),
    .rtp_checksums = episode(.bound, 1, @import("udp_filtering.zig").EchoCall, true),
    .gateway_failover = episode(.bound, 1, @import("gateway_failover.zig"), false),
    .pipelined_dns = episode(.bound, 1, @import("pipelined_dns.zig"), true),
    .negative_dns = episode(.bound, 1, @import("negative_dns.zig"), true),
    .edns_udp = episode(.bound, 1, @import("edns.zig"), true),
    .udp_hairpin = episode(.bound, 1, @import("udp_hairpin.zig"), false),
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
    guest_lost_offer,
    guest_discovery,
    guest_requests,
    guest_connectivity,
    guest_echo_replies,
    guest_first_release,
    guest_replacement_discover,
    guest_replacement_request,
    opening_syn,
    opening_retry_syn,
    opening_syn_ack,
    opening_lost_ack,
    opening_retry_syn_ack,
    opening_ack,
    opening_request,
    opening_response,
    opening_response_ack,
    guest_replacement_retry,
    guest_replacement_connectivity,
    guest_replacement_reply,
    guest_departures,
    static_inform,
    static_dns_query,
    static_dns_answer,
    decline,
    stun_initial_request,
    dns_initial_query,
    stun_retry_request,
    stun_success,
    dns_retransmit,
    dns_delayed_answer,
    dns_duplicate_answer,
    audio_start,
    audio_second,
    audio_third,
    audio_first_sr,
    audio_first_rr,
    audio_resume,
    audio_fifth,
    audio_sixth,
    audio_second_sr,
    audio_second_rr,
    persist_syn,
    persist_syn_ack,
    persist_request,
    persist_fill,
    persist_zero,
    persist_probe,
    persist_zero_ack,
    persist_lost_update,
    persist_retry,
    persist_open_ack,
    persist_resume,
    persist_done,
    udp_subscribe,
    udp_initial_reading,
    closing_server_fin,
    closing_client_ack,
    closing_client_fin,
    closing_lost_ack,
    closing_retry_fin,
    closing_ack,
    udp_first_ping,
    udp_first_pong,
    udp_second_ping,
    udp_second_pong,
    udp_last_live,
    udp_idle_deadline,
    udp_after_idle,
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
    nak_gateway,
    nak_lookup,
    nak_renew,
    nak_refusal,
    nak_offline,
    nak_offer,
    nak_second_offer,
    nak_bind,
    nak_retry,
    nak_resolve_gateway,
    nak_answer,
    rebind_server_neighbor,
    rebind_unicast,
    rebind_broadcast,
    rebind_ack,
    rebind_lookup,
    rebind_route,
    rebind_answer,
    rebind_backup_neighbor,
    rebind_backup_renewal,

    pub fn at(step: Lifecycle, traffic_end: usize, network: *const Sim.Network) u64 {
        var random = std.Random.DefaultPrng.init(network.seed);
        const after_offer_timeout = traffic_end + random.random().intRangeAtMost(u16, 3000, 5000);
        const after_ack_timeout = after_offer_timeout + random.random().intRangeAtMost(u16, 3000, 5000);
        const first_query = after_ack_timeout + 1500;
        const dns_retry = first_query + random.random().intRangeAtMost(u16, 2000, 5000);
        const audio_start = dns_retry + 250;
        const persist = audio_start + 8000;
        const subscriptions = persist + 3500;
        const probes = @import("lease.zig").reclaimTimes(after_ack_timeout + 1000);
        return switch (step) {
            .contact_peers => traffic_end + 1,
            .delayed_replies => traffic_end + 2,
            .guest_lost_offer => traffic_end + 10,
            .guest_discovery => after_offer_timeout + 10,
            .guest_requests => after_offer_timeout + 30,
            .guest_connectivity => after_offer_timeout + 80,
            .guest_echo_replies => after_offer_timeout + 110,
            .guest_first_release => after_offer_timeout + 250,
            .guest_replacement_discover => after_offer_timeout + 400,
            .guest_replacement_request => after_offer_timeout + 425,
            .opening_syn => after_offer_timeout + 500,
            .opening_retry_syn => after_offer_timeout + 1500,
            .opening_syn_ack => after_offer_timeout + 1525,
            .opening_lost_ack => after_offer_timeout + 1550,
            .opening_retry_syn_ack => after_offer_timeout + 2525,
            .opening_ack => after_offer_timeout + 2550,
            .opening_request => after_offer_timeout + 2700,
            .opening_response => after_offer_timeout + 2750,
            .opening_response_ack => after_offer_timeout + 2775,
            .guest_replacement_retry => after_ack_timeout + 425,
            .guest_replacement_connectivity => after_ack_timeout + 500,
            .guest_replacement_reply => after_ack_timeout + 530,
            .guest_departures => after_ack_timeout + 950,
            .static_inform => after_ack_timeout + 960,
            .static_dns_query => after_ack_timeout + 970,
            .static_dns_answer => after_ack_timeout + 990,
            .decline => after_ack_timeout + 1000,
            .stun_initial_request => first_query - 480,
            .dns_initial_query => first_query,
            .stun_retry_request => first_query + 20,
            .stun_success => first_query + 20 + random.random().intRangeAtMost(u16, 15, 90),
            .dns_retransmit => dns_retry,
            .dns_delayed_answer => dns_retry + 45,
            .dns_duplicate_answer => dns_retry + 215,
            .audio_start, .audio_second, .audio_third, .audio_first_sr, .audio_first_rr, .audio_resume, .audio_fifth, .audio_sixth, .audio_second_sr, .audio_second_rr => @import("rtcp.zig").at(audio_start, network.seed, step),
            .persist_syn => persist,
            .persist_syn_ack => persist + 25,
            .persist_request => persist + 50,
            .persist_fill => persist + 75,
            .persist_zero => persist + 100,
            .persist_probe => persist + 1100,
            .persist_zero_ack => persist + 1125,
            .persist_lost_update => persist + 1400,
            .persist_retry => persist + 3100,
            .persist_open_ack => persist + 3125,
            .persist_resume => persist + 3150,
            .persist_done => persist + 3175,
            .udp_subscribe => subscriptions,
            .udp_initial_reading => subscriptions + 5,
            .closing_server_fin => subscriptions + 5000,
            .closing_client_ack => subscriptions + 5025,
            .closing_client_fin => subscriptions + 5075,
            .closing_lost_ack => subscriptions + 5100,
            .closing_retry_fin => subscriptions + 6075,
            .closing_ack => subscriptions + 6100,
            .udp_first_ping => subscriptions + 120_000,
            .udp_first_pong => subscriptions + 120_005,
            .udp_second_ping => subscriptions + 240_000,
            .udp_second_pong => subscriptions + 240_005,
            .udp_last_live => subscriptions + 299_999,
            .udp_idle_deadline => subscriptions + 300_000,
            .udp_after_idle => subscriptions + 300_001,
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
            .nak_gateway => 3615900,
            .nak_lookup => 3615950,
            .nak_renew => 3616006,
            .nak_refusal => 3616031,
            .nak_offline => 3628031,
            .nak_offer => 3628081,
            .nak_second_offer => 3628095,
            .nak_bind => 3628110,
            .nak_retry, .nak_resolve_gateway, .nak_answer => 3628031 + @as(u64, random.random().intRangeAtMost(u16, 2000, 5000)) + @as(u64, switch (step) {
                .nak_retry => 0,
                .nak_resolve_gateway => 2,
                else => 40,
            }),
            .rebind_server_neighbor, .rebind_unicast, .rebind_broadcast, .rebind_ack, .rebind_lookup, .rebind_route, .rebind_answer, .rebind_backup_neighbor, .rebind_backup_renewal => network.renewal_nak.offers.rebindTime(network.started, step),
        };
    }
};
