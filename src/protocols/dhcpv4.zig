const std = @import("std");
const Router = @import("router");

const Cli = Router.Debug.Cli;
const CsvParser = DHCPv4Fixtures.CsvParser;
const DHCPv4Fixtures = Router.TestFixtures.DHCPv4;
const DhcpTable = Router.Tables.DhcpTable.DhcpTable;
const Ethernet = Router.Protocols.Ethernet;
const EthernetFrameView = Router.Protocols.Ethernet.EthernetFrameView;
const FixtureUtils = Router.TestFixtures.Utils;
const Format = Router.Meta.Format;
const IFace = Router.Nic.Api.IFace;
const IPv4 = Router.Protocols.IPv4.IPv4;
const IPv4PacketView = Router.Protocols.IPv4.IPv4PacketView;
const IPv4Protocol = Router.Protocols.IPv4;
const Mac = Router.Protocols.Ethernet.Mac;
const NicApi = Router.Nic.Api.Api;
const PcapParser = Router.TestFixtures.PcapParser;
const UdpPacketView = Router.Protocols.Udp.UdpPacketView;
const UdpProtocol = Router.Protocols.Udp;
const View = Router.Meta.View.View;
const ViewStack = Router.Protocols.ViewStack;

const classifyDestination = Router.Protocols.IPv4.classifyDestination;
const expectHexBytes = FixtureUtils.expectHexBytes;
const queueForArpResolution = Router.Protocols.Arp.queueForArpResolution;

const dhcp_table = &Router.State.dhcp_table;
const lan_ip = &Router.State.lan_ip;
const lan_subnet_mask = &Router.State.lan_subnet_mask;
const wan_arp_table = &Router.State.wan_arp_table;
const wan_lease = &Router.State.wan_lease;

const ZERO_IP: IPv4 = .{ 0, 0, 0, 0 };
const BROADCAST_IP: IPv4 = .{0xff} ** 4;
const BROADCAST_MAC: Mac = .{0xff} ** 6;
const DHCP_HEADER_LEN = 240;
const MAX_OPTIONS_LEN = 576 - 20 - 8 - DHCP_HEADER_LEN;
const MIN_OPTIONS_LEN = 300 - DHCP_HEADER_LEN;
const LAN_DNS = [2]IPv4{ .{ 8, 8, 8, 8 }, .{ 8, 8, 4, 4 } };
const LAN_LEASE = std.Io.Duration.fromSeconds(86_400);
const OFFER_HOLD = std.Io.Duration.fromSeconds(30);
const INITIAL_RETRY_SECONDS = 4;
const MAX_RETRY_SECONDS = 64;

const WAN_PARAMETER_REQUEST_LIST = [_]OptionType{
    .subnet_mask,
    .router,
    .dns_servers,
    .lease_time,
    .server_id,
    .renewal_time,
    .rebinding_time,
};

const WanTransaction = struct {
    xid: u32,
    started_at: std.Io.Timestamp,
    discover_secs: u16 = 0,
    requested_ip: ?IPv4 = null,
    expected_server: ?IPv4 = null,
    request_sent_at: ?std.Io.Timestamp = null,
    next_send: std.Io.Timestamp = .zero,
    retry_seconds: i64 = INITIAL_RETRY_SECONDS,
};

const RxOptions = struct {
    message_type: ?MessageType = null,
    requested_ip_address: ?IPv4 = null,
    server_id: ?IPv4 = null,
    client_id: ?[]u8 = null,
    subnet_mask: ?IPv4 = null,
    router: ?IPv4 = null,
    lease_time: ?std.Io.Duration = null,
    renewal_time: ?std.Io.Duration = null,
    rebinding_time: ?std.Io.Duration = null,
};

const Tx = struct {
    kind: MessageType,
    xid: u32,
    mac: Mac,
    client_id: ?[]u8 = null,
    secs: u16 = 0,
    ciaddr: IPv4 = ZERO_IP,
    yiaddr: IPv4 = ZERO_IP,
    server_id: ?IPv4 = null,
    requested_ip: ?IPv4 = null,
    lease_time: ?std.Io.Duration = null,
    src_ip: IPv4 = ZERO_IP,
    dst_ip: IPv4 = BROADCAST_IP,
    dst_mac: Mac = BROADCAST_MAC,
    arp_target: ?IPv4 = null,
    broadcast: bool,
    vlan_tags: []u8 = &.{},
};

var wan_transaction: ?WanTransaction = null;

pub const DHCPv4Lease = struct {
    ip: IPv4,
    subnet_mask: IPv4,
    router: IPv4,
    server_id: IPv4,
    renewal_deadline: std.Io.Timestamp,
    rebinding_deadline: std.Io.Timestamp,
    expiration_deadline: std.Io.Timestamp,
};

pub const Op = enum(u8) {
    BOOTREQUEST = 0x1,
    BOOTREPLY = 0x2,
    _,
};

const DHCPV4_MAGIC = 0x63825363;

pub const DHCPv4Packet = struct {
    op: Op,
    htype: u8 = 0x1,
    hlen: u8 = 0x6,
    hops: u8 = 0,
    xid: u32,
    secs: u16,
    broadcast_flag: bool,
    reserved_flags: u15 = 0,
    client_ip: IPv4,
    your_ip: IPv4,
    next_server_ip: IPv4,
    relay_agent_ip: IPv4,
    client_hw_addr: [16]u8,
    server_name: [64]u8,
    file: [128]u8,
    magic: u32 = DHCPV4_MAGIC,
    options: []u8,
};

pub const DHCPv4PacketView = View(DHCPv4Packet);

pub const OptionType = enum(u8) {
    pad = 0,
    subnet_mask = 1,
    router = 3,
    dns_servers = 6,
    host_name = 12,
    domain_name = 15,
    interface_mtu = 26,
    broadcast_address = 28,
    static_route = 33,
    requested_ip_address = 50,
    lease_time = 51,
    message_type = 53,
    server_id = 54,
    parameter_request_list = 55,
    max_message_size = 57,
    renewal_time = 58,
    rebinding_time = 59,
    client_id = 61,
    domain_search = 119,
    classless_static_route = 121,
    end = 255,
    _,
};

pub const Option = struct {
    code: OptionType,
    len: u8,
    data: []u8,
};

pub const OptionView = View(Option);

pub const MessageType = enum(u8) {
    discover = 0x1,
    offer = 0x2,
    request = 0x3,
    decline = 0x4,
    ack = 0x5,
    nak = 0x6,
    release = 0x7,
    inform = 0x8,
    _,
};

pub const StaticRoute = extern struct {
    destination: IPv4,
    router: IPv4,
};

pub const OptionValue = union(enum) {
    subnet_mask: IPv4,
    router: []const IPv4,
    dns_servers: []const IPv4,
    host_name: []u8,
    domain_name: []u8,
    interface_mtu: u16,
    broadcast_address: IPv4,
    static_route: []const StaticRoute,
    requested_ip_address: IPv4,
    lease_time: std.Io.Duration,
    message_type: MessageType,
    server_id: IPv4,
    parameter_request_list: []const OptionType,
    max_message_size: u16,
    renewal_time: std.Io.Duration,
    rebinding_time: std.Io.Duration,
    client_id: []u8,
    domain_search: []u8,
    classless_static_route: []u8,
};

pub fn validate(view: DHCPv4PacketView) !void {
    try view.validate(.htype, .{ .eq = 0x1 });
    try view.validate(.hlen, .{ .eq = 0x6 });
    try view.validate(.reserved_flags, .{ .eq = 0 });
    try view.validate(.magic, .{ .eq = DHCPV4_MAGIC });
}

pub fn parse(buffer: []const u8) !DHCPv4PacketView {
    var view: DHCPv4PacketView = undefined;
    var reader: std.Io.Reader = .fixed(buffer);
    try view.takeFields(.op, .magic, &reader);
    try view.takeBytes(.options, reader.bufferedLen(), &reader);
    try validate(view);
    return view;
}

pub fn parseOption(reader: *std.Io.Reader) !?OptionValue {
    while (true) {
        const code: OptionType = @enumFromInt(try reader.peekByte());
        switch (code) {
            .pad => {
                _ = try reader.takeByte();
                continue;
            },
            .end => {
                _ = try reader.takeByte();
                return null;
            },
            else => {},
        }

        var view: OptionView = undefined;
        try view.takeFields(.code, .len, reader);
        try view.takeBytes(.data, view.get(.len), reader);

        const data = view.get(.data);
        switch (code) {
            inline .subnet_mask, .broadcast_address, .requested_ip_address, .server_id => |tag| {
                try view.validate(.len, .{ .eq = 4 });
                const ip: IPv4 = std.mem.bytesAsValue(IPv4, data).*;
                return @unionInit(OptionValue, @tagName(tag), ip);
            },
            inline .router, .dns_servers => |tag| {
                try view.validate(.len, .{ .gte = 4 });
                try view.validate(.len, .{ .multiple_of = 4 });
                const addresses: []const IPv4 = std.mem.bytesAsSlice(IPv4, data);
                return @unionInit(OptionValue, @tagName(tag), addresses);
            },
            inline .host_name, .domain_name, .domain_search => |tag| {
                try view.validate(.len, .{ .gte = 1 });
                return @unionInit(OptionValue, @tagName(tag), data);
            },
            inline .lease_time, .renewal_time, .rebinding_time => |tag| {
                try view.validate(.len, .{ .eq = @sizeOf(u32) });
                const seconds = std.mem.bigToNative(u32, std.mem.bytesAsValue(u32, data).*);
                return @unionInit(OptionValue, @tagName(tag), std.Io.Duration.fromSeconds(seconds));
            },
            .interface_mtu => {
                try view.validate(.len, .{ .eq = @sizeOf(u16) });
                const mtu = std.mem.bigToNative(u16, std.mem.bytesAsValue(u16, data).*);
                if (mtu < 68) return error.InvalidOption;
                return .{ .interface_mtu = mtu };
            },
            .static_route => {
                try view.validate(.len, .{ .gte = @sizeOf(StaticRoute) });
                try view.validate(.len, .{ .multiple_of = @sizeOf(StaticRoute) });
                return .{ .static_route = std.mem.bytesAsSlice(StaticRoute, data) };
            },
            .message_type => {
                try view.validate(.len, .{ .eq = 1 });
                return .{ .message_type = @enumFromInt(std.mem.bytesAsValue(u8, data).*) };
            },
            .parameter_request_list => {
                try view.validate(.len, .{ .gte = 1 });
                return .{ .parameter_request_list = std.mem.bytesAsSlice(OptionType, data) };
            },
            .max_message_size => {
                try view.validate(.len, .{ .eq = @sizeOf(u16) });
                return .{ .max_message_size = std.mem.bigToNative(u16, std.mem.bytesAsValue(u16, data).*) };
            },
            .client_id => {
                try view.validate(.len, .{ .gte = 2 });
                return .{ .client_id = data };
            },
            .classless_static_route => {
                try view.validate(.len, .{ .gte = 5 });
                return .{ .classless_static_route = data };
            },
            else => continue,
        }
    }
}

fn serializeOption(code: OptionType, value: anytype, writer: *std.Io.Writer) !void {
    const Value = @TypeOf(value);
    const encoded = switch (@typeInfo(Value)) {
        .int => std.mem.nativeToBig(Value, value),
        .@"enum" => |info| std.mem.nativeToBig(info.tag_type, @intFromEnum(value)),
        .array, .pointer => value,
        else => @compileError("DHCP options expect integers, enums, or bytes"),
    };
    const bytes: []const u8 = switch (@typeInfo(@TypeOf(encoded))) {
        .int => std.mem.asBytes(&encoded),
        .array => &encoded,
        .pointer => encoded,
        else => unreachable,
    };
    const len = std.math.cast(u8, bytes.len) orelse return error.OptionTooLong;
    try writer.writeAll(&.{ @intFromEnum(code), len });
    try writer.writeAll(bytes);
}

pub fn handle(
    buffer: []u8,
    device: NicApi,
    iface: IFace,
    views: *ViewStack,
) !void {
    const view = try parse(views.getView(.udp).get(.payload));
    Cli.enter(.dhcpv4, view);

    var options: RxOptions = .{};
    var reader: std.Io.Reader = .fixed(view.get(.options));
    while (try parseOption(&reader)) |value| {
        switch (value) {
            .message_type => |message_type| {
                if (options.message_type != null) return error.DuplicateMessageType;
                options.message_type = message_type;
            },
            .requested_ip_address => |ip| options.requested_ip_address = ip,
            .server_id => |ip| options.server_id = ip,
            .client_id => |id| options.client_id = id,
            .subnet_mask => |mask| options.subnet_mask = mask,
            .router => |routers| options.router = routers[0],
            .lease_time => |time| options.lease_time = time,
            .renewal_time => |time| options.renewal_time = time,
            .rebinding_time => |time| options.rebinding_time = time,
            else => continue,
        }
    }

    const message_type = options.message_type orelse return error.MissingMessageType;
    const mac = view.get(.client_hw_addr)[0..6].*;
    const xid = view.get(.xid);

    switch (iface) {
        .lan => {
            if (!view.fieldCmp(.op, .{ .eq = .BOOTREQUEST }) or
                !view.fieldCmp(.relay_agent_ip, .{ .eq = ZERO_IP }))
                return device.release(buffer);

            const server = options.server_id orelse lan_ip.*;
            if (!std.meta.eql(server, lan_ip.*)) return device.release(buffer);

            const client: DhcpTable.Client = if (options.client_id) |id|
                .{ .id = id }
            else
                .{ .mac = mac };
            const ciaddr = view.get(.client_ip);
            const has_ciaddr = !std.meta.eql(ciaddr, ZERO_IP);

            var assigned_ip: ?IPv4 = null;
            const reply: MessageType = switch (message_type) {
                .decline => {
                    const ip = options.requested_ip_address orelse return device.release(buffer);
                    dhcp_table.decline(client, ip);
                    return device.release(buffer);
                },
                .discover => offer: {
                    assigned_ip = try dhcp_table.offer(
                        client,
                        mac,
                        options.requested_ip_address,
                        OFFER_HOLD,
                    ) orelse return device.release(buffer);
                    break :offer .offer;
                },
                .inform => if (has_ciaddr) .ack else return device.release(buffer),
                .release => {
                    dhcp_table.release(client, ciaddr);
                    return device.release(buffer);
                },
                .request => request: {
                    const requested = if (has_ciaddr)
                        ciaddr
                    else
                        options.requested_ip_address orelse return device.release(buffer);

                    if (!has_ciaddr and options.server_id == null and
                        classifyDestination(requested) == .lan and
                        dhcp_table.lookupByClient(client) == null)
                        return device.release(buffer);

                    dhcp_table.bindOrRenew(client, mac, requested, LAN_LEASE) catch |err| switch (err) {
                        error.InvalidIP, error.InvalidMac => break :request .nak,
                        else => return err,
                    };
                    assigned_ip = requested;
                    break :request .ack;
                },
                else => {
                    std.debug.print("DHCPv4: message type {f} unhandled by {s}\n", .{
                        Format.enumLabel(message_type), @tagName(iface),
                    });
                    return device.release(buffer);
                },
            };

            const broadcast_flag = view.get(.broadcast_flag);
            const unicast = reply != .nak and (has_ciaddr or !broadcast_flag);
            const yiaddr = assigned_ip orelse ZERO_IP;
            const client_ip = if (has_ciaddr) ciaddr else yiaddr;

            try transmit(device, .lan, .{
                .kind = reply,
                .xid = xid,
                .mac = mac,
                .client_id = options.client_id,
                .ciaddr = ciaddr,
                .yiaddr = yiaddr,
                .server_id = lan_ip.*,
                .lease_time = if (assigned_ip != null) LAN_LEASE else null,
                .src_ip = lan_ip.*,
                .dst_ip = if (unicast) client_ip else BROADCAST_IP,
                .dst_mac = if (unicast) mac else BROADCAST_MAC,
                .broadcast = broadcast_flag,
                .vlan_tags = views.getView(.ethernet).get(.vlan_tags),
            });
        },
        .wan => {
            const transaction = if (wan_transaction) |*pending| pending else return device.release(buffer);
            if (!view.fieldCmp(.op, .{ .eq = .BOOTREPLY }) or xid != transaction.xid or
                !std.meta.eql(mac, device.macAddress(.wan)))
                return device.release(buffer);

            const server = options.server_id orelse return device.release(buffer);
            if (std.meta.eql(server, ZERO_IP)) return device.release(buffer);
            const offered_ip = view.get(.your_ip);
            const matches_server = if (transaction.expected_server) |expected|
                std.meta.eql(server, expected)
            else
                true;
            const request_sent_at = if (matches_server) transaction.request_sent_at else null;

            switch (message_type) {
                .ack => {
                    const sent_at = request_sent_at orelse return device.release(buffer);
                    const requested_ip = transaction.requested_ip orelse return device.release(buffer);
                    if (!std.meta.eql(offered_ip, requested_ip)) return device.release(buffer);

                    const mask = options.subnet_mask orelse return device.release(buffer);
                    const gateway = options.router orelse return device.release(buffer);
                    const lifetime = options.lease_time orelse return device.release(buffer);
                    const lease_ns = lifetime.toNanoseconds();
                    const t1: std.Io.Duration = options.renewal_time orelse .fromNanoseconds(@divTrunc(lease_ns, 2));
                    const t2: std.Io.Duration = options.rebinding_time orelse .fromNanoseconds(@divTrunc(lease_ns * 7, 8));
                    if (t1.toNanoseconds() <= 0 or t1.toNanoseconds() >= t2.toNanoseconds() or
                        t2.toNanoseconds() >= lease_ns)
                        return device.release(buffer);

                    wan_lease.* = .{
                        .ip = offered_ip,
                        .subnet_mask = mask,
                        .router = gateway,
                        .server_id = server,
                        .renewal_deadline = sent_at.addDuration(t1),
                        .rebinding_deadline = sent_at.addDuration(t2),
                        .expiration_deadline = sent_at.addDuration(lifetime),
                    };
                    wan_transaction = null;
                },
                .nak => {
                    if (request_sent_at == null) return device.release(buffer);
                    wan_lease.* = null;
                    wan_transaction = null;
                },
                .offer => {
                    if (wan_lease.* != null or transaction.requested_ip != null or
                        std.meta.eql(offered_ip, ZERO_IP))
                        return device.release(buffer);

                    transaction.requested_ip = offered_ip;
                    transaction.expected_server = server;
                    transaction.next_send = .zero;
                    transaction.retry_seconds = INITIAL_RETRY_SECONDS;
                },
                else => std.debug.print("DHCPv4: message type {f} unhandled by {s}\n", .{
                    Format.enumLabel(message_type), @tagName(iface),
                }),
            }
        },
    }

    device.release(buffer);
}

pub fn tickWan(io: std.Io, device: NicApi) !void {
    const now = std.Io.Timestamp.now(io, .boot);
    const now_ns = now.toNanoseconds();

    if (wan_lease.*) |lease| {
        if (now_ns >= lease.expiration_deadline.toNanoseconds()) {
            wan_lease.* = null;
            wan_transaction = null;
        } else if (now_ns < lease.renewal_deadline.toNanoseconds()) {
            return;
        }
    }

    const lease = wan_lease.*;
    if (wan_transaction) |transaction| {
        if (now_ns < transaction.next_send.toNanoseconds()) return;

        const offer_timed_out = lease == null and transaction.requested_ip != null and
            transaction.retry_seconds == MAX_RETRY_SECONDS;
        if (offer_timed_out) wan_transaction = null;
    }

    if (wan_transaction == null) {
        var xid: u32 = undefined;
        io.random(std.mem.asBytes(&xid));
        wan_transaction = .{ .xid = xid, .started_at = now };
    }
    const transaction = &wan_transaction.?;

    var tx: Tx = .{
        .kind = .request,
        .xid = transaction.xid,
        .mac = device.macAddress(.wan),
        .secs = @intCast(@min(transaction.started_at.durationTo(now).toSeconds(), std.math.maxInt(u16))),
        .broadcast = true,
    };
    var next_send = now.addDuration(.fromSeconds(transaction.retry_seconds));

    if (lease) |active| {
        tx.ciaddr = active.ip;
        tx.src_ip = active.ip;
        const renewing = now_ns < active.rebinding_deadline.toNanoseconds();
        if (renewing) {
            tx.dst_ip = active.server_id;
            tx.broadcast = false;
        }

        const boundary = if (renewing) active.rebinding_deadline else active.expiration_deadline;
        const remaining = now.durationTo(boundary).toSeconds();
        const retry = now.addDuration(.fromSeconds(@max(60, @divTrunc(remaining, 2))));
        next_send = if (retry.toNanoseconds() < boundary.toNanoseconds()) retry else boundary;
    } else if (transaction.requested_ip) |requested| {
        tx.secs = transaction.discover_secs;
        tx.requested_ip = requested;
        tx.server_id = transaction.expected_server;
    } else {
        tx.kind = .discover;
    }

    if (!tx.broadcast) {
        const active = lease.?;
        const mask: u32 = @bitCast(active.subnet_mask);
        const local: u32 = @bitCast(active.ip);
        const destination: u32 = @bitCast(tx.dst_ip);
        const on_link = (local & mask) == (destination & mask);
        const next_hop = if (on_link) tx.dst_ip else active.router;
        const mac = wan_arp_table.lookup(next_hop);
        tx.dst_mac = mac orelse .{0} ** 6;
        if (mac == null) tx.arp_target = next_hop;
    }

    transaction.next_send = next_send;
    try transmit(device, .wan, tx);

    if (lease) |active| {
        transaction.requested_ip = active.ip;
        transaction.expected_server = if (tx.broadcast) null else active.server_id;
    } else {
        transaction.retry_seconds = @min(transaction.retry_seconds * 2, MAX_RETRY_SECONDS);
    }

    if (tx.kind == .discover) {
        transaction.discover_secs = tx.secs;
    } else if (transaction.request_sent_at == null) {
        transaction.request_sent_at = now;
    }
}

fn transmit(device: NicApi, iface: IFace, tx: Tx) !void {
    var option_bytes = [_]u8{0} ** MAX_OPTIONS_LEN;
    var option_writer: std.Io.Writer = .fixed(&option_bytes);
    try serializeOption(.message_type, tx.kind, &option_writer);

    if (tx.server_id) |ip| try serializeOption(.server_id, ip, &option_writer);
    if (tx.requested_ip) |ip| try serializeOption(.requested_ip_address, ip, &option_writer);

    if (iface == .wan) {
        const client_id = [_]u8{1} ++ tx.mac;
        try serializeOption(.client_id, client_id, &option_writer);
        try serializeOption(
            .parameter_request_list,
            std.mem.asBytes(&WAN_PARAMETER_REQUEST_LIST),
            &option_writer,
        );
    } else if (tx.client_id) |id| {
        try serializeOption(.client_id, id, &option_writer);
    }

    if (tx.lease_time) |duration| {
        const seconds: u32 = @intCast(duration.toSeconds());
        try serializeOption(.lease_time, seconds, &option_writer);
    }
    if (iface == .lan and tx.kind != .nak) {
        try serializeOption(.subnet_mask, lan_subnet_mask.*, &option_writer);
        try serializeOption(.router, tx.src_ip, &option_writer);
        try serializeOption(.dns_servers, std.mem.asBytes(&LAN_DNS), &option_writer);
    }
    try option_writer.writeByte(@intFromEnum(OptionType.end));
    const options_len = @max(option_writer.end, MIN_OPTIONS_LEN);
    const udp_length: u16 = @intCast(8 + DHCP_HEADER_LEN + options_len);

    const tx_buffer = device.nextTxBuffer(iface);
    errdefer device.release(tx_buffer);
    var writer: std.Io.Writer = .fixed(tx_buffer);

    try EthernetFrameView.serialize(.{
        .dst_mac = tx.dst_mac,
        .src_mac = device.macAddress(iface),
        .vlan_tags = tx.vlan_tags,
        .ethertype = .ipv4,
        .payload = &.{},
    }, &writer);

    const ip_start = writer.end;
    try IPv4PacketView.serialize(.{
        .version = 4,
        .ihl = 5,
        .dscp = 0,
        .ecn = 0,
        .total_length = 20 + udp_length,
        .identification = 0,
        .reserved = 0,
        .dont_fragment = true,
        .more_fragments = false,
        .fragment_offset = 0,
        .ttl = 64,
        .protocol = .udp,
        .header_checksum = 0,
        .src = tx.src_ip,
        .dst = tx.dst_ip,
        .options = &.{},
        .payload = &.{},
    }, &writer);
    try UdpPacketView.serialize(.{
        .src_port = if (iface == .wan) 68 else 67,
        .dst_port = if (iface == .wan) 67 else 68,
        .length = udp_length,
        .checksum = 0,
        .payload = &.{},
    }, &writer);

    var client_hw_addr = [_]u8{0} ** 16;
    client_hw_addr[0..6].* = tx.mac;
    try DHCPv4PacketView.serialize(.{
        .op = if (iface == .wan) .BOOTREQUEST else .BOOTREPLY,
        .xid = tx.xid,
        .secs = tx.secs,
        .broadcast_flag = tx.broadcast,
        .client_ip = if (tx.kind == .nak) ZERO_IP else tx.ciaddr,
        .your_ip = tx.yiaddr,
        .next_server_ip = ZERO_IP,
        .relay_agent_ip = ZERO_IP,
        .client_hw_addr = client_hw_addr,
        .server_name = .{0} ** 64,
        .file = .{0} ** 128,
        .options = option_bytes[0..options_len],
    }, &writer);

    var reader: std.Io.Reader = .fixed(tx_buffer[ip_start..writer.end]);
    var ip: IPv4PacketView = undefined;
    try ip.takeFields(.version, .dst, &reader);
    try ip.takeBytes(.options, 0, &reader);

    var udp: UdpPacketView = undefined;
    try udp.takeFields(.src_port, .checksum, &reader);
    try udp.takeBytes(.payload, reader.bufferedLen(), &reader);

    var ip_checksum = ip.checksum();
    ip_checksum.addFields(.version, .options);
    ip.set(.header_checksum, ip_checksum.finish());

    var udp_checksum = udp.checksum();
    try udp_checksum.addPseudoheader(ip);
    udp_checksum.addFields(.src_port, .payload);
    const checksum = udp_checksum.finish();
    udp.set(.checksum, if (checksum == 0) 0xffff else checksum);

    const frame = tx_buffer[0..writer.end];
    if (tx.arp_target) |target_ip|
        return queueForArpResolution(frame, device, .{ .iface = iface, .ip = target_ip });
    device.transmit(frame);
}

const test_packet = blk: {
    var packet = [_]u8{0} ** 245;
    packet[0] = 1; // BOOTREQUEST
    packet[1] = 1; // Ethernet
    packet[2] = 6; // MAC length
    packet[4] = 0x12;
    packet[5] = 0x34;
    packet[6] = 0x56;
    packet[7] = 0x78;
    packet[9] = 42; // seconds elapsed
    packet[10] = 0x80; // broadcast flag
    packet[12] = 192;
    packet[14] = 2;
    packet[15] = 10;
    packet[16] = 198;
    packet[17] = 51;
    packet[18] = 100;
    packet[19] = 20;
    packet[20] = 203;
    packet[22] = 113;
    packet[23] = 7;
    packet[28] = 0x02;
    packet[29] = 0x11;
    packet[30] = 0x22;
    packet[31] = 0x33;
    packet[32] = 0x44;
    packet[33] = 0x55;
    packet[44] = 'b';
    packet[45] = 'o';
    packet[46] = 'o';
    packet[47] = 't';
    packet[108] = 'p';
    packet[109] = 'x';
    packet[110] = 'e';
    packet[236] = 0x63;
    packet[237] = 0x82;
    packet[238] = 0x53;
    packet[239] = 0x63;
    packet[240] = 53; // DHCP message type
    packet[241] = 1;
    packet[242] = 1; // Discover
    packet[243] = 255; // End
    packet[244] = 0; // Padding after End
    break :blk packet;
};

test "parse() reads DHCPv4 fixed fields and leaves the remaining bytes as options" {
    const view = try parse(&test_packet);
    try std.testing.expectEqual(Op.BOOTREQUEST, view.get(.op));
    try std.testing.expectEqual(@as(u8, 1), view.get(.htype));
    try std.testing.expectEqual(@as(u8, 6), view.get(.hlen));
    try std.testing.expectEqual(@as(u8, 0), view.get(.hops));
    try std.testing.expectEqual(@as(u32, 0x12345678), view.get(.xid));
    try std.testing.expectEqual(@as(u16, 42), view.get(.secs));
    try std.testing.expect(view.get(.broadcast_flag));
    try std.testing.expectEqual(@as(u15, 0), view.get(.reserved_flags));
    try std.testing.expectEqualDeep(IPv4{ 192, 0, 2, 10 }, view.get(.client_ip));
    try std.testing.expectEqualDeep(IPv4{ 198, 51, 100, 20 }, view.get(.your_ip));
    try std.testing.expectEqualDeep(IPv4{ 203, 0, 113, 7 }, view.get(.next_server_ip));
    try std.testing.expectEqualDeep(IPv4{ 0, 0, 0, 0 }, view.get(.relay_agent_ip));
    try std.testing.expectEqualDeep(test_packet[28..44].*, view.get(.client_hw_addr));
    try std.testing.expectEqualDeep(test_packet[44..108].*, view.get(.server_name));
    try std.testing.expectEqualDeep(test_packet[108..236].*, view.get(.file));
    try std.testing.expectEqual(@as(u32, DHCPV4_MAGIC), view.get(.magic));
    try std.testing.expectEqualSlices(u8, test_packet[240..], view.get(.options));
}

test "parse() rejects truncated fixed headers" {
    for (0..240) |len| {
        try std.testing.expectError(error.EndOfStream, parse(test_packet[0..len]));
    }
}

test "parse() rejects invalid DHCPv4 metadata" {
    const invalid_fields = [_]struct { offset: usize, value: u8 }{
        .{ .offset = 1, .value = 2 }, // non-Ethernet hardware type
        .{ .offset = 2, .value = 5 }, // wrong Ethernet address length
        .{ .offset = 10, .value = 0x81 }, // reserved flag set
        .{ .offset = 236, .value = 0 }, // invalid magic cookie
    };
    for (invalid_fields) |invalid| {
        var packet = test_packet;
        packet[invalid.offset] = invalid.value;
        try std.testing.expectError(error.InvalidField, parse(&packet));
    }
}

fn expectWiresharkOptionValue(option: OptionValue, hex: []const u8) !void {
    switch (option) {
        inline .subnet_mask, .broadcast_address, .requested_ip_address, .server_id => |ip| {
            try expectHexBytes(&ip, hex);
        },
        inline .router, .dns_servers => |addresses| {
            try expectHexBytes(std.mem.sliceAsBytes(addresses), hex);
        },
        inline .host_name, .domain_name, .domain_search, .classless_static_route => |bytes| {
            try expectHexBytes(bytes, hex);
        },
        .static_route => |routes| try expectHexBytes(std.mem.sliceAsBytes(routes), hex),
        inline .lease_time, .renewal_time, .rebinding_time => |duration| {
            try std.testing.expectEqual(
                @as(i64, try std.fmt.parseInt(u32, hex, 16)),
                duration.toSeconds(),
            );
        },
        .message_type => |message_type| {
            try std.testing.expectEqual(try std.fmt.parseInt(u8, hex, 16), @intFromEnum(message_type));
        },
        .parameter_request_list => |codes| {
            try std.testing.expectEqual(codes.len * 2, hex.len);
            for (codes, 0..) |code, i| {
                try std.testing.expectEqual(
                    try std.fmt.parseInt(u8, hex[i * 2 ..][0..2], 16),
                    @intFromEnum(code),
                );
            }
        },
        .interface_mtu, .max_message_size => |size| {
            try std.testing.expectEqual(try std.fmt.parseInt(u16, hex, 16), size);
        },
        .client_id => |bytes| try expectHexBytes(bytes, hex),
    }
}

test "parse() on wireshark captured frames matches wireshark's parsed output" {
    const pcap_file = DHCPv4Fixtures.pcap_file;
    const csv_file = DHCPv4Fixtures.csv_file;

    var parsed_pcap = try PcapParser.parse(pcap_file, std.testing.allocator);
    defer parsed_pcap.deinit(std.testing.allocator);
    const parsed_packets = try CsvParser.parse(csv_file, std.testing.allocator);
    defer std.testing.allocator.free(parsed_packets);

    try std.testing.expectEqual(parsed_packets.len, parsed_pcap.packet_bytes.len);
    for (parsed_packets, 0..) |ws_packet, i| {
        const frame = try Ethernet.parse(parsed_pcap.packet_bytes[i]);
        try std.testing.expectEqual(Ethernet.Ethertype.ipv4, frame.get(.ethertype));
        const ip_view = try IPv4Protocol.parse(frame.get(.payload));
        try std.testing.expectEqual(IPv4Protocol.Protocol.udp, ip_view.get(.protocol));
        const udp_view = try UdpProtocol.parse(ip_view.get(.payload), ip_view);
        const view = try parse(udp_view.get(.payload));
        try std.testing.expect(view.isEqualIgnoringSlices(&ws_packet.packet));

        var options_reader: std.Io.Reader = .fixed(view.get(.options));
        var types = std.mem.splitScalar(u8, ws_packet.option_types, ';');
        var values = std.mem.splitScalar(u8, ws_packet.option_values, ';');
        var saw_end = false;
        while (types.next()) |type_text| {
            const code: OptionType = @enumFromInt(try std.fmt.parseInt(u8, type_text, 10));
            if (code == .pad) {
                // TShark reports the DHCP End marker as a final option type 0.
                saw_end = true;
                break;
            }
            const value = values.next() orelse return error.MissingWiresharkOptionValue;
            switch (code) {
                .subnet_mask,
                .router,
                .dns_servers,
                .host_name,
                .domain_name,
                .interface_mtu,
                .broadcast_address,
                .static_route,
                .requested_ip_address,
                .lease_time,
                .message_type,
                .server_id,
                .parameter_request_list,
                .max_message_size,
                .renewal_time,
                .rebinding_time,
                .client_id,
                .domain_search,
                .classless_static_route,
                => {
                    const option = (try parseOption(&options_reader)) orelse return error.MissingOption;
                    try std.testing.expectEqualStrings(@tagName(code), @tagName(std.meta.activeTag(option)));
                    try expectWiresharkOptionValue(option, value);
                    if (code == .message_type) {
                        try std.testing.expectEqual(ws_packet.message_type, @intFromEnum(option.message_type));
                    }
                },
                else => {}, // parseOption skips unsupported options.
            }
        }
        try std.testing.expect(saw_end);
        try std.testing.expect(values.next() == null);
        try std.testing.expect((try parseOption(&options_reader)) == null);
    }
}

test "parseOption() decodes supported DHCPv4 option values" {
    const bytes = [_]u8{
        1, 4, 255, 255, 255, 0, // subnet mask
        3, 8, 192, 0, 2, 1, 192, 0, 2, 2, // two routers
        6, 8, 8, 8, 8, 8, 1, 1, 1, 1, // two DNS servers
        50, 4, 192, 0, 2, 100, // requested address
        51, 4, 0, 0, 0x0e, 0x10, // 3600 second lease
        53, 1, 3, // Request
        54, 4, 192, 0, 2, 254, // server identifier
        55, 3, 1, 3, 250, // request list, including an unknown code
        57, 2, 0x05, 0xdc, // 1500 byte maximum message size
        58, 4, 0, 0, 0x07, 0x08, // 1800 second renewal time
        59, 4, 0, 0, 0x0c, 0x4e, // 3150 second rebinding time
        61,  7, 1, 2, 0x11, 0x22, 0x33, 0x44, 0x55, // client identifier
        255,
    };
    var client_id = [_]u8{ 1, 2, 0x11, 0x22, 0x33, 0x44, 0x55 };
    const expected = [_]OptionValue{
        .{ .subnet_mask = .{ 255, 255, 255, 0 } },
        .{ .router = &[_]IPv4{ .{ 192, 0, 2, 1 }, .{ 192, 0, 2, 2 } } },
        .{ .dns_servers = &[_]IPv4{ .{ 8, 8, 8, 8 }, .{ 1, 1, 1, 1 } } },
        .{ .requested_ip_address = .{ 192, 0, 2, 100 } },
        .{ .lease_time = std.Io.Duration.fromSeconds(3600) },
        .{ .message_type = .request },
        .{ .server_id = .{ 192, 0, 2, 254 } },
        .{ .parameter_request_list = &[_]OptionType{ .subnet_mask, .router, @enumFromInt(250) } },
        .{ .max_message_size = 1500 },
        .{ .renewal_time = std.Io.Duration.fromSeconds(1800) },
        .{ .rebinding_time = std.Io.Duration.fromSeconds(3150) },
        .{ .client_id = &client_id },
    };

    var reader: std.Io.Reader = .fixed(&bytes);
    for (expected) |item| {
        const actual = (try parseOption(&reader)) orelse return error.MissingOption;
        try std.testing.expectEqualDeep(item, actual);
    }
    try std.testing.expect((try parseOption(&reader)) == null);
    try std.testing.expectEqual(bytes.len, reader.seek);
}

test "parseOption() decodes requested DHCPv4 option values" {
    const bytes = [_]u8{
        12, 4, 'h', 'o', 's', 't', // host name
        15, 3, 'l', 'a', 'n', // domain name
        26, 2, 0x05, 0xdc, // interface MTU 1500
        28, 4, 192, 0, 2, 255, // broadcast address
        33, 8, 192, 0, 2, 0, 192, 0, 2, 1, // static route
        119, 5, 3, 'l', 'a', 'n', 0, // encoded domain search list
        121, 5, 0, 192, 0, 2, 1, // encoded classless default route
        252, 2, 0xaa, 0xbb, // private use: still unknown
        255,
    };
    var reader: std.Io.Reader = .fixed(&bytes);
    try std.testing.expectEqualSlices(u8, "host", (try parseOption(&reader)).?.host_name);
    try std.testing.expectEqualSlices(u8, "lan", (try parseOption(&reader)).?.domain_name);
    try std.testing.expectEqual(@as(u16, 1500), (try parseOption(&reader)).?.interface_mtu);
    try std.testing.expectEqualDeep(IPv4{ 192, 0, 2, 255 }, (try parseOption(&reader)).?.broadcast_address);
    const routes = (try parseOption(&reader)).?.static_route;
    try std.testing.expectEqual(@as(usize, 1), routes.len);
    try std.testing.expectEqualDeep(IPv4{ 192, 0, 2, 0 }, routes[0].destination);
    try std.testing.expectEqualDeep(IPv4{ 192, 0, 2, 1 }, routes[0].router);
    try std.testing.expectEqualSlices(u8, &.{ 3, 'l', 'a', 'n', 0 }, (try parseOption(&reader)).?.domain_search);
    try std.testing.expectEqualSlices(u8, &.{ 0, 192, 0, 2, 1 }, (try parseOption(&reader)).?.classless_static_route);
    try std.testing.expect((try parseOption(&reader)) == null);
    try std.testing.expectEqual(bytes.len, reader.seek);
}

test "parseOption() skips padding and unknown options and stops at End" {
    const bytes = [_]u8{ 0, 60, 3, 'a', 'b', 'c', 53, 1, 5, 255, 0, 0 };
    var reader: std.Io.Reader = .fixed(&bytes);

    const option = (try parseOption(&reader)) orelse return error.MissingOption;
    try std.testing.expectEqualDeep(OptionValue{ .message_type = .ack }, option);
    try std.testing.expect((try parseOption(&reader)) == null);
    try std.testing.expectEqual(bytes.len - 2, reader.seek);
}

test "parseOption() preserves unrecognized DHCP message type values" {
    const bytes = [_]u8{ 53, 1, 250, 255 };
    var reader: std.Io.Reader = .fixed(&bytes);
    const option = (try parseOption(&reader)) orelse return error.MissingOption;
    try std.testing.expectEqual(@as(u8, 250), @intFromEnum(option.message_type));
}

test "parseOption() rejects invalid lengths and truncated options" {
    const invalid = [_][]const u8{
        &.{ 1, 3, 255, 255, 255 }, // IPv4 address must have four bytes
        &.{ 3, 0 }, // router list cannot be empty
        &.{ 6, 5, 1, 2, 3, 4, 5 }, // address list must contain whole addresses
        &.{ 51, 3, 0, 0, 1 }, // duration requires four bytes
        &.{ 53, 2, 1, 2 }, // message type requires one byte
        &.{ 55, 0 }, // parameter list cannot be empty
        &.{ 57, 4, 0, 0, 0, 1 }, // maximum message size requires two bytes
        &.{ 61, 1, 1 }, // client identifier requires at least two bytes
        &.{ 12, 0 }, // host name cannot be empty
        &.{ 15, 0 }, // domain name cannot be empty
        &.{ 26, 1, 0 }, // MTU needs two bytes
        &.{ 28, 3, 192, 0, 2 }, // broadcast address needs four bytes
        &.{ 33, 7, 192, 0, 2, 0, 192, 0, 2 }, // static route needs address pairs
        &.{ 119, 0 }, // domain search list cannot be empty
        &.{ 121, 4, 0, 192, 0, 2 }, // classless route needs at least five bytes
    };
    for (invalid) |bytes| {
        var reader: std.Io.Reader = .fixed(bytes);
        try std.testing.expectError(error.InvalidField, parseOption(&reader));
    }

    var invalid_mtu: std.Io.Reader = .fixed(&.{ 26, 2, 0, 67 });
    try std.testing.expectError(error.InvalidOption, parseOption(&invalid_mtu));

    const truncated = [_][]const u8{
        &.{1}, // missing length
        &.{ 1, 4, 1, 2 }, // known option value is short
        &.{ 60, 3, 1, 2 }, // unknown option value is short
        &.{ 53, 1, 1 }, // missing End marker
    };
    for (truncated) |bytes| {
        var reader: std.Io.Reader = .fixed(bytes);
        if (bytes[0] == 53) _ = try parseOption(&reader);
        try std.testing.expectError(error.EndOfStream, parseOption(&reader));
    }
}

test "parse() then serialize() returns the original bytes" {
    const pcap_file = DHCPv4Fixtures.pcap_file;

    var parsed_pcap = try PcapParser.parse(pcap_file, std.testing.allocator);
    defer parsed_pcap.deinit(std.testing.allocator);

    for (parsed_pcap.packet_bytes) |packet| {
        const frame = try Ethernet.parse(packet);
        try std.testing.expectEqual(Ethernet.Ethertype.ipv4, frame.get(.ethertype));
        const ip_view = try IPv4Protocol.parse(frame.get(.payload));
        try std.testing.expectEqual(IPv4Protocol.Protocol.udp, ip_view.get(.protocol));
        const udp_view = try UdpProtocol.parse(ip_view.get(.payload), ip_view);
        const dhcp_bytes = udp_view.get(.payload);
        var view = try parse(dhcp_bytes);
        const buffer = try std.testing.allocator.alloc(u8, dhcp_bytes.len);
        defer std.testing.allocator.free(buffer);
        var writer: std.Io.Writer = .fixed(buffer);

        try DHCPv4PacketView.serialize(view.copy(), &writer);
        try std.testing.expectEqual(dhcp_bytes.len, writer.end);
        try std.testing.expectEqualSlices(u8, dhcp_bytes, buffer);
    }
}
