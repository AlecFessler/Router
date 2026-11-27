//! Deterministic Ethernet pcap scenarios for the two-interface cutover profile.
const std = @import("std");
const Router = @import("router");
pub const fixtures = @import("../regression_tests.zig");
pub const P = fixtures.Packets;
pub const H = fixtures.Harness;
pub const Nic = fixtures.RecordingNic;
pub const IP = Router.Protocols.IPv4;
pub const Eth = Router.Protocols.Ethernet;
pub const D = Router.Protocols.DHCPv4;
pub const Iface = Router.Nic.Api.IFace;
pub const client: [4]u8 = .{ 192, 168, 86, 42 };
pub const public: [4]u8 = .{ 203, 0, 113, 50 };
pub const gateway: [4]u8 = .{ 203, 0, 113, 1 };
pub const dhcp_server: [4]u8 = .{ 192, 0, 2, 15 };
pub const peer: [4]u8 = .{ 198, 51, 100, 8 };
pub const cm: Eth.Mac = .{ 2, 0, 0, 0, 1, 42 };
pub const gm: Eth.Mac = .{ 2, 0, 0, 0, 2, 1 };

pub fn activeLease() D.DHCPv4Lease {
    const now = std.Io.Timestamp.now(std.testing.io, .boot);
    return .{ .ip = public, .subnet_mask = .{ 255, 255, 255, 0 }, .router = gateway, .server_id = gateway, .renewal_deadline = now.addDuration(.fromSeconds(1800)), .rebinding_deadline = now.addDuration(.fromSeconds(3150)), .expiration_deadline = now.addDuration(.fromSeconds(3600)) };
}

pub fn warm() !H {
    var h = try H.init(std.testing.allocator, std.testing.io, .{ .wan_lease = activeLease() });
    h.cacheArp(.lan, client, cm);
    h.cacheArp(.wan, gateway, gm);
    return h;
}

// Each record crosses the pcap parser, RX queue and Ethernet handler. Parsing
// the emitted frame separately also validates its IPv4 header checksum.
pub fn inject(h: *H, side: Iface, frame: []const u8) !void {
    const pcap = try P.pcap(h.alloc, &.{frame});
    defer h.alloc.free(pcap);
    try h.injectPcap(side, pcap);
    try std.testing.expectEqual(@as(usize, 1), h.runAll(side));
}

pub fn send(h: *H, side: Iface, opts: P.Ipv4Opts) !void {
    const ip = try P.ipv4(h.alloc, opts);
    defer h.alloc.free(ip);
    const frame = try P.eth(h.alloc, .{
        .src = if (side == .lan) cm else gm,
        .dst = if (side == .lan) Nic.lan_mac else Nic.wan_mac,
        .ethertype = 0x0800,
        .payload = ip,
    });
    defer h.alloc.free(frame);
    try inject(h, side, frame);
}

pub fn emitted(h: *H, index: usize, side: Iface) !IP.IPv4PacketView {
    try std.testing.expect(index < h.txCount());
    const tx = h.txAt(index);
    try std.testing.expectEqual(side, tx.iface);
    const eth = try Eth.parse(tx.bytes);
    return IP.parse(eth.get(.payload));
}

pub fn server(h: *H, xid: u32, kind: u8) !void {
    const opts = try fixtures.dhcpServerOptions(h.alloc, kind, dhcp_server, .{ 255, 255, 255, 0 }, gateway, 3600);
    defer h.alloc.free(opts);
    const frame = try fixtures.dhcpFrame(h.alloc, 2, xid, Nic.wan_mac, .{0} ** 4, public, dhcp_server, .{255} ** 4, opts);
    defer h.alloc.free(frame);
    try inject(h, .wan, frame);
}

pub fn option(packet: D.DHCPv4PacketView, comptime tag: std.meta.Tag(D.OptionValue)) !@FieldType(D.OptionValue, @tagName(tag)) {
    var r: std.Io.Reader = .fixed(packet.get(.options));
    while (try D.parseOption(&r)) |value| {
        if (value == tag) return @field(value, @tagName(tag));
    }
    return error.MissingDhcpOption;
}

pub fn message(h: *H, side: Iface, kind: D.MessageType) !D.DHCPv4PacketView {
    const tx = h.lastTx() orelse return error.MissingDhcpPacket;
    try std.testing.expectEqual(side, tx.iface);
    return fixtures.expectDhcpMessage(tx.bytes, kind);
}

/// A bound client already owns its source IP and unicasts to the DHCP server.
pub fn boundClient(h: *H, mac: Eth.Mac, opts: fixtures.DhcpClient.Opts) !void {
    const payload = try fixtures.DhcpClient.payload(h.alloc, mac, opts);
    defer h.alloc.free(payload);
    const server_ip = Router.State.lan_ip;
    const udp = try P.udp(h.alloc, opts.ciaddr, server_ip, .{ .src_port = 68, .dst_port = 67, .payload = payload });
    defer h.alloc.free(udp);
    const ip = try P.ipv4(h.alloc, .{ .src = opts.ciaddr, .dst = server_ip, .payload = udp });
    defer h.alloc.free(ip);
    const frame = try P.eth(h.alloc, .{ .src = mac, .dst = Nic.lan_mac, .ethertype = 0x0800, .payload = ip });
    defer h.alloc.free(frame);
    try inject(h, .lan, frame);
}
