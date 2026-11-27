//! LAN DNS forwarding. The upstream resolver handles the DNS message and TCP stream.
const std = @import("std");
const Router = @import("router");
const IP = Router.Protocols.IPv4;

pub const port = 53;
pub const resolvers = [2]IP.IPv4{
    .{ 8, 8, 8, 8 },
    .{ 8, 8, 4, 4 },
};

pub const upstream: Router.Tables.NatTable.NatTable.Peer = .{
    .ip = resolvers[0],
    .port = port,
};

pub fn isLanEndpoint(
    iface: Router.Nic.Api.IFace,
    dst: IP.IPv4,
    dst_port: u16,
) bool {
    return iface == .lan and dst_port == port and std.meta.eql(dst, Router.State.lan_ip);
}

pub fn handle(
    buffer: []u8,
    device: Router.Nic.Api.Api,
    views: *Router.Protocols.ViewStack,
    transport: anytype,
    allocator: *Router.Tables.NatTable.PortAllocator,
    timeout: std.Io.Duration,
) !void {
    return IP.forwardNat(
        buffer,
        device,
        .lan,
        views,
        transport,
        .{
            .lan = .src_port,
            .wan = .dst_port,
            .service_peer = upstream,
        },
        allocator,
        timeout,
    );
}
