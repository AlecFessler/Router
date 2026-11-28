const std = @import("std");
const Router = @import("router");
const Sim = @import("../network_sim.zig");
const Dhcp = Router.Protocols.DHCPv4;
const Fixtures = Router.TestFixtures.Synthetic;
const IPv4 = Router.Protocols.IPv4.IPv4;
const State = Router.State;

job: Sim.Job,
gateway: IPv4 = @splat(0),
generation: u64,
mapping_count: usize,
deadline: std.Io.Timestamp = .zero,

pub fn step(self: *@This(), peer: *Sim.Peer, phase: Sim.Scenarios.Lifecycle) !void {
    const network = peer.network;
    const nat = &State.nat_table;
    var scratch = std.heap.FixedBufferAllocator.init(&peer.scratch);
    const alloc = scratch.allocator();
    if (phase == .static_inform) {
        self.* = .{
            .job = network.cold,
            .generation = network.binding_count + network.conversation_bindings,
            .mapping_count = nat.inside.count(),
        };
        var prng = std.Random.DefaultPrng.init(network.seed);
        const random = prng.random();
        self.job.lan_address = .{ 192, 168, 86, random.intRangeAtMost(u8, 32, 127) };
        self.job.source_port = random.intRangeAtMost(u16, 58000, 58999);
        self.job.remote_port = 53;
        self.job.choice.token = random.int(u32);
    }
    const job = &self.job;
    const host = job.host();
    const mac = job.mac();
    const client_id = [1]u8{1} ++ mac;
    if (State.dhcp_table.lookupByIp(host) != null or State.dhcp_table.lookupByClient(.{ .id = &client_id }) != null or
        State.dhcp_table.lookupByClient(.{ .mac = mac }) != null) return error.UnexpectedStaticLease;
    switch (phase) {
        .static_inform => {
            const xid = job.choice.token;
            const boot = try Fixtures.DhcpClient.payload(alloc, mac, .{
                .xid = xid,
                .message_type = 8,
                .ciaddr = host,
                .client_id = &client_id,
                .requested_options = &.{ 1, 3, 6 },
            });
            var padded: [300]u8 = @splat(0);
            @memcpy(padded[0..boot.len], boot);
            const broadcast: IPv4 = @splat(255);
            try peer.inject(try Sim.wire(alloc, mac, @splat(255), .{
                .src = host,
                .dst = broadcast,
                .payload = try Fixtures.Packets.udp(alloc, host, broadcast, .{ .src_port = 68, .dst_port = 67, .payload = &padded }),
            }));
            _ = try peer.dhcp(.ack, .{ .xid = xid, .client_ip = host, .client_id = &client_id }, mac, @splat(0));

            const ack = try peer.observation.take(0, .lan);
            const reply = try Dhcp.parse(ack[42..]);
            var options = std.Io.Reader.fixed(reply.get(.options));
            var mask: IPv4 = @splat(0);
            while (try Dhcp.parseOption(&options)) |option| switch (option) {
                .subnet_mask => |ip| mask = ip,
                .router => |ips| self.gateway = ips[0],
                .dns_servers => |ips| job.remote = ips[network.seed % ips.len],
                else => {},
            };
            // The advertised resolver is off-link. The advertised gateway must be on this LAN.
            const local: u32 = @bitCast(host);
            const bits: u32 = @bitCast(mask);
            if (local & bits != @as(u32, @bitCast(self.gateway)) & bits or
                local & bits == @as(u32, @bitCast(job.remote)) & bits) return error.WrongStaticRoute;
        },
        .static_dns_query => {
            try peer.inject(try Sim.arp(alloc, mac, host, self.gateway, null));
            try peer.count(1);
            _ = try peer.expect(0, .lan, try Sim.arp(alloc, Sim.lan_mac, self.gateway, host, mac));
            if (network.newConversationBinding() != self.generation) return error.WrongStaticGeneration;
            job.public_port = network.reservePort(.udp, job.source_port);
            self.deadline = std.Io.Timestamp.now(network.io, .boot).addDuration(.fromSeconds(300));
            job.makeDnsQuery(@truncate(job.choice.token), "www".*);
            _ = try peer.send(alloc, job, false);
        },
        .static_dns_answer => {
            const address_len: usize = if (job.choice.token & 2 == 0) 4 else 16;
            job.len = @import("dns.zig").addressResponse(&job.payload, job.len, address_len, 1, false);
            try peer.inject(try Sim.packet(alloc, job.*, true, false, 64));
            try peer.count(1);
            _ = try peer.expect(0, .lan, try Sim.packet(alloc, job.*, true, true, 63));
        },
        else => unreachable,
    }
    const bound: usize = @intFromBool(phase != .static_inform);
    if (bound != 0) try job.checkUdpMapping(self.generation, self.deadline, &.{.{ .ip = job.remote, .port = 53 }});
    if (nat.inside.count() != self.mapping_count + bound or nat.outside.count() != self.mapping_count + bound or
        nat.next_generation != self.generation + bound or State.dhcp_table.reclaim != null or State.dhcp_table.excluded_ips.items.len != 0)
        return error.WrongStaticHostState;
}
