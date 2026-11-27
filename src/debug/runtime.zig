//! Shared state setup and teardown for the replay and shadow harnesses.
const std = @import("std");
const Router = @import("router");

const ArpTable = Router.Tables.ArpTable.ArpTable;
const ArpWaitersTable = Router.Tables.ArpWaitersTable.ArpWaitersTable;
const DhcpTable = Router.Tables.DhcpTable.DhcpTable;
const IPv4FragmentTable = Router.Tables.IPv4FragmentTable.IPv4FragmentTable;
const NatTable = Router.Tables.NatTable.NatTable;
const State = Router.State;

const ARP_CAPACITY: u32 = 256;
const ARP_TTL = std.Io.Duration.fromSeconds(300);
const ARP_WAITERS_CAPACITY: usize = 256;
const ARP_WAITERS_TIMEOUT = std.Io.Duration.fromSeconds(2);
const FRAGMENT_CAPACITY: u32 = 256;
const FRAGMENT_TIMEOUT = std.Io.Duration.fromSeconds(30);
const NAT_CAPACITY: u32 = 16_384;

pub fn setup(alloc: std.mem.Allocator, io: std.Io, nic: Router.Nic.Api.Api, lan_ip: [4]u8, lan_mask: [4]u8) !void {
    State.lan_ip = lan_ip;
    State.lan_subnet_mask = lan_mask;
    State.wan_lease = null;
    State.wan_transaction = null;

    State.lan_arp_table = try ArpTable.init(alloc, io, ARP_CAPACITY, ARP_TTL);
    errdefer State.lan_arp_table.deinit(alloc);

    State.wan_arp_table = try ArpTable.init(alloc, io, ARP_CAPACITY, ARP_TTL);
    errdefer State.wan_arp_table.deinit(alloc);

    State.arp_waiters_table = try ArpWaitersTable.init(
        alloc,
        io,
        ARP_WAITERS_CAPACITY,
        ARP_WAITERS_TIMEOUT,
    );
    errdefer State.arp_waiters_table.deinit(alloc);

    State.dhcp_table = blk: {
        var ip_pool: DhcpTable.IpPool = .empty;
        errdefer ip_pool.deinit(alloc);
        for (2..255) |host| {
            var ip = lan_ip;
            ip[3] = @intCast(host);
            if (ip[3] == lan_ip[3]) continue;
            try ip_pool.append(alloc, ip);
        }
        break :blk try DhcpTable.init(alloc, io, ip_pool);
    };
    errdefer State.dhcp_table.deinit(alloc);

    State.nat_table = try NatTable.init(alloc, io, NAT_CAPACITY);
    errdefer State.nat_table.deinit(alloc);

    State.lan_fragment_table = try IPv4FragmentTable.init(alloc, io, FRAGMENT_CAPACITY, FRAGMENT_TIMEOUT);
    errdefer State.lan_fragment_table.deinit(alloc, nic);

    State.wan_fragment_table = try IPv4FragmentTable.init(alloc, io, FRAGMENT_CAPACITY, FRAGMENT_TIMEOUT);
}

pub fn teardown(alloc: std.mem.Allocator, nic: Router.Nic.Api.Api) void {
    State.wan_fragment_table.deinit(alloc, nic);
    State.lan_fragment_table.deinit(alloc, nic);
    State.arp_waiters_table.expireAll(nic);
    State.nat_table.deinit(alloc);
    State.dhcp_table.deinit(alloc);
    State.arp_waiters_table.deinit(alloc);
    State.wan_arp_table.deinit(alloc);
    State.lan_arp_table.deinit(alloc);
}
