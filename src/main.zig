const std = @import("std");
const Router = @import("router");

const ArpTable = Router.Tables.ArpTable.ArpTable;
const ArpWaitersTable = Router.Tables.ArpWaitersTable.ArpWaitersTable;
const DhcpTable = Router.Tables.DhcpTable.DhcpTable;
const Ethernet = Router.Protocols.Ethernet;
const ICMPv4Fixtures = Router.TestFixtures.ICMPv4;
const IFace = Router.Nic.Api.IFace;
const IPv4FragmentTable = Router.Tables.IPv4FragmentTable.IPv4FragmentTable;
const Mock = Router.Nic.Testing.Mock;
const NatTable = Router.Tables.NatTable.NatTable;
const State = Router.State;
const ViewStack = Router.Protocols.ViewStack;

const tickWan = Router.Protocols.DHCPv4.tickWan;

const ARP_CAPACITY: u32 = 256;
const ARP_TTL = std.Io.Duration.fromSeconds(300);
const ARP_WAITERS_CAPACITY: usize = 256;
const ARP_WAITERS_TIMEOUT = std.Io.Duration.fromSeconds(2);
const FRAGMENT_CAPACITY: u32 = 256;
const FRAGMENT_TIMEOUT = std.Io.Duration.fromSeconds(30);
const NAT_CAPACITY: u32 = 16_384;

pub fn main(init: std.process.Init) !void {
    var args = try std.process.Args.Iterator.initAllocator(init.minimal.args, init.gpa);
    defer args.deinit();
    _ = args.skip();
    const iface_arg = args.next() orelse {
        std.debug.print("Usage: router <lan|wan>\n", .{});
        return error.InvalidArguments;
    };
    const iface: IFace = if (std.mem.eql(u8, iface_arg, "lan"))
        .lan
    else if (std.mem.eql(u8, iface_arg, "wan"))
        .wan
    else {
        std.debug.print("Usage: router <lan|wan>\n", .{});
        return error.InvalidArguments;
    };
    if (args.next() != null) {
        std.debug.print("Usage: router <lan|wan>\n", .{});
        return error.InvalidArguments;
    }

    State.lan_ip = .{ 192, 168, 86, 1 };
    State.lan_subnet_mask = .{ 255, 255, 255, 0 };

    State.lan_arp_table = try ArpTable.init(init.gpa, init.io, ARP_CAPACITY, ARP_TTL);
    defer State.lan_arp_table.deinit(init.gpa);

    State.wan_arp_table = try ArpTable.init(init.gpa, init.io, ARP_CAPACITY, ARP_TTL);
    defer State.wan_arp_table.deinit(init.gpa);

    State.arp_waiters_table = try ArpWaitersTable.init(
        init.gpa,
        init.io,
        ARP_WAITERS_CAPACITY,
        ARP_WAITERS_TIMEOUT,
    );
    defer State.arp_waiters_table.deinit(init.gpa);

    State.dhcp_table = blk: {
        var ip_pool: DhcpTable.IpPool = .empty;
        errdefer ip_pool.deinit(init.gpa);
        for (2..255) |host| {
            try ip_pool.append(init.gpa, .{ 192, 168, 86, @intCast(host) });
        }
        break :blk try DhcpTable.init(init.gpa, init.io, ip_pool);
    };
    defer State.dhcp_table.deinit(init.gpa);

    State.nat_table = try NatTable.init(init.gpa, init.io, NAT_CAPACITY);
    defer State.nat_table.deinit(init.gpa);

    const pcap_file = ICMPv4Fixtures.message_types_pcap_file;
    var mock = try Mock.init(pcap_file, init.gpa);
    defer mock.deinit();
    const mock_nic = mock.api();

    defer State.arp_waiters_table.expireAll(mock_nic);

    State.lan_fragment_table = try IPv4FragmentTable.init(init.gpa, init.io, FRAGMENT_CAPACITY, FRAGMENT_TIMEOUT);
    defer State.lan_fragment_table.deinit(init.gpa, mock_nic);

    State.wan_fragment_table = try IPv4FragmentTable.init(init.gpa, init.io, FRAGMENT_CAPACITY, FRAGMENT_TIMEOUT);
    defer State.wan_fragment_table.deinit(init.gpa, mock_nic);

    while (true) {
        State.arp_waiters_table.expire(mock_nic);
        if (iface == .wan) {
            tickWan(init.io, mock_nic) catch |err| {
                std.debug.print("DHCPv4: {t}\n", .{err});
            };
        }
        const packet = mock_nic.receive(iface) orelse break;
        var views: ViewStack = .{};
        Ethernet.handle(packet, mock_nic, iface, &views) catch |err| {
            mock_nic.release(packet);
            std.debug.print("Error: {}\n", .{err});
        };
        std.debug.print("\n", .{});
    }
}
