const std = @import("std");
const Router = @import("router");

const Ethernet = Router.Protocols.Ethernet;
const IFace = Router.Nic.Api.IFace;
const Mock = Router.Nic.Testing.Mock;
const State = Router.State;
const Tables = Router.Tables;

const ARP_CAPACITY: u32 = 256;
const ARP_TTL = std.Io.Duration.fromSeconds(300);
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

    State.arp_table = try Tables.ArpTable.ArpTable.init(init.gpa, init.io, ARP_CAPACITY, ARP_TTL);
    defer State.arp_table.deinit(init.gpa);

    State.dhcp_table = blk: {
        var ip_pool: Tables.DhcpTable.DhcpTable.IpPool = .empty;
        errdefer ip_pool.deinit(init.gpa);
        for (2..255) |host| {
            try ip_pool.append(init.gpa, .{ 192, 168, 86, @intCast(host) });
        }
        break :blk try Tables.DhcpTable.DhcpTable.init(init.gpa, init.io, ip_pool);
    };
    defer State.dhcp_table.deinit(init.gpa);

    State.nat_table = try Tables.NatTable.NatTable.init(init.gpa, init.io, NAT_CAPACITY);
    defer State.nat_table.deinit(init.gpa);

    const pcap_file = Router.TestFixtures.ICMPv4.message_types_pcap_file;
    var mock = try Mock.init(pcap_file, init.gpa);
    defer mock.deinit();
    const mock_nic = mock.api();

    var packet_num: usize = 1;
    while (true) {
        const packet = mock_nic.receive(iface) orelse break;
        Ethernet.handle(packet, mock_nic, iface) catch |err| {
            mock_nic.release(packet);
            std.debug.print("Error: {}\n", .{err});
        };
        std.debug.print("\n", .{});
        packet_num += 1;
    }
}
