const std = @import("std");
const Router = @import("router");
const Runtime = @import("debug/runtime.zig");

const Ethernet = Router.Protocols.Ethernet;
const ICMPv4Fixtures = Router.TestFixtures.ICMPv4;
const IFace = Router.Nic.Api.IFace;
const Mock = Router.Nic.Testing.Mock;
const ViewStack = Router.Protocols.ViewStack;

const tickWan = Router.Protocols.DHCPv4.tickWan;

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

    const pcap_file = ICMPv4Fixtures.message_types_pcap_file;
    var mock = try Mock.init(pcap_file, init.gpa);
    defer mock.deinit();
    const mock_nic = mock.api();

    try Runtime.setup(init.gpa, init.io, mock_nic, .{ 192, 168, 86, 1 }, .{ 255, 255, 255, 0 });
    defer Runtime.teardown(init.gpa, mock_nic);

    while (true) {
        Router.State.arp_waiters_table.expire(mock_nic);
        if (iface == .wan) {
            tickWan(init.io, mock_nic) catch |err| {
                std.debug.print("DHCPv4: {t}\n", .{err});
            };
        }
        if (mock_nic.receive(iface)) |packet| {
            var views: ViewStack = .{};
            Ethernet.handle(packet, mock_nic, iface, &views) catch |err| {
                mock_nic.release(packet);
                std.debug.print("Error: {}\n", .{err});
            };
            std.debug.print("\n", .{});
        } else if (iface != .lan or Router.State.dhcp_table.reclaim == null) {
            break;
        }
        if (iface == .lan) Router.State.dhcp_table.tickReclaim(mock_nic) catch |err| {
            std.log.scoped(.dhcp).warn("LAN address reclaim failed: {t}", .{err});
        };
    }
}
