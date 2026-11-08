const std = @import("std");
const Router = @import("router");

const Ethernet = Router.Protocols.Ethernet;
const IFace = Router.Nic.Api.IFace;
const Mock = Router.Nic.Testing.Mock;
const pcap_file = Router.TestFixtures.Ethernet.pcap_file;

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

    var mock = try Mock.init(pcap_file, init.gpa);
    defer mock.deinit();
    const mock_nic = mock.api();

    var packet_num: usize = 1;
    while (true) {
        const packet = mock_nic.receive(iface) orelse break;
        std.debug.print("Packet #{}\n", .{packet_num});
        Ethernet.handle(packet, mock_nic, iface) catch |err| {
            mock_nic.release(packet);
            std.debug.print("Error: {}\n", .{err});
        };
        std.debug.print("\n", .{});
        packet_num += 1;
    }
}
