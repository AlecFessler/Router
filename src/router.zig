pub const Async = @import("async/async.zig");
pub const Debug = @import("debug/debug.zig");
pub const Meta = @import("meta/meta.zig");
pub const Nic = @import("nic/nic.zig");
pub const Protocols = @import("protocols/protocols.zig");
pub const State = @import("state.zig");
pub const Tables = @import("tables/tables.zig");
pub const TestFixtures = @import("test_fixtures");

test {
    _ = Async.Fiber;
    _ = Async.FiberPool;
    _ = Meta.Checksum;
    _ = Meta.View;
    _ = Protocols.Arp;
    _ = Protocols.DHCPv4;
    _ = Protocols.Ethernet;
    _ = Protocols.ICMPv4;
    _ = Protocols.ICMPv4Messages.DestinationUnreachable;
    _ = Protocols.ICMPv4Messages.Echo;
    _ = Protocols.ICMPv4Messages.TimeExceeded;
    _ = Protocols.IPv4;
    _ = Protocols.Tcp;
    _ = Protocols.Udp;
    _ = Tables.ArpTable;
    _ = Tables.ArpWaitersTable;
    _ = Tables.DhcpTable;
    _ = Tables.NatTable;
}
