pub const DataStructures = @import("data_structures/data_structures.zig");
pub const Debug = @import("debug/debug.zig");
pub const Meta = @import("meta/meta.zig");
pub const Nic = @import("nic/nic.zig");
pub const Protocols = @import("protocols/protocols.zig");
pub const TestFixtures = @import("test_fixtures");

test {
    _ = DataStructures.ArpTable;
    _ = Meta.Checksum;
    _ = Meta.View;
    _ = Protocols.Arp;
    _ = Protocols.Ethernet;
    _ = Protocols.IPv4;
    _ = Protocols.Udp;
}
