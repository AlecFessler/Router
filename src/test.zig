const ethernet = @import("protocols/ethernet.zig");
pub const EthernetFrame = ethernet.EthernetFrame;
pub const TPID = ethernet.TPID;
pub const Mac = ethernet.Mac;
pub const VlanTag = ethernet.VlanTag;

test {
    _ = @import("protocols/arp.zig");
    _ = @import("protocols/dhcp_client.zig");
    _ = @import("protocols/dhcp_server.zig");
    _ = ethernet;
    _ = @import("protocols/icmp.zig");
    _ = @import("protocols/ipv4.zig");
    _ = @import("protocols/nat.zig");
    _ = @import("protocols/routing.zig");
    _ = @import("protocols/udp.zig");
}
