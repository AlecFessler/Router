const Router = @import("router");

const EthernetFrameView = Router.Protocols.Ethernet.EthernetFrameView;
const ICMPv4PacketView = Router.Protocols.ICMPv4.ICMPv4PacketView;
const IPv4PacketView = Router.Protocols.IPv4.IPv4PacketView;
const TcpPacketView = Router.Protocols.Tcp.TcpPacketView;
const UdpPacketView = Router.Protocols.Udp.UdpPacketView;

// Parent handlers keep these views alive until their child handler returns.
views: [3]*anyopaque = undefined,

pub const Protocol = enum {
    ethernet,
    ipv4,
    tcp,
    udp,
    icmpv4,
};

fn ProtocolToViewType(comptime protocol: Protocol) type {
    return switch (protocol) {
        .ethernet => *EthernetFrameView,
        .ipv4 => *IPv4PacketView,
        .tcp => *TcpPacketView,
        .udp => *UdpPacketView,
        .icmpv4 => *ICMPv4PacketView,
    };
}

fn viewIndex(comptime protocol: Protocol) usize {
    return switch (protocol) {
        .ethernet => 0,
        .ipv4 => 1,
        .tcp, .udp, .icmpv4 => 2,
    };
}

pub fn getView(
    self: *const @This(),
    comptime protocol: Protocol,
) ProtocolToViewType(protocol) {
    return @ptrCast(@alignCast(self.views[viewIndex(protocol)]));
}

pub fn setView(
    self: *@This(),
    comptime protocol: Protocol,
    view: ProtocolToViewType(protocol),
) void {
    self.views[viewIndex(protocol)] = @ptrCast(view);
}
