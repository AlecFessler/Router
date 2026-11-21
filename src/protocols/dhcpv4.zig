const std = @import("std");
const Router = @import("router");

const Cli = Router.Debug.Cli;
const IFace = Router.Nic.Api.IFace;
const NicApi = Router.Nic.Api.Api;
const View = Router.Meta.View.View;

pub const DHCPv4Packet = struct {};

pub const DHCPv4PacketView = View(DHCPv4Packet);

pub fn validate(view: DHCPv4PacketView) !void {
    _ = view;
}

pub fn parse(buffer: []const u8) !DHCPv4PacketView {
    _ = buffer;
}

pub fn handle(
    buffer: []u8, // the full ethernet frame
    packet: []u8,
    device: NicApi,
    iface: IFace,
) !void {
    _ = iface;
    const view = try parse(packet);
    Cli.enter(.dhcpv4, view);
    device.release(buffer);
}
