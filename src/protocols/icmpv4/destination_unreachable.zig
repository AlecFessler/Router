const std = @import("std");
const Router = @import("router");

const Cli = Router.Debug.Cli;
const IFace = Router.Nic.Api.IFace;
const NicApi = Router.Nic.Api.Api;
const View = Router.Meta.View.View;

pub const DestinationUnreachableMsg = struct {};

pub const DestinationUnreachableMsgView = View(DestinationUnreachableMsg);

pub fn validate(view: DestinationUnreachableMsgView) !void {
    _ = view;
}

pub fn parse(buffer: []const u8) !DestinationUnreachableMsgView {
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
    Cli.enter(.destination_unreachable, view);
    device.release(buffer);
}
