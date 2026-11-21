const std = @import("std");
const Router = @import("router");

const Cli = Router.Debug.Cli;
const IFace = Router.Nic.Api.IFace;
const NicApi = Router.Nic.Api.Api;
const View = Router.Meta.View.View;

pub const EchoMsg = struct {};

pub const EchoMsgView = View(EchoMsg);

pub fn validate(view: EchoMsgView) !void {
    _ = view;
}

pub fn parse(buffer: []const u8) !EchoMsgView {
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
    Cli.enter(.echo, view);
    device.release(buffer);
}
