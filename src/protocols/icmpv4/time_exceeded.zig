const std = @import("std");
const Router = @import("router");

const Cli = Router.Debug.Cli;
const IFace = Router.Nic.Api.IFace;
const NicApi = Router.Nic.Api.Api;
const View = Router.Meta.View.View;

pub const TimeExceeddedMsg = struct {};

pub const TimeExceeddedMsgView = View(TimeExceeddedMsg);

pub fn validate(view: TimeExceeddedMsgView) !void {
    _ = view;
}

pub fn parse(buffer: []const u8) !TimeExceeddedMsgView {
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
    Cli.enter(.time_exceeded, view);
    device.release(buffer);
}
