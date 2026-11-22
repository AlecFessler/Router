const std = @import("std");
const Router = @import("router");

const Cli = Router.Debug.Cli;
const Format = Router.Meta.Format;
const ICMPv4PacketView = Router.Protocols.ICMPv4.ICMPv4PacketView;
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
    icmpv4_view: ICMPv4PacketView,
    device: NicApi,
    iface: IFace,
) !void {
    const view = try parse(icmpv4_view.get(.payload));
    Cli.enter(.echo, view);
    std.debug.print("ICMPv4: packet with type {f} code {} unhandled by {s} interface\n", .{
        Format.enumLabel(icmpv4_view.get(.message_type)), icmpv4_view.get(.code), @tagName(iface),
    });
    device.release(buffer);
}
