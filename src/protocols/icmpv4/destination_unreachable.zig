const std = @import("std");
const Router = @import("router");

const Cli = Router.Debug.Cli;
const Format = Router.Meta.Format;
const ICMPv4PacketView = Router.Protocols.ICMPv4.ICMPv4PacketView;
const IFace = Router.Nic.Api.IFace;
const NicApi = Router.Nic.Api.Api;
const View = Router.Meta.View.View;

pub const Code = enum(u8) {
    host_unreachable = 1,
    port_unreachable = 3,
    fragmentation_needed = 4,
    _,
};

pub const DestinationUnreachableMsg = struct {
    reserved: u16, // RFC 4884 may use the low byte as a quote-length field.
    next_hop_mtu: u16, // meaningful for fragmentation_needed
    quoted_packet: []u8,
};

pub const DestinationUnreachableMsgView = View(DestinationUnreachableMsg);

pub fn validate(view: DestinationUnreachableMsgView, icmpv4_view: ICMPv4PacketView) !void {
    if (icmpv4_view.get(.message_type) != .destination_unreachable) return error.InvalidField;
    // The quote contains the original IPv4 header and at least eight data bytes.
    if (view.get(.quoted_packet).len < 28) return error.InvalidField;
}

pub fn parse(icmpv4_view: ICMPv4PacketView) !DestinationUnreachableMsgView {
    var view: DestinationUnreachableMsgView = undefined;
    var reader: std.Io.Reader = .fixed(icmpv4_view.get(.payload));
    try view.takeFields(.reserved, .next_hop_mtu, &reader);
    try view.takeBytes(.quoted_packet, reader.bufferedLen(), &reader);
    try validate(view, icmpv4_view);
    return view;
}

pub fn handle(
    buffer: []u8,
    device: NicApi,
    iface: IFace,
    views: *Router.Protocols.ViewStack,
) !void {
    const icmpv4_view = views.getView(.icmpv4);
    const view = try parse(icmpv4_view.*);
    Cli.enter(.destination_unreachable, view);
    const code: Code = @enumFromInt(icmpv4_view.get(.code));
    switch (code) {
        .host_unreachable => std.debug.print(
            "ICMPv4: {f} unhandled by {s} interface\n",
            .{ Format.enumLabel(code), @tagName(iface) },
        ),
        .port_unreachable => std.debug.print(
            "ICMPv4: {f} unhandled by {s} interface\n",
            .{ Format.enumLabel(code), @tagName(iface) },
        ),
        .fragmentation_needed => std.debug.print("ICMPv4: {f} (next-hop MTU {}) unhandled by {s} interface\n", .{
            Format.enumLabel(code), view.get(.next_hop_mtu), @tagName(iface),
        }),
        else => std.debug.print(
            "ICMPv4: {f} unhandled by {s} interface\n",
            .{ Format.enumLabel(code), @tagName(iface) },
        ),
    }
    device.release(buffer);
}

test "parse() reads destination unreachable messages from the WAN capture" {
    const PcapParser = Router.TestFixtures.PcapParser;
    const pcap_file = Router.TestFixtures.ICMPv4.message_types_pcap_file;
    var parsed_pcap = try PcapParser.parse(pcap_file, std.testing.allocator);
    defer parsed_pcap.deinit(std.testing.allocator);

    const samples = [_]struct { frame_number: usize, code: Code, mtu: u16 }{
        .{ .frame_number = 49, .code = .port_unreachable, .mtu = 0 },
        .{ .frame_number = 303, .code = .host_unreachable, .mtu = 0 },
        .{ .frame_number = 4394, .code = .fragmentation_needed, .mtu = 1253 },
    };
    for (samples) |sample| {
        const frame = try Router.Protocols.Ethernet.parse(parsed_pcap.packet_bytes[sample.frame_number - 1]);
        const ip_view = try Router.Protocols.IPv4.parse(frame.get(.payload));
        const icmpv4_view = try Router.Protocols.ICMPv4.parse(ip_view.get(.payload));
        try std.testing.expectEqual(Router.Protocols.ICMPv4.MessageType.destination_unreachable, icmpv4_view.get(.message_type));
        try std.testing.expectEqual(sample.code, @as(Code, @enumFromInt(icmpv4_view.get(.code))));

        var view = try parse(icmpv4_view);
        try std.testing.expectEqual(sample.mtu, view.get(.next_hop_mtu));
        try std.testing.expect(view.get(.quoted_packet).len >= 28);
        try std.testing.expectEqual(@as(u8, 4), view.get(.quoted_packet)[0] >> 4);

        const message = icmpv4_view.get(.payload);
        const bytes = try std.testing.allocator.alloc(u8, message.len);
        defer std.testing.allocator.free(bytes);
        var writer: std.Io.Writer = .fixed(bytes);
        try DestinationUnreachableMsgView.serialize(view.copy(), &writer);
        try std.testing.expectEqual(message.len, writer.end);
        try std.testing.expectEqualSlices(u8, message, bytes);
    }
}

test "parse() on captured destination unreachable frames matches Wireshark's fields" {
    const PcapParser = Router.TestFixtures.PcapParser;
    const CsvParser = Router.TestFixtures.ICMPv4.DestinationUnreachableCsvParser;
    var parsed_pcap = try PcapParser.parse(Router.TestFixtures.ICMPv4.message_types_pcap_file, std.testing.allocator);
    defer parsed_pcap.deinit(std.testing.allocator);
    const rows = try CsvParser.parse(Router.TestFixtures.ICMPv4.destination_unreachable_csv_file, std.testing.allocator);
    defer std.testing.allocator.free(rows);

    try std.testing.expect(rows.len > 0);
    for (rows) |expected| {
        const frame = try Router.Protocols.Ethernet.parse(parsed_pcap.packet_bytes[expected.frame_number - 1]);
        const ip_view = try Router.Protocols.IPv4.parse(frame.get(.payload));
        const icmpv4_view = try Router.Protocols.ICMPv4.parse(ip_view.get(.payload));
        try std.testing.expectEqual(Router.Protocols.ICMPv4.MessageType.destination_unreachable, icmpv4_view.get(.message_type));
        try std.testing.expectEqual(expected.code, @as(Code, @enumFromInt(icmpv4_view.get(.code))));
        const view = try parse(icmpv4_view);
        try std.testing.expectEqual(expected.reserved, view.get(.reserved));
        try std.testing.expectEqual(expected.next_hop_mtu, view.get(.next_hop_mtu));
    }
}

test "parse() accepts an unrecognized code and rejects truncated messages" {
    const packet = [_]u8{ 3, 250, 0, 0, 0, 0, 0, 0 } ++ [_]u8{0} ** 28;
    const icmpv4_view = try Router.Protocols.ICMPv4.parse(&packet);
    const code: Code = @enumFromInt(icmpv4_view.get(.code));
    try std.testing.expectEqual(@as(u8, 250), @intFromEnum(code));
    _ = try parse(icmpv4_view);

    for (0..4) |body_len| {
        const short_view = try Router.Protocols.ICMPv4.parse(packet[0 .. 4 + body_len]);
        try std.testing.expectError(error.EndOfStream, parse(short_view));
    }
    const no_quote = try Router.Protocols.ICMPv4.parse(packet[0..8]);
    try std.testing.expectError(error.InvalidField, parse(no_quote));
}

test "parse() rejects a different ICMPv4 message type" {
    const packet = [_]u8{ 8, 0, 0, 0, 0, 0, 0, 0 } ++ [_]u8{0} ** 28;
    const icmpv4_view = try Router.Protocols.ICMPv4.parse(&packet);
    try std.testing.expectError(error.InvalidField, parse(icmpv4_view));
}
