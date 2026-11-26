const std = @import("std");
const Router = @import("router");

const Cli = Router.Debug.Cli;
const CsvParser = ICMPv4Fixtures.TimeExceededCsvParser;
const Ethernet = Router.Protocols.Ethernet;
const Format = Router.Meta.Format;
const ICMPv4 = Router.Protocols.ICMPv4;
const ICMPv4Fixtures = Router.TestFixtures.ICMPv4;
const ICMPv4PacketView = Router.Protocols.ICMPv4.ICMPv4PacketView;
const IFace = Router.Nic.Api.IFace;
const IPv4Protocol = Router.Protocols.IPv4;
const NicApi = Router.Nic.Api.Api;
const PcapParser = Router.TestFixtures.PcapParser;
const View = Router.Meta.View.View;
const ViewStack = Router.Protocols.ViewStack;

pub const Code = enum(u8) {
    ttl_exceeded = 0,
    fragment_reassembly_timeout = 1,
};

pub const TimeExceededMsg = struct {
    reserved: u32, // RFC 4884 may use its second byte as a quote-length field.
    quoted_packet: []u8,
};

pub const TimeExceededMsgView = View(TimeExceededMsg);

pub fn validate(view: TimeExceededMsgView, icmpv4_view: ICMPv4PacketView) !void {
    if (!icmpv4_view.fieldCmp(.message_type, .{ .eq = .time_exceeded })) return error.InvalidField;
    try icmpv4_view.validate(.code, .{ .lte = 1 });
    if (view.get(.quoted_packet).len < 28) return error.InvalidField;
}

pub fn parse(icmpv4_view: ICMPv4PacketView) !TimeExceededMsgView {
    var view: TimeExceededMsgView = undefined;
    var reader: std.Io.Reader = .fixed(icmpv4_view.get(.payload));
    try view.takeField(.reserved, &reader);
    try view.takeBytes(.quoted_packet, reader.bufferedLen(), &reader);
    try validate(view, icmpv4_view);
    return view;
}

pub fn handle(
    buffer: []u8,
    device: NicApi,
    iface: IFace,
    views: *ViewStack,
) !void {
    const icmpv4_view = views.getView(.icmpv4);
    const view = try parse(icmpv4_view.*);
    Cli.enter(.time_exceeded, view);
    const code: Code = @enumFromInt(icmpv4_view.get(.code));
    switch (code) {
        .ttl_exceeded => std.debug.print(
            "ICMPv4: {f} unhandled by {s} interface\n",
            .{ Format.enumLabel(code), @tagName(iface) },
        ),
        .fragment_reassembly_timeout => std.debug.print(
            "ICMPv4: {f} unhandled by {s} interface\n",
            .{ Format.enumLabel(code), @tagName(iface) },
        ),
    }
    device.release(buffer);
}

test "parse() on synthetic captured frames matches Wireshark's fields" {
    var parsed_pcap = try PcapParser.parse(ICMPv4Fixtures.time_exceeded_pcap_file, std.testing.allocator);
    defer parsed_pcap.deinit(std.testing.allocator);
    const rows = try CsvParser.parse(ICMPv4Fixtures.time_exceeded_csv_file, std.testing.allocator);
    defer std.testing.allocator.free(rows);

    try std.testing.expectEqual(@as(usize, 2), rows.len);
    try std.testing.expectEqual(parsed_pcap.packet_bytes.len, rows.len);
    for (rows) |expected| {
        const frame = try Ethernet.parse(parsed_pcap.packet_bytes[expected.frame_number - 1]);
        const ip_view = try IPv4Protocol.parse(frame.get(.payload));
        const icmpv4_view = try ICMPv4.parse(ip_view.get(.payload));
        try std.testing.expectEqual(ICMPv4.MessageType.time_exceeded, icmpv4_view.get(.message_type));
        try std.testing.expectEqual(expected.code, @as(Code, @enumFromInt(icmpv4_view.get(.code))));

        var view = try parse(icmpv4_view);
        try std.testing.expectEqual(expected.reserved, view.get(.reserved));
        try std.testing.expectEqual(@as(usize, 28), view.get(.quoted_packet).len);
        try std.testing.expectEqual(@as(u8, 4), view.get(.quoted_packet)[0] >> 4);

        const message = icmpv4_view.get(.payload);
        const bytes = try std.testing.allocator.alloc(u8, message.len);
        defer std.testing.allocator.free(bytes);
        var writer: std.Io.Writer = .fixed(bytes);
        try TimeExceededMsgView.serialize(view.copy(), &writer);
        try std.testing.expectEqual(message.len, writer.end);
        try std.testing.expectEqualSlices(u8, message, bytes);
    }
}

test "parse() rejects truncated messages, invalid codes, and other types" {
    const packet = [_]u8{ 11, 0, 0, 0, 0, 0, 0, 0 } ++ [_]u8{0} ** 28;
    for (0..4) |body_len| {
        const short_view = try ICMPv4.parse(packet[0 .. 4 + body_len]);
        try std.testing.expectError(error.EndOfStream, parse(short_view));
    }
    const no_quote = try ICMPv4.parse(packet[0..8]);
    try std.testing.expectError(error.InvalidField, parse(no_quote));

    var invalid = packet;
    invalid[1] = 2;
    try std.testing.expectError(error.InvalidField, parse(try ICMPv4.parse(&invalid)));
    invalid[0] = 3;
    invalid[1] = 0;
    try std.testing.expectError(error.InvalidField, parse(try ICMPv4.parse(&invalid)));
}
