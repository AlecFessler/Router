const std = @import("std");
const Router = @import("router");

const Cli = Router.Debug.Cli;
const CsvParser = ICMPv4Fixtures.EchoCsvParser;
const Ethernet = Router.Protocols.Ethernet;
const ICMPv4 = Router.Protocols.ICMPv4;
const ICMPv4Fixtures = Router.TestFixtures.ICMPv4;
const ICMPv4PacketView = Router.Protocols.ICMPv4.ICMPv4PacketView;
const IFace = Router.Nic.Api.IFace;
const IPv4Protocol = Router.Protocols.IPv4;
const NicApi = Router.Nic.Api.Api;
const PcapParser = Router.TestFixtures.PcapParser;
const View = Router.Meta.View.View;
const ViewStack = Router.Protocols.ViewStack;

pub const EchoMsg = struct {
    identifier: u16,
    sequence_number: u16,
    data: []u8,
};

pub const EchoMsgView = View(EchoMsg);

pub fn validate(icmpv4_view: ICMPv4PacketView) !void {
    switch (icmpv4_view.get(.message_type)) {
        .echo_request, .echo_reply => {},
        else => return error.InvalidField,
    }
    try icmpv4_view.validate(.code, .{ .eq = 0 });
}

pub fn parse(icmpv4_view: ICMPv4PacketView) !EchoMsgView {
    var view: EchoMsgView = undefined;
    var reader: std.Io.Reader = .fixed(icmpv4_view.get(.payload));
    try view.takeFields(.identifier, .sequence_number, &reader);
    try view.takeBytes(.data, reader.bufferedLen(), &reader);
    try validate(icmpv4_view);
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
    Cli.enter(.echo, view);
    switch (icmpv4_view.get(.message_type)) {
        .echo_request => std.debug.print("ICMPv4 echo request unhandled by {s} interface\n", .{@tagName(iface)}),
        .echo_reply => std.debug.print("ICMPv4 echo reply unhandled by {s} interface\n", .{@tagName(iface)}),
        else => unreachable,
    }
    device.release(buffer);
}

const test_request = [_]u8{ 0x08, 0x00, 0x21, 0x68, 0x12, 0x34, 0x00, 0x01, 'a', 'b', 'c' };
const test_reply = [_]u8{ 0x00, 0x00, 0x29, 0x68, 0x12, 0x34, 0x00, 0x01, 'a', 'b', 'c' };

test "parse() reads echo request and reply fields" {
    inline for (.{ test_request, test_reply }) |packet| {
        const icmpv4_view = try ICMPv4.parse(&packet);
        const view = try parse(icmpv4_view);
        try std.testing.expectEqual(@as(u16, 0x1234), view.get(.identifier));
        try std.testing.expectEqual(@as(u16, 1), view.get(.sequence_number));
        try std.testing.expectEqualSlices(u8, "abc", view.get(.data));
    }
}

test "parse() accepts empty data and rejects truncated echo fields" {
    const packet = [_]u8{ 0x08, 0x00, 0x00, 0x00, 0x12, 0x34, 0x00, 0x01 };
    for (0..4) |body_len| {
        const icmpv4_view = try ICMPv4.parse(packet[0 .. 4 + body_len]);
        try std.testing.expectError(error.EndOfStream, parse(icmpv4_view));
    }
    const icmpv4_view = try ICMPv4.parse(&packet);
    const view = try parse(icmpv4_view);
    try std.testing.expectEqual(@as(usize, 0), view.get(.data).len);
}

test "parse() rejects nonzero echo code and non-echo message type" {
    var packet = test_request;
    packet[1] = 1;
    packet[2] = 0;
    packet[3] = 0;
    try std.testing.expectError(error.InvalidField, parse(try ICMPv4.parse(&packet)));
    packet[0] = 3;
    packet[1] = 0;
    try std.testing.expectError(error.InvalidField, parse(try ICMPv4.parse(&packet)));
}

test "parse() on captured echo frames matches Wireshark's fields" {
    var parsed_pcap = try PcapParser.parse(ICMPv4Fixtures.pcap_file, std.testing.allocator);
    defer parsed_pcap.deinit(std.testing.allocator);
    const rows = try CsvParser.parse(ICMPv4Fixtures.echo_csv_file, std.testing.allocator);
    defer std.testing.allocator.free(rows);

    try std.testing.expectEqual(parsed_pcap.packet_bytes.len, rows.len);
    for (rows) |expected| {
        const frame = try Ethernet.parse(parsed_pcap.packet_bytes[expected.frame_number - 1]);
        const ip_view = try IPv4Protocol.parse(frame.get(.payload));
        const icmpv4_view = try ICMPv4.parse(ip_view.get(.payload));
        try std.testing.expectEqual(expected.message_type, icmpv4_view.get(.message_type));
        const view = try parse(icmpv4_view);
        try std.testing.expectEqual(expected.identifier, view.get(.identifier));
        try std.testing.expectEqual(expected.sequence_number, view.get(.sequence_number));
    }
}

test "parse() then serialize() returns captured echo message bytes" {
    const pcap_file = ICMPv4Fixtures.pcap_file;
    var parsed_pcap = try PcapParser.parse(pcap_file, std.testing.allocator);
    defer parsed_pcap.deinit(std.testing.allocator);

    var echo_count: usize = 0;
    for (parsed_pcap.packet_bytes) |packet| {
        const frame = try Ethernet.parse(packet);
        const ip_view = try IPv4Protocol.parse(frame.get(.payload));
        const icmpv4_view = try ICMPv4.parse(ip_view.get(.payload));
        switch (icmpv4_view.get(.message_type)) {
            .echo_request, .echo_reply => {},
            else => continue,
        }
        echo_count += 1;
        var view = try parse(icmpv4_view);
        const message = icmpv4_view.get(.payload);
        const buffer = try std.testing.allocator.alloc(u8, message.len);
        defer std.testing.allocator.free(buffer);
        var writer: std.Io.Writer = .fixed(buffer);
        try EchoMsgView.serialize(view.copy(), &writer);
        try std.testing.expectEqual(message.len, writer.end);
        try std.testing.expectEqualSlices(u8, message, buffer);
    }
    try std.testing.expect(echo_count > 0);
}
