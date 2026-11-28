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
const TestUtils = Router.TestFixtures.Utils;
const View = Router.Meta.View.View;
const ViewStack = Router.Protocols.ViewStack;

const classifyDestination = Router.Protocols.IPv4.classifyDestination;
const forwardNat = Router.Protocols.IPv4.forwardNat;

const lan_ip = &Router.State.lan_ip;
const wan_lease = &Router.State.wan_lease;

const NAT_TIMEOUT = std.Io.Duration.fromSeconds(60);
const REPLY_TTL: u8 = 64;

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
    var view = try parse(icmpv4_view.*);
    Cli.enter(.echo, view);

    const ip_view = views.getView(.ipv4);
    const message_type = icmpv4_view.get(.message_type);
    const my_ip = switch (iface) {
        .lan => lan_ip.*,
        .wan => (wan_lease.* orelse return device.release(buffer)).ip,
    };
    const addressed_to_me = ip_view.fieldCmp(.dst, .{ .eq = my_ip });

    const should_forward = switch (iface) {
        .lan => message_type == .echo_request and !addressed_to_me,
        .wan => message_type == .echo_reply,
    };
    if (should_forward) {
        return forwardNat(
            buffer,
            device,
            iface,
            views,
            &view,
            .{ .lan = .identifier, .wan = .identifier },
            &Router.State.nat_table.icmp_ports,
            NAT_TIMEOUT,
        );
    }
    if (message_type != .echo_request or !addressed_to_me) return device.release(buffer);

    try reply(buffer, device, iface, views);
    device.release(buffer);
}

pub fn replyReassembled(frame: []u8, device: NicApi, iface: IFace) !void {
    var ethernet = try Ethernet.parse(frame);
    var header = try IPv4Protocol.parse(ethernet.get(.payload));
    var icmp = try ICMPv4.parse(header.get(.payload));
    _ = try parse(icmp);
    if (icmp.get(.message_type) != .echo_request) return;
    var views: ViewStack = .{};
    views.setView(.ethernet, &ethernet);
    views.setView(.ipv4, &header);
    views.setView(.icmpv4, &icmp);
    try reply(frame, device, iface, &views);
}

fn reply(buffer: []u8, device: NicApi, iface: IFace, views: *ViewStack) !void {
    const ip_view = views.getView(.ipv4);
    const icmpv4_view = views.getView(.icmpv4);
    const ethernet_view = views.getView(.ethernet);
    const sender_ip = ip_view.get(.src);
    const sender_class = classifyDestination(sender_ip);
    if (ethernet_view.get(.src_mac)[0] & 1 != 0 or
        sender_class == .broadcast or
        sender_class == .multicast or
        sender_class == .drop) return;

    const frame_len = buffer.len - ethernet_view.get(.payload).len + ip_view.get(.total_length);

    ethernet_view.set(.dst_mac, ethernet_view.get(.src_mac));
    ethernet_view.set(.src_mac, device.macAddress(iface));
    ip_view.setUpdateChecksum(.src, ip_view.get(.dst), views);
    ip_view.setUpdateChecksum(.dst, sender_ip, views);
    ip_view.setUpdateChecksum(.ttl, REPLY_TTL, views);
    icmpv4_view.setUpdateChecksum(.message_type, .echo_reply, views);

    const payload = ip_view.get(.payload);
    const prefix = buffer[0 .. frame_len - payload.len];
    const header_len = @as(usize, ip_view.get(.ihl)) * 4;
    const max_chunk = (Ethernet.PAYLOAD_LEN_MAX - header_len) & ~@as(usize, 7);
    const split = ip_view.get(.total_length) > Ethernet.PAYLOAD_LEN_MAX and !ip_view.get(.dont_fragment);
    const options = ip_view.get(.options);
    var scratch: [40]u8 = undefined;
    const copied_options = scratch[0..options.len];
    if (split) {
        @memcpy(copied_options, options);
        try keepCopiedOptions(copied_options);
    }
    var offset: usize = 0;
    while (offset < payload.len) {
        const len = if (split) @min(max_chunk, payload.len - offset) else payload.len;
        if (split) {
            if (offset == max_chunk) @memcpy(options, copied_options);
            ip_view.set(.total_length, @intCast(header_len + len));
            ip_view.set(.more_fragments, offset + len < payload.len);
            ip_view.set(.fragment_offset, @intCast(offset / 8));
            ip_view.set(.header_checksum, 0);
            var checksum = ip_view.checksum();
            checksum.addFields(.version, .options);
            ip_view.set(.header_checksum, checksum.finish());
        }
        const tx_buffer = device.nextTxBuffer(iface);
        errdefer device.release(tx_buffer);
        var writer: std.Io.Writer = .fixed(tx_buffer);
        try writer.writeAll(prefix);
        try writer.writeAll(payload[offset..][0..len]);
        device.transmit(tx_buffer[0..writer.end]);
        offset += len;
    }
}

// Preserve option alignment while removing first-fragment-only options.
fn keepCopiedOptions(options: []u8) !void {
    var i: usize = 0;
    while (i < options.len) {
        const kind = options[i];
        if (kind == 0) break;
        if (kind == 1) {
            i += 1;
            continue;
        }
        if (i + 1 >= options.len) return error.InvalidField;
        const len = options[i + 1];
        if (len < 2 or i + len > options.len) return error.InvalidField;
        if (kind & 0x80 == 0) @memset(options[i..][0..len], 1);
        i += len;
    }
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
    var packet = [_]u8{ 0x08, 0x00, 0x00, 0x00, 0x12, 0x34, 0x00, 0x01 };
    TestUtils.writeIcmpv4Checksum(&packet);
    for (0..4) |body_len| {
        var short: [7]u8 = undefined;
        @memcpy(short[0 .. 4 + body_len], packet[0 .. 4 + body_len]);
        TestUtils.writeIcmpv4Checksum(short[0 .. 4 + body_len]);
        const icmpv4_view = try ICMPv4.parse(short[0 .. 4 + body_len]);
        try std.testing.expectError(error.EndOfStream, parse(icmpv4_view));
    }
    const icmpv4_view = try ICMPv4.parse(&packet);
    const view = try parse(icmpv4_view);
    try std.testing.expectEqual(@as(usize, 0), view.get(.data).len);
}

test "parse() rejects nonzero echo code and non-echo message type" {
    var packet = test_request;
    packet[1] = 1;
    TestUtils.writeIcmpv4Checksum(&packet);
    try std.testing.expectError(error.InvalidField, parse(try ICMPv4.parse(&packet)));
    packet[0] = 3;
    packet[1] = 0;
    TestUtils.writeIcmpv4Checksum(&packet);
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
