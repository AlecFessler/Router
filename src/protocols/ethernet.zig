//! Ethernet frame layout:
//!         ________________________________________________________________________
//! Field: | Preamble | Dest MAC | Src MAC | 802.1Q Tag | Type/Len | Payload | FCS |
//!        -------------------------------------------------------------------------
//! Bytes: |    8     |    6     |    6    |    (4)     |    2     | 42-1.5k |  4  |
//!        -------------------------------------------------------------------------
//!
//! Generally, NICs will trim the preamble and the FCS (Frame Check Sequence).
//!
//! Ethernet packets are expected to be a minimum of 64 bytes, so packets with
//! a payload less than 46 bytes (64 - (6 + 6 + 2 + 4)) will be padded to 46.
//!
//! The 802.1Q tag, or VLAN tag, is 4 bytes, and is optional. With it, the
//! minimum payload size is 42. When the VLAN tag is present, the 2 bytes
//! following the src MAC, known as the tag protocol identifier (TPID) will
//! be 0x8100, the following 2 bytes, known as the tag control information
//! (TCI), are further broken down into 3 more fields. The first 3 bits are
//! the priority code point (PCP), the next bit is the drop eligible indicator
//! (DEI), and the final 12 bits are the VLAN identifier (VID). The expected
//! Type/Len field follows the VLAN tag.
//!
//! 802.1Q tag layout:
//!         _________________________
//! Field: | TPID | PCP | DEI | VID |
//!        --------------------------
//! Bits:  |  16  |  3  |  1  | 12  |
//!        --------------------------
//!
//! An Ethernet host is addressed by its Ethernet MAC address, a 6 byte number such
//! as 08:00:08:15:ca:fe. The first three bytes of the address are assigned to a
//! specific vendor or organization; referred to as an Organizationally Unique
//! Identifier, or an OUI.
//!
//! A destination MAC address of ff:ff:ff:ff:ff:ff indicates a Broadcast, meaning
//! the packet is sent from one host to any other on that network.
//!
//! A destination MAC address where the low-order bit of the first byte is set,
//! which is to say, the byte is an odd integer, indicates a Multicast, meaning
//! the packet is sent from one host to all hosts on the network interested in
//! packets sent to that MAC address.
//!
//! The Type/Len field depends on if it's an IEEE 802.3 frame (Len) or an Ethernet
//! version 2 frame format (Type/Ethertype). The field is interpreted as a length
//! field if it has a value <= 1500 and as a type field if it has a value > 1500.
//!
//! Examples of values in the Type/Len field:
//!   - 0-1500 Len,  IEEE 802.3 and/or 802.2
//!   - 0x0800 IPv4, Internet Protocol version 4
//!   - 0x0806 ARP,  Address Resolution Protocol
//!   - 0x8137 IPX,  Internet Packet eXchange
//!   - 0x86dd IPv6, Internet Protocol version 6

const std = @import("std");
const Router = @import("router");

const Arp = Router.Protocols.Arp;
const Cli = Router.Debug.Cli;
const IFace = Router.Nic.Api.IFace;
const IPv4 = Router.Protocols.IPv4;
const NicApi = Router.Nic.Api.Api;
const View = Router.Meta.View.View;

pub const PAYLOAD_LEN_MAX = 1500;
pub const VALID_ETHERTYPE_MIN = 1535;

pub const Mac = [6]u8;

pub const Ethertype = enum(u16) {
    ipv4 = 0x0800,
    arp = 0x0806,
    tpid = 0x8100,
    _,
};

pub const EthernetFrame = struct {
    dst_mac: Mac,
    src_mac: Mac,
    tpid: ?Ethertype, // tag protocol identifier
    // tag control information
    pcp: ?u3, // priority code point
    dei: ?bool, // drop eligible indicator
    vid: ?u12, // VLAN identifier
    ethertype: Ethertype,
    payload: []u8,
};

pub const EthernetFrameView = View(EthernetFrame);

pub fn validate(view: EthernetFrameView) !void {
    if (view.get(.tpid) != null) {
        try view.validate(.tpid, .{ .eq = .tpid });
        if (view.get(.pcp) == null or view.get(.dei) == null or view.get(.vid) == null)
            return error.InvalidField;
    } else {
        if (view.get(.pcp) != null or view.get(.dei) != null or view.get(.vid) != null)
            return error.InvalidField;
    }

    const ethertype = @intFromEnum(view.get(.ethertype));
    const is_ethernet_II_frame = ethertype > PAYLOAD_LEN_MAX;
    const ethertype_invalid = is_ethernet_II_frame and ethertype <= VALID_ETHERTYPE_MIN;
    if (ethertype_invalid) {
        return error.InvalidEthertype;
    }
}

pub fn parse(buffer: []const u8) !EthernetFrameView {
    var frame_view: EthernetFrameView = undefined;
    var reader: std.Io.Reader = .fixed(buffer);

    try frame_view.takeField(.dst_mac, &reader);
    try frame_view.takeField(.src_mac, &reader);

    const vlan_tag_present = try reader.peekInt(u16, .big) == @intFromEnum(Ethertype.tpid);
    if (vlan_tag_present) {
        try frame_view.takeFields(.tpid, .ethertype, &reader);
    } else {
        frame_view.set(.tpid, null);
        frame_view.set(.pcp, null);
        frame_view.set(.dei, null);
        frame_view.set(.vid, null);
        try frame_view.takeField(.ethertype, &reader);
    }

    const ethertype = @intFromEnum(frame_view.get(.ethertype));
    const payload_len = if (ethertype <= PAYLOAD_LEN_MAX)
        ethertype
    else
        reader.bufferedLen();
    try frame_view.takeBytes(.payload, payload_len, &reader);

    try validate(frame_view);
    return frame_view;
}

pub fn handle(
    buffer: []u8,
    device: NicApi,
    iface: IFace,
) !void {
    const view = try parse(buffer);
    Cli.enter(.ethernet, view);
    const ethertype = view.get(.ethertype);
    switch (ethertype) {
        .ipv4 => try IPv4.handle(buffer, view.get(.payload), device, iface),
        .arp => try Arp.handle(buffer, view.get(.payload), device, iface),
        else => {
            const name = std.enums.tagName(Ethertype, ethertype);
            if (name) |tag| {
                std.debug.print(
                    "Ethernet: packet with ethertype {s} unhandled by {s} interface\n",
                    .{ tag, @tagName(iface) },
                );
            } else {
                std.debug.print(
                    "Ethernet: packet with ethertype 0x{x:0>4} unhandled by {s} interface\n",
                    .{ @intFromEnum(ethertype), @tagName(iface) },
                );
            }
            device.release(buffer);
        },
    }
}

const test_frame = [_]u8{
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
    0x08, 0x06,
};

test "parse() rejects insufficient sized buffers" {
    for (0..14) |invalid_size| {
        const buffer = try std.testing.allocator.alloc(u8, invalid_size);
        defer std.testing.allocator.free(buffer);
        try std.testing.expectError(
            error.EndOfStream,
            parse(buffer),
        );
    }
}

test "parse() rejects invalid ethertypes" {
    for (1501..1536) |invalid_ethertype| {
        var packet = test_frame;
        packet[12] = @intCast(invalid_ethertype >> 8);
        packet[13] = @intCast(invalid_ethertype & 0xff);
        try std.testing.expectError(error.InvalidEthertype, parse(&packet));
    }
}

test "parse() uses the 802.3 length field and excludes padding" {
    const payload = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const untagged = [_]u8{
        0, 1, 2,    3,    4,    5,    6, 7, 8, 9, 10, 11,
        0, 4, 0xaa, 0xbb, 0xcc, 0xdd,
    };
    const tagged = [_]u8{
        0,    1,    2,    3,    4, 5, 6,    7,    8,    9,    10, 11,
        0x81, 0x00, 0x60, 0x64, 0, 4, 0xaa, 0xbb, 0xcc, 0xdd,
    };

    for ([_][]const u8{ &untagged, &tagged }) |packet| {
        var buffer: [64]u8 = .{0xee} ** 64;
        @memcpy(buffer[0..packet.len], packet);

        const view = try parse(&buffer);
        try std.testing.expectEqual(@as(u16, payload.len), @intFromEnum(view.get(.ethertype)));
        try std.testing.expectEqualSlices(u8, &payload, view.get(.payload));
        try std.testing.expectEqual(
            @intFromPtr(&buffer[packet.len - payload.len]),
            @intFromPtr(view.get(.payload).ptr),
        );
        try std.testing.expectError(error.EndOfStream, parse(buffer[0 .. packet.len - 1]));
    }
}

test "parse() reads VLAN bit fields and validate() rejects partial tags" {
    var packet = [_]u8{
        0,    1,    2,    3,    4,    5,    6, 7, 8, 9, 10, 11,
        0x81, 0x00, 0x60, 0x64, 0x08, 0x00,
    };
    var view = try parse(&packet);
    try std.testing.expectEqual(@as(?u3, 3), view.get(.pcp));
    try std.testing.expectEqual(@as(?bool, false), view.get(.dei));
    try std.testing.expectEqual(@as(?u12, 100), view.get(.vid));

    view.set(.pcp, null);
    try std.testing.expectError(error.InvalidField, validate(view));
    var without_tpid = try parse(&packet);
    without_tpid.set(.tpid, null);
    try std.testing.expectError(error.InvalidField, validate(without_tpid));
}

test "parse() on wireshark captured frames matches wireshark's parsed output" {
    const PcapParser = Router.TestFixtures.PcapParser;
    const CsvParser = Router.TestFixtures.Ethernet.CsvParser;
    const pcap_file = Router.TestFixtures.Ethernet.pcap_file;
    const csv_file = Router.TestFixtures.Ethernet.csv_file;

    var parsed_pcap = try PcapParser.parse(pcap_file, std.testing.allocator);
    defer parsed_pcap.deinit(std.testing.allocator);
    const parsed_frames = try CsvParser.parse(csv_file, std.testing.allocator);
    defer std.testing.allocator.free(parsed_frames);

    for (parsed_frames, 0..) |ws_frame, i| {
        const my_frame = try parse(parsed_pcap.packet_bytes[i]);
        try std.testing.expect(my_frame.isEqualIgnoringSlices(&ws_frame));
    }
}

test "parse() then serialize() returns the original bytes" {
    const PcapParser = Router.TestFixtures.PcapParser;
    const pcap_file = Router.TestFixtures.Ethernet.pcap_file;

    var parsed_pcap = try PcapParser.parse(pcap_file, std.testing.allocator);
    defer parsed_pcap.deinit(std.testing.allocator);

    for (parsed_pcap.packet_bytes) |packet| {
        const buffer = try std.testing.allocator.alloc(u8, packet.len);
        defer std.testing.allocator.free(buffer);
        var writer: std.Io.Writer = .fixed(buffer);

        var frame_view = try parse(packet);
        const copy = frame_view.copy();
        try EthernetFrameView.serialize(copy, &writer);
        const header_len: usize = if (copy.tpid != null) 18 else 14;
        try std.testing.expectEqual(header_len + copy.payload.len, writer.end);
        try std.testing.expectEqualSlices(u8, packet[0..writer.end], buffer[0..writer.end]);
    }
}
