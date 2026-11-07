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
const router = @import("router");

const View = router.meta.view.View;

pub const PAYLOAD_LEN_MAX = 1500;
pub const VALID_ETHERTYPE_MIN = 1535;

pub const Mac = [6]u8;

pub const TPID = 0x8100;

// zig lays out packed structs starting from the least significant bit,
// so correct parsing depends on the ordering of these fields being as they are
pub const Tci = packed struct(u16) {
    vid: u12, // VLAN identifier
    dei: bool, // drop eligible indicator
    pcp: u3, // priority code point
};

pub const EthernetFrame = struct {
    dst_mac: Mac,
    src_mac: Mac,
    tpid: ?u16, // tag protocol identifier
    tci: ?Tci, // tag control information
    ethertype: u16,
    payload: []const u8,
};

pub const EthernetFrameView = View(EthernetFrame);

pub fn validate(view: EthernetFrameView) !void {
    if (view.get(.tpid) != null) {
        // if these are not both null or set together, that's a parse() bug
        std.debug.assert(view.get(.tci) != null);
    }

    const ethertype = view.get(.ethertype);
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

    const vlan_tag_present = try reader.peekInt(u16, .big) == TPID;
    if (vlan_tag_present) {
        try frame_view.takeField(.tpid, &reader);
        try frame_view.takeField(.tci, &reader);
        try frame_view.takeField(.ethertype, &reader);
    } else {
        frame_view.set(.tpid, null);
        frame_view.set(.tci, null);
        try frame_view.takeField(.ethertype, &reader);
    }

    try frame_view.takeBytes(.payload, reader.bufferedLen(), &reader);

    try validate(frame_view);
    return frame_view;
}

test "parse() on wireshark captured frames matches wireshark's parsed output" {
    const pcap_parser = router.test_fixtures.ethernet.pcap_parser;
    const csv_parser = router.test_fixtures.ethernet.csv_parser;
    const pcap_file = router.test_fixtures.ethernet.pcap;
    const csv_file = router.test_fixtures.ethernet.csv;

    var parsed_pcap = try pcap_parser.parse(pcap_file, std.testing.allocator);
    defer parsed_pcap.deinit(std.testing.allocator);
    const parsed_frames = try csv_parser.parse(csv_file, std.testing.allocator);
    defer std.testing.allocator.free(parsed_frames);

    for (parsed_frames, 0..) |ws_frame, i| {
        const my_frame = try parse(parsed_pcap.packet_bytes[i]);
        try std.testing.expect(my_frame.isEqualIgnoringSlices(&ws_frame));
    }
}

test "parse() then serialize() returns the original bytes" {
    const pcap_parser = router.test_fixtures.ethernet.pcap_parser;
    const pcap_file = router.test_fixtures.ethernet.pcap;

    var parsed_pcap = try pcap_parser.parse(pcap_file, std.testing.allocator);
    defer parsed_pcap.deinit(std.testing.allocator);

    for (parsed_pcap.packet_bytes) |packet| {
        const buffer = try std.testing.allocator.alloc(u8, packet.len);
        defer std.testing.allocator.free(buffer);
        var writer: std.Io.Writer = .fixed(buffer);

        var frame_view = try parse(packet);
        const copy = frame_view.copy();
        try EthernetFrameView.serialize(copy, &writer);
        try std.testing.expectEqualSlices(u8, packet, buffer);
    }
}

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
    const base_test_buffer: [60]u8 = result: {
        var frame: EthernetFrame = undefined;
        frame.dst_mac = Mac{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
        frame.src_mac = Mac{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
        frame.tpid = null;
        frame.tci = null;
        frame.ethertype = 0x0806;
        frame.payload = &([_]u8{0x11} ** 46);

        var buffer: [60]u8 = undefined;
        var writer: std.Io.Writer = .fixed(&buffer);
        EthernetFrameView.serialize(frame, &writer) catch unreachable;
        break :result buffer;
    };

    for (1501..1536) |invalid_ethertype| {
        var packet = base_test_buffer;
        var frame_view = try parse(&packet);
        frame_view.set(.ethertype, @intCast(invalid_ethertype));
        const copy = frame_view.copy();
        var buffer: [base_test_buffer.len]u8 = undefined;
        var writer: std.Io.Writer = .fixed(&buffer);
        try EthernetFrameView.serialize(copy, &writer);
        try std.testing.expectError(
            error.InvalidEthertype,
            parse(writer.buffer),
        );
    }
}
