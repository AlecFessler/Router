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

pub const VlanTag = packed struct(u32) {
    tpid: u16 = TPID, // tag protocol identifier
    tci: Tci, // tag control information
};

pub const EthernetFrame = struct {
    dst_mac: Mac,
    src_mac: Mac,
    vlan_tag: ?VlanTag = null,
    ethertype: u16,
    payload: []const u8,

    pub fn isEqual(self: *const EthernetFrame, other: *const EthernetFrame) bool {
        if (!std.mem.eql(u8, &self.dst_mac, &other.dst_mac)) {
            return false;
        }
        if (!std.mem.eql(u8, &self.src_mac, &other.src_mac)) {
            return false;
        }
        if (!std.meta.eql(self.vlan_tag, other.vlan_tag)) {
            return false;
        }
        if (self.ethertype != other.ethertype) {
            return false;
        }
        return true;
    }

    pub fn printDebug(self: *const EthernetFrame) void {
        std.debug.print("Dst MAC: ", .{});
        std.debug.print("{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}\n", .{
            self.dst_mac[0],
            self.dst_mac[1],
            self.dst_mac[2],
            self.dst_mac[3],
            self.dst_mac[4],
            self.dst_mac[5],
        });
        std.debug.print("Src MAC: ", .{});
        std.debug.print("{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}\n", .{
            self.src_mac[0],
            self.src_mac[1],
            self.src_mac[2],
            self.src_mac[3],
            self.src_mac[4],
            self.src_mac[5],
        });
        std.debug.print("Ethertype: 0x{X:0>4}\n", .{self.ethertype});
        if (self.vlan_tag != null) {
            const vlan_tag = self.vlan_tag.?;
            std.debug.print("TPID: 0x{X}\nPCP: {}\nDEI: {}\nVID: {}\n", .{
                vlan_tag.tpid,
                vlan_tag.tci.pcp,
                vlan_tag.tci.dei,
                vlan_tag.tci.vid,
            });
        }
        std.debug.print("\n", .{});
    }
};

pub fn parse(buffer: []const u8) !EthernetFrame {
    var frame: EthernetFrame = undefined;
    var reader: std.Io.Reader = .fixed(buffer);

    try reader.readSliceAll(&frame.dst_mac);
    try reader.readSliceAll(&frame.src_mac);
    const discriminator = try reader.takeInt(u16, .big);

    var is_ethernet_II_frame = discriminator > PAYLOAD_LEN_MAX;
    var ethertype_invalid = is_ethernet_II_frame and discriminator <= VALID_ETHERTYPE_MIN;
    if (ethertype_invalid) {
        return error.InvalidEthertype;
    }

    const vlan_tag_present = discriminator == TPID;
    if (vlan_tag_present) {
        const tci_bits = try reader.takeInt(u16, .big);
        frame.vlan_tag = .{
            .tpid = discriminator,
            .tci = @bitCast(tci_bits),
        };
        frame.ethertype = try reader.takeInt(u16, .big);

        is_ethernet_II_frame = frame.ethertype > PAYLOAD_LEN_MAX;
        ethertype_invalid = is_ethernet_II_frame and frame.ethertype <= VALID_ETHERTYPE_MIN;
        if (ethertype_invalid) {
            return error.InvalidEthertype;
        }
    } else {
        frame.ethertype = discriminator;
        frame.vlan_tag = null;
    }

    if (is_ethernet_II_frame) {
        frame.payload = reader.buffer[reader.seek..reader.end];
    } else { // is IEEE 802.3 frame
        frame.payload = try reader.take(discriminator);
    }

    return frame;
}

pub fn serialize(frame: EthernetFrame, buffer: []u8) ![]u8 {
    var writer: std.Io.Writer = .fixed(buffer);
    try writer.writeAll(&frame.dst_mac);
    try writer.writeAll(&frame.src_mac);
    if (frame.vlan_tag != null) {
        try writer.writeInt(u16, frame.vlan_tag.?.tpid, .big);
        try writer.writeInt(u16, @bitCast(frame.vlan_tag.?.tci), .big);
    }
    try writer.writeInt(u16, frame.ethertype, .big);
    try writer.writeAll(frame.payload);
    return writer.buffer[0..writer.end];
}

test "parse() on wireshark captured frames matches wireshark's parsed output" {
    const pcap_parser = @import("pcap_parser");
    const csv_parser = @import("ethernet_csv_parser");
    const pcap_file = @embedFile("ethernet_test_pcap");
    const csv_file = @embedFile("ethernet_test_csv");

    var parsed_pcap = try pcap_parser.parse(pcap_file, std.testing.allocator);
    defer parsed_pcap.deinit(std.testing.allocator);
    const parsed_frames = try csv_parser.parse(csv_file, std.testing.allocator);
    defer std.testing.allocator.free(parsed_frames);

    for (parsed_frames, 0..) |ws_frame, i| {
        const my_frame = try parse(parsed_pcap.packet_bytes[i]);
        const is_equal = my_frame.isEqual(&ws_frame);
        if (!is_equal) {
            std.debug.print("Frame #{}\n\n", .{i + 1});
            std.debug.print("My frame:\n", .{});
            my_frame.printDebug();
            std.debug.print("Wireshark frame:\n", .{});
            ws_frame.printDebug();
        }
        try std.testing.expect(is_equal);
    }
}

test "parse() then serialize() returns the original bytes" {
    const pcap_parser = @import("pcap_parser");
    const pcap_file = @embedFile("ethernet_test_pcap");

    var parsed_pcap = try pcap_parser.parse(pcap_file, std.testing.allocator);
    defer parsed_pcap.deinit(std.testing.allocator);

    for (parsed_pcap.packet_bytes) |packet| {
        const buffer = try std.testing.allocator.alloc(u8, packet.len);
        defer std.testing.allocator.free(buffer);

        const serialized = try serialize(try parse(packet), buffer);
        try std.testing.expectEqualSlices(u8, packet, serialized);
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
        const dst_mac = Mac{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
        const src_mac = Mac{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
        const ethertype: u16 = 0x0806;
        const payload: [46]u8 = .{0x11} ** 46;
        var buffer: [60]u8 = undefined;
        var writer: std.Io.Writer = .fixed(&buffer);
        writer.writeAll(&dst_mac) catch {};
        writer.writeAll(&src_mac) catch {};
        writer.writeInt(u16, ethertype, .big) catch {};
        writer.writeAll(&payload) catch {};
        break :result buffer;
    };

    for (1501..1536) |invalid_ethertype| {
        var frame = try parse(&base_test_buffer);
        frame.ethertype = @intCast(invalid_ethertype);
        var buffer: [base_test_buffer.len]u8 = undefined;
        const serialized = try serialize(frame, &buffer);
        try std.testing.expectError(
            error.InvalidEthertype,
            parse(serialized),
        );
    }
}
