const std = @import("std");
const Router = @import("router");

const EthernetFrame = Router.Protocols.Ethernet.EthernetFrame;
const Mac = Router.Protocols.Ethernet.Mac;
const Tci = Router.Protocols.Ethernet.Tci;

fn parseMac(str: []const u8) !Mac {
    var parts = std.mem.splitScalar(u8, str, ':');
    var mac: Mac = undefined;
    for (&mac) |*byte| {
        const hex = parts.next() orelse return error.InvalidMac;
        byte.* = try std.fmt.parseInt(u8, hex, 16);
    }
    return mac;
}

pub fn parse(file: []const u8, alloc: std.mem.Allocator) ![]EthernetFrame {
    var reader: std.Io.Reader = .fixed(file);

    var frames: std.ArrayList(EthernetFrame) = .empty;
    defer frames.deinit(alloc);

    _ = try reader.takeDelimiter('\n') orelse return error.UnexpectedFileFormat; // skip header line

    while (true) {
        const row = try reader.takeDelimiter('\n') orelse break;
        var row_reader: std.Io.Reader = .fixed(row);

        _ = try row_reader.takeDelimiter(',') orelse return error.UnexpectedFileFormat; // skip the frame number
        const dst_mac_str = try row_reader.takeDelimiter(',') orelse return error.UnexpectedFileFormat;
        const src_mac_str = try row_reader.takeDelimiter(',') orelse return error.UnexpectedFileFormat;
        const ethertype_str = try row_reader.takeDelimiter(',') orelse return error.UnexpecetedFileFormat;
        const len_str = try row_reader.takeDelimiter(',') orelse return error.UnexpectedFileFormat;
        const vlan_vid_str = try row_reader.takeDelimiter(',') orelse return error.UnexpectedFileFormat;
        const vlan_pcp_str = try row_reader.takeDelimiter(',') orelse return error.UnexpectedFileFormat;
        const vlan_dei_str = try row_reader.takeDelimiter(',') orelse return error.UnexpectedFileFormat;
        const vlan_etype_str = row_reader.buffer[row_reader.seek..row_reader.end];

        var frame: EthernetFrame = undefined;

        frame.dst_mac = try parseMac(dst_mac_str);
        frame.src_mac = try parseMac(src_mac_str);

        if (ethertype_str.len != 0) {
            // trim the 0x or else parseInt errors
            frame.ethertype = @enumFromInt(try std.fmt.parseInt(u16, ethertype_str[2..], 16));
        } else { // is IEEE 802.3 frame
            if (len_str.len == 0) {
                return error.UnexpectedFileFormat;
            }
            frame.ethertype = @enumFromInt(try std.fmt.parseInt(u16, len_str, 10));
        }

        if (vlan_vid_str.len != 0) {
            if (vlan_pcp_str.len == 0 or vlan_dei_str.len == 0 or vlan_etype_str.len == 0) {
                return error.UnexpectedFileFormat;
            }

            // if a vlan tag is present, wireshark uses vlan.etype for the ethertype
            // trim the 0x or else parseInt errors
            frame.ethertype = @enumFromInt(try std.fmt.parseInt(u16, vlan_etype_str[2..], 16));

            var tci: Tci = undefined;
            frame.tpid = .tpid;
            tci.vid = try std.fmt.parseInt(u12, vlan_vid_str, 10);
            tci.pcp = try std.fmt.parseInt(u3, vlan_pcp_str, 10);

            if (std.mem.eql(u8, vlan_dei_str, "True")) {
                tci.dei = true;
            } else if (std.mem.eql(u8, vlan_dei_str, "False")) {
                tci.dei = false;
            } else {
                return error.UnexpectedFileFormat;
            }

            frame.tci = tci;
        } else {
            frame.tpid = null;
            frame.tci = null;
        }

        try frames.append(alloc, frame);
    }

    return try frames.toOwnedSlice(alloc);
}
