const std = @import("std");

pub const TimestampFormat = enum {
    micros,
    nanos,
};

pub const LinkType = enum(u8) {
    NULL = 0,
    ETHERNET = 1,
    // I don't need the others for now
};

pub const GlobalHeader = extern struct {
    magic_number: u32,
    major_version: u16,
    minor_version: u16,
    _reserved1: u32 = 0,
    _reserved2: u32 = 0,
    snap_len: u32,
    link_type: u32,
};

pub const PacketHeader = extern struct {
    timestamp_major: u32,
    timestamp_minor: u32,
    captured_len: u32,
    original_len: u32,
};

pub const ParsedPCAP = struct {
    global_header: GlobalHeader,
    timestamp_format: TimestampFormat,
    link_type: LinkType,
    packet_headers: []const PacketHeader,
    packet_bytes: [][]const u8,

    pub fn deinit(self: *ParsedPCAP, alloc: std.mem.Allocator) void {
        alloc.free(self.packet_headers);
        alloc.free(self.packet_bytes);
    }
};

pub fn parse(file: []const u8, alloc: std.mem.Allocator) !ParsedPCAP {
    var reader: std.Io.Reader = .fixed(file);

    var parsed_pcap: ParsedPCAP = undefined;

    var packet_headers: std.ArrayList(PacketHeader) = .empty;
    defer packet_headers.deinit(alloc);
    var packet_bytes: std.ArrayList([]const u8) = .empty;
    defer packet_bytes.deinit(alloc);

    const global_header_bytes = try reader.take(@sizeOf(GlobalHeader));
    parsed_pcap.global_header = std.mem.bytesAsValue(GlobalHeader, global_header_bytes).*;

    switch (parsed_pcap.global_header.magic_number) {
        0xA1B2C3D4 => {
            parsed_pcap.timestamp_format = .micros;
        },
        0xA1B23CD4 => {
            parsed_pcap.timestamp_format = .nanos;
        },
        else => {
            return error.UnexpectedMagicNumber;
        },
    }

    switch (parsed_pcap.global_header.link_type) {
        @intFromEnum(LinkType.NULL) => {
            parsed_pcap.link_type = .NULL;
        },
        @intFromEnum(LinkType.ETHERNET) => {
            parsed_pcap.link_type = .ETHERNET;
        },
        else => {
            return error.UnexpectedLinkType;
        },
    }

    while (reader.bufferedLen() != 0) {
        if (reader.bufferedLen() < @sizeOf(PacketHeader)) {
            return error.TruncatedPacketHeader;
        }
        const packet_header_bytes = try reader.take(@sizeOf(PacketHeader));
        const packet_header = std.mem.bytesAsValue(PacketHeader, packet_header_bytes).*;

        if (reader.bufferedLen() < packet_header.captured_len) {
            return error.TruncatedPacketData;
        }
        const bytes = try reader.take(packet_header.captured_len);

        try packet_headers.append(alloc, packet_header);
        try packet_bytes.append(alloc, bytes);
    }

    parsed_pcap.packet_headers = try packet_headers.toOwnedSlice(alloc);
    parsed_pcap.packet_bytes = try packet_bytes.toOwnedSlice(alloc);

    return parsed_pcap;
}
