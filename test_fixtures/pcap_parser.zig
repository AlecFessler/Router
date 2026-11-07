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

fn readU16(bytes: []const u8) u16 {
    return std.mem.readInt(u16, bytes[0..2], .little);
}

fn readU32(bytes: []const u8) u32 {
    return std.mem.readInt(u32, bytes[0..4], .little);
}

fn parsePcapNg(file: []const u8, alloc: std.mem.Allocator) !ParsedPCAP {
    var parsed_pcap: ParsedPCAP = undefined;
    var packet_headers: std.ArrayList(PacketHeader) = .empty;
    defer packet_headers.deinit(alloc);
    var packet_bytes: std.ArrayList([]const u8) = .empty;
    defer packet_bytes.deinit(alloc);

    var offset: usize = 0;
    var interface_count: u32 = 0;
    while (offset < file.len) {
        if (file.len - offset < 12) return error.TruncatedBlock;
        const block_type = readU32(file[offset..]);
        const block_len = readU32(file[offset + 4 ..]);
        if (block_len < 12 or block_len % 4 != 0 or block_len > file.len - offset)
            return error.InvalidBlock;
        if (readU32(file[offset + block_len - 4 ..]) != block_len)
            return error.InvalidBlock;

        switch (block_type) {
            0x0a0d0d0a => {
                if (block_len < 28) return error.InvalidBlock;
                if (readU32(file[offset + 8 ..]) != 0x1a2b3c4d)
                    return error.UnsupportedByteOrder;
            },
            1 => {
                if (block_len < 20) return error.InvalidBlock;
                if (interface_count != 0) return error.UnsupportedInterface;
                const link_type = readU16(file[offset + 8 ..]);
                parsed_pcap.link_type = switch (link_type) {
                    @intFromEnum(LinkType.NULL) => .NULL,
                    @intFromEnum(LinkType.ETHERNET) => .ETHERNET,
                    else => return error.UnexpectedLinkType,
                };
                parsed_pcap.timestamp_format = .micros;
                parsed_pcap.global_header = .{
                    .magic_number = 0xA1B2C3D4,
                    .major_version = 1,
                    .minor_version = 0,
                    .snap_len = readU32(file[offset + 12 ..]),
                    .link_type = link_type,
                };
                var option_offset = offset + 16;
                const options_end = offset + block_len - 4;
                while (option_offset + 4 <= options_end) {
                    const code = readU16(file[option_offset..]);
                    const len = readU16(file[option_offset + 2 ..]);
                    option_offset += 4;
                    if (code == 0) break;
                    if (len > options_end - option_offset) return error.InvalidBlock;
                    if (code == 9 and len == 1 and file[option_offset] == 9) {
                        parsed_pcap.timestamp_format = .nanos;
                        parsed_pcap.global_header.magic_number = 0xA1B23CD4;
                    }
                    option_offset += std.mem.alignForward(usize, len, 4);
                }
                interface_count += 1;
            },
            6 => {
                if (block_len < 32) return error.InvalidBlock;
                if (interface_count == 0 or readU32(file[offset + 8 ..]) != 0)
                    return error.UnsupportedInterface;
                const captured_len = readU32(file[offset + 20 ..]);
                if (captured_len > block_len - 32) return error.TruncatedPacketData;
                try packet_headers.append(alloc, .{
                    .timestamp_major = readU32(file[offset + 12 ..]),
                    .timestamp_minor = readU32(file[offset + 16 ..]),
                    .captured_len = captured_len,
                    .original_len = readU32(file[offset + 24 ..]),
                });
                try packet_bytes.append(alloc, file[offset + 28 ..][0..captured_len]);
            },
            else => {},
        }
        offset += block_len;
    }

    if (interface_count == 0) return error.UnsupportedInterface;
    parsed_pcap.packet_headers = try packet_headers.toOwnedSlice(alloc);
    parsed_pcap.packet_bytes = try packet_bytes.toOwnedSlice(alloc);
    return parsed_pcap;
}

pub fn parse(file: []const u8, alloc: std.mem.Allocator) !ParsedPCAP {
    if (file.len >= 4 and readU32(file) == 0x0a0d0d0a)
        return parsePcapNg(file, alloc);

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
