const std = @import("std");
const Router = @import("router");

const Cli = Router.Debug.Cli;
const Format = Router.Meta.Format;
const IFace = Router.Nic.Api.IFace;
const IPv4 = Router.Protocols.IPv4.IPv4;
const Mac = Router.Protocols.Ethernet.Mac;
const NicApi = Router.Nic.Api.Api;
const View = Router.Meta.View.View;

pub var g_wan_lease: DHCPv4Lease = .{};

pub const DHCPv4Lease = struct {
    ip: IPv4,
};

pub const Op = enum(u8) {
    BOOTREQUEST = 0x1,
    BOOTREPLY = 0x2,
    _,
};

const DHCPV4_MAGIC = 0x63825363;

pub const DHCPv4Packet = struct {
    op: Op,
    htype: u8 = 0x1,
    hlen: u8 = 0x6,
    hops: u8 = 0,
    xid: u32,
    secs: u16,
    broadcast_flag: bool,
    reserved_flags: u15 = 0,
    client_ip: IPv4,
    your_ip: IPv4,
    next_server_ip: IPv4,
    relay_agent_ip: IPv4,
    client_hw_addr: [16]u8,
    server_name: [64]u8,
    file: [128]u8,
    magic: u32 = DHCPV4_MAGIC,
    options: []u8,
};

pub const DHCPv4PacketView = View(DHCPv4Packet);

pub const OptionType = enum(u8) {
    pad = 0,
    subnet_mask = 1,
    router = 3,
    dns_servers = 6,
    host_name = 12,
    domain_name = 15,
    interface_mtu = 26,
    broadcast_address = 28,
    static_route = 33,
    requested_ip_address = 50,
    lease_time = 51,
    message_type = 53,
    server_id = 54,
    parameter_request_list = 55,
    max_message_size = 57,
    renewal_time = 58,
    rebinding_time = 59,
    client_id = 61,
    domain_search = 119,
    classless_static_route = 121,
    end = 255,
    _,
};

pub const Option = struct {
    code: OptionType,
    len: u8,
    data: []u8,
};

pub const OptionView = View(Option);

pub const MessageType = enum(u8) {
    discover = 0x1,
    offer = 0x2,
    request = 0x3,
    decline = 0x4,
    ack = 0x5,
    nak = 0x6,
    release = 0x7,
    inform = 0x8,
    _,
};

pub const StaticRoute = extern struct {
    destination: IPv4,
    router: IPv4,
};

pub const OptionValue = union(enum) {
    subnet_mask: IPv4,
    router: []const IPv4,
    dns_servers: []const IPv4,
    host_name: []u8,
    domain_name: []u8,
    interface_mtu: u16,
    broadcast_address: IPv4,
    static_route: []const StaticRoute,
    requested_ip_address: IPv4,
    lease_time: std.Io.Duration,
    message_type: MessageType,
    server_id: IPv4,
    parameter_request_list: []const OptionType,
    max_message_size: u16,
    renewal_time: std.Io.Duration,
    rebinding_time: std.Io.Duration,
    client_id: []u8,
    domain_search: []u8,
    classless_static_route: []u8,
};

pub fn validate(view: DHCPv4PacketView) !void {
    try view.validate(.htype, .{ .eq = 0x1 });
    try view.validate(.hlen, .{ .eq = 0x6 });
    try view.validate(.reserved_flags, .{ .eq = 0 });
    try view.validate(.magic, .{ .eq = DHCPV4_MAGIC });
}

pub fn parse(buffer: []const u8) !DHCPv4PacketView {
    var view: DHCPv4PacketView = undefined;
    var reader: std.Io.Reader = .fixed(buffer);
    try view.takeFields(.op, .magic, &reader);
    try view.takeBytes(.options, reader.bufferedLen(), &reader);
    try validate(view);
    return view;
}

pub fn parseOption(reader: *std.Io.Reader) !?OptionValue {
    while (true) {
        const code: OptionType = @enumFromInt(try reader.peekByte());
        switch (code) {
            .pad => {
                _ = try reader.takeByte();
                continue;
            },
            .end => {
                _ = try reader.takeByte();
                return null;
            },
            else => {},
        }

        var view: OptionView = undefined;
        try view.takeField(.code, reader);
        try view.takeField(.len, reader);
        try view.takeBytes(.data, view.get(.len), reader);

        const data = view.get(.data);
        switch (code) {
            inline .subnet_mask, .broadcast_address, .requested_ip_address, .server_id => |tag| {
                try view.validate(.len, .{ .eq = 4 });
                const ip: IPv4 = std.mem.bytesAsValue(IPv4, data).*;
                return @unionInit(OptionValue, @tagName(tag), ip);
            },
            inline .router, .dns_servers => |tag| {
                try view.validate(.len, .{ .gte = 4 });
                try view.validate(.len, .{ .multiple_of = 4 });
                const addresses: []const IPv4 = std.mem.bytesAsSlice(IPv4, data);
                return @unionInit(OptionValue, @tagName(tag), addresses);
            },
            inline .host_name, .domain_name, .domain_search => |tag| {
                try view.validate(.len, .{ .gte = 1 });
                return @unionInit(OptionValue, @tagName(tag), data);
            },
            inline .lease_time, .renewal_time, .rebinding_time => |tag| {
                try view.validate(.len, .{ .eq = @sizeOf(u32) });
                const seconds = std.mem.bigToNative(u32, std.mem.bytesAsValue(u32, data).*);
                return @unionInit(OptionValue, @tagName(tag), std.Io.Duration.fromSeconds(seconds));
            },
            .interface_mtu => {
                try view.validate(.len, .{ .eq = @sizeOf(u16) });
                const mtu = std.mem.bigToNative(u16, std.mem.bytesAsValue(u16, data).*);
                if (mtu < 68) return error.InvalidOption;
                return .{ .interface_mtu = mtu };
            },
            .static_route => {
                try view.validate(.len, .{ .gte = @sizeOf(StaticRoute) });
                try view.validate(.len, .{ .multiple_of = @sizeOf(StaticRoute) });
                return .{ .static_route = std.mem.bytesAsSlice(StaticRoute, data) };
            },
            .message_type => {
                try view.validate(.len, .{ .eq = 1 });
                return .{ .message_type = @enumFromInt(std.mem.bytesAsValue(u8, data).*) };
            },
            .parameter_request_list => {
                try view.validate(.len, .{ .gte = 1 });
                return .{ .parameter_request_list = std.mem.bytesAsSlice(OptionType, data) };
            },
            .max_message_size => {
                try view.validate(.len, .{ .eq = @sizeOf(u16) });
                return .{ .max_message_size = std.mem.bigToNative(u16, std.mem.bytesAsValue(u16, data).*) };
            },
            .client_id => {
                try view.validate(.len, .{ .gte = 2 });
                return .{ .client_id = data };
            },
            .classless_static_route => {
                try view.validate(.len, .{ .gte = 5 });
                return .{ .classless_static_route = data };
            },
            else => continue,
        }
    }
}

pub fn handle(
    buffer: []u8, // the full ethernet frame
    packet: []u8,
    device: NicApi,
    iface: IFace,
) !void {
    const view = try parse(packet);
    Cli.enter(.dhcpv4, view);

    var message_type_scanner: std.Io.Reader = .fixed(view.get(.options));
    var maybe_message_type: ?MessageType = null;
    while (try parseOption(&message_type_scanner)) |value| {
        switch (value) {
            .message_type => |message_type| {
                if (maybe_message_type != null) return error.DuplicateMessageType;
                maybe_message_type = message_type;
            },
            else => continue,
        }
    }

    const message_type = maybe_message_type orelse return error.MissingMessageType;
    switch (iface) {
        .lan => {
            switch (message_type) {
                .decline => {
                    std.debug.print("DHCPv4: message type {f} unhandled by {s}\n", .{
                        Format.enumLabel(message_type), @tagName(iface),
                    });
                    device.release(buffer);
                },
                .discover => {
                    std.debug.print("DHCPv4: message type {f} unhandled by {s}\n", .{
                        Format.enumLabel(message_type), @tagName(iface),
                    });
                    device.release(buffer);
                },
                .inform => {
                    std.debug.print("DHCPv4: message type {f} unhandled by {s}\n", .{
                        Format.enumLabel(message_type), @tagName(iface),
                    });
                    device.release(buffer);
                },
                .request => {
                    std.debug.print("DHCPv4: message type {f} unhandled by {s}\n", .{
                        Format.enumLabel(message_type), @tagName(iface),
                    });
                    device.release(buffer);
                },

                .release => {
                    std.debug.print("DHCPv4: message type {f} unhandled by {s}\n", .{
                        Format.enumLabel(message_type), @tagName(iface),
                    });
                    device.release(buffer);
                },
                else => {
                    std.debug.print("DHCPv4: message type {f} unhandled by {s}\n", .{
                        Format.enumLabel(message_type), @tagName(iface),
                    });
                    device.release(buffer);
                },
            }
        },
        .wan => {
            switch (message_type) {
                .ack => {
                    std.debug.print("DHCPv4: message type {f} unhandled by {s}\n", .{
                        Format.enumLabel(message_type), @tagName(iface),
                    });
                    device.release(buffer);
                },
                .nak => {
                    std.debug.print("DHCPv4: message type {f} unhandled by {s}\n", .{
                        Format.enumLabel(message_type), @tagName(iface),
                    });
                    device.release(buffer);
                },
                .offer => {
                    std.debug.print("DHCPv4: message type {f} unhandled by {s}\n", .{
                        Format.enumLabel(message_type), @tagName(iface),
                    });
                    device.release(buffer);
                },
                else => {
                    std.debug.print("DHCPv4: message type {f} unhandled by {s}\n", .{
                        Format.enumLabel(message_type), @tagName(iface),
                    });
                    device.release(buffer);
                },
            }
        },
    }
}

const test_packet = blk: {
    var packet = [_]u8{0} ** 245;
    packet[0] = 1; // BOOTREQUEST
    packet[1] = 1; // Ethernet
    packet[2] = 6; // MAC length
    packet[4] = 0x12;
    packet[5] = 0x34;
    packet[6] = 0x56;
    packet[7] = 0x78;
    packet[9] = 42; // seconds elapsed
    packet[10] = 0x80; // broadcast flag
    packet[12] = 192;
    packet[14] = 2;
    packet[15] = 10;
    packet[16] = 198;
    packet[17] = 51;
    packet[18] = 100;
    packet[19] = 20;
    packet[20] = 203;
    packet[22] = 113;
    packet[23] = 7;
    packet[28] = 0x02;
    packet[29] = 0x11;
    packet[30] = 0x22;
    packet[31] = 0x33;
    packet[32] = 0x44;
    packet[33] = 0x55;
    packet[44] = 'b';
    packet[45] = 'o';
    packet[46] = 'o';
    packet[47] = 't';
    packet[108] = 'p';
    packet[109] = 'x';
    packet[110] = 'e';
    packet[236] = 0x63;
    packet[237] = 0x82;
    packet[238] = 0x53;
    packet[239] = 0x63;
    packet[240] = 53; // DHCP message type
    packet[241] = 1;
    packet[242] = 1; // Discover
    packet[243] = 255; // End
    packet[244] = 0; // Padding after End
    break :blk packet;
};

test "parse() reads DHCPv4 fixed fields and leaves the remaining bytes as options" {
    const view = try parse(&test_packet);
    try std.testing.expectEqual(Op.BOOTREQUEST, view.get(.op));
    try std.testing.expectEqual(@as(u8, 1), view.get(.htype));
    try std.testing.expectEqual(@as(u8, 6), view.get(.hlen));
    try std.testing.expectEqual(@as(u8, 0), view.get(.hops));
    try std.testing.expectEqual(@as(u32, 0x12345678), view.get(.xid));
    try std.testing.expectEqual(@as(u16, 42), view.get(.secs));
    try std.testing.expect(view.get(.broadcast_flag));
    try std.testing.expectEqual(@as(u15, 0), view.get(.reserved_flags));
    try std.testing.expectEqualDeep(IPv4{ 192, 0, 2, 10 }, view.get(.client_ip));
    try std.testing.expectEqualDeep(IPv4{ 198, 51, 100, 20 }, view.get(.your_ip));
    try std.testing.expectEqualDeep(IPv4{ 203, 0, 113, 7 }, view.get(.next_server_ip));
    try std.testing.expectEqualDeep(IPv4{ 0, 0, 0, 0 }, view.get(.relay_agent_ip));
    try std.testing.expectEqualDeep(test_packet[28..44].*, view.get(.client_hw_addr));
    try std.testing.expectEqualDeep(test_packet[44..108].*, view.get(.server_name));
    try std.testing.expectEqualDeep(test_packet[108..236].*, view.get(.file));
    try std.testing.expectEqual(@as(u32, DHCPV4_MAGIC), view.get(.magic));
    try std.testing.expectEqualSlices(u8, test_packet[240..], view.get(.options));
}

test "parse() rejects truncated fixed headers" {
    for (0..240) |len| {
        try std.testing.expectError(error.EndOfStream, parse(test_packet[0..len]));
    }
}

test "parse() rejects invalid DHCPv4 metadata" {
    const invalid_fields = [_]struct { offset: usize, value: u8 }{
        .{ .offset = 1, .value = 2 }, // non-Ethernet hardware type
        .{ .offset = 2, .value = 5 }, // wrong Ethernet address length
        .{ .offset = 10, .value = 0x81 }, // reserved flag set
        .{ .offset = 236, .value = 0 }, // invalid magic cookie
    };
    for (invalid_fields) |invalid| {
        var packet = test_packet;
        packet[invalid.offset] = invalid.value;
        try std.testing.expectError(error.InvalidField, parse(&packet));
    }
}

fn expectWiresharkOptionValue(option: OptionValue, hex: []const u8) !void {
    const expectHexBytes = Router.TestFixtures.Utils.expectHexBytes;
    switch (option) {
        inline .subnet_mask, .broadcast_address, .requested_ip_address, .server_id => |ip| {
            try expectHexBytes(&ip, hex);
        },
        inline .router, .dns_servers => |addresses| {
            try expectHexBytes(std.mem.sliceAsBytes(addresses), hex);
        },
        inline .host_name, .domain_name, .domain_search, .classless_static_route => |bytes| {
            try expectHexBytes(bytes, hex);
        },
        .static_route => |routes| try expectHexBytes(std.mem.sliceAsBytes(routes), hex),
        inline .lease_time, .renewal_time, .rebinding_time => |duration| {
            try std.testing.expectEqual(
                @as(i64, try std.fmt.parseInt(u32, hex, 16)),
                duration.toSeconds(),
            );
        },
        .message_type => |message_type| {
            try std.testing.expectEqual(try std.fmt.parseInt(u8, hex, 16), @intFromEnum(message_type));
        },
        .parameter_request_list => |codes| {
            try std.testing.expectEqual(codes.len * 2, hex.len);
            for (codes, 0..) |code, i| {
                try std.testing.expectEqual(
                    try std.fmt.parseInt(u8, hex[i * 2 ..][0..2], 16),
                    @intFromEnum(code),
                );
            }
        },
        .interface_mtu, .max_message_size => |size| {
            try std.testing.expectEqual(try std.fmt.parseInt(u16, hex, 16), size);
        },
        .client_id => |bytes| try expectHexBytes(bytes, hex),
    }
}

test "parse() on wireshark captured frames matches wireshark's parsed output" {
    const PcapParser = Router.TestFixtures.PcapParser;
    const CsvParser = Router.TestFixtures.DHCPv4.CsvParser;
    const pcap_file = Router.TestFixtures.DHCPv4.pcap_file;
    const csv_file = Router.TestFixtures.DHCPv4.csv_file;

    var parsed_pcap = try PcapParser.parse(pcap_file, std.testing.allocator);
    defer parsed_pcap.deinit(std.testing.allocator);
    const parsed_packets = try CsvParser.parse(csv_file, std.testing.allocator);
    defer std.testing.allocator.free(parsed_packets);

    try std.testing.expectEqual(parsed_packets.len, parsed_pcap.packet_bytes.len);
    for (parsed_packets, 0..) |ws_packet, i| {
        const frame = try Router.Protocols.Ethernet.parse(parsed_pcap.packet_bytes[i]);
        try std.testing.expectEqual(Router.Protocols.Ethernet.Ethertype.ipv4, frame.get(.ethertype));
        const ip_view = try Router.Protocols.IPv4.parse(frame.get(.payload));
        try std.testing.expectEqual(Router.Protocols.IPv4.Protocol.udp, ip_view.get(.protocol));
        const udp_view = try Router.Protocols.Udp.parse(ip_view.get(.payload), ip_view);
        const view = try parse(udp_view.get(.payload));
        try std.testing.expect(view.isEqualIgnoringSlices(&ws_packet.packet));

        var options_reader: std.Io.Reader = .fixed(view.get(.options));
        var types = std.mem.splitScalar(u8, ws_packet.option_types, ';');
        var values = std.mem.splitScalar(u8, ws_packet.option_values, ';');
        var saw_end = false;
        while (types.next()) |type_text| {
            const code: OptionType = @enumFromInt(try std.fmt.parseInt(u8, type_text, 10));
            if (code == .pad) {
                // TShark reports the DHCP End marker as a final option type 0.
                saw_end = true;
                break;
            }
            const value = values.next() orelse return error.MissingWiresharkOptionValue;
            switch (code) {
                .subnet_mask,
                .router,
                .dns_servers,
                .host_name,
                .domain_name,
                .interface_mtu,
                .broadcast_address,
                .static_route,
                .requested_ip_address,
                .lease_time,
                .message_type,
                .server_id,
                .parameter_request_list,
                .max_message_size,
                .renewal_time,
                .rebinding_time,
                .client_id,
                .domain_search,
                .classless_static_route,
                => {
                    const option = (try parseOption(&options_reader)) orelse return error.MissingOption;
                    try std.testing.expectEqualStrings(@tagName(code), @tagName(std.meta.activeTag(option)));
                    try expectWiresharkOptionValue(option, value);
                    if (code == .message_type) {
                        try std.testing.expectEqual(ws_packet.message_type, @intFromEnum(option.message_type));
                    }
                },
                else => {}, // parseOption skips unsupported options.
            }
        }
        try std.testing.expect(saw_end);
        try std.testing.expect(values.next() == null);
        try std.testing.expect((try parseOption(&options_reader)) == null);
    }
}

test "parseOption() decodes supported DHCPv4 option values" {
    const bytes = [_]u8{
        1, 4, 255, 255, 255, 0, // subnet mask
        3, 8, 192, 0, 2, 1, 192, 0, 2, 2, // two routers
        6, 8, 8, 8, 8, 8, 1, 1, 1, 1, // two DNS servers
        50, 4, 192, 0, 2, 100, // requested address
        51, 4, 0, 0, 0x0e, 0x10, // 3600 second lease
        53, 1, 3, // Request
        54, 4, 192, 0, 2, 254, // server identifier
        55, 3, 1, 3, 250, // request list, including an unknown code
        57, 2, 0x05, 0xdc, // 1500 byte maximum message size
        58, 4, 0, 0, 0x07, 0x08, // 1800 second renewal time
        59, 4, 0, 0, 0x0c, 0x4e, // 3150 second rebinding time
        61,  7, 1, 2, 0x11, 0x22, 0x33, 0x44, 0x55, // client identifier
        255,
    };
    var client_id = [_]u8{ 1, 2, 0x11, 0x22, 0x33, 0x44, 0x55 };
    const expected = [_]OptionValue{
        .{ .subnet_mask = .{ 255, 255, 255, 0 } },
        .{ .router = &[_]IPv4{ .{ 192, 0, 2, 1 }, .{ 192, 0, 2, 2 } } },
        .{ .dns_servers = &[_]IPv4{ .{ 8, 8, 8, 8 }, .{ 1, 1, 1, 1 } } },
        .{ .requested_ip_address = .{ 192, 0, 2, 100 } },
        .{ .lease_time = std.Io.Duration.fromSeconds(3600) },
        .{ .message_type = .request },
        .{ .server_id = .{ 192, 0, 2, 254 } },
        .{ .parameter_request_list = &[_]OptionType{ .subnet_mask, .router, @enumFromInt(250) } },
        .{ .max_message_size = 1500 },
        .{ .renewal_time = std.Io.Duration.fromSeconds(1800) },
        .{ .rebinding_time = std.Io.Duration.fromSeconds(3150) },
        .{ .client_id = &client_id },
    };

    var reader: std.Io.Reader = .fixed(&bytes);
    for (expected) |item| {
        const actual = (try parseOption(&reader)) orelse return error.MissingOption;
        try std.testing.expectEqualDeep(item, actual);
    }
    try std.testing.expect((try parseOption(&reader)) == null);
    try std.testing.expectEqual(bytes.len, reader.seek);
}

test "parseOption() decodes requested DHCPv4 option values" {
    const bytes = [_]u8{
        12, 4, 'h', 'o', 's', 't', // host name
        15, 3, 'l', 'a', 'n', // domain name
        26, 2, 0x05, 0xdc, // interface MTU 1500
        28, 4, 192, 0, 2, 255, // broadcast address
        33, 8, 192, 0, 2, 0, 192, 0, 2, 1, // static route
        119, 5, 3, 'l', 'a', 'n', 0, // encoded domain search list
        121, 5, 0, 192, 0, 2, 1, // encoded classless default route
        252, 2, 0xaa, 0xbb, // private use: still unknown
        255,
    };
    var reader: std.Io.Reader = .fixed(&bytes);
    try std.testing.expectEqualSlices(u8, "host", (try parseOption(&reader)).?.host_name);
    try std.testing.expectEqualSlices(u8, "lan", (try parseOption(&reader)).?.domain_name);
    try std.testing.expectEqual(@as(u16, 1500), (try parseOption(&reader)).?.interface_mtu);
    try std.testing.expectEqualDeep(IPv4{ 192, 0, 2, 255 }, (try parseOption(&reader)).?.broadcast_address);
    const routes = (try parseOption(&reader)).?.static_route;
    try std.testing.expectEqual(@as(usize, 1), routes.len);
    try std.testing.expectEqualDeep(IPv4{ 192, 0, 2, 0 }, routes[0].destination);
    try std.testing.expectEqualDeep(IPv4{ 192, 0, 2, 1 }, routes[0].router);
    try std.testing.expectEqualSlices(u8, &.{ 3, 'l', 'a', 'n', 0 }, (try parseOption(&reader)).?.domain_search);
    try std.testing.expectEqualSlices(u8, &.{ 0, 192, 0, 2, 1 }, (try parseOption(&reader)).?.classless_static_route);
    try std.testing.expect((try parseOption(&reader)) == null);
    try std.testing.expectEqual(bytes.len, reader.seek);
}

test "parseOption() skips padding and unknown options and stops at End" {
    const bytes = [_]u8{ 0, 60, 3, 'a', 'b', 'c', 53, 1, 5, 255, 0, 0 };
    var reader: std.Io.Reader = .fixed(&bytes);

    const option = (try parseOption(&reader)) orelse return error.MissingOption;
    try std.testing.expectEqualDeep(OptionValue{ .message_type = .ack }, option);
    try std.testing.expect((try parseOption(&reader)) == null);
    try std.testing.expectEqual(bytes.len - 2, reader.seek);
}

test "parseOption() preserves unrecognized DHCP message type values" {
    const bytes = [_]u8{ 53, 1, 250, 255 };
    var reader: std.Io.Reader = .fixed(&bytes);
    const option = (try parseOption(&reader)) orelse return error.MissingOption;
    try std.testing.expectEqual(@as(u8, 250), @intFromEnum(option.message_type));
}

test "parseOption() rejects invalid lengths and truncated options" {
    const invalid = [_][]const u8{
        &.{ 1, 3, 255, 255, 255 }, // IPv4 address must have four bytes
        &.{ 3, 0 }, // router list cannot be empty
        &.{ 6, 5, 1, 2, 3, 4, 5 }, // address list must contain whole addresses
        &.{ 51, 3, 0, 0, 1 }, // duration requires four bytes
        &.{ 53, 2, 1, 2 }, // message type requires one byte
        &.{ 55, 0 }, // parameter list cannot be empty
        &.{ 57, 4, 0, 0, 0, 1 }, // maximum message size requires two bytes
        &.{ 61, 1, 1 }, // client identifier requires at least two bytes
        &.{ 12, 0 }, // host name cannot be empty
        &.{ 15, 0 }, // domain name cannot be empty
        &.{ 26, 1, 0 }, // MTU needs two bytes
        &.{ 28, 3, 192, 0, 2 }, // broadcast address needs four bytes
        &.{ 33, 7, 192, 0, 2, 0, 192, 0, 2 }, // static route needs address pairs
        &.{ 119, 0 }, // domain search list cannot be empty
        &.{ 121, 4, 0, 192, 0, 2 }, // classless route needs at least five bytes
    };
    for (invalid) |bytes| {
        var reader: std.Io.Reader = .fixed(bytes);
        try std.testing.expectError(error.InvalidField, parseOption(&reader));
    }

    var invalid_mtu: std.Io.Reader = .fixed(&.{ 26, 2, 0, 67 });
    try std.testing.expectError(error.InvalidOption, parseOption(&invalid_mtu));

    const truncated = [_][]const u8{
        &.{1}, // missing length
        &.{ 1, 4, 1, 2 }, // known option value is short
        &.{ 60, 3, 1, 2 }, // unknown option value is short
        &.{ 53, 1, 1 }, // missing End marker
    };
    for (truncated) |bytes| {
        var reader: std.Io.Reader = .fixed(bytes);
        if (bytes[0] == 53) _ = try parseOption(&reader);
        try std.testing.expectError(error.EndOfStream, parseOption(&reader));
    }
}

test "parse() then serialize() returns the original bytes" {
    const PcapParser = Router.TestFixtures.PcapParser;
    const pcap_file = Router.TestFixtures.DHCPv4.pcap_file;

    var parsed_pcap = try PcapParser.parse(pcap_file, std.testing.allocator);
    defer parsed_pcap.deinit(std.testing.allocator);

    for (parsed_pcap.packet_bytes) |packet| {
        const frame = try Router.Protocols.Ethernet.parse(packet);
        try std.testing.expectEqual(Router.Protocols.Ethernet.Ethertype.ipv4, frame.get(.ethertype));
        const ip_view = try Router.Protocols.IPv4.parse(frame.get(.payload));
        try std.testing.expectEqual(Router.Protocols.IPv4.Protocol.udp, ip_view.get(.protocol));
        const udp_view = try Router.Protocols.Udp.parse(ip_view.get(.payload), ip_view);
        const dhcp_bytes = udp_view.get(.payload);
        var view = try parse(dhcp_bytes);
        const buffer = try std.testing.allocator.alloc(u8, dhcp_bytes.len);
        defer std.testing.allocator.free(buffer);
        var writer: std.Io.Writer = .fixed(buffer);

        try DHCPv4PacketView.serialize(view.copy(), &writer);
        try std.testing.expectEqual(dhcp_bytes.len, writer.end);
        try std.testing.expectEqualSlices(u8, dhcp_bytes, buffer);
    }
}
