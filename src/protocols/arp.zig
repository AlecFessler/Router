//! "The world is a jungle in general, and the networking game contributes many animals" - David C. Plummer 1982 RFC #826
//! ARP packet structure:
//!         ________________________________________________________________________________________
//! Field: | Hardware | Protocol | HW Size | PRTCL Size | Opcode | Tx MAC | Tx IP | Rx MAC | Rx IP |
//!        -----------------------------------------------------------------------------------------
//! Bytes: |     2    |     2    |    1    |      1     |    2   |    6   |   4   |    6   |   4   |
//!        -----------------------------------------------------------------------------------------
//!
//! Generally the first four fields are expected to be 1, 0x0800, 6, and 4 for Ethernet, IP, MAC len, and IP len, respectively.
//!
//! An opcode of 1 indicates a request, and 2 indicates a reply.

const std = @import("std");
const Router = @import("router");

const ArpFixtures = Router.TestFixtures.Arp;
const ArpTableModule = Router.Tables.ArpTable;
const ArpWaitersTable = Router.Tables.ArpWaitersTable.ArpWaitersTable;
const Cli = Router.Debug.Cli;
const CsvParser = ArpFixtures.CsvParser;
const Ethernet = Router.Protocols.Ethernet;
const EthernetFrame = Router.Protocols.Ethernet.EthernetFrame;
const EthernetFrameView = Router.Protocols.Ethernet.EthernetFrameView;
const Fiber = Router.Async.Fiber.Fiber;
const IFace = Router.Nic.Api.IFace;
const IPv4 = Router.Protocols.IPv4.IPv4;
const Mac = Router.Protocols.Ethernet.Mac;
const NicApi = Router.Nic.Api.Api;
const PcapParser = Router.TestFixtures.PcapParser;
const ReadyQueue = Router.Async.ReadyQueue.ReadyQueue;
const View = Router.Meta.View.View;
const ViewStack = Router.Protocols.ViewStack;

const getRunning = Router.Async.getRunning;
const setRunning = Router.Async.setRunning;

const arp_waiters_table = &Router.State.arp_waiters_table;
const lan_arp_table = &Router.State.lan_arp_table;
const lan_ip = &Router.State.lan_ip;
const lan_ready_queue = &Router.State.lan_ready_queue;
const wan_arp_table = &Router.State.wan_arp_table;
const wan_lease = &Router.State.wan_lease;
const wan_ready_queue = &Router.State.wan_ready_queue;

pub const OpCode = enum(u16) {
    request = 1,
    reply = 2,
};

pub const ArpPacket = struct {
    hardware_type: u16 = 1,
    protocol_type: u16 = 0x0800,
    hardware_size: u8 = 6,
    protocol_size: u8 = 4,
    opcode: OpCode = .request,
    sender_mac: Mac = .{0} ** 6,
    sender_ip: IPv4 = .{0} ** 4,
    target_mac: Mac = .{0} ** 6,
    target_ip: IPv4 = .{0} ** 4,
};

pub const ArpPacketView = View(ArpPacket);

pub fn validate(view: ArpPacketView) !void {
    try view.validate(.hardware_type, .{ .eq = 1 });
    try view.validate(.protocol_type, .{ .eq = 0x0800 });
    try view.validate(.hardware_size, .{ .eq = 6 });
    try view.validate(.protocol_size, .{ .eq = 4 });
    try view.validate(.opcode, .any);
}

pub fn parse(buffer: []const u8) !ArpPacketView {
    var view: ArpPacketView = undefined;
    var reader: std.Io.Reader = .fixed(buffer);
    try view.takeFields(.hardware_type, .target_ip, &reader);
    try validate(view);
    return view;
}

pub fn handle(
    buffer: []u8,
    device: NicApi,
    iface: IFace,
    views: *ViewStack,
) !void {
    const ethernet_view = views.getView(.ethernet);
    var view = try parse(ethernet_view.get(.payload));
    Cli.enter(.arp, view);

    const table = switch (iface) {
        .lan => lan_arp_table,
        .wan => wan_arp_table,
    };
    const my_ip = switch (iface) {
        .lan => lan_ip.*,
        .wan => if (wan_lease.*) |lease|
            lease.ip
        else
            null,
    };
    const my_mac = device.macAddress(iface);

    if (my_ip == null) {
        device.release(buffer);
        return;
    }

    if (view.fieldCmp(.sender_mac, .{ .eq = my_mac })) {
        device.release(buffer);
        return;
    }

    if (view.fieldCmp(.sender_ip, .{ .eq = my_ip.? })) {
        // TODO: defend this interface's IP against a conflicting MAC.
        // Queue at most one ARP announcement every 10 seconds.
        device.release(buffer);
        return;
    }

    const opcode = view.get(.opcode);
    switch (opcode) {
        .request => {
            if (view.fieldCmp(.target_ip, .{ .eq = my_ip.? })) {
                const tx_buffer = device.nextTxBuffer(iface);
                errdefer device.release(tx_buffer);
                var writer: std.Io.Writer = .fixed(tx_buffer);

                try EthernetFrameView.serialize(.{
                    .dst_mac = view.get(.sender_mac),
                    .src_mac = my_mac,
                    .vlan_tags = ethernet_view.get(.vlan_tags),
                    .ethertype = .arp,
                    .payload = &.{},
                }, &writer);
                try ArpPacketView.serialize(
                    reply(my_mac, view.copy()),
                    &writer,
                );

                device.transmit(tx_buffer[0..writer.end]);
                defer device.release(buffer);

                if (view.fieldCmp(.sender_ip, .{ .eq = IPv4{ 0, 0, 0, 0 } })) return;
                table.cache(view.get(.sender_ip), view.get(.sender_mac));
            } else {
                device.release(buffer);
            }
        },
        .reply => {
            defer device.release(buffer);
            if (!view.fieldCmp(.target_mac, .{ .eq = my_mac })) return;
            if (view.fieldCmp(.sender_ip, .{ .eq = IPv4{ 0, 0, 0, 0 } })) return;
            if (view.fieldCmp(.target_ip, .{ .eq = my_ip.? })) {
                table.cache(view.get(.sender_ip), view.get(.sender_mac));
                arp_waiters_table.resolve(
                    .{ .iface = iface, .ip = view.get(.sender_ip) },
                    view.get(.sender_mac),
                );
            }
        },
    }
}

pub fn waitForArpResolution(
    device: NicApi,
    key: ArpWaitersTable.Key,
) !Mac {
    const running = getRunning() orelse return error.NotInFiber;
    const sender_ip = switch (key.iface) {
        .lan => lan_ip.*,
        .wan => if (wan_lease.*) |lease| lease.ip else return error.NoWanLease,
    };
    const ready_queue = switch (running.owner) {
        .lan => lan_ready_queue,
        .wan => wan_ready_queue,
    };

    var outcome: ArpWaitersTable.Outcome = undefined;
    var node: ReadyQueue.Node = .{ .fiber = running.fiber };
    const send_request = try arp_waiters_table.register(key, .{
        .node = &node,
        .ready_queue = ready_queue,
        .outcome = &outcome,
    });

    if (send_request) {
        const sender_mac = device.macAddress(key.iface);
        const tx_buffer = device.nextTxBuffer(key.iface);
        var writer: std.Io.Writer = .fixed(tx_buffer);

        EthernetFrameView.serialize(.{
            .dst_mac = .{0xff} ** 6,
            .src_mac = sender_mac,
            .vlan_tags = &.{},
            .ethertype = .arp,
            .payload = &.{},
        }, &writer) catch unreachable;
        ArpPacketView.serialize(
            request(sender_ip, sender_mac, key.ip, null),
            &writer,
        ) catch unreachable;

        device.transmit(tx_buffer[0..writer.end]);
    }

    Fiber.switchTo(running.fiber, running.loop_context);
    return switch (outcome) {
        .resolved => |mac| mac,
        .timed_out => error.ArpResolutionTimedOut,
    };
}

pub fn reply(
    sender_mac: Mac, // this is me
    req: ArpPacket, // my ip is already here, that's why I'm replying
) ArpPacket {
    var packet = ArpPacket{};
    packet.opcode = .reply;
    packet.sender_ip = req.target_ip;
    packet.sender_mac = sender_mac;
    packet.target_ip = req.sender_ip;
    packet.target_mac = req.sender_mac;
    return packet;
}

pub fn request(
    sender_ip: IPv4, // this is me
    sender_mac: Mac, // this is also me
    target_ip: IPv4, // who has this? tell me
    target_mac: ?Mac, // non-null for confirmation unicast, null for broadcast
) ArpPacket {
    var packet = ArpPacket{};
    packet.opcode = .request;
    packet.sender_ip = sender_ip;
    packet.sender_mac = sender_mac;
    packet.target_ip = target_ip;
    if (target_mac != null) packet.target_mac = target_mac.?;
    return packet;
}

const test_packet = [_]u8{
    0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01,
} ++ ([_]u8{0} ** 20);

const invalid_fields = [_]struct { offset: usize, value: u8 }{
    .{ .offset = 1, .value = 2 },
    .{ .offset = 3, .value = 1 },
    .{ .offset = 4, .value = 7 },
    .{ .offset = 5, .value = 5 },
    .{ .offset = 7, .value = 3 },
};

test "parse() reads ARP fields from wire bytes" {
    const expected = ArpPacket{};
    const view = try parse(&test_packet);
    try std.testing.expect(view.isEqual(&expected));
}

test "parse() rejects truncated packets and accepts trailing bytes" {
    const buffer = test_packet ++ [_]u8{0xff};

    for (0..test_packet.len) |len| {
        try std.testing.expectError(error.EndOfStream, parse(buffer[0..len]));
    }

    const expected = ArpPacket{};
    const view = try parse(&buffer);
    try std.testing.expect(view.isEqual(&expected));
}

test "parse() rejects invalid metadata fields" {
    for (invalid_fields) |invalid| {
        var buffer = test_packet;
        buffer[invalid.offset] = invalid.value;
        try std.testing.expectError(error.InvalidField, parse(&buffer));
    }
}

test "parse() on wireshark captured frames matches wireshark's parsed output" {
    const pcap_file = ArpFixtures.pcap_file;
    const csv_file = ArpFixtures.csv_file;

    var parsed_pcap = try PcapParser.parse(pcap_file, std.testing.allocator);
    defer parsed_pcap.deinit(std.testing.allocator);
    const parsed_packets = try CsvParser.parse(csv_file, std.testing.allocator);
    defer std.testing.allocator.free(parsed_packets);

    try std.testing.expectEqual(parsed_packets.len, parsed_pcap.packet_bytes.len);
    for (parsed_packets, 0..) |ws_packet, i| {
        const frame = try Ethernet.parse(parsed_pcap.packet_bytes[i]);
        try std.testing.expectEqual(Ethernet.Ethertype.arp, frame.get(.ethertype));
        const view = try parse(frame.get(.payload));
        try std.testing.expect(view.isEqual(&ws_packet));
    }
}

test "parse() then serialize() returns the original bytes" {
    const pcap_file = ArpFixtures.pcap_file;

    var parsed_pcap = try PcapParser.parse(pcap_file, std.testing.allocator);
    defer parsed_pcap.deinit(std.testing.allocator);

    for (parsed_pcap.packet_bytes) |packet| {
        const frame = try Ethernet.parse(packet);
        const arp_bytes = frame.get(.payload);
        var view = try parse(arp_bytes);
        var buffer: [@sizeOf(ArpPacket)]u8 = undefined;
        var writer: std.Io.Writer = .fixed(&buffer);
        try ArpPacketView.serialize(view.copy(), &writer);
        try std.testing.expectEqualSlices(u8, arp_bytes[0..buffer.len], &buffer);
    }
}

test "request() returns a packet struct with valid metadata fields" {
    const default_packet = ArpPacket{};
    const request_value = request(
        default_packet.sender_ip,
        default_packet.sender_mac,
        default_packet.target_ip,
        default_packet.target_mac,
    );
    try std.testing.expectEqual(default_packet.hardware_type, request_value.hardware_type);
    try std.testing.expectEqual(default_packet.hardware_size, request_value.hardware_size);
    try std.testing.expectEqual(default_packet.protocol_type, request_value.protocol_type);
    try std.testing.expectEqual(default_packet.protocol_size, request_value.protocol_size);
    try std.testing.expectEqual(.request, request_value.opcode);
}

test "request() populates the packet struct's address fields and sets the request opcode" {
    const sender_mac: Mac = .{ 0x90, 0xca, 0xfa, 0x60, 0x3c, 0xec };
    const sender_ip: IPv4 = .{ 192, 168, 86, 1 };
    const target_mac: Mac = .{ 0xf8, 0x54, 0xf6, 0x41, 0x3a, 0xe8 };
    const target_ip: IPv4 = .{ 192, 168, 86, 198 };
    try std.testing.expectEqualDeep(
        ArpPacket{
            .sender_mac = sender_mac,
            .sender_ip = sender_ip,
            .target_mac = target_mac,
            .target_ip = target_ip,
            .opcode = .request,
        },
        request(sender_ip, sender_mac, target_ip, target_mac),
    );
}

test "request() sets target mac to 00:00:00:00:00:00 if the corresponding argument is null" {
    const sender_mac: Mac = .{ 0x90, 0xca, 0xfa, 0x60, 0x3c, 0xec };
    const sender_ip: IPv4 = .{ 192, 168, 86, 1 };
    const target_mac: Mac = .{ 0, 0, 0, 0, 0, 0 };
    const target_ip: IPv4 = .{ 192, 168, 86, 198 };
    try std.testing.expectEqualDeep(
        ArpPacket{
            .sender_mac = sender_mac,
            .sender_ip = sender_ip,
            .target_mac = target_mac,
            .target_ip = target_ip,
            .opcode = .request,
        },
        request(sender_ip, sender_mac, target_ip, null),
    );
}

test "reply() returns a packet struct with valid metadata fields" {
    const default_packet = ArpPacket{};
    const reply_value = reply(default_packet.sender_mac, default_packet);
    try std.testing.expectEqual(default_packet.hardware_type, reply_value.hardware_type);
    try std.testing.expectEqual(default_packet.hardware_size, reply_value.hardware_size);
    try std.testing.expectEqual(default_packet.protocol_type, reply_value.protocol_type);
    try std.testing.expectEqual(default_packet.protocol_size, reply_value.protocol_size);
    try std.testing.expectEqual(.reply, reply_value.opcode);
}

test "reply() swaps the request's address fields, sets the sender mac, and sets the reply opcode" {
    const sender_mac: Mac = .{ 0xf8, 0x54, 0xf6, 0x41, 0x3a, 0xe8 };
    const sender_ip: IPv4 = .{ 192, 168, 86, 198 };
    const target_mac: Mac = .{ 0x90, 0xca, 0xfa, 0x60, 0x3c, 0xec };
    const target_ip: IPv4 = .{ 192, 168, 86, 1 };
    const expected = ArpPacket{
        .sender_mac = sender_mac,
        .sender_ip = sender_ip,
        .target_mac = target_mac,
        .target_ip = target_ip,
        .opcode = .reply,
    };
    const request_packet = request(target_ip, target_mac, sender_ip, null);
    try std.testing.expectEqualDeep(expected, reply(sender_mac, request_packet));

    var buffer: [@sizeOf(ArpPacket)]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    try ArpPacketView.serialize(request_packet, &writer);
    var request_view = try parse(&buffer);
    try std.testing.expectEqualDeep(expected, reply(sender_mac, request_view.copy()));
}

const HandlerTestNic = struct {
    const LAN_MAC: Mac = .{ 0x02, 0, 0, 0, 0, 1 };
    const WAN_MAC: Mac = .{ 0x02, 0, 0, 0, 0, 2 };

    rx: [256]u8 = undefined,
    tx: [256]u8 = .{0xa5} ** 256,
    tx_capacity: usize = 256,
    rx_releases: usize = 0,
    tx_releases: usize = 0,
    tx_iface: ?IFace = null,
    tx_len: ?usize = null,

    fn api(self: *HandlerTestNic) NicApi {
        return .{
            .ptr = self,
            .vtable = &.{
                .receive = receive,
                .nextTxBuffer = nextTxBuffer,
                .macAddress = macAddress,
                .release = releaseBuffer,
                .transmit = transmit,
            },
        };
    }

    fn receive(_: *anyopaque, _: IFace) ?[]u8 {
        unreachable;
    }

    fn nextTxBuffer(ctx: *anyopaque, iface: IFace) []u8 {
        const self: *HandlerTestNic = @ptrCast(@alignCast(ctx));
        self.tx_iface = iface;
        return self.tx[0..self.tx_capacity];
    }

    fn macAddress(_: *anyopaque, iface: IFace) Mac {
        return switch (iface) {
            .lan => LAN_MAC,
            .wan => WAN_MAC,
        };
    }

    fn releaseBuffer(ctx: *anyopaque, buffer: []u8) void {
        const self: *HandlerTestNic = @ptrCast(@alignCast(ctx));
        if (buffer.ptr == self.rx[0..].ptr) {
            self.rx_releases += 1;
        } else if (buffer.ptr == self.tx[0..].ptr) {
            self.tx_releases += 1;
        } else {
            @panic("unexpected test NIC buffer");
        }
    }

    fn transmit(ctx: *anyopaque, buffer: []u8) void {
        const self: *HandlerTestNic = @ptrCast(@alignCast(ctx));
        std.debug.assert(buffer.ptr == self.tx[0..].ptr);
        std.debug.assert(self.tx_len == null);
        self.tx_len = buffer.len;
    }
};

fn testArpFrame(
    nic: *HandlerTestNic,
    dst_mac: Mac,
    tags: []u8,
    arp: ArpPacket,
) ![]u8 {
    var writer: std.Io.Writer = .fixed(&nic.rx);
    try EthernetFrameView.serialize(.{
        .dst_mac = dst_mac,
        .src_mac = arp.sender_mac,
        .vlan_tags = tags,
        .ethertype = .arp,
        .payload = &.{},
    }, &writer);
    try ArpPacketView.serialize(arp, &writer);
    return nic.rx[0..writer.end];
}

fn testHandle(
    frame: []u8,
    ethernet_view: EthernetFrameView,
    device: NicApi,
    iface: IFace,
) !void {
    var parent_view = ethernet_view;
    var views: ViewStack = .{};
    views.setView(.ethernet, &parent_view);
    try handle(frame, device, iface, &views);
}

test "handle() replies to LAN requests and probes with the incoming VLAN tags" {
    const my_ip: IPv4 = .{ 192, 168, 86, 1 };
    const peer_ip: IPv4 = .{ 192, 168, 86, 42 };
    const peer_mac: Mac = .{ 0x02, 0x11, 0x22, 0x33, 0x44, 0x55 };

    for ([_]struct { sender_ip: IPv4, tag_count: usize }{
        .{ .sender_ip = peer_ip, .tag_count = 0 },
        .{ .sender_ip = .{ 0, 0, 0, 0 }, .tag_count = 5 },
    }) |case| {
        lan_ip.* = my_ip;
        lan_arp_table.* = try ArpTableModule.ArpTable.init(
            std.testing.allocator,
            std.testing.io,
            8,
            .fromSeconds(60),
        );
        defer lan_arp_table.*.deinit(std.testing.allocator);

        var nic: HandlerTestNic = .{};
        var tag_storage: [20]u8 = undefined;
        for (0..case.tag_count) |i| {
            tag_storage[i * 4 + 0] = 0x81;
            tag_storage[i * 4 + 1] = 0x00;
            tag_storage[i * 4 + 2] = 0x00;
            tag_storage[i * 4 + 3] = @intCast(i + 1);
        }
        const tags = tag_storage[0 .. case.tag_count * 4];
        const frame = try testArpFrame(
            &nic,
            .{0xff} ** 6,
            tags,
            request(case.sender_ip, peer_mac, my_ip, null),
        );
        const ethernet_view = try Ethernet.parse(frame);
        try testHandle(frame, ethernet_view, nic.api(), .lan);

        const arp_start = 14 + tags.len;
        const arp_end = arp_start + 28;
        try std.testing.expectEqual(@as(usize, 1), nic.rx_releases);
        try std.testing.expectEqual(@as(usize, 0), nic.tx_releases);
        try std.testing.expectEqual(IFace.lan, nic.tx_iface.?);
        try std.testing.expectEqual(arp_end, nic.tx_len.?);
        try std.testing.expectEqualSlices(u8, &peer_mac, nic.tx[0..6]);
        try std.testing.expectEqualSlices(u8, &HandlerTestNic.LAN_MAC, nic.tx[6..12]);
        try std.testing.expectEqualSlices(u8, tags, nic.tx[12 .. 12 + tags.len]);
        try std.testing.expectEqualSlices(u8, &.{ 0x08, 0x06 }, nic.tx[12 + tags.len .. arp_start]);
        try std.testing.expectEqualSlices(u8, &.{ 0, 1, 8, 0, 6, 4, 0, 2 }, nic.tx[arp_start .. arp_start + 8]);
        try std.testing.expectEqualSlices(u8, &HandlerTestNic.LAN_MAC, nic.tx[arp_start + 8 .. arp_start + 14]);
        try std.testing.expectEqualSlices(u8, &my_ip, nic.tx[arp_start + 14 .. arp_start + 18]);
        try std.testing.expectEqualSlices(u8, &peer_mac, nic.tx[arp_start + 18 .. arp_start + 24]);
        try std.testing.expectEqualSlices(u8, &case.sender_ip, nic.tx[arp_start + 24 .. arp_end]);
        if (std.meta.eql(case.sender_ip, IPv4{ 0, 0, 0, 0 })) {
            try std.testing.expectEqual(null, lan_arp_table.*.lookup(case.sender_ip));
        } else {
            try std.testing.expectEqual(peer_mac, lan_arp_table.*.lookup(case.sender_ip).?);
        }
    }
}

test "handle() learns WAN replies addressed to this interface and drops ARP without a lease" {
    const wan_ip: IPv4 = .{ 136, 48, 33, 52 };
    const gateway_ip: IPv4 = .{ 136, 48, 32, 1 };
    const gateway_mac: Mac = .{ 0x02, 0x21, 0x22, 0x23, 0x24, 0x25 };
    const now = std.Io.Timestamp.now(std.testing.io, .boot);

    wan_lease.* = .{
        .ip = wan_ip,
        .subnet_mask = .{ 255, 255, 240, 0 },
        .router = gateway_ip,
        .server_id = gateway_ip,
        .renewal_deadline = now,
        .rebinding_deadline = now,
        .expiration_deadline = now,
    };
    defer wan_lease.* = null;
    wan_arp_table.* = try ArpTableModule.ArpTable.init(
        std.testing.allocator,
        std.testing.io,
        8,
        .fromSeconds(60),
    );
    defer wan_arp_table.*.deinit(std.testing.allocator);
    arp_waiters_table.* = try ArpWaitersTable.init(std.testing.allocator, std.testing.io, 8, .fromSeconds(2));
    defer arp_waiters_table.*.deinit(std.testing.allocator);

    var nic: HandlerTestNic = .{};
    const frame = try testArpFrame(&nic, HandlerTestNic.WAN_MAC, &.{}, .{
        .opcode = .reply,
        .sender_mac = gateway_mac,
        .sender_ip = gateway_ip,
        .target_mac = HandlerTestNic.WAN_MAC,
        .target_ip = wan_ip,
    });
    const ethernet_view = try Ethernet.parse(frame);
    try testHandle(frame, ethernet_view, nic.api(), .wan);
    try std.testing.expectEqual(gateway_mac, wan_arp_table.*.lookup(gateway_ip).?);
    try std.testing.expectEqual(@as(usize, 1), nic.rx_releases);
    try std.testing.expectEqual(null, nic.tx_len);

    wan_lease.* = null;
    var unconfigured: HandlerTestNic = .{};
    const unconfigured_frame = try testArpFrame(
        &unconfigured,
        .{0xff} ** 6,
        &.{},
        request(gateway_ip, gateway_mac, wan_ip, null),
    );
    const unconfigured_view = try Ethernet.parse(unconfigured_frame);
    try testHandle(unconfigured_frame, unconfigured_view, unconfigured.api(), .wan);
    try std.testing.expectEqual(@as(usize, 1), unconfigured.rx_releases);
    try std.testing.expectEqual(null, unconfigured.tx_len);
}

test "handle() releases unrelated requests and transmit buffers on serialization failure" {
    const my_ip: IPv4 = .{ 192, 168, 86, 1 };
    const peer_ip: IPv4 = .{ 192, 168, 86, 42 };
    const peer_mac: Mac = .{ 0x02, 0x11, 0x22, 0x33, 0x44, 0x55 };
    lan_ip.* = my_ip;
    lan_arp_table.* = try ArpTableModule.ArpTable.init(
        std.testing.allocator,
        std.testing.io,
        8,
        .fromSeconds(60),
    );
    defer lan_arp_table.*.deinit(std.testing.allocator);

    var unrelated: HandlerTestNic = .{};
    const unrelated_frame = try testArpFrame(
        &unrelated,
        .{0xff} ** 6,
        &.{},
        request(peer_ip, peer_mac, .{ 192, 168, 86, 99 }, null),
    );
    const unrelated_view = try Ethernet.parse(unrelated_frame);
    try testHandle(unrelated_frame, unrelated_view, unrelated.api(), .lan);
    try std.testing.expectEqual(@as(usize, 1), unrelated.rx_releases);
    try std.testing.expectEqual(null, unrelated.tx_len);
    try std.testing.expectEqual(null, lan_arp_table.*.lookup(peer_ip));

    var failing: HandlerTestNic = .{ .tx_capacity = 8 };
    const frame = try testArpFrame(
        &failing,
        .{0xff} ** 6,
        &.{},
        request(peer_ip, peer_mac, my_ip, null),
    );
    const ethernet_view = try Ethernet.parse(frame);
    try std.testing.expectError(
        error.WriteFailed,
        testHandle(frame, ethernet_view, failing.api(), .lan),
    );
    try std.testing.expectEqual(@as(usize, 1), failing.tx_releases);
    try std.testing.expectEqual(@as(usize, 0), failing.rx_releases);
    try std.testing.expectEqual(null, failing.tx_len);
    failing.api().release(frame); // The caller releases RX when handle returns an error.
    try std.testing.expectEqual(@as(usize, 1), failing.rx_releases);
}

test "ARP reply resumes a WAN fiber waiting for a LAN neighbor" {
    const WaitTask = struct {
        loop_context: *std.Io.fiber.Context,
        device: NicApi,
        key: ArpWaitersTable.Key,
        mac: ?Mac = null,
        err: ?anyerror = null,
        done: bool = false,

        fn start(fiber: *Fiber, arg: *anyopaque) noreturn {
            const self: *@This() = @ptrCast(@alignCast(arg));
            if (waitForArpResolution(self.device, self.key)) |mac| {
                self.mac = mac;
            } else |err| {
                self.err = err;
            }
            self.done = true;
            Fiber.switchTo(fiber, self.loop_context);
            unreachable;
        }
    };

    const peer_ip: IPv4 = .{ 192, 168, 86, 42 };
    const peer_mac: Mac = .{ 0x02, 0x11, 0x22, 0x33, 0x44, 0x55 };
    lan_ip.* = .{ 192, 168, 86, 1 };
    lan_arp_table.* = try ArpTableModule.ArpTable.init(std.testing.allocator, std.testing.io, 8, .fromSeconds(60));
    defer lan_arp_table.*.deinit(std.testing.allocator);
    arp_waiters_table.* = try ArpWaitersTable.init(std.testing.allocator, std.testing.io, 8, .fromSeconds(30));
    defer arp_waiters_table.*.deinit(std.testing.allocator);
    lan_ready_queue.* = ReadyQueue.init(std.testing.io);
    wan_ready_queue.* = ReadyQueue.init(std.testing.io);
    defer setRunning(null);

    var nic: HandlerTestNic = .{};
    var loop_context: std.Io.fiber.Context = undefined;
    var task: WaitTask = .{
        .loop_context = &loop_context,
        .device = nic.api(),
        .key = .{ .iface = .lan, .ip = peer_ip },
    };
    var fiber = try Fiber.init(std.testing.allocator, 8 * 1024, WaitTask.start, &task);
    defer fiber.deinit(std.testing.allocator);

    setRunning(.{ .fiber = &fiber, .loop_context = &loop_context, .owner = .wan });
    Fiber.switchTo(&loop_context, &fiber);
    setRunning(null);
    try std.testing.expect(!task.done);
    try std.testing.expectEqual(IFace.lan, nic.tx_iface.?);
    const request_frame = try Ethernet.parse(nic.tx[0..nic.tx_len.?]);
    const request_packet = try parse(request_frame.get(.payload));
    try std.testing.expectEqual(OpCode.request, request_packet.get(.opcode));
    try std.testing.expectEqual(peer_ip, request_packet.get(.target_ip));

    var reply_nic: HandlerTestNic = .{};
    const reply_frame = try testArpFrame(&reply_nic, HandlerTestNic.LAN_MAC, &.{}, .{
        .opcode = .reply,
        .sender_mac = peer_mac,
        .sender_ip = peer_ip,
        .target_mac = HandlerTestNic.LAN_MAC,
        .target_ip = lan_ip.*,
    });
    const reply_view = try Ethernet.parse(reply_frame);
    try testHandle(reply_frame, reply_view, reply_nic.api(), .lan);
    try std.testing.expectEqual(peer_mac, lan_arp_table.*.lookup(peer_ip).?);
    try std.testing.expect(lan_ready_queue.pop() == null);
    try std.testing.expect(wan_ready_queue.pop() == &fiber);

    setRunning(.{ .fiber = &fiber, .loop_context = &loop_context, .owner = .wan });
    Fiber.switchTo(&loop_context, &fiber);
    setRunning(null);
    try std.testing.expect(task.done);
    try std.testing.expectEqual(peer_mac, task.mac.?);
    try std.testing.expect(task.err == null);
}

test "ARP wait returns capacity and timeout errors" {
    const WaitTask = struct {
        loop_context: *std.Io.fiber.Context,
        device: NicApi,
        key: ArpWaitersTable.Key,
        err: ?anyerror = null,
        done: bool = false,

        fn start(fiber: *Fiber, arg: *anyopaque) noreturn {
            const self: *@This() = @ptrCast(@alignCast(arg));
            _ = waitForArpResolution(self.device, self.key) catch |err| {
                self.err = err;
                self.done = true;
                Fiber.switchTo(fiber, self.loop_context);
                unreachable;
            };
            unreachable;
        }
    };

    lan_ip.* = .{ 192, 168, 86, 1 };
    lan_ready_queue.* = ReadyQueue.init(std.testing.io);
    wan_ready_queue.* = ReadyQueue.init(std.testing.io);
    defer setRunning(null);
    var nic: HandlerTestNic = .{};
    var loop_context: std.Io.fiber.Context = undefined;
    var task: WaitTask = .{
        .loop_context = &loop_context,
        .device = nic.api(),
        .key = .{ .iface = .lan, .ip = .{ 192, 168, 86, 99 } },
    };
    var fiber = try Fiber.init(std.testing.allocator, 8 * 1024, WaitTask.start, &task);
    defer fiber.deinit(std.testing.allocator);

    arp_waiters_table.* = try ArpWaitersTable.init(std.testing.allocator, std.testing.io, 0, .fromSeconds(1));
    setRunning(.{ .fiber = &fiber, .loop_context = &loop_context, .owner = .wan });
    Fiber.switchTo(&loop_context, &fiber);
    setRunning(null);
    try std.testing.expect(task.done);
    try std.testing.expectEqual(error.ArpWaitersTableFull, task.err.?);
    try std.testing.expect(nic.tx_len == null);
    arp_waiters_table.*.deinit(std.testing.allocator);

    arp_waiters_table.* = try ArpWaitersTable.init(std.testing.allocator, std.testing.io, 1, .fromNanoseconds(0));
    defer arp_waiters_table.*.deinit(std.testing.allocator);
    task.err = null;
    task.done = false;
    var timeout_fiber = try Fiber.init(std.testing.allocator, 8 * 1024, WaitTask.start, &task);
    defer timeout_fiber.deinit(std.testing.allocator);
    setRunning(.{ .fiber = &timeout_fiber, .loop_context = &loop_context, .owner = .wan });
    Fiber.switchTo(&loop_context, &timeout_fiber);
    setRunning(null);
    try std.testing.expect(!task.done);
    arp_waiters_table.expire();
    try std.testing.expect(wan_ready_queue.pop() == &timeout_fiber);
    setRunning(.{ .fiber = &timeout_fiber, .loop_context = &loop_context, .owner = .wan });
    Fiber.switchTo(&loop_context, &timeout_fiber);
    setRunning(null);
    try std.testing.expect(task.done);
    try std.testing.expectEqual(error.ArpResolutionTimedOut, task.err.?);
}
