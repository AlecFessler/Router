const std = @import("std");
const Router = @import("router");

const ArpTable = Router.Tables.ArpTable.ArpTable;
const ArpWaitersTable = Router.Tables.ArpWaitersTable.ArpWaitersTable;
const DhcpTable = Router.Tables.DhcpTable.DhcpTable;
const DHCPv4Lease = Router.Protocols.DHCPv4.DHCPv4Lease;
const Ethernet = Router.Protocols.Ethernet;
const IFace = Router.Nic.Api.IFace;
const IPv4 = Router.Protocols.IPv4.IPv4;
const IPv4FragmentTable = Router.Tables.IPv4FragmentTable.IPv4FragmentTable;
const Mac = Router.Protocols.Ethernet.Mac;
const NatTable = Router.Tables.NatTable.NatTable;
const NatFilteringMode = Router.Tables.NatTable.NatTable.FilteringMode;
const NicApi = Router.Nic.Api.Api;
const PcapParser = Router.TestFixtures.PcapParser;
const State = Router.State;
const ViewStack = Router.Protocols.ViewStack;

/// Records transmitted frames and owns the backing buffers for test packets.
pub const RecordingNic = struct {
    /// Large enough for any IPv4 frame the parser accepts (65535-byte payload).
    pub const TX_BUFFER_SIZE: usize = 65_550;

    const Origin = enum { rx_lan, rx_wan, tx_lan, tx_wan };

    const Outstanding = struct {
        allocation: []u8,
        origin: Origin,
    };

    pub const TxRecord = struct {
        iface: IFace,
        bytes: []u8,
    };

    alloc: std.mem.Allocator,
    outstanding: std.ArrayList(Outstanding) = .empty,
    rx_lan: std.ArrayList([]u8) = .empty,
    rx_wan: std.ArrayList([]u8) = .empty,
    tx_log: std.ArrayList(TxRecord) = .empty,
    error_count: usize = 0,
    drop_count: usize = 0,

    pub const lan_mac: Mac = .{ 0x02, 0, 0, 0, 0, 0x01 };
    pub const wan_mac: Mac = .{ 0x02, 0, 0, 0, 0, 0x02 };

    pub fn init(alloc: std.mem.Allocator) RecordingNic {
        return .{ .alloc = alloc };
    }

    pub fn deinit(self: *RecordingNic) void {
        for (self.rx_lan.items) |frame| self.alloc.free(frame);
        for (self.rx_wan.items) |frame| self.alloc.free(frame);
        self.rx_lan.deinit(self.alloc);
        self.rx_wan.deinit(self.alloc);
        for (self.tx_log.items) |record| self.alloc.free(record.bytes);
        self.tx_log.deinit(self.alloc);
        for (self.outstanding.items) |entry| self.alloc.free(entry.allocation);
        self.outstanding.deinit(self.alloc);
    }

    pub fn api(self: *RecordingNic) NicApi {
        return .{
            .ptr = self,
            .vtable = &.{
                .receive = receive,
                .nextTxBuffer = nextTxBuffer,
                .macAddress = macAddress,
                .release = release,
                .transmit = transmit,
            },
        };
    }

    /// Queue a frame for `receive()`. The NIC owns a copy.
    pub fn enqueue(self: *RecordingNic, iface: IFace, frame: []const u8) !void {
        const copy = try self.alloc.dupe(u8, frame);
        errdefer self.alloc.free(copy);
        switch (iface) {
            .lan => try self.rx_lan.append(self.alloc, copy),
            .wan => try self.rx_wan.append(self.alloc, copy),
        }
    }

    pub fn txAt(self: *const RecordingNic, index: usize) TxRecord {
        return self.tx_log.items[index];
    }

    pub fn lastTx(self: *const RecordingNic) ?TxRecord {
        if (self.tx_log.items.len == 0) return null;
        return self.tx_log.items[self.tx_log.items.len - 1];
    }

    pub fn resetLogs(self: *RecordingNic) void {
        for (self.tx_log.items) |record| self.alloc.free(record.bytes);
        self.tx_log.clearRetainingCapacity();
        self.error_count = 0;
        self.drop_count = 0;
    }

    fn originFor(iface: IFace) Origin {
        return switch (iface) {
            .lan => .rx_lan,
            .wan => .rx_wan,
        };
    }

    fn txOriginFor(iface: IFace) Origin {
        return switch (iface) {
            .lan => .tx_lan,
            .wan => .tx_wan,
        };
    }

    fn track(self: *RecordingNic, allocation: []u8, origin: Origin) void {
        self.outstanding.append(self.alloc, .{
            .allocation = allocation,
            .origin = origin,
        }) catch unreachable;
    }

    fn take(self: *RecordingNic, buffer: []u8) ?Outstanding {
        const start = @intFromPtr(buffer.ptr);
        const end = start + buffer.len;
        for (self.outstanding.items, 0..) |entry, i| {
            const alloc_start = @intFromPtr(entry.allocation.ptr);
            const alloc_end = alloc_start + entry.allocation.len;
            if (start >= alloc_start and end <= alloc_end) {
                return self.outstanding.swapRemove(i);
            }
        }
        return null;
    }

    fn receive(ctx: *anyopaque, iface: IFace) ?[]u8 {
        const self: *RecordingNic = @ptrCast(@alignCast(ctx));
        const queue = switch (iface) {
            .lan => &self.rx_lan,
            .wan => &self.rx_wan,
        };
        if (queue.items.len == 0) return null;
        const frame = queue.orderedRemove(0);
        self.track(frame, originFor(iface));
        return frame;
    }

    fn nextTxBuffer(ctx: *anyopaque, iface: IFace) []u8 {
        const self: *RecordingNic = @ptrCast(@alignCast(ctx));
        const buffer = self.alloc.alloc(u8, TX_BUFFER_SIZE) catch unreachable;
        self.track(buffer, txOriginFor(iface));
        return buffer;
    }

    fn macAddress(_: *anyopaque, iface: IFace) Mac {
        return switch (iface) {
            .lan => lan_mac,
            .wan => wan_mac,
        };
    }

    fn release(ctx: *anyopaque, buffer: []u8) void {
        const self: *RecordingNic = @ptrCast(@alignCast(ctx));
        const entry = self.take(buffer) orelse return;
        switch (entry.origin) {
            .rx_lan, .rx_wan => self.drop_count += 1,
            .tx_lan, .tx_wan => {},
        }
        self.alloc.free(entry.allocation);
    }

    fn transmit(ctx: *anyopaque, buffer: []u8) void {
        const self: *RecordingNic = @ptrCast(@alignCast(ctx));
        const entry = self.take(buffer) orelse return;
        // A buffer received on one interface is forwarded out the other; a
        // freshly allocated TX buffer is sent on the interface it came from.
        const egress: IFace = switch (entry.origin) {
            .rx_lan => .wan,
            .rx_wan => .lan,
            .tx_lan => .lan,
            .tx_wan => .wan,
        };
        const copy = self.alloc.dupe(u8, buffer) catch unreachable;
        self.tx_log.append(self.alloc, .{ .iface = egress, .bytes = copy }) catch unreachable;
        self.alloc.free(entry.allocation);
    }
};

/// End-to-end harness: sets up and tears down the process-global `State` the
/// same way `src/main.zig` does, then feeds frames to `Ethernet.handle`.
pub const Harness = struct {
    pub const Options = struct {
        lan_ip: IPv4 = .{ 192, 168, 86, 1 },
        lan_subnet_mask: IPv4 = .{ 255, 255, 255, 0 },
        arp_capacity: u32 = 256,
        arp_ttl: std.Io.Duration = std.Io.Duration.fromSeconds(300),
        arp_waiters_capacity: usize = 256,
        arp_waiters_timeout: std.Io.Duration = std.Io.Duration.fromSeconds(2),
        fragment_capacity: u32 = 256,
        fragment_timeout: std.Io.Duration = std.Io.Duration.fromSeconds(30),
        nat_capacity: u32 = 16_384,
        /// `null` uses `192.168.86.2 ..= 192.168.86.254` like `src/main.zig`.
        dhcp_pool: ?[]const IPv4 = null,
        wan_lease: ?DHCPv4Lease = null,
        nat_filtering_mode: NatFilteringMode = .address_restricted,
    };

    alloc: std.mem.Allocator,
    nic: RecordingNic,
    ready: struct {
        lan_arp: bool = false,
        wan_arp: bool = false,
        waiters: bool = false,
        dhcp: bool = false,
        nat: bool = false,
        lan_fragments: bool = false,
        wan_fragments: bool = false,
        reassembly_tables: usize = 0,
    } = .{},

    pub fn init(alloc: std.mem.Allocator, io: std.Io, options: Options) !Harness {
        var self: Harness = .{
            .alloc = alloc,
            .nic = RecordingNic.init(alloc),
        };
        errdefer self.deinit();

        State.lan_ip = options.lan_ip;
        State.lan_subnet_mask = options.lan_subnet_mask;
        State.wan_lease = options.wan_lease;
        State.nat_filtering_mode = options.nat_filtering_mode;
        State.wan_transaction = null;

        State.lan_arp_table = try ArpTable.init(alloc, io, options.arp_capacity, options.arp_ttl);
        self.ready.lan_arp = true;
        State.wan_arp_table = try ArpTable.init(alloc, io, options.arp_capacity, options.arp_ttl);
        self.ready.wan_arp = true;

        State.arp_waiters_table = try ArpWaitersTable.init(
            alloc,
            io,
            options.arp_waiters_capacity,
            options.arp_waiters_timeout,
        );
        self.ready.waiters = true;

        var ip_pool: DhcpTable.IpPool = .empty;
        errdefer ip_pool.deinit(alloc);
        if (options.dhcp_pool) |pool| {
            try ip_pool.appendSlice(alloc, pool);
        } else {
            for (2..255) |host| {
                try ip_pool.append(alloc, .{ 192, 168, 86, @intCast(host) });
            }
        }
        State.dhcp_table = try DhcpTable.init(alloc, io, ip_pool);
        self.ready.dhcp = true;

        State.nat_table = try NatTable.init(alloc, io, options.nat_capacity);
        self.ready.nat = true;

        State.lan_fragment_table = try IPv4FragmentTable.init(
            alloc,
            io,
            options.fragment_capacity,
            options.fragment_timeout,
        );
        self.ready.lan_fragments = true;
        State.wan_fragment_table = try IPv4FragmentTable.init(
            alloc,
            io,
            options.fragment_capacity,
            options.fragment_timeout,
        );
        self.ready.wan_fragments = true;
        for (&State.reassembly_tables) |*table| {
            table.* = try .init(alloc, io, 16, .fromSeconds(60));
            self.ready.reassembly_tables += 1;
        }

        return self;
    }

    pub fn deinit(self: *Harness) void {
        // Drain ARP waiters first so their queued buffers are released while
        // the NIC is still alive.
        if (self.ready.waiters) {
            State.arp_waiters_table.expireAll(self.nic.api());
            State.arp_waiters_table.deinit(self.alloc);
            self.ready.waiters = false;
        }
        for (State.reassembly_tables[0..self.ready.reassembly_tables]) |*table| table.deinit(self.alloc);
        self.ready.reassembly_tables = 0;
        if (self.ready.lan_fragments) {
            State.lan_fragment_table.deinit(self.alloc, self.nic.api());
            self.ready.lan_fragments = false;
        }
        if (self.ready.wan_fragments) {
            State.wan_fragment_table.deinit(self.alloc, self.nic.api());
            self.ready.wan_fragments = false;
        }
        if (self.ready.nat) {
            State.nat_table.deinit(self.alloc);
            self.ready.nat = false;
        }
        if (self.ready.dhcp) {
            State.dhcp_table.deinit(self.alloc);
            self.ready.dhcp = false;
        }
        if (self.ready.lan_arp) {
            State.lan_arp_table.deinit(self.alloc);
            self.ready.lan_arp = false;
        }
        if (self.ready.wan_arp) {
            State.wan_arp_table.deinit(self.alloc);
            self.ready.wan_arp = false;
        }
        State.wan_lease = null;
        State.nat_filtering_mode = .address_restricted;
        State.wan_transaction = null;
        self.nic.deinit();
    }

    /// Queue one raw Ethernet frame (without FCS) for `iface`.
    pub fn inject(self: *Harness, iface: IFace, frame: []const u8) !void {
        try self.nic.enqueue(iface, frame);
    }

    /// Parse a synthetic/classic pcap and queue every packet for `iface`.
    pub fn injectPcap(self: *Harness, iface: IFace, pcap_bytes: []const u8) !void {
        var parsed = try PcapParser.parse(pcap_bytes, self.alloc);
        defer parsed.deinit(self.alloc);
        for (parsed.packet_bytes) |packet| try self.inject(iface, packet);
    }

    /// Receive and handle at most one packet from `iface`.
    /// Returns false when the interface's RX queue is empty.
    pub fn runOne(self: *Harness, iface: IFace) bool {
        const packet = self.nic.api().receive(iface) orelse return false;
        var views: ViewStack = .{};
        Ethernet.handle(packet, self.nic.api(), iface, &views) catch {
            // Mirror the production loop: the caller owns the RX buffer when
            // the handler returns an error.
            self.nic.api().release(packet);
            self.nic.error_count += 1;
        };
        return true;
    }

    /// Drain `iface`, processing packets in FIFO order. Returns packet count.
    pub fn runAll(self: *Harness, iface: IFace) usize {
        var count: usize = 0;
        while (self.runOne(iface)) count += 1;
        return count;
    }

    pub fn txCount(self: *const Harness) usize {
        return self.nic.tx_log.items.len;
    }

    pub fn txAt(self: *const Harness, index: usize) RecordingNic.TxRecord {
        return self.nic.txAt(index);
    }

    pub fn lastTx(self: *const Harness) ?RecordingNic.TxRecord {
        return self.nic.lastTx();
    }

    pub fn dropCount(self: *const Harness) usize {
        return self.nic.drop_count;
    }

    pub fn errorCount(self: *const Harness) usize {
        return self.nic.error_count;
    }

    pub fn cacheArp(self: *Harness, iface: IFace, ip: IPv4, mac: Mac) void {
        _ = self;
        switch (iface) {
            .lan => State.lan_arp_table.cache(ip, mac),
            .wan => State.wan_arp_table.cache(ip, mac),
        }
    }

    pub fn setWanLease(self: *Harness, lease: ?DHCPv4Lease) void {
        _ = self;
        State.wan_lease = lease;
    }
};

/// Synthesized packet/frame/pcap builders.
pub const Packets = struct {
    pub const VlanTag = struct {
        tpid: u16 = 0x8100,
        pcp: u3 = 0,
        dei: bool = false,
        vid: u12 = 0,
    };

    pub const EthOpts = struct {
        dst: Mac = .{0xff} ** 6,
        src: Mac = .{ 0x02, 0x11, 0x22, 0x33, 0x44, 0x55 },
        vlan_tags: []const VlanTag = &.{},
        /// EtherType when > 1500, 802.3 length when <= 1500.
        ethertype: u16 = 0x0800,
        payload: []const u8 = &.{},
        /// Zero-pad the frame to at least this length (no FCS).
        min_len: ?usize = null,
    };

    pub const Ipv4Opts = struct {
        src: IPv4 = .{ 192, 168, 86, 42 },
        dst: IPv4 = .{ 8, 8, 8, 8 },
        protocol: u8 = 17,
        ttl: u8 = 64,
        identification: u16 = 0,
        version: u4 = 4,
        reserved: u1 = 0,
        dont_fragment: bool = false,
        more_fragments: bool = false,
        fragment_offset: u13 = 0,
        dscp: u6 = 0,
        ecn: u2 = 0,
        /// Header options; padded to a multiple of four bytes.
        options: []const u8 = &.{},
        /// Override the IHL nibble written to the wire.
        ihl: ?u4 = null,
        /// Override the total_length field.
        total_length: ?u16 = null,
        /// `null` computes the header checksum from the written header.
        checksum: ?u16 = null,
        payload: []const u8 = &.{},
        /// Bytes appended after the payload but not counted in total_length.
        trailing: []const u8 = &.{},
    };

    pub const UdpOpts = struct {
        src_port: u16 = 40_000,
        dst_port: u16 = 53,
        /// Override the UDP length field.
        length: ?u16 = null,
        /// `null` computes the checksum; `0` disables it.
        checksum: ?u16 = null,
        payload: []const u8 = &.{},
    };

    pub const TcpOpts = struct {
        src_port: u16 = 40_000,
        dst_port: u16 = 80,
        seq_number: u32 = 0,
        ack_number: u32 = 0,
        /// Override the data-offset nibble (in 32-bit words).
        data_offset: ?u4 = null,
        reserved: u3 = 0,
        ae: bool = false,
        cwr: bool = false,
        ece: bool = false,
        urg: bool = false,
        ack: bool = true,
        psh: bool = false,
        rst: bool = false,
        syn: bool = false,
        fin: bool = false,
        window: u16 = 4096,
        urgent_ptr: u16 = 0,
        /// TCP options; padded to a multiple of four bytes.
        options: []const u8 = &.{},
        /// `null` computes the checksum.
        checksum: ?u16 = null,
        payload: []const u8 = &.{},
    };

    pub const IcmpOpts = struct {
        message_type: u8 = 8,
        code: u8 = 0,
        /// Raw bytes after the four-byte ICMPv4 header.
        body: []const u8 = &.{},
        /// `null` computes the checksum; `0` writes a zero checksum.
        checksum: ?u16 = null,
    };

    pub const EchoOpts = struct {
        message_type: u8 = 8,
        code: u8 = 0,
        identifier: u16 = 0x1234,
        sequence_number: u16 = 1,
        data: []const u8 = &.{},
        checksum: ?u16 = null,
    };

    pub const ArpOpts = struct {
        hardware_type: u16 = 1,
        protocol_type: u16 = 0x0800,
        hardware_size: u8 = 6,
        protocol_size: u8 = 4,
        opcode: u16 = 1,
        sender_mac: Mac = .{ 0x02, 0x11, 0x22, 0x33, 0x44, 0x55 },
        sender_ip: IPv4 = .{ 192, 168, 86, 42 },
        target_mac: Mac = .{0} ** 6,
        target_ip: IPv4 = .{ 192, 168, 86, 1 },
    };

    const Bytes = std.ArrayList(u8);

    fn appendU8(list: *Bytes, alloc: std.mem.Allocator, value: u8) !void {
        try list.append(alloc, value);
    }

    fn appendU16(list: *Bytes, alloc: std.mem.Allocator, value: u16) !void {
        var bytes: [2]u8 = undefined;
        std.mem.writeInt(u16, &bytes, value, .big);
        try list.appendSlice(alloc, &bytes);
    }

    fn appendU32(list: *Bytes, alloc: std.mem.Allocator, value: u32) !void {
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, value, .big);
        try list.appendSlice(alloc, &bytes);
    }

    fn appendBytes(list: *Bytes, alloc: std.mem.Allocator, bytes: []const u8) !void {
        try list.appendSlice(alloc, bytes);
    }

    /// Unfolded one's-complement sum over network-order bytes (zero padding an
    /// odd trailing byte).
    fn sumBytes(sum_in: u64, bytes: []const u8) u64 {
        var sum = sum_in;
        var i: usize = 0;
        while (i + 1 < bytes.len) : (i += 2) {
            sum += (@as(u16, bytes[i]) << 8) | bytes[i + 1];
        }
        if (i < bytes.len) sum += @as(u16, bytes[i]) << 8;
        return sum;
    }

    fn finish(sum_in: u64) u16 {
        var sum = sum_in;
        while (sum >> 16 != 0) sum = (sum & 0xffff) + (sum >> 16);
        return ~@as(u16, @intCast(sum));
    }

    fn ipv4Checksum(header: []const u8) u16 {
        return finish(sumBytes(0, header));
    }

    fn transportChecksum(
        src: IPv4,
        dst: IPv4,
        protocol: u8,
        length: u16,
        segment: []const u8,
    ) u16 {
        var sum: u64 = 0;
        sum = sumBytes(sum, &src);
        sum = sumBytes(sum, &dst);
        sum += protocol;
        sum += length;
        sum = sumBytes(sum, segment);
        return finish(sum);
    }

    fn writeU16At(bytes: []u8, offset: usize, value: u16) void {
        std.mem.writeInt(u16, bytes[offset..][0..2], value, .big);
    }

    /// Build an Ethernet frame (without FCS).
    pub fn eth(alloc: std.mem.Allocator, opts: EthOpts) ![]u8 {
        var list: Bytes = .empty;
        errdefer list.deinit(alloc);

        try appendBytes(&list, alloc, &opts.dst);
        try appendBytes(&list, alloc, &opts.src);
        for (opts.vlan_tags) |tag| {
            try appendU16(&list, alloc, tag.tpid);
            const tci: u16 = (@as(u16, tag.pcp) << 13) |
                (@as(u16, @intFromBool(tag.dei)) << 12) |
                @as(u16, tag.vid);
            try appendU16(&list, alloc, tci);
        }
        try appendU16(&list, alloc, opts.ethertype);
        try appendBytes(&list, alloc, opts.payload);

        if (opts.min_len) |min_len| {
            while (list.items.len < min_len) try list.append(alloc, 0);
        }
        return list.toOwnedSlice(alloc);
    }

    /// Build an IPv4 packet (header + payload).
    pub fn ipv4(alloc: std.mem.Allocator, opts: Ipv4Opts) ![]u8 {
        var header: Bytes = .empty;
        defer header.deinit(alloc);

        const options_len = std.mem.alignForward(usize, opts.options.len, 4);
        const actual_header_len = 20 + options_len;
        const ihl: u4 = opts.ihl orelse @intCast(actual_header_len / 4);
        const declared_header_len: usize = @as(usize, ihl) * 4;

        try appendU8(&header, alloc, (@as(u8, opts.version) << 4) | @as(u8, ihl));
        try appendU8(&header, alloc, (@as(u8, opts.dscp) << 2) | @as(u8, opts.ecn));
        const total_length: u16 = opts.total_length orelse
            @intCast(actual_header_len + opts.payload.len);
        try appendU16(&header, alloc, total_length);
        try appendU16(&header, alloc, opts.identification);
        const flags: u16 = (@as(u16, opts.reserved) << 15) |
            (@as(u16, @intFromBool(opts.dont_fragment)) << 14) |
            (@as(u16, @intFromBool(opts.more_fragments)) << 13) |
            @as(u16, opts.fragment_offset);
        try appendU16(&header, alloc, flags);
        try appendU8(&header, alloc, opts.ttl);
        try appendU8(&header, alloc, opts.protocol);
        try appendU16(&header, alloc, 0); // checksum placeholder
        try appendBytes(&header, alloc, &opts.src);
        try appendBytes(&header, alloc, &opts.dst);
        try appendBytes(&header, alloc, opts.options);
        while (header.items.len < actual_header_len) try header.append(alloc, 0);

        // The checksum covers the header as interpreted by the declared IHL.
        if (declared_header_len > header.items.len) {
            while (header.items.len < declared_header_len) try header.append(alloc, 0);
        }
        const checksum = opts.checksum orelse
            ipv4Checksum(header.items[0..declared_header_len]);
        writeU16At(header.items, 10, checksum);

        var list: Bytes = .empty;
        errdefer list.deinit(alloc);
        try appendBytes(&list, alloc, header.items);
        try appendBytes(&list, alloc, opts.payload);
        try appendBytes(&list, alloc, opts.trailing);
        return list.toOwnedSlice(alloc);
    }

    /// Build a UDP datagram. `src`/`dst` are the enclosing IPv4 addresses and
    /// are only used for checksum computation.
    pub fn udp(
        alloc: std.mem.Allocator,
        src: IPv4,
        dst: IPv4,
        opts: UdpOpts,
    ) ![]u8 {
        var list: Bytes = .empty;
        errdefer list.deinit(alloc);

        const length: u16 = opts.length orelse @intCast(8 + opts.payload.len);
        try appendU16(&list, alloc, opts.src_port);
        try appendU16(&list, alloc, opts.dst_port);
        try appendU16(&list, alloc, length);
        try appendU16(&list, alloc, 0); // checksum placeholder
        try appendBytes(&list, alloc, opts.payload);

        const checksum = opts.checksum orelse
            transportChecksum(src, dst, 17, length, list.items);
        writeU16At(list.items, 6, checksum);
        return list.toOwnedSlice(alloc);
    }

    /// Build a TCP segment. `src`/`dst` are the enclosing IPv4 addresses and
    /// are only used for checksum computation.
    pub fn tcp(
        alloc: std.mem.Allocator,
        src: IPv4,
        dst: IPv4,
        opts: TcpOpts,
    ) ![]u8 {
        var list: Bytes = .empty;
        errdefer list.deinit(alloc);

        const options_len = std.mem.alignForward(usize, opts.options.len, 4);
        const actual_header_len = 20 + options_len;
        const data_offset: u4 = opts.data_offset orelse @intCast(actual_header_len / 4);

        try appendU16(&list, alloc, opts.src_port);
        try appendU16(&list, alloc, opts.dst_port);
        try appendU32(&list, alloc, opts.seq_number);
        try appendU32(&list, alloc, opts.ack_number);
        try appendU8(&list, alloc, (@as(u8, data_offset) << 4) | (@as(u8, opts.reserved) << 1) |
            @as(u8, @intFromBool(opts.ae)));
        var flags: u8 = 0;
        if (opts.cwr) flags |= 0x80;
        if (opts.ece) flags |= 0x40;
        if (opts.urg) flags |= 0x20;
        if (opts.ack) flags |= 0x10;
        if (opts.psh) flags |= 0x08;
        if (opts.rst) flags |= 0x04;
        if (opts.syn) flags |= 0x02;
        if (opts.fin) flags |= 0x01;
        try appendU8(&list, alloc, flags);
        try appendU16(&list, alloc, opts.window);
        try appendU16(&list, alloc, 0); // checksum placeholder
        try appendU16(&list, alloc, opts.urgent_ptr);
        try appendBytes(&list, alloc, opts.options);
        while (list.items.len < actual_header_len) try list.append(alloc, 0);
        try appendBytes(&list, alloc, opts.payload);

        const segment_len: u16 = @intCast(list.items.len);
        const checksum = opts.checksum orelse
            transportChecksum(src, dst, 6, segment_len, list.items);
        writeU16At(list.items, 16, checksum);
        return list.toOwnedSlice(alloc);
    }

    /// Build an ICMPv4 message (four-byte header + body).
    pub fn icmp(alloc: std.mem.Allocator, opts: IcmpOpts) ![]u8 {
        var list: Bytes = .empty;
        errdefer list.deinit(alloc);

        try appendU8(&list, alloc, opts.message_type);
        try appendU8(&list, alloc, opts.code);
        try appendU16(&list, alloc, 0); // checksum placeholder
        try appendBytes(&list, alloc, opts.body);

        const checksum = opts.checksum orelse finish(sumBytes(0, list.items));
        writeU16At(list.items, 2, checksum);
        return list.toOwnedSlice(alloc);
    }

    /// Build an ICMPv4 echo request/reply message.
    pub fn echo(alloc: std.mem.Allocator, opts: EchoOpts) ![]u8 {
        var body: Bytes = .empty;
        defer body.deinit(alloc);
        try appendU16(&body, alloc, opts.identifier);
        try appendU16(&body, alloc, opts.sequence_number);
        try appendBytes(&body, alloc, opts.data);
        return icmp(alloc, .{
            .message_type = opts.message_type,
            .code = opts.code,
            .body = body.items,
            .checksum = opts.checksum,
        });
    }

    /// Build an ARP packet.
    pub fn arp(alloc: std.mem.Allocator, opts: ArpOpts) ![]u8 {
        var list: Bytes = .empty;
        errdefer list.deinit(alloc);

        try appendU16(&list, alloc, opts.hardware_type);
        try appendU16(&list, alloc, opts.protocol_type);
        try appendU8(&list, alloc, opts.hardware_size);
        try appendU8(&list, alloc, opts.protocol_size);
        try appendU16(&list, alloc, opts.opcode);
        try appendBytes(&list, alloc, &opts.sender_mac);
        try appendBytes(&list, alloc, &opts.sender_ip);
        try appendBytes(&list, alloc, &opts.target_mac);
        try appendBytes(&list, alloc, &opts.target_ip);
        return list.toOwnedSlice(alloc);
    }

    /// Write a classic little-endian pcap (linktype 1 / Ethernet) around frames.
    pub fn pcap(alloc: std.mem.Allocator, frames: []const []const u8) ![]u8 {
        var list: Bytes = .empty;
        errdefer list.deinit(alloc);

        var global_header: [24]u8 = .{0} ** 24;
        std.mem.writeInt(u32, global_header[0..4], 0xA1B2C3D4, .little);
        std.mem.writeInt(u16, global_header[4..6], 2, .little);
        std.mem.writeInt(u16, global_header[6..8], 4, .little);
        std.mem.writeInt(u32, global_header[16..20], 65_535, .little);
        std.mem.writeInt(u32, global_header[20..24], 1, .little);
        try appendBytes(&list, alloc, &global_header);

        for (frames, 0..) |frame, i| {
            var header: [16]u8 = .{0} ** 16;
            std.mem.writeInt(u32, header[0..4], @intCast(i), .little);
            std.mem.writeInt(u32, header[4..8], 0, .little);
            std.mem.writeInt(u32, header[8..12], @intCast(frame.len), .little);
            std.mem.writeInt(u32, header[12..16], @intCast(frame.len), .little);
            try appendBytes(&list, alloc, &header);
            try appendBytes(&list, alloc, frame);
        }
        return list.toOwnedSlice(alloc);
    }
};

fn testWanLease(io: std.Io) DHCPv4Lease {
    const now = std.Io.Timestamp.now(io, .boot);
    return .{
        .ip = .{ 203, 0, 113, 50 },
        .subnet_mask = .{ 255, 255, 255, 0 },
        .router = .{ 203, 0, 113, 1 },
        .server_id = .{ 203, 0, 113, 1 },
        .renewal_deadline = now,
        .rebinding_deadline = now,
        .expiration_deadline = now,
    };
}

const client_mac: Mac = .{ 0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee };
const gateway_mac: Mac = .{ 0x02, 0x99, 0x88, 0x77, 0x66, 0x55 };
const client_ip: IPv4 = .{ 192, 168, 86, 42 };

test "harness smoke: LAN to WAN UDP is NATed, checksummed, and transmitted on WAN" {
    const alloc = std.testing.allocator;
    var h = try Harness.init(alloc, std.testing.io, .{
        .wan_lease = testWanLease(std.testing.io),
    });
    defer h.deinit();

    const lease_ip: IPv4 = .{ 203, 0, 113, 50 };
    const remote_ip: IPv4 = .{ 8, 8, 8, 8 };
    h.cacheArp(.wan, .{ 203, 0, 113, 1 }, gateway_mac);

    const udp_bytes = try Packets.udp(alloc, client_ip, remote_ip, .{
        .src_port = 40_000,
        .dst_port = 53,
        .payload = "hello",
    });
    defer alloc.free(udp_bytes);
    const ip_bytes = try Packets.ipv4(alloc, .{
        .src = client_ip,
        .dst = remote_ip,
        .protocol = 17,
        .dont_fragment = true,
        .payload = udp_bytes,
    });
    defer alloc.free(ip_bytes);
    const frame = try Packets.eth(alloc, .{
        .dst = RecordingNic.lan_mac,
        .src = client_mac,
        .ethertype = 0x0800,
        .payload = ip_bytes,
    });
    defer alloc.free(frame);

    // Exercise the synthetic classic-pcap writer and the pcap loading path.
    const pcap_bytes = try Packets.pcap(alloc, &[_][]const u8{frame});
    defer alloc.free(pcap_bytes);
    try h.injectPcap(.lan, pcap_bytes);
    try std.testing.expectEqual(@as(usize, 1), h.runAll(.lan));

    try std.testing.expectEqual(@as(usize, 1), h.txCount());
    const tx = h.txAt(0);
    try std.testing.expectEqual(IFace.wan, tx.iface);

    const tx_eth = try Ethernet.parse(tx.bytes);
    try std.testing.expectEqual(RecordingNic.wan_mac, tx_eth.get(.src_mac));
    try std.testing.expectEqual(gateway_mac, tx_eth.get(.dst_mac));
    try std.testing.expectEqual(Ethernet.Ethertype.ipv4, tx_eth.get(.ethertype));

    const tx_ip = try Router.Protocols.IPv4.parse(tx_eth.get(.payload));
    try std.testing.expectEqual(lease_ip, tx_ip.get(.src));
    try std.testing.expectEqual(remote_ip, tx_ip.get(.dst));
    try std.testing.expectEqual(@as(u8, 63), tx_ip.get(.ttl));

    const tx_udp = try Router.Protocols.Udp.parse(tx_ip.get(.payload), tx_ip);
    try std.testing.expectEqual(@as(u16, 40_000), tx_udp.get(.src_port));
    try std.testing.expectEqual(@as(u16, 53), tx_udp.get(.dst_port));
    try std.testing.expectEqualStrings("hello", tx_udp.get(.payload));

    const inside, _ = State.nat_table.inboundEntry(.{
        .protocol = .udp,
        .ip = lease_ip,
        .port = 40_000,
    }).?;
    try std.testing.expectEqual(client_ip, inside.ip);
    try std.testing.expectEqual(@as(u16, 40_000), inside.port);

    try std.testing.expectEqual(@as(usize, 0), h.dropCount());
    try std.testing.expectEqual(@as(usize, 0), h.errorCount());
}

test "harness smoke: ICMP echo request to the LAN IP gets a LAN echo reply" {
    const alloc = std.testing.allocator;
    var h = try Harness.init(alloc, std.testing.io, .{});
    defer h.deinit();

    const payload = "ping-data";
    const icmp_bytes = try Packets.echo(alloc, .{
        .identifier = 0x4321,
        .sequence_number = 7,
        .data = payload,
    });
    defer alloc.free(icmp_bytes);
    const ip_bytes = try Packets.ipv4(alloc, .{
        .src = client_ip,
        .dst = .{ 192, 168, 86, 1 },
        .protocol = 1,
        .dont_fragment = true,
        .payload = icmp_bytes,
    });
    defer alloc.free(ip_bytes);
    const frame = try Packets.eth(alloc, .{
        .dst = RecordingNic.lan_mac,
        .src = client_mac,
        .ethertype = 0x0800,
        .payload = ip_bytes,
    });
    defer alloc.free(frame);

    try h.inject(.lan, frame);
    try std.testing.expectEqual(@as(usize, 1), h.runAll(.lan));

    try std.testing.expectEqual(@as(usize, 1), h.txCount());
    const tx = h.txAt(0);
    try std.testing.expectEqual(IFace.lan, tx.iface);

    const tx_eth = try Ethernet.parse(tx.bytes);
    try std.testing.expectEqual(RecordingNic.lan_mac, tx_eth.get(.src_mac));
    try std.testing.expectEqual(client_mac, tx_eth.get(.dst_mac));

    const tx_ip = try Router.Protocols.IPv4.parse(tx_eth.get(.payload));
    try std.testing.expectEqual(IPv4{ 192, 168, 86, 1 }, tx_ip.get(.src));
    try std.testing.expectEqual(client_ip, tx_ip.get(.dst));

    const tx_icmp = try Router.Protocols.ICMPv4.parse(tx_ip.get(.payload));
    try std.testing.expectEqual(Router.Protocols.ICMPv4.MessageType.echo_reply, tx_icmp.get(.message_type));
    const tx_echo = try Router.Protocols.ICMPv4Messages.Echo.parse(tx_icmp);
    try std.testing.expectEqual(@as(u16, 0x4321), tx_echo.get(.identifier));
    try std.testing.expectEqual(@as(u16, 7), tx_echo.get(.sequence_number));
    try std.testing.expectEqualStrings(payload, tx_echo.get(.data));

    try std.testing.expectEqual(@as(usize, 1), h.dropCount());
    try std.testing.expectEqual(@as(usize, 0), h.errorCount());
}

/// Minimal DHCPv4 client message builder used by the state-table regressions.
pub const DhcpClient = struct {
    pub const Opts = struct {
        message_type: u8,
        vlan_tags: []const Packets.VlanTag = &.{},
        xid: u32 = 0x1122_3344,
        ciaddr: IPv4 = .{ 0, 0, 0, 0 },
        client_id: ?[]const u8 = null,
        requested_ip: ?IPv4 = null,
        server_id: ?IPv4 = null,
        broadcast_flag: bool = false,
        secs: u16 = 0,
        /// Overrides the payload chaddr while leaving the Ethernet source
        /// address as `mac`; used to prove chaddr is not an authorisation.
        chaddr: ?Mac = null,
    };

    fn u16be(list: *std.ArrayList(u8), alloc: std.mem.Allocator, value: u16) !void {
        var bytes: [2]u8 = undefined;
        std.mem.writeInt(u16, &bytes, value, .big);
        try list.appendSlice(alloc, &bytes);
    }

    fn u32be(list: *std.ArrayList(u8), alloc: std.mem.Allocator, value: u32) !void {
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, value, .big);
        try list.appendSlice(alloc, &bytes);
    }

    fn option(list: *std.ArrayList(u8), alloc: std.mem.Allocator, code: u8, data: []const u8) !void {
        try list.append(alloc, code);
        try list.append(alloc, @intCast(data.len));
        try list.appendSlice(alloc, data);
    }

    /// Build the DHCPv4 payload (fixed BOOTP header + options).
    pub fn payload(
        alloc: std.mem.Allocator,
        mac: Mac,
        opts: Opts,
    ) ![]u8 {
        var list: std.ArrayList(u8) = .empty;
        errdefer list.deinit(alloc);

        try list.append(alloc, 1); // BOOTREQUEST
        try list.append(alloc, 1); // Ethernet
        try list.append(alloc, 6); // hardware address length
        try list.append(alloc, 0); // hops
        try u32be(&list, alloc, opts.xid);
        try u16be(&list, alloc, opts.secs);
        try u16be(&list, alloc, if (opts.broadcast_flag) 0x8000 else 0);
        try list.appendSlice(alloc, &opts.ciaddr);
        try list.appendSlice(alloc, &([_]u8{0} ** 4)); // yiaddr
        try list.appendSlice(alloc, &([_]u8{0} ** 4)); // siaddr
        try list.appendSlice(alloc, &([_]u8{0} ** 4)); // giaddr
        try list.appendSlice(alloc, &(opts.chaddr orelse mac));
        try list.appendSlice(alloc, &([_]u8{0} ** 10)); // chaddr padding
        try list.appendSlice(alloc, &([_]u8{0} ** 64)); // sname
        try list.appendSlice(alloc, &([_]u8{0} ** 128)); // file
        try list.appendSlice(alloc, &.{ 0x63, 0x82, 0x53, 0x63 });

        const message_type = [_]u8{opts.message_type};
        try option(&list, alloc, 53, &message_type);
        if (opts.client_id) |id| try option(&list, alloc, 61, id);
        if (opts.requested_ip) |ip| try option(&list, alloc, 50, &ip);
        if (opts.server_id) |ip| try option(&list, alloc, 54, &ip);
        try list.append(alloc, 255); // end

        return list.toOwnedSlice(alloc);
    }

    /// Build a full Ethernet/IPv4/UDP DHCP client frame (68 -> 67).
    pub fn frame(
        alloc: std.mem.Allocator,
        mac: Mac,
        opts: Opts,
    ) ![]u8 {
        const dhcp = try payload(alloc, mac, opts);
        defer alloc.free(dhcp);

        const udp_bytes = try Packets.udp(alloc, .{ 0, 0, 0, 0 }, .{ 255, 255, 255, 255 }, .{
            .src_port = 68,
            .dst_port = 67,
            .checksum = 0,
            .payload = dhcp,
        });
        defer alloc.free(udp_bytes);

        const ip_bytes = try Packets.ipv4(alloc, .{
            .src = .{ 0, 0, 0, 0 },
            .dst = .{ 255, 255, 255, 255 },
            .protocol = 17,
            .dont_fragment = true,
            .payload = udp_bytes,
        });
        defer alloc.free(ip_bytes);

        return Packets.eth(alloc, .{
            .dst = .{0xff} ** 6,
            .src = mac,
            .vlan_tags = opts.vlan_tags,
            .ethertype = 0x0800,
            .payload = ip_bytes,
        });
    }
};

test "a DHCPDECLINE from a different client MAC must not delete another client's lease" {
    const alloc = std.testing.allocator;
    var h = try Harness.init(alloc, std.testing.io, .{
        .dhcp_pool = &[_]IPv4{
            .{ 192, 168, 86, 10 },
            .{ 192, 168, 86, 11 },
            .{ 192, 168, 86, 12 },
        },
    });
    defer h.deinit();

    const victim_mac: Mac = .{ 0x02, 0xaa, 0x00, 0x00, 0x00, 0x01 };
    const attacker_mac: Mac = .{ 0x02, 0xbb, 0x00, 0x00, 0x00, 0x02 };
    const victim_id = "victim-client";
    const victim_ip: IPv4 = .{ 192, 168, 86, 10 };
    const lan_ip: IPv4 = .{ 192, 168, 86, 1 };

    // The victim obtains a normal lease: DISCOVER -> OFFER -> REQUEST -> ACK.
    const discover = try DhcpClient.frame(alloc, victim_mac, .{
        .message_type = 1,
        .xid = 0x0a0b_0c0d,
        .client_id = victim_id,
    });
    defer alloc.free(discover);
    try h.inject(.lan, discover);
    _ = h.runAll(.lan);

    const request = try DhcpClient.frame(alloc, victim_mac, .{
        .message_type = 3,
        .xid = 0x0a0b_0c0d,
        .client_id = victim_id,
        .requested_ip = victim_ip,
        .server_id = lan_ip,
    });
    defer alloc.free(request);
    try h.inject(.lan, request);
    _ = h.runAll(.lan);

    // Sanity: the victim's lease is bound to the victim's address.
    try std.testing.expect(State.dhcp_table.lookupByIp(victim_ip) != null);
    try std.testing.expect(State.dhcp_table.lookupByClient(.{ .id = victim_id }) != null);
    try std.testing.expectEqual(@as(usize, 0), State.dhcp_table.excluded_ips.items.len);

    // Attack: a different MAC sends DHCPDECLINE while claiming the victim's
    // client identifier and address. A lease is bound to both the client id and
    // the MAC (see DhcpTable.bindOrRenew), so this must be ignored.
    const decline = try DhcpClient.frame(alloc, attacker_mac, .{
        .message_type = 4,
        .xid = 0x0e0f_1011,
        .client_id = victim_id,
        .requested_ip = victim_ip,
        .server_id = lan_ip,
    });
    defer alloc.free(decline);
    try h.inject(.lan, decline);
    _ = h.runAll(.lan);

    // The victim must still own its lease and the address must remain usable.
    try std.testing.expect(State.dhcp_table.lookupByClient(.{ .id = victim_id }) != null);
    try std.testing.expect(State.dhcp_table.lookupByIp(victim_ip) != null);
    try std.testing.expectEqual(@as(usize, 0), State.dhcp_table.excluded_ips.items.len);
}

test "a DHCPDECLINE with a spoofed chaddr from another Ethernet source must be rejected" {
    const alloc = std.testing.allocator;
    var h = try Harness.init(alloc, std.testing.io, .{
        .dhcp_pool = &[_]IPv4{
            .{ 192, 168, 86, 10 },
            .{ 192, 168, 86, 11 },
        },
    });
    defer h.deinit();

    const victim_mac: Mac = .{ 0x02, 0xaa, 0x00, 0x00, 0x00, 0x01 };
    const attacker_mac: Mac = .{ 0x02, 0xbb, 0x00, 0x00, 0x00, 0x02 };
    const victim_id = "victim-client";
    const victim_ip: IPv4 = .{ 192, 168, 86, 10 };
    const lan_ip: IPv4 = .{ 192, 168, 86, 1 };

    const discover = try DhcpClient.frame(alloc, victim_mac, .{
        .message_type = 1,
        .xid = 0x1111_2222,
        .client_id = victim_id,
    });
    defer alloc.free(discover);
    try h.inject(.lan, discover);
    _ = h.runAll(.lan);

    const request = try DhcpClient.frame(alloc, victim_mac, .{
        .message_type = 3,
        .xid = 0x1111_2222,
        .client_id = victim_id,
        .requested_ip = victim_ip,
        .server_id = lan_ip,
    });
    defer alloc.free(request);
    try h.inject(.lan, request);
    _ = h.runAll(.lan);
    try std.testing.expect(State.dhcp_table.lookupByIp(victim_ip) != null);

    // The attacker knows the victim's client id *and* copies its chaddr into
    // the payload, but its Ethernet source address is its own. The handler
    // must reject the DECLINE on the link-layer identity.
    const decline = try DhcpClient.frame(alloc, attacker_mac, .{
        .message_type = 4,
        .xid = 0x3333_4444,
        .client_id = victim_id,
        .requested_ip = victim_ip,
        .server_id = lan_ip,
        .chaddr = victim_mac,
    });
    defer alloc.free(decline);
    try h.inject(.lan, decline);
    _ = h.runAll(.lan);

    try std.testing.expect(State.dhcp_table.lookupByClient(.{ .id = victim_id }) != null);
    try std.testing.expect(State.dhcp_table.lookupByIp(victim_ip) != null);
    try std.testing.expectEqual(@as(usize, 0), State.dhcp_table.excluded_ips.items.len);
}

const wan_lease_ip: IPv4 = .{ 203, 0, 113, 50 };
const wan_gateway_ip: IPv4 = .{ 203, 0, 113, 1 };
const wan_gateway_mac: Mac = .{ 0x02, 0x99, 0x88, 0x77, 0x66, 0x55 };
const lan_client_ip: IPv4 = .{ 192, 168, 86, 42 };
const lan_client_mac: Mac = .{ 0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee };

test "LAN datagrams to loopback, this-network, link-local, or reserved destinations must not be forwarded to the WAN" {
    const alloc = std.testing.allocator;
    const io = std.testing.io;

    var h = try Harness.init(alloc, io, .{ .wan_lease = testWanLease(io) });
    defer h.deinit();
    h.cacheArp(.wan, wan_gateway_ip, wan_gateway_mac);

    // Positive control: an ordinary routable WAN destination must still be
    // forwarded (and NATed) once, so the drop assertions below cannot pass
    // vacuously if LAN->WAN forwarding is broken.
    {
        const udp_bytes = try Packets.udp(alloc, lan_client_ip, .{ 8, 8, 8, 8 }, .{
            .src_port = 40_100,
            .dst_port = 53,
            .payload = "control",
        });
        defer alloc.free(udp_bytes);
        const ip_bytes = try Packets.ipv4(alloc, .{
            .src = lan_client_ip,
            .dst = .{ 8, 8, 8, 8 },
            .protocol = 17,
            .dont_fragment = true,
            .payload = udp_bytes,
        });
        defer alloc.free(ip_bytes);
        const frame = try Packets.eth(alloc, .{
            .dst = RecordingNic.lan_mac,
            .src = lan_client_mac,
            .ethertype = 0x0800,
            .payload = ip_bytes,
        });
        defer alloc.free(frame);

        try h.inject(.lan, frame);
        _ = h.runAll(.lan);

        try std.testing.expectEqual(@as(usize, 1), h.txCount());
        const tx = h.txAt(0);
        try std.testing.expectEqual(IFace.wan, tx.iface);
        const tx_eth = try Ethernet.parse(tx.bytes);
        const tx_ip = try Router.Protocols.IPv4.parse(tx_eth.get(.payload));
        try std.testing.expectEqual(wan_lease_ip, tx_ip.get(.src));
        try std.testing.expectEqual(IPv4{ 8, 8, 8, 8 }, tx_ip.get(.dst));
        try std.testing.expectEqual(@as(u8, 63), tx_ip.get(.ttl));
        try std.testing.expectEqual(@as(usize, 1), State.nat_table.inside.count());
        h.nic.resetLogs();
    }

    // Destinations that can never be valid on the WAN link. RFC 1122 3.2.1.3
    // and RFC 1812 3.3.6 require a router to discard datagrams addressed to
    // the loopback network, "this network" (0/8), and other reserved space;
    // RFC 3927 7 forbids forwarding link-local destinations to another link.
    const forbidden = [_]IPv4{
        .{ 127, 0, 0, 1 }, // loopback
        .{ 0, 0, 0, 0 }, // "this network"
        .{ 169, 254, 1, 1 }, // link-local
        .{ 240, 0, 0, 1 }, // reserved / class E
    };

    for (forbidden, 0..) |dst, i| {
        h.nic.resetLogs();

        const udp_bytes = try Packets.udp(alloc, lan_client_ip, dst, .{
            .src_port = @intCast(40_000 + i),
            .dst_port = 53,
            .payload = "must-not-leave",
        });
        defer alloc.free(udp_bytes);
        const ip_bytes = try Packets.ipv4(alloc, .{
            .src = lan_client_ip,
            .dst = dst,
            .protocol = 17,
            .dont_fragment = true,
            .payload = udp_bytes,
        });
        defer alloc.free(ip_bytes);
        const frame = try Packets.eth(alloc, .{
            .dst = RecordingNic.lan_mac,
            .src = lan_client_mac,
            .ethertype = 0x0800,
            .payload = ip_bytes,
        });
        defer alloc.free(frame);

        try h.inject(.lan, frame);
        _ = h.runAll(.lan);

        // The datagram must be dropped: no WAN transmission at all.
        try std.testing.expectEqual(@as(usize, 0), h.txCount());
        try std.testing.expectEqual(@as(usize, 1), h.dropCount());
    }

    // Dropping the datagrams must not create any additional NAT state.
    try std.testing.expectEqual(@as(usize, 1), State.nat_table.inside.count());
}

test "a NAT mapping only accepts inbound packets from the peer the inside host sent to" {
    const alloc = std.testing.allocator;
    var h = try Harness.init(alloc, std.testing.io, .{
        .wan_lease = testWanLease(std.testing.io),
    });
    defer h.deinit();

    const lease_ip: IPv4 = .{ 203, 0, 113, 50 };
    const gateway_ip: IPv4 = .{ 203, 0, 113, 1 };
    const inside_ip: IPv4 = client_ip; // 192.168.86.42
    const inside_mac = client_mac;
    const query_peer: IPv4 = .{ 8, 8, 8, 8 };
    const other_peer: IPv4 = .{ 6, 6, 6, 6 };
    const inside_port: u16 = 40_000;

    // The router can reach both the inside host and the WAN gateway.
    h.cacheArp(.wan, gateway_ip, gateway_mac);
    h.cacheArp(.lan, inside_ip, inside_mac);

    // Inside host opens a UDP flow to 8.8.8.8:53; the NAT mapping is created.
    const query = try Packets.udp(alloc, inside_ip, query_peer, .{
        .src_port = inside_port,
        .dst_port = 53,
        .payload = "dns-query",
    });
    defer alloc.free(query);
    const query_ip = try Packets.ipv4(alloc, .{
        .src = inside_ip,
        .dst = query_peer,
        .protocol = 17,
        .dont_fragment = true,
        .payload = query,
    });
    defer alloc.free(query_ip);
    const query_frame = try Packets.eth(alloc, .{
        .dst = RecordingNic.lan_mac,
        .src = inside_mac,
        .ethertype = 0x0800,
        .payload = query_ip,
    });
    defer alloc.free(query_frame);

    try h.inject(.lan, query_frame);
    try std.testing.expectEqual(@as(usize, 1), h.runAll(.lan));
    try std.testing.expectEqual(@as(usize, 1), h.txCount());

    // Recover the external port the router chose for this mapping.
    const out_ip = try Router.Protocols.IPv4.parse((try Ethernet.parse(h.txAt(0).bytes)).get(.payload));
    const out_udp = try Router.Protocols.Udp.parse(out_ip.get(.payload), out_ip);
    const outside_port = out_udp.get(.src_port);
    try std.testing.expect(State.nat_table.inboundEntry(.{
        .protocol = .udp,
        .ip = lease_ip,
        .port = outside_port,
    }) != null);

    // Positive control: a reply from the peer the inside host contacted is
    // still delivered, so the drop below is a peer check rather than a
    // blanket WAN-ingress drop.
    {
        const reply = try Packets.udp(alloc, query_peer, lease_ip, .{
            .src_port = 53,
            .dst_port = outside_port,
            .payload = "dns-reply",
        });
        defer alloc.free(reply);
        const reply_ip = try Packets.ipv4(alloc, .{
            .src = query_peer,
            .dst = lease_ip,
            .protocol = 17,
            .dont_fragment = true,
            .payload = reply,
        });
        defer alloc.free(reply_ip);
        const reply_frame = try Packets.eth(alloc, .{
            .dst = RecordingNic.wan_mac,
            .src = gateway_mac,
            .ethertype = 0x0800,
            .payload = reply_ip,
        });
        defer alloc.free(reply_frame);
        try h.inject(.wan, reply_frame);
        try std.testing.expectEqual(@as(usize, 1), h.runAll(.wan));
        try std.testing.expectEqual(@as(usize, 2), h.txCount());
        try std.testing.expectEqual(IFace.lan, h.txAt(1).iface);
        h.nic.resetLogs();
    }

    // An unrelated WAN peer (different address AND port) sends a datagram to
    // the router's external port. The mapping's remote endpoint is 8.8.8.8:53,
    // so this unsolicited packet must not be delivered to the inside host.
    const injected = try Packets.udp(alloc, other_peer, lease_ip, .{
        .src_port = 1234,
        .dst_port = outside_port,
        .payload = "injected",
    });
    defer alloc.free(injected);
    const injected_ip = try Packets.ipv4(alloc, .{
        .src = other_peer,
        .dst = lease_ip,
        .protocol = 17,
        .dont_fragment = true,
        .payload = injected,
    });
    defer alloc.free(injected_ip);
    const injected_frame = try Packets.eth(alloc, .{
        .dst = RecordingNic.wan_mac,
        .src = gateway_mac,
        .ethertype = 0x0800,
        .payload = injected_ip,
    });
    defer alloc.free(injected_frame);

    try h.inject(.wan, injected_frame);
    try std.testing.expectEqual(@as(usize, 1), h.runAll(.wan));

    // No packet may be forwarded to the LAN for this unsolicited peer.
    try std.testing.expectEqual(@as(usize, 0), h.txCount());
    try std.testing.expectEqual(@as(usize, 1), h.dropCount());
}

const conflict_lease_ip: IPv4 = .{ 203, 0, 113, 50 };
const conflict_gateway: IPv4 = .{ 203, 0, 113, 1 };
const conflict_gateway_mac: Mac = .{ 0x02, 0x99, 0x88, 0x77, 0x66, 0x55 };
const conflict_client_ip: IPv4 = .{ 192, 168, 86, 42 };
const conflict_client_mac: Mac = .{ 0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee };
const conflict_other_client_ip: IPv4 = .{ 192, 168, 86, 43 };
const conflict_other_client_mac: Mac = .{ 0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x44 };
const conflict_peer_ip: IPv4 = .{ 8, 8, 8, 8 };
const conflict_other_ip: IPv4 = .{ 198, 51, 100, 99 };
const conflict_client_port: u16 = 40_000;
const conflict_other_client_port: u16 = 40_001;

fn conflictQuotedUdp(
    alloc: std.mem.Allocator,
    src: IPv4,
    dst: IPv4,
    src_port: u16,
    dst_port: u16,
) ![]u8 {
    var header: [8]u8 = .{0} ** 8;
    std.mem.writeInt(u16, header[0..2], src_port, .big);
    std.mem.writeInt(u16, header[2..4], dst_port, .big);
    std.mem.writeInt(u16, header[4..6], 8, .big);
    return Packets.ipv4(alloc, .{
        .src = src,
        .dst = dst,
        .protocol = 17,
        .dont_fragment = true,
        .payload = &header,
    });
}

fn conflictIcmpErrorFrame(
    alloc: std.mem.Allocator,
    iface: IFace,
    eth_src: Mac,
    outer_src: IPv4,
    outer_dst: IPv4,
    icmp_type: u8,
    icmp_code: u8,
    mtu: u16,
    quoted: []const u8,
) ![]u8 {
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(alloc);
    try body.appendSlice(alloc, &.{ 0, 0, @intCast(mtu >> 8), @intCast(mtu & 0xff) });
    try body.appendSlice(alloc, quoted);
    const icmp_bytes = try Packets.icmp(alloc, .{
        .message_type = icmp_type,
        .code = icmp_code,
        .body = body.items,
    });
    defer alloc.free(icmp_bytes);
    const ip_bytes = try Packets.ipv4(alloc, .{
        .src = outer_src,
        .dst = outer_dst,
        .protocol = 1,
        .dont_fragment = true,
        .payload = icmp_bytes,
    });
    defer alloc.free(ip_bytes);
    return Packets.eth(alloc, .{
        .dst = switch (iface) {
            .lan => RecordingNic.lan_mac,
            .wan => RecordingNic.wan_mac,
        },
        .src = eth_src,
        .ethertype = 0x0800,
        .payload = ip_bytes,
    });
}

fn conflictUdpFrame(
    alloc: std.mem.Allocator,
    src_ip: IPv4,
    src_mac: Mac,
    dst_ip: IPv4,
    src_port: u16,
    dst_port: u16,
    payload: []const u8,
) ![]u8 {
    const udp_bytes = try Packets.udp(alloc, src_ip, dst_ip, .{
        .src_port = src_port,
        .dst_port = dst_port,
        .payload = payload,
    });
    defer alloc.free(udp_bytes);
    const ip_bytes = try Packets.ipv4(alloc, .{
        .src = src_ip,
        .dst = dst_ip,
        .protocol = 17,
        .dont_fragment = true,
        .payload = udp_bytes,
    });
    defer alloc.free(ip_bytes);
    return Packets.eth(alloc, .{
        .dst = RecordingNic.lan_mac,
        .src = src_mac,
        .ethertype = 0x0800,
        .payload = ip_bytes,
    });
}

test "ICMP errors quoting a packet outside the sender's flow must not be forwarded" {
    const alloc = std.testing.allocator;
    const io = std.testing.io;

    var h = try Harness.init(alloc, io, .{ .wan_lease = testWanLease(io) });
    defer h.deinit();
    h.cacheArp(.wan, conflict_gateway, conflict_gateway_mac);
    h.cacheArp(.lan, conflict_client_ip, conflict_client_mac);
    h.cacheArp(.lan, conflict_other_client_ip, conflict_other_client_mac);

    // Two independent LAN clients each open one UDP flow:
    //   192.168.86.42:40000 -> 8.8.8.8:53  (public 203.0.113.50:40000)
    //   192.168.86.43:40001 -> 8.8.8.8:53  (public 203.0.113.50:40001)
    {
        const frame_a = try conflictUdpFrame(alloc, conflict_client_ip, conflict_client_mac, conflict_peer_ip, conflict_client_port, 53, "flow-a");
        defer alloc.free(frame_a);
        try h.inject(.lan, frame_a);
        _ = h.runAll(.lan);
        try std.testing.expectEqual(@as(usize, 1), h.txCount());

        const frame_b = try conflictUdpFrame(alloc, conflict_other_client_ip, conflict_other_client_mac, conflict_peer_ip, conflict_other_client_port, 53, "flow-b");
        defer alloc.free(frame_b);
        try h.inject(.lan, frame_b);
        _ = h.runAll(.lan);
        try std.testing.expectEqual(@as(usize, 2), h.txCount());
        h.nic.resetLogs();
    }

    // LAN-origin mirror: client .42 forges an ICMP fragmentation-needed that
    // quotes client .43's flow. It is not .42's packet, so the router must not
    // relay it to 8.8.8.8 on .42's behalf.
    {
        const quoted = try conflictQuotedUdp(alloc, conflict_peer_ip, conflict_other_client_ip, 53, conflict_other_client_port);
        defer alloc.free(quoted);
        const frame = try conflictIcmpErrorFrame(
            alloc,
            .lan,
            conflict_client_mac,
            conflict_client_ip,
            conflict_peer_ip,
            3,
            4,
            1200,
            quoted,
        );
        defer alloc.free(frame);

        try h.inject(.lan, frame);
        _ = h.runAll(.lan);

        try std.testing.expectEqual(@as(usize, 0), h.txCount());
        try std.testing.expectEqual(@as(usize, 1), h.dropCount());
        h.nic.resetLogs();
    }

    // WAN-origin: an ICMP error may quote only the datagram it reports on. This
    // quote has the client's public source (so the (protocol, ip, port) NAT
    // lookup succeeds) but a destination the client never sent anything to, so
    // it cannot belong to any flow the client owns. The router must drop it
    // (RFC 4787 REQ-10) instead of rewriting it and delivering it to the client.
    {
        const quoted = try conflictQuotedUdp(alloc, conflict_lease_ip, conflict_other_ip, conflict_client_port, 53);
        defer alloc.free(quoted);
        const frame = try conflictIcmpErrorFrame(
            alloc,
            .wan,
            conflict_gateway_mac,
            conflict_peer_ip,
            conflict_lease_ip,
            3,
            3,
            0,
            quoted,
        );
        defer alloc.free(frame);

        try h.inject(.wan, frame);
        _ = h.runAll(.wan);

        try std.testing.expectEqual(@as(usize, 0), h.txCount());
        try std.testing.expectEqual(@as(usize, 1), h.dropCount());
        h.nic.resetLogs();
    }

    // Positive control (LAN): the owner of the quoted flow may report an error
    // about it; it is translated to the public identity and sent to the peer.
    {
        const quoted = try conflictQuotedUdp(alloc, conflict_peer_ip, conflict_other_client_ip, 53, conflict_other_client_port);
        defer alloc.free(quoted);
        const frame = try conflictIcmpErrorFrame(
            alloc,
            .lan,
            conflict_other_client_mac,
            conflict_other_client_ip,
            conflict_peer_ip,
            3,
            4,
            1200,
            quoted,
        );
        defer alloc.free(frame);

        try h.inject(.lan, frame);
        _ = h.runAll(.lan);

        try std.testing.expectEqual(@as(usize, 1), h.txCount());
        const tx = h.txAt(0);
        try std.testing.expectEqual(IFace.wan, tx.iface);
        const tx_eth = try Ethernet.parse(tx.bytes);
        const tx_ip = try Router.Protocols.IPv4.parse(tx_eth.get(.payload));
        try std.testing.expectEqual(conflict_lease_ip, tx_ip.get(.src));
        const tx_icmp = try Router.Protocols.ICMPv4.parse(tx_ip.get(.payload));
        const tx_msg = try Router.Protocols.ICMPv4Messages.DestinationUnreachable.parse(tx_icmp);
        const quote = try Router.Protocols.IPv4.parseQuoted(tx_msg.get(.quoted_packet));
        try std.testing.expectEqual(conflict_peer_ip, quote.get(.src));
        try std.testing.expectEqual(conflict_lease_ip, quote.get(.dst));
        try std.testing.expectEqual(
            @as(u16, conflict_other_client_port),
            std.mem.readInt(u16, quote.get(.payload)[2..4], .big),
        );
        h.nic.resetLogs();
    }

    // Positive control (WAN): an ICMP error that quotes the client's real flow
    // (203.0.113.50:40000 -> 8.8.8.8:53) is still translated and delivered.
    {
        const quoted = try conflictQuotedUdp(alloc, conflict_lease_ip, conflict_peer_ip, conflict_client_port, 53);
        defer alloc.free(quoted);
        const frame = try conflictIcmpErrorFrame(
            alloc,
            .wan,
            conflict_gateway_mac,
            conflict_peer_ip,
            conflict_lease_ip,
            3,
            3,
            0,
            quoted,
        );
        defer alloc.free(frame);

        try h.inject(.wan, frame);
        _ = h.runAll(.wan);

        try std.testing.expectEqual(@as(usize, 1), h.txCount());
        const tx = h.txAt(0);
        try std.testing.expectEqual(IFace.lan, tx.iface);
        const tx_eth = try Ethernet.parse(tx.bytes);
        const tx_ip = try Router.Protocols.IPv4.parse(tx_eth.get(.payload));
        try std.testing.expectEqual(conflict_client_ip, tx_ip.get(.dst));
        const tx_icmp = try Router.Protocols.ICMPv4.parse(tx_ip.get(.payload));
        const tx_msg = try Router.Protocols.ICMPv4Messages.DestinationUnreachable.parse(tx_icmp);
        const quote = try Router.Protocols.IPv4.parseQuoted(tx_msg.get(.quoted_packet));
        try std.testing.expectEqual(conflict_client_ip, quote.get(.src));
        try std.testing.expectEqual(conflict_peer_ip, quote.get(.dst));
        try std.testing.expectEqual(
            @as(u16, conflict_client_port),
            std.mem.readInt(u16, quote.get(.payload)[0..2], .big),
        );
    }
}

/// Build a complete LAN->WAN UDP Ethernet frame with correct checksums.
fn lanUdpFrame(
    alloc: std.mem.Allocator,
    src_ip: IPv4,
    src_mac: Mac,
    dst_ip: IPv4,
    src_port: u16,
    dst_port: u16,
) ![]u8 {
    const udp_bytes = try Packets.udp(alloc, src_ip, dst_ip, .{
        .src_port = src_port,
        .dst_port = dst_port,
        .payload = "x",
    });
    defer alloc.free(udp_bytes);
    const ip_bytes = try Packets.ipv4(alloc, .{
        .src = src_ip,
        .dst = dst_ip,
        .protocol = 17,
        .dont_fragment = true,
        .payload = udp_bytes,
    });
    defer alloc.free(ip_bytes);
    return Packets.eth(alloc, .{
        .dst = RecordingNic.lan_mac,
        .src = src_mac,
        .ethertype = 0x0800,
        .payload = ip_bytes,
    });
}

test "one LAN host exhausting the NAT table must not deny NAT service to other hosts" {
    const alloc = std.testing.allocator;
    var h = try Harness.init(alloc, std.testing.io, .{
        .wan_lease = testWanLease(std.testing.io),
        .nat_capacity = 2,
    });
    defer h.deinit();

    const gateway_ip: IPv4 = .{ 203, 0, 113, 1 };
    const remote_ip: IPv4 = .{ 8, 8, 8, 8 };
    const attacker_ip: IPv4 = .{ 192, 168, 86, 42 };
    const victim_ip: IPv4 = .{ 192, 168, 86, 43 };
    const attacker_mac: Mac = .{ 0x02, 0xaa, 0x00, 0x00, 0x00, 0x01 };
    const victim_mac: Mac = .{ 0x02, 0xbb, 0x00, 0x00, 0x00, 0x02 };
    h.cacheArp(.wan, gateway_ip, gateway_mac);

    // A single LAN host opens as many flows as the table can hold.
    for ([_]u16{ 40_000, 40_001 }) |src_port| {
        const frame = try lanUdpFrame(alloc, attacker_ip, attacker_mac, remote_ip, src_port, 53);
        defer alloc.free(frame);
        try h.inject(.lan, frame);
        _ = h.runAll(.lan);
    }
    try std.testing.expectEqual(@as(usize, 2), h.txCount());
    try std.testing.expectEqual(@as(usize, 0), h.errorCount());

    // A different, independent LAN host opens its own flow. Filling the table
    // from one host must not make the router deny everyone else.
    const victim_frame = try lanUdpFrame(alloc, victim_ip, victim_mac, remote_ip, 50_000, 53);
    defer alloc.free(victim_frame);
    try h.inject(.lan, victim_frame);
    _ = h.runAll(.lan);

    try std.testing.expectEqual(@as(usize, 3), h.txCount());
    try std.testing.expectEqual(@as(usize, 0), h.errorCount());
    try std.testing.expectEqual(@as(usize, 0), h.dropCount());
}

const echo_lease_ip: IPv4 = .{ 203, 0, 113, 50 };
const echo_gateway_mac: Mac = .{ 0x02, 0x99, 0x88, 0x77, 0x66, 0x55 };
const echo_broadcast_mac: Mac = .{0xff} ** 6;

fn echoEchoRequestFrame(
    alloc: std.mem.Allocator,
    src_mac: Mac,
    src_ip: IPv4,
    data: []const u8,
) ![]u8 {
    const icmp_bytes = try Packets.echo(alloc, .{
        .message_type = 8,
        .identifier = 0x5151,
        .sequence_number = 1,
        .data = data,
    });
    defer alloc.free(icmp_bytes);
    const ip_bytes = try Packets.ipv4(alloc, .{
        .src = src_ip,
        .dst = echo_lease_ip,
        .protocol = 1,
        .dont_fragment = true,
        .payload = icmp_bytes,
    });
    defer alloc.free(ip_bytes);
    return Packets.eth(alloc, .{
        .dst = RecordingNic.wan_mac,
        .src = src_mac,
        .ethertype = 0x0800,
        .payload = ip_bytes,
    });
}

test "ICMP echo requests from broadcast, multicast, or martian sources must not be answered" {
    const alloc = std.testing.allocator;
    const io = std.testing.io;

    var h = try Harness.init(alloc, io, .{ .wan_lease = testWanLease(io) });
    defer h.deinit();

    // A reply is an IP datagram back to the request's source address and the
    // request's Ethernet source address. If either source is a group (or
    // otherwise non-routable) address the reply itself is a broadcast/
    // multicast transmission - a reflector an attacker can aim at an ISP
    // segment - and an Ethernet source with the I/G bit set is invalid.
    const forbidden = [_]struct { src_mac: Mac, src_ip: IPv4 }{
        .{ .src_mac = echo_gateway_mac, .src_ip = .{ 255, 255, 255, 255 } }, // limited broadcast source IP
        .{ .src_mac = echo_gateway_mac, .src_ip = .{ 224, 0, 0, 1 } }, // multicast source IP
        .{ .src_mac = echo_gateway_mac, .src_ip = .{ 0, 0, 0, 0 } }, // this-network source IP
        .{ .src_mac = echo_broadcast_mac, .src_ip = .{ 8, 8, 8, 8 } }, // broadcast source MAC
    };

    for (forbidden) |case| {
        h.nic.resetLogs();
        const frame = try echoEchoRequestFrame(alloc, case.src_mac, case.src_ip, "reflect-me");
        defer alloc.free(frame);

        try h.inject(.wan, frame);
        _ = h.runAll(.wan);

        // No reply may be emitted for a non-unicast/invalid source.
        try std.testing.expectEqual(@as(usize, 0), h.txCount());
        try std.testing.expectEqual(@as(usize, 1), h.dropCount());
    }

    // Positive control: a normal unicast request to the router's WAN address
    // must still be answered on the WAN interface.
    {
        h.nic.resetLogs();
        const frame = try echoEchoRequestFrame(alloc, echo_gateway_mac, .{ 8, 8, 8, 8 }, "ping");
        defer alloc.free(frame);
        try h.inject(.wan, frame);
        _ = h.runAll(.wan);

        try std.testing.expectEqual(@as(usize, 1), h.txCount());
        const tx = h.txAt(0);
        try std.testing.expectEqual(IFace.wan, tx.iface);
        const tx_eth = try Ethernet.parse(tx.bytes);
        try std.testing.expectEqual(echo_gateway_mac, tx_eth.get(.dst_mac));
        const tx_ip = try Router.Protocols.IPv4.parse(tx_eth.get(.payload));
        try std.testing.expectEqual(IPv4{ 8, 8, 8, 8 }, tx_ip.get(.dst));
        const tx_icmp = try Router.Protocols.ICMPv4.parse(tx_ip.get(.payload));
        try std.testing.expectEqual(Router.Protocols.ICMPv4.MessageType.echo_reply, tx_icmp.get(.message_type));
    }
}

test "an ICMPv4 message with an invalid zero checksum must not be acted on" {
    const alloc = std.testing.allocator;
    var h = try Harness.init(alloc, std.testing.io, .{});
    defer h.deinit();

    const lan_ip: IPv4 = .{ 192, 168, 86, 1 };
    const echo_body = struct {
        fn build(alloc_: std.mem.Allocator, checksum: ?u16) ![]u8 {
            return Packets.echo(alloc_, .{
                .identifier = 0x1234,
                .sequence_number = 1,
                .data = "zero-checksum-bypass",
                .checksum = checksum,
            });
        }
    };

    // Positive control: the same echo request with a valid checksum is answered.
    const valid_icmp = try echo_body.build(alloc, null);
    defer alloc.free(valid_icmp);
    const valid_ip = try Packets.ipv4(alloc, .{
        .src = client_ip,
        .dst = lan_ip,
        .protocol = 1,
        .dont_fragment = true,
        .payload = valid_icmp,
    });
    defer alloc.free(valid_ip);
    const valid_frame = try Packets.eth(alloc, .{
        .dst = RecordingNic.lan_mac,
        .src = client_mac,
        .ethertype = 0x0800,
        .payload = valid_ip,
    });
    defer alloc.free(valid_frame);
    try h.inject(.lan, valid_frame);
    try std.testing.expectEqual(@as(usize, 1), h.runAll(.lan));
    try std.testing.expectEqual(@as(usize, 1), h.txCount());

    // An ICMPv4 checksum of zero is not a "checksum disabled" marker: the
    // checksum is the one's-complement sum of the whole message, so a message
    // whose computed checksum is not zero but whose field is zero is corrupt
    // and must be dropped. The router must not answer it.
    h.nic.resetLogs();
    const bad_icmp = try echo_body.build(alloc, 0);
    defer alloc.free(bad_icmp);
    const bad_ip = try Packets.ipv4(alloc, .{
        .src = client_ip,
        .dst = lan_ip,
        .protocol = 1,
        .dont_fragment = true,
        .payload = bad_icmp,
    });
    defer alloc.free(bad_ip);
    const bad_frame = try Packets.eth(alloc, .{
        .dst = RecordingNic.lan_mac,
        .src = client_mac,
        .ethertype = 0x0800,
        .payload = bad_ip,
    });
    defer alloc.free(bad_frame);
    try h.inject(.lan, bad_frame);
    try std.testing.expectEqual(@as(usize, 1), h.runAll(.lan));

    try std.testing.expectEqual(@as(usize, 0), h.txCount());
}

const group_lease_ip: IPv4 = .{ 203, 0, 113, 50 };
const group_gateway_ip: IPv4 = .{ 203, 0, 113, 1 };
const group_gateway_mac: Mac = .{ 0x02, 0x99, 0x88, 0x77, 0x66, 0x55 };
const group_client_ip: IPv4 = .{ 192, 168, 86, 42 };
const group_client_mac: Mac = .{ 0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee };
const group_group_mac: Mac = .{0xff} ** 6;

test "ARP must not learn a group sender MAC as a neighbour" {
    const alloc = std.testing.allocator;
    const io = std.testing.io;

    var h = try Harness.init(alloc, io, .{ .wan_lease = testWanLease(io) });
    defer h.deinit();
    // The real gateway is already resolved; forwarding works.
    h.cacheArp(.wan, group_gateway_ip, group_gateway_mac);
    h.cacheArp(.lan, group_client_ip, group_client_mac);

    // An ARP reply that names the gateway's IP but a group (broadcast) sender
    // hardware address. IEEE 802.3 requires the source address field to be a
    // unicast address, and caching a group MAC as a next hop means every
    // forwarded frame is sent to that group address.
    {
        const arp_bytes = try Packets.arp(alloc, .{
            .opcode = 2,
            .sender_mac = group_group_mac,
            .sender_ip = group_gateway_ip,
            .target_mac = RecordingNic.wan_mac,
            .target_ip = group_lease_ip,
        });
        defer alloc.free(arp_bytes);
        const frame = try Packets.eth(alloc, .{
            .dst = RecordingNic.wan_mac,
            .src = group_gateway_mac,
            .ethertype = 0x0806,
            .payload = arp_bytes,
        });
        defer alloc.free(frame);
        try h.inject(.wan, frame);
        _ = h.runAll(.wan);
        h.nic.resetLogs();
    }

    // The forged reply must be ignored: the gateway keeps its unicast MAC.
    try std.testing.expectEqual(group_gateway_mac, State.wan_arp_table.lookup(group_gateway_ip).?);

    // Consequently a forwarded datagram must still be sent to the gateway's
    // real unicast MAC, not flooded to the whole WAN segment.
    const udp_bytes = try Packets.udp(alloc, group_client_ip, .{ 8, 8, 8, 8 }, .{
        .src_port = 40_000,
        .dst_port = 53,
        .payload = "forward-me",
    });
    defer alloc.free(udp_bytes);
    const ip_bytes = try Packets.ipv4(alloc, .{
        .src = group_client_ip,
        .dst = .{ 8, 8, 8, 8 },
        .protocol = 17,
        .dont_fragment = true,
        .payload = udp_bytes,
    });
    defer alloc.free(ip_bytes);
    const frame = try Packets.eth(alloc, .{
        .dst = RecordingNic.lan_mac,
        .src = group_client_mac,
        .ethertype = 0x0800,
        .payload = ip_bytes,
    });
    defer alloc.free(frame);
    try h.inject(.lan, frame);
    _ = h.runAll(.lan);

    try std.testing.expectEqual(@as(usize, 1), h.txCount());
    const tx = h.txAt(0);
    try std.testing.expectEqual(IFace.wan, tx.iface);
    const tx_eth = try Ethernet.parse(tx.bytes);
    try std.testing.expectEqual(group_gateway_mac, tx_eth.get(.dst_mac));
}

test "an unsolicited ARP reply must not overwrite the cached gateway mapping" {
    const alloc = std.testing.allocator;
    var h = try Harness.init(alloc, std.testing.io, .{
        .wan_lease = testWanLease(std.testing.io),
    });
    defer h.deinit();

    const lease_ip: IPv4 = .{ 203, 0, 113, 50 };
    const gateway_ip: IPv4 = .{ 203, 0, 113, 1 };
    const remote_ip: IPv4 = .{ 8, 8, 8, 8 };
    const attacker_mac: Mac = .{ 0x02, 0x66, 0x66, 0x66, 0x66, 0x66 };

    // The router has learned the real gateway MAC (e.g. from a solicited reply).
    h.cacheArp(.wan, gateway_ip, gateway_mac);

    const udp_bytes = try Packets.udp(alloc, client_ip, remote_ip, .{
        .src_port = 40_000,
        .dst_port = 53,
        .payload = "one",
    });
    defer alloc.free(udp_bytes);
    const ip_bytes = try Packets.ipv4(alloc, .{
        .src = client_ip,
        .dst = remote_ip,
        .protocol = 17,
        .dont_fragment = true,
        .payload = udp_bytes,
    });
    defer alloc.free(ip_bytes);
    const frame = try Packets.eth(alloc, .{
        .dst = RecordingNic.lan_mac,
        .src = client_mac,
        .ethertype = 0x0800,
        .payload = ip_bytes,
    });
    defer alloc.free(frame);

    try h.inject(.lan, frame);
    _ = h.runAll(.lan);
    try std.testing.expectEqual(@as(usize, 1), h.txCount());
    try std.testing.expectEqual(gateway_mac, (try Ethernet.parse(h.txAt(0).bytes)).get(.dst_mac));

    // An off-path WAN host sends an unsolicited ARP reply binding the gateway's
    // IP to its own MAC. The router never asked for this mapping.
    const spoofed_arp = try Packets.arp(alloc, .{
        .opcode = 2, // reply
        .sender_mac = attacker_mac,
        .sender_ip = gateway_ip,
        .target_mac = RecordingNic.wan_mac,
        .target_ip = lease_ip,
    });
    defer alloc.free(spoofed_arp);
    const spoofed_frame = try Packets.eth(alloc, .{
        .dst = RecordingNic.wan_mac,
        .src = attacker_mac,
        .ethertype = 0x0806,
        .payload = spoofed_arp,
    });
    defer alloc.free(spoofed_frame);

    try h.inject(.wan, spoofed_frame);
    _ = h.runAll(.wan);

    // The legitimate gateway mapping must be retained...
    try std.testing.expectEqual(gateway_mac, State.wan_arp_table.lookup(gateway_ip).?);

    // ...so subsequent WAN traffic still goes to the real gateway, not the attacker.
    try h.inject(.lan, frame);
    _ = h.runAll(.lan);
    try std.testing.expectEqual(@as(usize, 2), h.txCount());
    try std.testing.expectEqual(gateway_mac, (try Ethernet.parse(h.txAt(1).bytes)).get(.dst_mac));
}

test "a fragmented ICMPv4 echo must not be answered from its first fragment" {
    const alloc = std.testing.allocator;
    var h = try Harness.init(alloc, std.testing.io, .{});
    defer h.deinit();

    // 8-byte ICMP header + 8 bytes of data = 16 bytes, a whole number of
    // 8-byte fragment units, so an MF=1 first fragment is well-formed IPv4.
    const icmp_bytes = try Packets.echo(alloc, .{
        .identifier = 0x5150,
        .sequence_number = 9,
        .data = "fragping",
    });
    defer alloc.free(icmp_bytes);

    const buildFrame = struct {
        fn build(alloc_: std.mem.Allocator, icmp: []const u8, more_fragments: bool) ![]u8 {
            const ip_bytes = try Packets.ipv4(alloc_, .{
                .src = client_ip,
                .dst = .{ 192, 168, 86, 1 },
                .protocol = 1,
                .dont_fragment = false,
                .more_fragments = more_fragments,
                .fragment_offset = 0,
                .identification = 0x7777,
                .payload = icmp,
            });
            defer alloc_.free(ip_bytes);
            return Packets.eth(alloc_, .{
                .dst = RecordingNic.lan_mac,
                .src = client_mac,
                .ethertype = 0x0800,
                .payload = ip_bytes,
            });
        }
    };

    // Positive control: the same complete echo request is answered.
    const complete = try buildFrame.build(alloc, icmp_bytes, false);
    defer alloc.free(complete);
    try h.inject(.lan, complete);
    _ = h.runAll(.lan);
    try std.testing.expectEqual(@as(usize, 1), h.txCount());
    {
        const tx_eth = try Ethernet.parse(h.txAt(0).bytes);
        const tx_ip = try Router.Protocols.IPv4.parse(tx_eth.get(.payload));
        const tx_icmp = try Router.Protocols.ICMPv4.parse(tx_ip.get(.payload));
        try std.testing.expectEqual(Router.Protocols.ICMPv4.MessageType.echo_reply, tx_icmp.get(.message_type));
        try std.testing.expect(!tx_ip.get(.more_fragments));
    }

    // A first fragment (MF=1) of an echo request is not a complete ICMP
    // message. The router must not treat its bytes as the whole message and
    // answer it, and it must never emit a *fragmented* echo reply generated
    // from a single fragment (receivers will wait for fragments that never
    // arrive; the fragment also carries attacker-chosen payload/ID).
    h.nic.resetLogs();
    const fragmented = try buildFrame.build(alloc, icmp_bytes, true);
    defer alloc.free(fragmented);
    try h.inject(.lan, fragmented);
    try std.testing.expectEqual(@as(usize, 1), h.runAll(.lan));

    // Safe: no reply, or a complete (non-fragmented) reply after reassembly.
    if (h.lastTx()) |tx| {
        const tx_eth = try Ethernet.parse(tx.bytes);
        const tx_ip = try Router.Protocols.IPv4.parse(tx_eth.get(.payload));
        try std.testing.expect(!tx_ip.get(.more_fragments));
        try std.testing.expectEqual(@as(u13, 0), tx_ip.get(.fragment_offset));
    }
}

const spoof_lease_ip: IPv4 = .{ 203, 0, 113, 50 };
const spoof_gateway: IPv4 = .{ 203, 0, 113, 1 };
const spoof_gateway_mac: Mac = .{ 0x02, 0x99, 0x88, 0x77, 0x66, 0x55 };
const spoof_client_ip: IPv4 = .{ 192, 168, 86, 42 };
const spoof_client_mac: Mac = .{ 0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee };
const spoof_remote_ip: IPv4 = .{ 8, 8, 8, 8 };

test "WAN ingress datagrams with LAN-side or martian sources must be dropped" {
    const alloc = std.testing.allocator;
    const io = std.testing.io;

    var h = try Harness.init(alloc, io, .{
        .wan_lease = testWanLease(io),
        // full-cone isolates source validation from the NAT peer filter.
        .nat_filtering_mode = .full_cone,
    });
    defer h.deinit();
    h.cacheArp(.wan, spoof_gateway, spoof_gateway_mac);
    h.cacheArp(.lan, spoof_client_ip, spoof_client_mac);

    // The LAN client opens a UDP flow, creating an inbound NAT mapping whose
    // public port is 40_000 on 203.0.113.50.
    {
        const udp_bytes = try Packets.udp(alloc, spoof_client_ip, spoof_remote_ip, .{
            .src_port = 40_000,
            .dst_port = 53,
            .payload = "open-flow",
        });
        defer alloc.free(udp_bytes);
        const ip_bytes = try Packets.ipv4(alloc, .{
            .src = spoof_client_ip,
            .dst = spoof_remote_ip,
            .protocol = 17,
            .dont_fragment = true,
            .payload = udp_bytes,
        });
        defer alloc.free(ip_bytes);
        const frame = try Packets.eth(alloc, .{
            .dst = RecordingNic.lan_mac,
            .src = spoof_client_mac,
            .ethertype = 0x0800,
            .payload = ip_bytes,
        });
        defer alloc.free(frame);
        try h.inject(.lan, frame);
        _ = h.runAll(.lan);
        try std.testing.expectEqual(@as(usize, 1), h.txCount());
        h.nic.resetLogs();
    }

    // Positive control: a legitimate reply from the contacted peer is still
    // delivered, so the drop below is source validation, not a blanket WAN drop.
    {
        const reply = try Packets.udp(alloc, spoof_remote_ip, spoof_lease_ip, .{
            .src_port = 53,
            .dst_port = 40_000,
            .payload = "legitimate-reply",
        });
        defer alloc.free(reply);
        const reply_ip = try Packets.ipv4(alloc, .{
            .src = spoof_remote_ip,
            .dst = spoof_lease_ip,
            .protocol = 17,
            .dont_fragment = true,
            .payload = reply,
        });
        defer alloc.free(reply_ip);
        const reply_frame = try Packets.eth(alloc, .{
            .dst = RecordingNic.wan_mac,
            .src = spoof_gateway_mac,
            .ethertype = 0x0800,
            .payload = reply_ip,
        });
        defer alloc.free(reply_frame);
        try h.inject(.wan, reply_frame);
        _ = h.runAll(.wan);
        try std.testing.expectEqual(@as(usize, 1), h.txCount());
        try std.testing.expectEqual(IFace.lan, h.txAt(0).iface);
        h.nic.resetLogs();
    }

    // A source address in any of these ranges cannot legitimately arrive from
    // the WAN: the LAN subnet is not routed over the WAN, loopback, "this
    // network", link-local, multicast and broadcast sources are never valid
    // off-link. Forwarding such a datagram to a LAN client lets a WAN attacker
    // impersonate the LAN gateway (192.168.86.1) or a LAN peer.
    const spoofed_sources = [_]IPv4{
        .{ 192, 168, 86, 1 }, // the LAN gateway / router's own LAN address
        .{ 192, 168, 86, 42 }, // the LAN client's own address
        .{ 127, 0, 0, 1 }, // loopback
        .{ 0, 0, 0, 0 }, // "this network"
        .{ 169, 254, 1, 1 }, // link-local
        .{ 224, 0, 0, 1 }, // multicast
        .{ 255, 255, 255, 255 }, // limited broadcast
    };

    for (spoofed_sources) |src| {
        h.nic.resetLogs();

        const udp_bytes = try Packets.udp(alloc, src, spoof_lease_ip, .{
            .src_port = 53,
            .dst_port = 40_000,
            .payload = "spoofed-reply",
        });
        defer alloc.free(udp_bytes);
        const ip_bytes = try Packets.ipv4(alloc, .{
            .src = src,
            .dst = spoof_lease_ip,
            .protocol = 17,
            .dont_fragment = true,
            .payload = udp_bytes,
        });
        defer alloc.free(ip_bytes);
        const frame = try Packets.eth(alloc, .{
            .dst = RecordingNic.wan_mac,
            .src = spoof_gateway_mac,
            .ethertype = 0x0800,
            .payload = ip_bytes,
        });
        defer alloc.free(frame);

        try h.inject(.wan, frame);
        _ = h.runAll(.wan);

        // The spoofed datagram must be dropped, not delivered to the LAN client.
        try std.testing.expectEqual(@as(usize, 0), h.txCount());
        try std.testing.expectEqual(@as(usize, 1), h.dropCount());
    }
}

fn sumNetworkWords(sum_in: u64, bytes: []const u8) u64 {
    var sum = sum_in;
    var i: usize = 0;
    while (i + 1 < bytes.len) : (i += 2) {
        sum += (@as(u16, bytes[i]) << 8) | bytes[i + 1];
    }
    if (i < bytes.len) sum += @as(u16, bytes[i]) << 8;
    return sum;
}

fn udpChecksumWithPseudoLength(
    src: IPv4,
    dst: IPv4,
    udp_bytes: []const u8,
    pseudo_length: u16,
) u16 {
    var sum: u64 = 0;
    sum = sumNetworkWords(sum, &src);
    sum = sumNetworkWords(sum, &dst);
    sum += 17; // protocol
    sum += pseudo_length;
    sum = sumNetworkWords(sum, udp_bytes);
    while (sum >> 16 != 0) sum = (sum & 0xffff) + (sum >> 16);
    return ~@as(u16, @intCast(sum));
}

test "UDP checksum must be validated over the UDP length, not the IPv4 payload length" {
    const alloc = std.testing.allocator;
    var h = try Harness.init(alloc, std.testing.io, .{
        .wan_lease = testWanLease(std.testing.io),
    });
    defer h.deinit();
    h.cacheArp(.wan, .{ 203, 0, 113, 1 }, gateway_mac);

    // Positive control: UDP length equals the IPv4 payload length and the
    // checksum is computed over that length, so it is forwarded.
    const good_udp = try Packets.udp(alloc, client_ip, .{ 8, 8, 8, 8 }, .{
        .src_port = 40_000,
        .dst_port = 53,
        .payload = "abcd",
    });
    defer alloc.free(good_udp);
    const good_ip = try Packets.ipv4(alloc, .{
        .src = client_ip,
        .dst = .{ 8, 8, 8, 8 },
        .protocol = 17,
        .dont_fragment = true,
        .payload = good_udp,
    });
    defer alloc.free(good_ip);
    const good_frame = try Packets.eth(alloc, .{
        .dst = RecordingNic.lan_mac,
        .src = client_mac,
        .ethertype = 0x0800,
        .payload = good_ip,
    });
    defer alloc.free(good_frame);
    try h.inject(.lan, good_frame);
    try std.testing.expectEqual(@as(usize, 1), h.runAll(.lan));
    try std.testing.expectEqual(@as(usize, 1), h.txCount());

    // RFC 768 checksums the pseudo-header's Length field from the UDP length
    // field. The router instead uses the whole IPv4 payload length, so a UDP
    // datagram whose length field is 8 while the IP payload is 12 (four
    // trailing bytes) accepts a checksum that no RFC 768 endpoint would accept.
    // Such a corrupt datagram must be dropped and must not create NAT state.
    h.nic.resetLogs();
    const bad_udp = try Packets.udp(alloc, client_ip, .{ 8, 8, 8, 8 }, .{
        .src_port = 40_001,
        .dst_port = 53,
        .length = 8,
        .checksum = 0,
        .payload = &.{},
    });
    defer alloc.free(bad_udp);
    var bad_datagram: [12]u8 = undefined;
    @memcpy(bad_datagram[0..8], bad_udp);
    @memset(bad_datagram[8..], 0xaa);
    // Checksum computed with the router's bogus pseudo-header length (12).
    const bogus = udpChecksumWithPseudoLength(client_ip, .{ 8, 8, 8, 8 }, bad_datagram[0..8], 12);
    std.mem.writeInt(u16, bad_datagram[6..8], bogus, .big);

    const bad_ip = try Packets.ipv4(alloc, .{
        .src = client_ip,
        .dst = .{ 8, 8, 8, 8 },
        .protocol = 17,
        .dont_fragment = true,
        .payload = &bad_datagram,
    });
    defer alloc.free(bad_ip);
    const bad_frame = try Packets.eth(alloc, .{
        .dst = RecordingNic.lan_mac,
        .src = client_mac,
        .ethertype = 0x0800,
        .payload = bad_ip,
    });
    defer alloc.free(bad_frame);
    try h.inject(.lan, bad_frame);
    try std.testing.expectEqual(@as(usize, 1), h.runAll(.lan));

    try std.testing.expectEqual(@as(usize, 0), h.txCount());
    try std.testing.expect(State.nat_table.inboundEntry(.{
        .protocol = .udp,
        .ip = .{ 203, 0, 113, 50 },
        .port = 40_001,
    }) == null);
}

test "NAT mappings for a LAN address are invalidated when its DHCP lease is released" {
    const alloc = std.testing.allocator;
    var h = try Harness.init(alloc, std.testing.io, .{
        .wan_lease = testWanLease(std.testing.io),
        .dhcp_pool = &[_]IPv4{.{ 192, 168, 86, 10 }},
    });
    defer h.deinit();

    const lease_ip: IPv4 = .{ 203, 0, 113, 50 };
    const gateway_ip: IPv4 = .{ 203, 0, 113, 1 };
    const remote_ip: IPv4 = .{ 8, 8, 8, 8 };
    const leased_ip: IPv4 = .{ 192, 168, 86, 10 };
    const victim_mac: Mac = .{ 0x02, 0xaa, 0x00, 0x00, 0x00, 0x01 };
    const attacker_mac: Mac = .{ 0x02, 0xbb, 0x00, 0x00, 0x00, 0x02 };
    const victim_id = "victim";
    const attacker_id = "attacker";
    const inside_port: u16 = 40_000;

    h.cacheArp(.wan, gateway_ip, gateway_mac);

    // Victim obtains the only address in the pool.
    const discover = try DhcpClient.frame(alloc, victim_mac, .{
        .message_type = 1,
        .xid = 0x0101_0101,
        .client_id = victim_id,
    });
    defer alloc.free(discover);
    try h.inject(.lan, discover);
    _ = h.runAll(.lan);
    const request = try DhcpClient.frame(alloc, victim_mac, .{
        .message_type = 3,
        .xid = 0x0101_0101,
        .client_id = victim_id,
        .requested_ip = leased_ip,
        .server_id = .{ 192, 168, 86, 1 },
    });
    defer alloc.free(request);
    try h.inject(.lan, request);
    _ = h.runAll(.lan);
    try std.testing.expect(State.dhcp_table.lookupByIp(leased_ip) != null);

    // Victim opens an outbound UDP flow through NAT.
    h.nic.resetLogs();
    const query = try lanUdpFrame(alloc, leased_ip, victim_mac, remote_ip, inside_port, 53);
    defer alloc.free(query);
    try h.inject(.lan, query);
    _ = h.runAll(.lan);
    try std.testing.expectEqual(@as(usize, 1), h.txCount());
    const out_ip = try Router.Protocols.IPv4.parse((try Ethernet.parse(h.txAt(0).bytes)).get(.payload));
    const out_udp = try Router.Protocols.Udp.parse(out_ip.get(.payload), out_ip);
    const outside_port = out_udp.get(.src_port);

    // Victim releases the lease. The address goes back to the free pool.
    const release = try DhcpClient.frame(alloc, victim_mac, .{
        .message_type = 7,
        .xid = 0x0202_0202,
        .ciaddr = leased_ip,
        .client_id = victim_id,
    });
    defer alloc.free(release);
    try h.inject(.lan, release);
    _ = h.runAll(.lan);
    try std.testing.expect(State.dhcp_table.lookupByIp(leased_ip) == null);

    // The released address must not keep forwarding state from its previous
    // owner: the NAT mapping (and hence its inbound traffic) must be gone.
    try std.testing.expect(State.nat_table.inboundEntry(.{
        .protocol = .udp,
        .ip = lease_ip,
        .port = outside_port,
    }) == null);

    // Another client takes over the same address.
    const attacker_discover = try DhcpClient.frame(alloc, attacker_mac, .{
        .message_type = 1,
        .xid = 0x0303_0303,
        .client_id = attacker_id,
    });
    defer alloc.free(attacker_discover);
    try h.inject(.lan, attacker_discover);
    _ = h.runAll(.lan);
    const attacker_request = try DhcpClient.frame(alloc, attacker_mac, .{
        .message_type = 3,
        .xid = 0x0303_0303,
        .client_id = attacker_id,
        .requested_ip = leased_ip,
        .server_id = .{ 192, 168, 86, 1 },
    });
    defer alloc.free(attacker_request);
    try h.inject(.lan, attacker_request);
    _ = h.runAll(.lan);
    try std.testing.expect(State.dhcp_table.lookupByIp(leased_ip) != null);

    // The remote peer replies to the victim's old mapping. If the mapping
    // survived the lease handover, the reply is delivered to the attacker.
    h.cacheArp(.lan, leased_ip, attacker_mac);
    h.nic.resetLogs();
    const reply_udp = try Packets.udp(alloc, remote_ip, lease_ip, .{
        .src_port = 53,
        .dst_port = outside_port,
        .payload = "dns-response",
    });
    defer alloc.free(reply_udp);
    const reply_ip = try Packets.ipv4(alloc, .{
        .src = remote_ip,
        .dst = lease_ip,
        .protocol = 17,
        .dont_fragment = true,
        .payload = reply_udp,
    });
    defer alloc.free(reply_ip);
    const reply_frame = try Packets.eth(alloc, .{
        .dst = RecordingNic.wan_mac,
        .src = gateway_mac,
        .ethertype = 0x0800,
        .payload = reply_ip,
    });
    defer alloc.free(reply_frame);
    try h.inject(.wan, reply_frame);
    _ = h.runAll(.wan);

    // Nothing from the previous lease holder's mapping may reach the LAN.
    try std.testing.expectEqual(@as(usize, 0), h.txCount());
}

const vlan_lease_ip: IPv4 = .{ 203, 0, 113, 50 };
const vlan_gateway: IPv4 = .{ 203, 0, 113, 1 };
const vlan_gateway_mac: Mac = .{ 0x02, 0x99, 0x88, 0x77, 0x66, 0x55 };
const vlan_client_ip: IPv4 = .{ 192, 168, 86, 42 };
const vlan_client_mac: Mac = .{ 0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee };
const vlan_remote_ip: IPv4 = .{ 8, 8, 8, 8 };

test "ingress 802.1Q tags must not be carried across interfaces when forwarding" {
    const alloc = std.testing.allocator;
    const io = std.testing.io;

    var h = try Harness.init(alloc, io, .{ .wan_lease = testWanLease(io) });
    defer h.deinit();
    h.cacheArp(.wan, vlan_gateway, vlan_gateway_mac);
    h.cacheArp(.lan, vlan_client_ip, vlan_client_mac);

    // Positive control: an ordinary untagged LAN datagram is forwarded to the
    // WAN with no VLAN tag, and creates the NAT mapping used below.
    {
        const udp_bytes = try Packets.udp(alloc, vlan_client_ip, vlan_remote_ip, .{
            .src_port = 40_000,
            .dst_port = 53,
            .payload = "untagged",
        });
        defer alloc.free(udp_bytes);
        const ip_bytes = try Packets.ipv4(alloc, .{
            .src = vlan_client_ip,
            .dst = vlan_remote_ip,
            .protocol = 17,
            .dont_fragment = true,
            .payload = udp_bytes,
        });
        defer alloc.free(ip_bytes);
        const frame = try Packets.eth(alloc, .{
            .dst = RecordingNic.lan_mac,
            .src = vlan_client_mac,
            .ethertype = 0x0800,
            .payload = ip_bytes,
        });
        defer alloc.free(frame);
        try h.inject(.lan, frame);
        _ = h.runAll(.lan);

        try std.testing.expectEqual(@as(usize, 1), h.txCount());
        const tx = h.txAt(0);
        try std.testing.expectEqual(IFace.wan, tx.iface);
        const tx_eth = try Ethernet.parse(tx.bytes);
        try std.testing.expectEqual(@as(usize, 0), tx_eth.get(.vlan_tags).len);
        h.nic.resetLogs();
    }

    // A LAN client tags a datagram with VLAN 100. That tag is meaningful only
    // on the LAN L2 domain; the WAN link has its own (ISP) VLAN space. The
    // forwarded frame must not carry the client's tag onto the WAN (dropping
    // tagged frames is also acceptable - the assertion only requires that the
    // tag never crosses the interface).
    {
        const udp_bytes = try Packets.udp(alloc, vlan_client_ip, vlan_remote_ip, .{
            .src_port = 40_001,
            .dst_port = 53,
            .payload = "tagged",
        });
        defer alloc.free(udp_bytes);
        const ip_bytes = try Packets.ipv4(alloc, .{
            .src = vlan_client_ip,
            .dst = vlan_remote_ip,
            .protocol = 17,
            .dont_fragment = true,
            .payload = udp_bytes,
        });
        defer alloc.free(ip_bytes);
        const frame = try Packets.eth(alloc, .{
            .dst = RecordingNic.lan_mac,
            .src = vlan_client_mac,
            .vlan_tags = &.{.{ .vid = 100 }},
            .ethertype = 0x0800,
            .payload = ip_bytes,
        });
        defer alloc.free(frame);
        try h.inject(.lan, frame);
        _ = h.runAll(.lan);

        if (h.txCount() > 0) {
            const tx = h.txAt(0);
            try std.testing.expectEqual(IFace.wan, tx.iface);
            const tx_eth = try Ethernet.parse(tx.bytes);
            try std.testing.expectEqual(@as(usize, 0), tx_eth.get(.vlan_tags).len);
        }
        h.nic.resetLogs();
    }

    // Same leak in the other direction: an ISP-tagged frame arriving on the WAN
    // must not deliver its tag to the LAN client.
    {
        const udp_bytes = try Packets.udp(alloc, vlan_remote_ip, vlan_lease_ip, .{
            .src_port = 53,
            .dst_port = 40_000,
            .payload = "tagged-back",
        });
        defer alloc.free(udp_bytes);
        const ip_bytes = try Packets.ipv4(alloc, .{
            .src = vlan_remote_ip,
            .dst = vlan_lease_ip,
            .protocol = 17,
            .dont_fragment = true,
            .payload = udp_bytes,
        });
        defer alloc.free(ip_bytes);
        const frame = try Packets.eth(alloc, .{
            .dst = RecordingNic.wan_mac,
            .src = vlan_gateway_mac,
            .vlan_tags = &.{.{ .vid = 200 }},
            .ethertype = 0x0800,
            .payload = ip_bytes,
        });
        defer alloc.free(frame);
        try h.inject(.wan, frame);
        _ = h.runAll(.wan);

        if (h.txCount() > 0) {
            const tx = h.txAt(0);
            try std.testing.expectEqual(IFace.lan, tx.iface);
            const tx_eth = try Ethernet.parse(tx.bytes);
            try std.testing.expectEqual(@as(usize, 0), tx_eth.get(.vlan_tags).len);
        }
    }
}

fn dhcpAppendU32(list: *std.ArrayList(u8), alloc: std.mem.Allocator, value: u32) !void {
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, value, .big);
    try list.appendSlice(alloc, &bytes);
}

/// DHCP server options used by the client handshake below.
pub fn dhcpServerOptions(
    alloc: std.mem.Allocator,
    message_type: u8,
    server_ip: IPv4,
    mask: IPv4,
    gateway: IPv4,
    lease_seconds: u32,
) ![]u8 {
    var options: std.ArrayList(u8) = .empty;
    errdefer options.deinit(alloc);
    try options.appendSlice(alloc, &.{ 53, 1, message_type });
    try options.appendSlice(alloc, &.{ 54, 4 });
    try options.appendSlice(alloc, &server_ip);
    try options.appendSlice(alloc, &.{ 1, 4 });
    try options.appendSlice(alloc, &mask);
    try options.appendSlice(alloc, &.{ 3, 4 });
    try options.appendSlice(alloc, &gateway);
    try options.appendSlice(alloc, &.{ 51, 4 });
    try dhcpAppendU32(&options, alloc, lease_seconds);
    return options.toOwnedSlice(alloc);
}

/// Build a DHCPv4 Ethernet frame (`op` = 1 BOOTREQUEST / 2 BOOTREPLY).
pub fn dhcpFrame(
    alloc: std.mem.Allocator,
    op: u8,
    xid: u32,
    chaddr: Mac,
    ciaddr: IPv4,
    yiaddr: IPv4,
    ip_src: IPv4,
    ip_dst: IPv4,
    options: []const u8,
) ![]u8 {
    var dhcp: std.ArrayList(u8) = .empty;
    defer dhcp.deinit(alloc);
    try dhcp.appendSlice(alloc, &.{ op, 1, 6, 0 }); // op, htype, hlen, hops
    try dhcpAppendU32(&dhcp, alloc, xid);
    try dhcp.appendSlice(alloc, &.{ 0, 0 }); // secs
    try dhcp.appendSlice(alloc, &.{ 0, 0 }); // flags
    try dhcp.appendSlice(alloc, &ciaddr);
    try dhcp.appendSlice(alloc, &yiaddr);
    try dhcp.appendSlice(alloc, &.{ 0, 0, 0, 0 }); // siaddr
    try dhcp.appendSlice(alloc, &.{ 0, 0, 0, 0 }); // giaddr
    var client_hw_addr = [_]u8{0} ** 16;
    client_hw_addr[0..6].* = chaddr;
    try dhcp.appendSlice(alloc, &client_hw_addr);
    try dhcp.appendSlice(alloc, &([_]u8{0} ** 64)); // sname
    try dhcp.appendSlice(alloc, &([_]u8{0} ** 128)); // file
    try dhcp.appendSlice(alloc, &.{ 0x63, 0x82, 0x53, 0x63 }); // magic
    try dhcp.appendSlice(alloc, options);
    try dhcp.append(alloc, 255); // End

    const udp_bytes = try Packets.udp(alloc, ip_src, ip_dst, .{
        .src_port = if (op == 2) 67 else 68,
        .dst_port = if (op == 2) 68 else 67,
        .checksum = 0,
        .payload = dhcp.items,
    });
    defer alloc.free(udp_bytes);
    const ip_bytes = try Packets.ipv4(alloc, .{
        .src = ip_src,
        .dst = ip_dst,
        .protocol = 17,
        .payload = udp_bytes,
    });
    defer alloc.free(ip_bytes);
    return Packets.eth(alloc, .{
        .dst = .{0xff} ** 6,
        .src = if (op == 2) gateway_mac else RecordingNic.wan_mac,
        .ethertype = 0x0800,
        .payload = ip_bytes,
    });
}

fn dhcpPacketOf(tx: []const u8) !Router.Protocols.DHCPv4.DHCPv4PacketView {
    const eth_view = try Ethernet.parse(tx);
    const ip_view = try Router.Protocols.IPv4.parse(eth_view.get(.payload));
    const udp_view = try Router.Protocols.Udp.parse(ip_view.get(.payload), ip_view);
    return Router.Protocols.DHCPv4.parse(udp_view.get(.payload));
}

/// Drive the WAN DHCP client through DISCOVER -> OFFER -> REQUEST -> ACK for
/// the given server-assigned address.
fn runWanDhcpHandshake(
    h: *Harness,
    alloc: std.mem.Allocator,
    offered_ip: IPv4,
    server_ip: IPv4,
    mask: IPv4,
    gateway: IPv4,
    lease_seconds: u32,
) !void {
    try Router.Protocols.DHCPv4.tickWan(std.testing.io, h.nic.api());
    const discover_tx = h.lastTx() orelse return error.TestUnexpectedResult;
    const discover = try dhcpPacketOf(discover_tx.bytes);
    const xid = discover.get(.xid);
    try std.testing.expect(discover.get(.op) == .BOOTREQUEST);

    const offer_options = try dhcpServerOptions(alloc, 2, server_ip, mask, gateway, lease_seconds);
    defer alloc.free(offer_options);
    const offer_frame = try dhcpFrame(
        alloc,
        2,
        xid,
        RecordingNic.wan_mac,
        .{ 0, 0, 0, 0 },
        offered_ip,
        server_ip,
        .{ 255, 255, 255, 255 },
        offer_options,
    );
    defer alloc.free(offer_frame);
    try h.inject(.wan, offer_frame);
    _ = h.runAll(.wan);

    try Router.Protocols.DHCPv4.tickWan(std.testing.io, h.nic.api());

    const ack_options = try dhcpServerOptions(alloc, 5, server_ip, mask, gateway, lease_seconds);
    defer alloc.free(ack_options);
    const ack_frame = try dhcpFrame(
        alloc,
        2,
        xid,
        RecordingNic.wan_mac,
        .{ 0, 0, 0, 0 },
        offered_ip,
        server_ip,
        .{ 255, 255, 255, 255 },
        ack_options,
    );
    defer alloc.free(ack_frame);
    try h.inject(.wan, ack_frame);
    _ = h.runAll(.wan);
}

test "DHCP client must reject a WAN lease that assigns a non-unicast address" {
    const alloc = std.testing.allocator;
    var h = try Harness.init(alloc, std.testing.io, .{});
    defer h.deinit();

    const server_ip: IPv4 = .{ 203, 0, 113, 1 };
    const mask: IPv4 = .{ 255, 255, 255, 0 };
    const gateway: IPv4 = .{ 203, 0, 113, 1 };

    // Positive control: a valid unicast offer/ack is accepted.
    try runWanDhcpHandshake(&h, alloc, .{ 203, 0, 113, 50 }, server_ip, mask, gateway, 3600);
    try std.testing.expectEqual(@as(?IPv4, .{ 203, 0, 113, 50 }), if (State.wan_lease) |lease| lease.ip else null);

    // Reset the negotiated lease so a second handshake starts clean.
    h.setWanLease(null);
    h.nic.resetLogs();

    // A DHCP server must never assign a loopback address to an interface. The
    // client currently accepts one and then uses it as the WAN source address
    // for every NATed packet (and in its ARP/DHCP traffic).
    try runWanDhcpHandshake(&h, alloc, .{ 127, 0, 0, 1 }, server_ip, mask, gateway, 3600);
    try std.testing.expectEqual(
        @as(?IPv4, null),
        if (State.wan_lease) |lease| lease.ip else null,
    );
}

/// Minimal DHCPv4 client message builder for the DHCP state-table regressions.
const DhcpClientMsg = struct {
    pub const Opts = struct {
        message_type: u8,
        xid: u32 = 0x1122_3344,
        ciaddr: IPv4 = .{ 0, 0, 0, 0 },
        client_id: ?[]const u8 = null,
        requested_ip: ?IPv4 = null,
        server_id: ?IPv4 = null,
        broadcast_flag: bool = false,
    };

    fn u16be(list: *std.ArrayList(u8), alloc: std.mem.Allocator, value: u16) !void {
        var bytes: [2]u8 = undefined;
        std.mem.writeInt(u16, &bytes, value, .big);
        try list.appendSlice(alloc, &bytes);
    }

    fn u32be(list: *std.ArrayList(u8), alloc: std.mem.Allocator, value: u32) !void {
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, value, .big);
        try list.appendSlice(alloc, &bytes);
    }

    fn option(list: *std.ArrayList(u8), alloc: std.mem.Allocator, code: u8, data: []const u8) !void {
        try list.append(alloc, code);
        try list.append(alloc, @intCast(data.len));
        try list.appendSlice(alloc, data);
    }

    pub fn frame(alloc: std.mem.Allocator, mac: Mac, opts: Opts) ![]u8 {
        var list: std.ArrayList(u8) = .empty;
        errdefer list.deinit(alloc);
        try list.append(alloc, 1); // BOOTREQUEST
        try list.append(alloc, 1); // Ethernet
        try list.append(alloc, 6); // hlen
        try list.append(alloc, 0); // hops
        try u32be(&list, alloc, opts.xid);
        try u16be(&list, alloc, 0); // secs
        try u16be(&list, alloc, if (opts.broadcast_flag) 0x8000 else 0);
        try list.appendSlice(alloc, &opts.ciaddr);
        try list.appendSlice(alloc, &([_]u8{0} ** 4));
        try list.appendSlice(alloc, &([_]u8{0} ** 4));
        try list.appendSlice(alloc, &([_]u8{0} ** 4));
        try list.appendSlice(alloc, &mac);
        try list.appendSlice(alloc, &([_]u8{0} ** 10));
        try list.appendSlice(alloc, &([_]u8{0} ** 64));
        try list.appendSlice(alloc, &([_]u8{0} ** 128));
        try list.appendSlice(alloc, &.{ 0x63, 0x82, 0x53, 0x63 });

        const message_type = [_]u8{opts.message_type};
        try option(&list, alloc, 53, &message_type);
        if (opts.client_id) |id| try option(&list, alloc, 61, id);
        if (opts.requested_ip) |ip| try option(&list, alloc, 50, &ip);
        if (opts.server_id) |ip| try option(&list, alloc, 54, &ip);
        try list.append(alloc, 255);

        const dhcp = try list.toOwnedSlice(alloc);
        defer alloc.free(dhcp);
        const udp_bytes = try Packets.udp(alloc, .{ 0, 0, 0, 0 }, .{ 255, 255, 255, 255 }, .{
            .src_port = 68,
            .dst_port = 67,
            .checksum = 0,
            .payload = dhcp,
        });
        defer alloc.free(udp_bytes);
        const ip_bytes = try Packets.ipv4(alloc, .{
            .src = .{ 0, 0, 0, 0 },
            .dst = .{ 255, 255, 255, 255 },
            .protocol = 17,
            .dont_fragment = true,
            .payload = udp_bytes,
        });
        defer alloc.free(ip_bytes);
        return Packets.eth(alloc, .{
            .dst = .{0xff} ** 6,
            .src = mac,
            .ethertype = 0x0800,
            .payload = ip_bytes,
        });
    }
};

test "one L2 client cannot reserve the whole DHCP pool with distinct client identifiers" {
    const alloc = std.testing.allocator;
    var h = try Harness.init(alloc, std.testing.io, .{
        .dhcp_pool = &[_]IPv4{ .{ 192, 168, 86, 10 }, .{ 192, 168, 86, 11 } },
    });
    defer h.deinit();

    const attacker_mac: Mac = .{ 0x02, 0xaa, 0x00, 0x00, 0x00, 0x01 };
    const legit_mac: Mac = .{ 0x02, 0xbb, 0x00, 0x00, 0x00, 0x02 };

    // A single attacker host claims every address with distinct client ids.
    for ([_][]const u8{ "spoof-1", "spoof-2", "spoof-3" }) |client_id| {
        const discover = try DhcpClientMsg.frame(alloc, attacker_mac, .{
            .message_type = 1,
            .xid = 0x1111_2222,
            .client_id = client_id,
        });
        defer alloc.free(discover);
        try h.inject(.lan, discover);
        _ = h.runAll(.lan);
    }
    try std.testing.expectEqual(@as(usize, 0), State.dhcp_table.ip_pool.items.len);

    // A legitimate client on the same segment now asks for an address. The
    // router must not let one L2 client deny DHCP service to the whole LAN.
    h.nic.resetLogs();
    const legit = try DhcpClientMsg.frame(alloc, legit_mac, .{
        .message_type = 1,
        .xid = 0x3333_4444,
        .client_id = "legit",
    });
    defer alloc.free(legit);
    try h.inject(.lan, legit);
    _ = h.runAll(.lan);

    // Exactly one DHCP OFFER must be sent to the legitimate client.
    try std.testing.expectEqual(@as(usize, 1), h.txCount());
    const tx_frame = try Ethernet.parse(h.txAt(0).bytes);
    const tx_ip = try Router.Protocols.IPv4.parse(tx_frame.get(.payload));
    const tx_udp = try Router.Protocols.Udp.parse(tx_ip.get(.payload), tx_ip);
    const tx_dhcp = try Router.Protocols.DHCPv4.parse(tx_udp.get(.payload));
    try std.testing.expectEqual(Router.Protocols.DHCPv4.Op.BOOTREPLY, tx_dhcp.get(.op));
    try std.testing.expect(!std.meta.eql(tx_dhcp.get(.your_ip), IPv4{ 0, 0, 0, 0 }));
}

test "one LAN host flooding spoofed ARP entries must not evict a live neighbour" {
    const alloc = std.testing.allocator;
    var h = try Harness.init(alloc, std.testing.io, .{});
    defer h.deinit();

    const lan_ip: IPv4 = .{ 192, 168, 86, 1 };
    const victim_ip: IPv4 = .{ 192, 168, 86, 42 };
    const victim_mac = client_mac;
    const attacker_mac: Mac = .{ 0x02, 0x66, 0x66, 0x66, 0x66, 0x66 };

    // The router learns the real neighbour from a normal ARP reply.
    const learn_arp = try Packets.arp(alloc, .{
        .opcode = 2, // reply
        .sender_mac = victim_mac,
        .sender_ip = victim_ip,
        .target_mac = RecordingNic.lan_mac,
        .target_ip = lan_ip,
    });
    defer alloc.free(learn_arp);
    const learn_frame = try Packets.eth(alloc, .{
        .dst = RecordingNic.lan_mac,
        .src = victim_mac,
        .ethertype = 0x0806,
        .payload = learn_arp,
    });
    defer alloc.free(learn_frame);
    try h.inject(.lan, learn_frame);
    _ = h.runAll(.lan);
    try std.testing.expect(State.lan_arp_table.lookup(victim_ip) != null);
    try std.testing.expect(std.meta.eql(State.lan_arp_table.lookup(victim_ip).?, victim_mac));

    // A single attacker host floods the cache with spoofed entries from one
    // MAC, using sender IPs it does not own (the cache has no on-link or
    // per-source accounting). The table holds 256 entries by default.
    for (0..256) |i| {
        const spoofed_ip: IPv4 = .{ 10, 0, @intCast(i >> 8), @intCast(i & 0xff) };
        const arp = try Packets.arp(alloc, .{
            .opcode = 2,
            .sender_mac = attacker_mac,
            .sender_ip = spoofed_ip,
            .target_mac = RecordingNic.lan_mac,
            .target_ip = lan_ip,
        });
        defer alloc.free(arp);
        const frame = try Packets.eth(alloc, .{
            .dst = RecordingNic.lan_mac,
            .src = attacker_mac,
            .ethertype = 0x0806,
            .payload = arp,
        });
        defer alloc.free(frame);
        try h.inject(.lan, frame);
        _ = h.runAll(.lan);
    }

    // The legitimate neighbour's mapping must survive the flood: one
    // unauthenticated host must not be able to displace valid entries with
    // spoofed ones (per-source quota and/or only caching entries the router
    // can legitimately learn).
    try std.testing.expect(State.lan_arp_table.lookup(victim_ip) != null);
    try std.testing.expect(std.meta.eql(State.lan_arp_table.lookup(victim_ip).?, victim_mac));
}

test "one LAN host cannot monopolize the fragment table and deny reassembly to other flows" {
    const alloc = std.testing.allocator;
    var h = try Harness.init(alloc, std.testing.io, .{
        .wan_lease = testWanLease(std.testing.io),
        .fragment_capacity = 4,
    });
    defer h.deinit();

    const gateway_ip: IPv4 = .{ 203, 0, 113, 1 };
    const remote_ip: IPv4 = .{ 8, 8, 8, 8 };
    const attacker_ip: IPv4 = .{ 192, 168, 86, 42 };
    const victim_ip: IPv4 = .{ 192, 168, 86, 43 };
    const attacker_mac: Mac = .{ 0x02, 0xaa, 0x00, 0x00, 0x00, 0x01 };
    const victim_mac: Mac = .{ 0x02, 0xbb, 0x00, 0x00, 0x00, 0x02 };
    h.cacheArp(.wan, gateway_ip, gateway_mac);

    // The attacker fills every live reassembly slot with one non-first
    // fragment per key. Only src/dst/identification/protocol are keyed, and
    // all of them are attacker-chosen, so one host can occupy every slot.
    for (1..5) |identification| {
        const payload = [_]u8{0xaa} ** 16;
        const ip_bytes = try Packets.ipv4(alloc, .{
            .src = attacker_ip,
            .dst = remote_ip,
            .protocol = 17,
            .identification = @intCast(identification),
            .more_fragments = false,
            .fragment_offset = 8,
            .payload = &payload,
        });
        defer alloc.free(ip_bytes);
        const frame = try Packets.eth(alloc, .{
            .dst = RecordingNic.lan_mac,
            .src = attacker_mac,
            .ethertype = 0x0800,
            .payload = ip_bytes,
        });
        defer alloc.free(frame);
        try h.inject(.lan, frame);
        _ = h.runAll(.lan);
    }
    try std.testing.expectEqual(@as(usize, 0), h.txCount());
    try std.testing.expectEqual(@as(usize, 0), h.errorCount());
    try std.testing.expectEqual(@as(usize, 4), State.lan_fragment_table.table.count());

    // A different host starts its own fragmented datagram. Live entries may be
    // reclaimed (LRU) or per-source quotas enforced, but one host filling the
    // table must not deny reassembly/forwarding to every other flow.
    h.nic.resetLogs();
    const udp_bytes = try Packets.udp(alloc, victim_ip, remote_ip, .{
        .src_port = 40_000,
        .dst_port = 53,
        .payload = "abcdefgh",
    });
    defer alloc.free(udp_bytes);
    const ip_bytes = try Packets.ipv4(alloc, .{
        .src = victim_ip,
        .dst = remote_ip,
        .protocol = 17,
        .identification = 7,
        .more_fragments = true,
        .fragment_offset = 0,
        .payload = udp_bytes,
    });
    defer alloc.free(ip_bytes);
    const frame = try Packets.eth(alloc, .{
        .dst = RecordingNic.lan_mac,
        .src = victim_mac,
        .ethertype = 0x0800,
        .payload = ip_bytes,
    });
    defer alloc.free(frame);
    try h.inject(.lan, frame);
    _ = h.runAll(.lan);

    // The victim's first fragment must be forwarded (one TX to the gateway),
    // not dropped because the attacker owns every reassembly slot.
    try std.testing.expectEqual(@as(usize, 1), h.txCount());
    try std.testing.expectEqual(@as(usize, 0), h.errorCount());
    try std.testing.expectEqual(IFace.wan, h.txAt(0).iface);
    try std.testing.expectEqual(gateway_mac, (try Ethernet.parse(h.txAt(0).bytes)).get(.dst_mac));
}

test "an ARP request must not overwrite an existing neighbour mapping" {
    const alloc = std.testing.allocator;
    const io = std.testing.io;
    var h = try Harness.init(alloc, io, .{ .wan_lease = testWanLease(io) });
    defer h.deinit();

    const lease_ip: IPv4 = .{ 203, 0, 113, 50 };
    const gateway_ip: IPv4 = .{ 203, 0, 113, 1 };
    const remote_ip: IPv4 = .{ 8, 8, 8, 8 };
    const lan_ip: IPv4 = .{ 192, 168, 86, 1 };
    const lan_victim_ip: IPv4 = .{ 192, 168, 86, 43 };
    const lan_victim_mac: Mac = .{ 0x02, 0xaa, 0x00, 0x00, 0x00, 0x03 };
    const attacker_mac: Mac = .{ 0x02, 0x66, 0x66, 0x66, 0x66, 0x66 };

    // The router has validated both neighbours (gateway on WAN, client on LAN).
    h.cacheArp(.wan, gateway_ip, gateway_mac);
    h.cacheArp(.lan, lan_victim_ip, lan_victim_mac);

    // Positive control: LAN->WAN forwarding uses the real gateway MAC.
    h.nic.resetLogs();
    {
        const udp_bytes = try Packets.udp(alloc, client_ip, remote_ip, .{ .src_port = 40_000, .dst_port = 53, .payload = "x" });
        defer alloc.free(udp_bytes);
        const ip_bytes = try Packets.ipv4(alloc, .{ .src = client_ip, .dst = remote_ip, .protocol = 17, .dont_fragment = true, .payload = udp_bytes });
        defer alloc.free(ip_bytes);
        const frame = try Packets.eth(alloc, .{ .dst = RecordingNic.lan_mac, .src = client_mac, .ethertype = 0x0800, .payload = ip_bytes });
        defer alloc.free(frame);
        try h.inject(.lan, frame);
        _ = h.runAll(.lan);
    }
    try std.testing.expectEqual(@as(usize, 1), h.txCount());
    try std.testing.expectEqual(gateway_mac, (try Ethernet.parse(h.txAt(0).bytes)).get(.dst_mac));

    // Positive control: a mapping held by the LAN neighbour is delivered to its
    // real MAC on the way back in.
    h.nic.resetLogs();
    {
        const udp_bytes = try Packets.udp(alloc, lan_victim_ip, remote_ip, .{ .src_port = 40_002, .dst_port = 53, .payload = "open" });
        defer alloc.free(udp_bytes);
        const ip_bytes = try Packets.ipv4(alloc, .{ .src = lan_victim_ip, .dst = remote_ip, .protocol = 17, .dont_fragment = true, .payload = udp_bytes });
        defer alloc.free(ip_bytes);
        const frame = try Packets.eth(alloc, .{ .dst = RecordingNic.lan_mac, .src = lan_victim_mac, .ethertype = 0x0800, .payload = ip_bytes });
        defer alloc.free(frame);
        try h.inject(.lan, frame);
        _ = h.runAll(.lan);
        const reply_udp = try Packets.udp(alloc, remote_ip, lease_ip, .{ .src_port = 53, .dst_port = 40_002, .payload = "back" });
        defer alloc.free(reply_udp);
        const reply_ip = try Packets.ipv4(alloc, .{ .src = remote_ip, .dst = lease_ip, .protocol = 17, .dont_fragment = true, .payload = reply_udp });
        defer alloc.free(reply_ip);
        const reply_frame = try Packets.eth(alloc, .{ .dst = RecordingNic.wan_mac, .src = gateway_mac, .ethertype = 0x0800, .payload = reply_ip });
        defer alloc.free(reply_frame);
        try h.inject(.wan, reply_frame);
        _ = h.runAll(.wan);
    }
    try std.testing.expectEqual(@as(usize, 2), h.txCount());
    try std.testing.expectEqual(lan_victim_mac, (try Ethernet.parse(h.txAt(1).bytes)).get(.dst_mac));

    // WAN variant: an on-link host sends an ARP *request* for the router's WAN
    // address but claims the gateway's IP in the sender fields. The router
    // answers it (fine) but must not replace the validated gateway mapping.
    {
        const arp_bytes = try Packets.arp(alloc, .{
            .opcode = 1,
            .sender_mac = attacker_mac,
            .sender_ip = gateway_ip,
            .target_mac = .{0} ** 6,
            .target_ip = lease_ip,
        });
        defer alloc.free(arp_bytes);
        const frame = try Packets.eth(alloc, .{ .dst = RecordingNic.wan_mac, .src = attacker_mac, .ethertype = 0x0806, .payload = arp_bytes });
        defer alloc.free(frame);
        try h.inject(.wan, frame);
        _ = h.runAll(.wan);
    }
    try std.testing.expectEqual(gateway_mac, State.wan_arp_table.lookup(gateway_ip).?);

    // LAN variant: a host claims a live neighbour's IP in an ARP request.
    {
        const arp_bytes = try Packets.arp(alloc, .{
            .opcode = 1,
            .sender_mac = attacker_mac,
            .sender_ip = lan_victim_ip,
            .target_mac = .{0} ** 6,
            .target_ip = lan_ip,
        });
        defer alloc.free(arp_bytes);
        const frame = try Packets.eth(alloc, .{ .dst = RecordingNic.lan_mac, .src = attacker_mac, .ethertype = 0x0806, .payload = arp_bytes });
        defer alloc.free(frame);
        try h.inject(.lan, frame);
        _ = h.runAll(.lan);
    }
    try std.testing.expectEqual(lan_victim_mac, State.lan_arp_table.lookup(lan_victim_ip).?);

    // Consequence check: forwarded traffic must still use the real MACs.
    h.nic.resetLogs();
    {
        const udp_bytes = try Packets.udp(alloc, client_ip, remote_ip, .{ .src_port = 40_001, .dst_port = 53, .payload = "y" });
        defer alloc.free(udp_bytes);
        const ip_bytes = try Packets.ipv4(alloc, .{ .src = client_ip, .dst = remote_ip, .protocol = 17, .dont_fragment = true, .payload = udp_bytes });
        defer alloc.free(ip_bytes);
        const frame = try Packets.eth(alloc, .{ .dst = RecordingNic.lan_mac, .src = client_mac, .ethertype = 0x0800, .payload = ip_bytes });
        defer alloc.free(frame);
        try h.inject(.lan, frame);
        _ = h.runAll(.lan);
    }
    try std.testing.expectEqual(@as(usize, 1), h.txCount());
    try std.testing.expectEqual(gateway_mac, (try Ethernet.parse(h.txAt(0).bytes)).get(.dst_mac));

    h.nic.resetLogs();
    {
        // The LAN variant poisoned no mapping: traffic for .43's existing
        // flow still goes to .43, not the attacker.
        const reply_udp = try Packets.udp(alloc, remote_ip, lease_ip, .{ .src_port = 53, .dst_port = 40_002, .payload = "again" });
        defer alloc.free(reply_udp);
        const reply_ip = try Packets.ipv4(alloc, .{ .src = remote_ip, .dst = lease_ip, .protocol = 17, .dont_fragment = true, .payload = reply_udp });
        defer alloc.free(reply_ip);
        const reply_frame = try Packets.eth(alloc, .{ .dst = RecordingNic.wan_mac, .src = gateway_mac, .ethertype = 0x0800, .payload = reply_ip });
        defer alloc.free(reply_frame);
        try h.inject(.wan, reply_frame);
        _ = h.runAll(.wan);
    }
    try std.testing.expectEqual(@as(usize, 1), h.txCount());
    try std.testing.expectEqual(lan_victim_mac, (try Ethernet.parse(h.txAt(0).bytes)).get(.dst_mac));
}

test "DHCP client must reject an ACK whose router option is an unusable next-hop" {
    const alloc = std.testing.allocator;
    var h = try Harness.init(alloc, std.testing.io, .{});
    defer h.deinit();

    const server_ip: IPv4 = .{ 203, 0, 113, 1 };
    const mask: IPv4 = .{ 255, 255, 255, 0 };
    const offered_ip: IPv4 = .{ 203, 0, 113, 50 };

    // Positive control: a normal gateway is installed.
    try runWanDhcpHandshake(&h, alloc, offered_ip, server_ip, mask, server_ip, 3_600);
    try std.testing.expectEqual(
        @as(?IPv4, server_ip),
        if (State.wan_lease) |lease| lease.router else null,
    );

    // A DHCP server must not be able to install 0.0.0.0 (or another
    // non-unicast/loopback address) as the default next-hop. The client
    // currently accepts it and every subsequent WAN forward uses it as the
    // ARP next hop, blackholing (or redirecting) all WAN traffic.
    h.setWanLease(null);
    h.nic.resetLogs();
    try runWanDhcpHandshake(&h, alloc, offered_ip, server_ip, mask, .{ 0, 0, 0, 0 }, 3_600);
    const zero_ip: IPv4 = .{ 0, 0, 0, 0 };
    try std.testing.expectEqual(
        @as(?IPv4, null),
        if (State.wan_lease) |lease|
            (if (std.meta.eql(lease.router, zero_ip)) lease.router else null)
        else
            null,
    );
}

test "a LAN host spoofing another host's source address must not create NAT pinholes for it" {
    const alloc = std.testing.allocator;
    const io = std.testing.io;
    var h = try Harness.init(alloc, io, .{ .wan_lease = testWanLease(io) });
    defer h.deinit();

    const lease_ip: IPv4 = .{ 203, 0, 113, 50 };
    const gateway_ip: IPv4 = .{ 203, 0, 113, 1 };
    const remote_ip: IPv4 = .{ 8, 8, 8, 8 };
    const victim_ip: IPv4 = .{ 192, 168, 86, 43 };
    const victim_mac: Mac = .{ 0x02, 0xaa, 0x00, 0x00, 0x00, 0x03 };
    const attacker_mac: Mac = .{ 0x02, 0x66, 0x66, 0x66, 0x66, 0x66 };

    h.cacheArp(.wan, gateway_ip, gateway_mac);
    h.cacheArp(.lan, victim_ip, victim_mac);

    // Positive control: the victim's own flow is NATed normally.
    {
        const udp_bytes = try Packets.udp(alloc, victim_ip, remote_ip, .{ .src_port = 9090, .dst_port = 53, .payload = "legit" });
        defer alloc.free(udp_bytes);
        const ip_bytes = try Packets.ipv4(alloc, .{ .src = victim_ip, .dst = remote_ip, .protocol = 17, .dont_fragment = true, .payload = udp_bytes });
        defer alloc.free(ip_bytes);
        const frame = try Packets.eth(alloc, .{ .dst = RecordingNic.lan_mac, .src = victim_mac, .ethertype = 0x0800, .payload = ip_bytes });
        defer alloc.free(frame);
        try h.inject(.lan, frame);
        _ = h.runAll(.lan);
    }
    try std.testing.expectEqual(@as(usize, 1), h.txCount());
    try std.testing.expect(State.nat_table.inboundEntry(.{ .protocol = .udp, .ip = lease_ip, .port = 9090 }) != null);

    // Attack: a different link-layer host sends a datagram whose IP source is
    // the victim's address (and a port the victim never used). The router must
    // not create forwarding state for a source the sender does not own.
    h.nic.resetLogs();
    {
        const udp_bytes = try Packets.udp(alloc, victim_ip, remote_ip, .{ .src_port = 8080, .dst_port = 53, .payload = "pinhole" });
        defer alloc.free(udp_bytes);
        const ip_bytes = try Packets.ipv4(alloc, .{ .src = victim_ip, .dst = remote_ip, .protocol = 17, .dont_fragment = true, .payload = udp_bytes });
        defer alloc.free(ip_bytes);
        const frame = try Packets.eth(alloc, .{ .dst = RecordingNic.lan_mac, .src = attacker_mac, .ethertype = 0x0800, .payload = ip_bytes });
        defer alloc.free(frame);
        try h.inject(.lan, frame);
        _ = h.runAll(.lan);
    }
    try std.testing.expect(State.nat_table.inboundEntry(.{ .protocol = .udp, .ip = lease_ip, .port = 8080 }) == null);
    try std.testing.expectEqual(@as(usize, 0), h.txCount());
    try std.testing.expectEqual(@as(usize, 1), h.dropCount());

    // Consequence: an external host must not be able to reach the victim's
    // never-opened port through a mapping created by the spoofed source.
    h.nic.resetLogs();
    {
        const udp_bytes = try Packets.udp(alloc, .{ 6, 6, 6, 6 }, lease_ip, .{ .src_port = 1234, .dst_port = 8080, .payload = "reach" });
        defer alloc.free(udp_bytes);
        const ip_bytes = try Packets.ipv4(alloc, .{ .src = .{ 6, 6, 6, 6 }, .dst = lease_ip, .protocol = 17, .dont_fragment = true, .payload = udp_bytes });
        defer alloc.free(ip_bytes);
        const frame = try Packets.eth(alloc, .{ .dst = RecordingNic.wan_mac, .src = gateway_mac, .ethertype = 0x0800, .payload = ip_bytes });
        defer alloc.free(frame);
        try h.inject(.wan, frame);
        _ = h.runAll(.wan);
    }
    try std.testing.expectEqual(@as(usize, 0), h.txCount());
    try std.testing.expectEqual(@as(usize, 1), h.dropCount());
}

const trailer_lease_ip: IPv4 = .{ 203, 0, 113, 50 };
const trailer_gateway: IPv4 = .{ 203, 0, 113, 1 };
const trailer_gateway_mac: Mac = .{ 0x02, 0x99, 0x88, 0x77, 0x66, 0x55 };
const trailer_client_ip: IPv4 = .{ 192, 168, 86, 42 };
const trailer_client_mac: Mac = .{ 0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee };
const trailer_peer_ip: IPv4 = .{ 8, 8, 8, 8 };
const trailer_marker: u8 = 0xa7;

fn trailerUdpFrame(
    alloc: std.mem.Allocator,
    iface: IFace,
    src_ip: IPv4,
    dst_ip: IPv4,
    src_port: u16,
    dst_port: u16,
    tags: []const Packets.VlanTag,
    trailer: []const u8,
) ![]u8 {
    const udp_bytes = try Packets.udp(alloc, src_ip, dst_ip, .{
        .src_port = src_port,
        .dst_port = dst_port,
        .payload = "",
    });
    defer alloc.free(udp_bytes);
    const ip_bytes = try Packets.ipv4(alloc, .{
        .src = src_ip,
        .dst = dst_ip,
        .protocol = 17,
        .dont_fragment = true,
        .payload = udp_bytes,
        // Bytes after the IP datagram but inside the Ethernet frame. They are
        // not counted in the IP total_length.
        .trailing = trailer,
    });
    defer alloc.free(ip_bytes);
    return Packets.eth(alloc, .{
        .dst = switch (iface) {
            .lan => RecordingNic.lan_mac,
            .wan => RecordingNic.wan_mac,
        },
        .src = switch (iface) {
            .lan => trailer_client_mac,
            .wan => trailer_gateway_mac,
        },
        .vlan_tags = tags,
        .ethertype = 0x0800,
        .payload = ip_bytes,
    });
}

test "L2 bytes after the IP packet must not be forwarded across interfaces" {
    const alloc = std.testing.allocator;
    const io = std.testing.io;

    var trailer: [200]u8 = undefined;
    @memset(&trailer, trailer_marker);

    var h = try Harness.init(alloc, io, .{ .wan_lease = testWanLease(io) });
    defer h.deinit();
    h.cacheArp(.wan, trailer_gateway, trailer_gateway_mac);
    h.cacheArp(.lan, trailer_client_ip, trailer_client_mac);

    // LAN -> WAN, untagged: 14 (Ethernet) + 28 (IP + UDP) bytes are meaningful;
    // the 200 bytes after the IP datagram must not reach the WAN link.
    {
        const frame = try trailerUdpFrame(alloc, .lan, trailer_client_ip, trailer_peer_ip, 40_000, 53, &.{}, &trailer);
        defer alloc.free(frame);
        try h.inject(.lan, frame);
        _ = h.runAll(.lan);
        try std.testing.expectEqual(@as(usize, 1), h.txCount());
        const tx = h.txAt(0);
        try std.testing.expectEqual(IFace.wan, tx.iface);
        try std.testing.expectEqual(@as(usize, 14 + 28), tx.bytes.len);
        try std.testing.expectEqual(
            @as(usize, 0),
            std.mem.count(u8, tx.bytes, &[_]u8{trailer_marker}),
        );
        h.nic.resetLogs();
    }

    // Tagged frames are refused by the cross-interface tag policy, so the
    // trailer cannot cross either; dropping is an accepted outcome.
    {
        const frame = try trailerUdpFrame(alloc, .lan, trailer_client_ip, trailer_peer_ip, 40_002, 53, &.{.{ .vid = 100 }}, &trailer);
        defer alloc.free(frame);
        try h.inject(.lan, frame);
        _ = h.runAll(.lan);
        try std.testing.expectEqual(@as(usize, 0), h.txCount());
        try std.testing.expectEqual(@as(usize, 1), h.dropCount());
        h.nic.resetLogs();
    }

    // WAN -> LAN: the mapping 40000 -> 192.168.86.42:40000 exists, and the
    // reply's trailer must not be delivered to the LAN client either.
    {
        const frame = try trailerUdpFrame(alloc, .wan, trailer_peer_ip, trailer_lease_ip, 53, 40_000, &.{}, &trailer);
        defer alloc.free(frame);
        try h.inject(.wan, frame);
        _ = h.runAll(.wan);
        try std.testing.expectEqual(@as(usize, 1), h.txCount());
        const tx = h.txAt(0);
        try std.testing.expectEqual(IFace.lan, tx.iface);
        try std.testing.expectEqual(@as(usize, 14 + 28), tx.bytes.len);
        try std.testing.expectEqual(
            @as(usize, 0),
            std.mem.count(u8, tx.bytes, &[_]u8{trailer_marker}),
        );
        h.nic.resetLogs();
    }

    // Positive control: a generated reply (echo reply) already trims to the IP
    // total length, so the forwarding path is the inconsistent one.
    {
        const icmp_bytes = try Packets.echo(alloc, .{ .identifier = 1, .sequence_number = 1, .data = "" });
        defer alloc.free(icmp_bytes);
        const ip_bytes = try Packets.ipv4(alloc, .{
            .src = trailer_client_ip,
            .dst = .{ 192, 168, 86, 1 },
            .protocol = 1,
            .dont_fragment = true,
            .payload = icmp_bytes,
            .trailing = &trailer,
        });
        defer alloc.free(ip_bytes);
        const frame = try Packets.eth(alloc, .{
            .dst = RecordingNic.lan_mac,
            .src = trailer_client_mac,
            .ethertype = 0x0800,
            .payload = ip_bytes,
        });
        defer alloc.free(frame);
        try h.inject(.lan, frame);
        _ = h.runAll(.lan);
        try std.testing.expectEqual(@as(usize, 1), h.txCount());
        const tx = h.txAt(0);
        try std.testing.expectEqual(@as(usize, 14 + 28), tx.bytes.len);
        try std.testing.expectEqual(
            @as(usize, 0),
            std.mem.count(u8, tx.bytes, &[_]u8{trailer_marker}),
        );
    }
}

pub fn expectDhcpMessage(frame: []const u8, kind: Router.Protocols.DHCPv4.MessageType) !Router.Protocols.DHCPv4.DHCPv4PacketView {
    const packet = try dhcpPacketOf(frame);
    var reader: std.Io.Reader = .fixed(packet.get(.options));
    while (try Router.Protocols.DHCPv4.parseOption(&reader)) |opt| {
        if (opt == .message_type) {
            try std.testing.expectEqual(kind, opt.message_type);
            return packet;
        }
    }
    return error.MissingMessageType;
}

test "readiness from cold start negotiates WAN and LAN leases and resolves gateway before NAT forwarding" {
    const alloc = std.testing.allocator;
    const outside: IPv4 = .{ 203, 0, 113, 50 };
    const gateway: IPv4 = .{ 203, 0, 113, 1 };
    const peer: IPv4 = .{ 198, 51, 100, 2 };
    var h = try Harness.init(alloc, std.testing.io, .{ .dhcp_pool = &.{client_ip} });
    defer h.deinit();
    try std.testing.expect(State.wan_lease == null);
    try runWanDhcpHandshake(&h, alloc, outside, gateway, .{ 255, 255, 255, 0 }, gateway, 3600);
    try std.testing.expectEqual(outside, State.wan_lease.?.ip);
    _ = try expectDhcpMessage(h.txAt(0).bytes, .discover);
    _ = try expectDhcpMessage(h.txAt(1).bytes, .request);
    h.nic.resetLogs();

    const discover = try DhcpClient.frame(alloc, client_mac, .{ .message_type = 1, .xid = 123 });
    defer alloc.free(discover);
    try h.inject(.lan, discover);
    _ = h.runAll(.lan);
    const offer = try expectDhcpMessage(h.txAt(0).bytes, .offer);
    const offered = offer.get(.your_ip);
    const request = try DhcpClient.frame(alloc, client_mac, .{
        .message_type = 3,
        .xid = 123,
        .requested_ip = offered,
        .server_id = State.lan_ip,
    });
    defer alloc.free(request);
    try h.inject(.lan, request);
    _ = h.runAll(.lan);
    const ack = try expectDhcpMessage(h.txAt(1).bytes, .ack);
    try std.testing.expectEqual(client_ip, ack.get(.your_ip));
    try std.testing.expect(State.dhcp_table.lookupByIp(client_ip) != null);
    h.nic.resetLogs();

    const data = try lanUdpFrame(alloc, client_ip, client_mac, peer, 41000, 53);
    defer alloc.free(data);
    try h.inject(.lan, data);
    _ = h.runAll(.lan);
    try std.testing.expectEqual(@as(usize, 1), h.txCount());
    const arp_eth = try Ethernet.parse(h.txAt(0).bytes);
    try std.testing.expectEqual(Ethernet.Ethertype.arp, arp_eth.get(.ethertype));
    const solicitation = try Router.Protocols.Arp.parse(arp_eth.get(.payload));
    try std.testing.expectEqual(gateway, solicitation.get(.target_ip));
    const reply = try Packets.arp(alloc, .{ .opcode = 2, .sender_ip = gateway, .sender_mac = gateway_mac, .target_ip = outside, .target_mac = RecordingNic.wan_mac });
    defer alloc.free(reply);
    const frame = try Packets.eth(alloc, .{ .dst = RecordingNic.wan_mac, .src = gateway_mac, .ethertype = 0x0806, .payload = reply });
    defer alloc.free(frame);
    try h.inject(.wan, frame);
    _ = h.runAll(.wan);
    try std.testing.expectEqual(@as(usize, 2), h.txCount());
    const forwarded = try Ethernet.parse(h.txAt(1).bytes);
    try std.testing.expectEqual(gateway_mac, forwarded.get(.dst_mac));
    const ip = try Router.Protocols.IPv4.parse(forwarded.get(.payload));
    try std.testing.expectEqual(outside, ip.get(.src));
    try std.testing.expectEqual(peer, ip.get(.dst));
    _ = try Router.Protocols.Udp.parse(ip.get(.payload), ip);
}
