//! Cross-cutting security regression tests.
//!
//! This file is its own test root (see `build.zig`). Audit branches add one
//! failing test per confirmed bug here. A regression test must encode the
//! *expected* (safe) router behavior, so it fails while the bug is present and
//! passes once the bug is fixed. Production code is intentionally not fixed by
//! the audit agents.
//!
//! It also hosts the shared end-to-end test harness announced on
//! `audit/harness-v1`:
//!
//! - `RecordingNic` implements `Router.Nic.Api.Api`, records every transmit
//!   (copying bytes before the buffer is freed), counts drops/errors, and frees
//!   every outstanding buffer on deinit.
//! - `Harness` initializes the same process-global `Router.State` tables that
//!   `src/main.zig` creates, injects pcap/raw frames, and runs them through
//!   `Router.Protocols.Ethernet.handle` with a fresh `ViewStack` per packet.
//! - `Packets` builds synthetic classic-pcap files and Ethernet/IPv4/UDP/TCP/
//!   ICMP/ARP frames with correct checksums plus override knobs for malformed
//!   fields (lengths, checksums, flags, IHL/data offset, VLAN tags, TTL, ...).

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
const NicApi = Router.Nic.Api.Api;
const PcapParser = Router.TestFixtures.PcapParser;
const State = Router.State;
const ViewStack = Router.Protocols.ViewStack;

const checksumContribution = Router.Meta.Checksum.checksumContribution;

test {
    _ = Router;
}

/// Recording test NIC.
///
/// RX and TX buffers are tracked by allocation so tests can detect leaked,
/// double-released, or untracked buffers without tripping the testing allocator.
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

    pub const ErrorRecord = struct {
        iface: IFace,
        name: []const u8,
    };

    alloc: std.mem.Allocator,
    outstanding: std.ArrayList(Outstanding) = .empty,
    rx_lan: std.ArrayList([]u8) = .empty,
    rx_wan: std.ArrayList([]u8) = .empty,
    tx_log: std.ArrayList(TxRecord) = .empty,
    errors: std.ArrayList(ErrorRecord) = .empty,
    rx_count: usize = 0,
    tx_count: usize = 0,
    drop_count: usize = 0,
    unexpected_releases: usize = 0,
    unexpected_transmits: usize = 0,
    outstanding_at_deinit: usize = 0,

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
        self.errors.deinit(self.alloc);
        self.outstanding_at_deinit = self.outstanding.items.len;
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

    pub fn lastError(self: *const RecordingNic) ?ErrorRecord {
        if (self.errors.items.len == 0) return null;
        return self.errors.items[self.errors.items.len - 1];
    }

    pub fn resetLogs(self: *RecordingNic) void {
        for (self.tx_log.items) |record| self.alloc.free(record.bytes);
        self.tx_log.clearRetainingCapacity();
        self.errors.clearRetainingCapacity();
        self.rx_count = 0;
        self.tx_count = 0;
        self.drop_count = 0;
        self.unexpected_releases = 0;
        self.unexpected_transmits = 0;
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

    fn originIface(origin: Origin) IFace {
        return switch (origin) {
            .rx_lan, .tx_lan => .lan,
            .rx_wan, .tx_wan => .wan,
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
        self.rx_count += 1;
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
        const entry = self.take(buffer) orelse {
            self.unexpected_releases += 1;
            return;
        };
        switch (entry.origin) {
            .rx_lan, .rx_wan => self.drop_count += 1,
            .tx_lan, .tx_wan => {},
        }
        self.alloc.free(entry.allocation);
    }

    fn transmit(ctx: *anyopaque, buffer: []u8) void {
        const self: *RecordingNic = @ptrCast(@alignCast(ctx));
        const entry = self.take(buffer) orelse {
            self.unexpected_transmits += 1;
            return;
        };
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
        self.tx_count += 1;
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
    };

    alloc: std.mem.Allocator,
    io: std.Io,
    nic: RecordingNic,
    ready: struct {
        lan_arp: bool = false,
        wan_arp: bool = false,
        waiters: bool = false,
        dhcp: bool = false,
        nat: bool = false,
        lan_fragments: bool = false,
        wan_fragments: bool = false,
    } = .{},

    pub fn init(alloc: std.mem.Allocator, io: std.Io, options: Options) !Harness {
        var self: Harness = .{
            .alloc = alloc,
            .io = io,
            .nic = RecordingNic.init(alloc),
        };
        errdefer self.deinit();

        State.lan_ip = options.lan_ip;
        State.lan_subnet_mask = options.lan_subnet_mask;
        State.wan_lease = options.wan_lease;

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
        Ethernet.handle(packet, self.nic.api(), iface, &views) catch |err| {
            // Mirror the production loop: the caller owns the RX buffer when
            // the handler returns an error.
            self.nic.api().release(packet);
            self.nic.errors.append(self.alloc, .{
                .iface = iface,
                .name = @errorName(err),
            }) catch unreachable;
        };
        return true;
    }

    /// Drain `iface`, processing packets in FIFO order. Returns packet count.
    pub fn runAll(self: *Harness, iface: IFace) usize {
        var count: usize = 0;
        while (self.runOne(iface)) count += 1;
        return count;
    }

    /// Drain LAN, then WAN.
    pub fn run(self: *Harness) void {
        _ = self.runAll(.lan);
        _ = self.runAll(.wan);
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
        return self.nic.errors.items.len;
    }

    pub fn lastError(self: *const Harness) ?RecordingNic.ErrorRecord {
        return self.nic.lastError();
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

    const inside_ip, const inside_port = State.nat_table.inboundLookup(.{
        .protocol = .udp,
        .ip = lease_ip,
        .port = 40_000,
    }).?;
    try std.testing.expectEqual(client_ip, inside_ip);
    try std.testing.expectEqual(@as(u16, 40_000), inside_port);

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
const DhcpClient = struct {
    pub const Opts = struct {
        message_type: u8,
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
