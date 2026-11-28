//! Streaming mock NIC for the readiness oracle.
const std = @import("std");
const Router = @import("router");

const Api = Router.Nic.Api.Api;
const IFace = Router.Nic.Api.IFace;
const Ethernet = Router.Protocols.Ethernet;
const Log = Router.Debug.Unhandled;

const max_frame = 16384;

pub const Mock = struct {
    const Buffer = struct {
        bytes: *[max_frame]u8,
        iface: IFace,
        rx_id: ?u64,
    };

    alloc: std.mem.Allocator,
    out: *std.Io.Writer,
    macs: [2]Ethernet.Mac,
    buffers: std.AutoHashMapUnmanaged([*]u8, Buffer) = .empty,
    input: ?[]u8 = null,
    current: ?u64 = null,
    failed: bool = false,
    ending: bool = false,

    pub fn deinit(self: *Mock) void {
        std.debug.assert(self.buffers.count() == 0);
        self.buffers.deinit(self.alloc);
    }

    pub fn api(self: *Mock) Api {
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

    fn allocate(self: *Mock, iface: IFace, rx_id: ?u64) []u8 {
        const bytes = self.alloc.create([max_frame]u8) catch @panic("shadow NIC allocation failed");
        self.buffers.putNoClobber(self.alloc, bytes, .{
            .bytes = bytes,
            .iface = iface,
            .rx_id = rx_id,
        }) catch @panic("shadow NIC buffer tracking failed");
        return bytes;
    }

    fn receive(ctx: *anyopaque, _: IFace) ?[]u8 {
        const self: *Mock = @ptrCast(@alignCast(ctx));
        const input = self.input;
        self.input = null;
        return input;
    }

    fn nextTxBuffer(ctx: *anyopaque, iface: IFace) []u8 {
        const self: *Mock = @ptrCast(@alignCast(ctx));
        return self.allocate(iface, null);
    }

    fn macAddress(ctx: *anyopaque, iface: IFace) Ethernet.Mac {
        const self: *Mock = @ptrCast(@alignCast(ctx));
        return self.macs[@intFromEnum(iface)];
    }

    fn release(ctx: *anyopaque, buffer: []u8) void {
        const self: *Mock = @ptrCast(@alignCast(ctx));
        const entry = self.buffers.fetchRemove(buffer.ptr) orelse @panic("shadow NIC released an unknown buffer");
        defer self.alloc.destroy(entry.value.bytes);
        if (entry.value.rx_id) |id| self.emit('X', id, &.{});
    }

    fn transmit(ctx: *anyopaque, buffer: []u8) void {
        const self: *Mock = @ptrCast(@alignCast(ctx));
        const entry = self.buffers.fetchRemove(buffer.ptr) orelse @panic("shadow NIC transmitted an unknown buffer");
        defer self.alloc.destroy(entry.value.bytes);
        if (entry.value.rx_id) |id| {
            self.emit('F', id, buffer);
        } else if (self.current) |id| {
            const ethernet = Ethernet.parse(buffer) catch return;
            // Suppress neighbor lookups and DHCP probes; report defensive announcements.
            if (ethernet.get(.ethertype) == .arp) {
                const arp = Router.Protocols.Arp.parse(ethernet.get(.payload)) catch return;
                if (arp.get(.opcode) == .request and !arp.fieldCmp(.sender_ip, .{ .eq = arp.get(.target_ip) })) return;
            }
            self.emit(if (entry.value.iface == .lan) 'R' else 'S', id, buffer);
        }
    }

    pub fn emit(self: *Mock, kind: u8, id: u64, bytes: []const u8) void {
        if (self.failed or self.ending) return;
        var header: [11]u8 = undefined;
        header[0] = kind;
        std.mem.writeInt(u64, header[1..9], id, .big);
        std.mem.writeInt(u16, header[9..11], @intCast(bytes.len), .big);
        self.out.writeAll(&header) catch {
            self.failed = true;
            return;
        };
        self.out.writeAll(bytes) catch {
            self.failed = true;
        };
    }

    pub fn replay(self: *Mock, iface: IFace, id: u64, input: *std.Io.Reader) !void {
        var length_bytes: [2]u8 = undefined;
        try input.readSliceAll(&length_bytes);
        const length = std.mem.readInt(u16, &length_bytes, .big);
        if (length > max_frame) return error.FrameTooLarge;
        const buffer = self.allocate(iface, id)[0..length];
        input.readSliceAll(buffer) catch |err| {
            release(self, buffer);
            return err;
        };
        self.input = buffer;
        self.current = id;
        defer self.current = null;
        Log.packet_id = id;
        Log.seen = false;
        defer Log.packet_id = null;
        const nic = self.api();
        var views: Router.Protocols.ViewStack = .{};
        Ethernet.handle(nic.receive(iface).?, nic, iface, &views) catch |err| {
            self.emit('E', id, @errorName(err));
            nic.release(buffer);
        };
        if (Log.seen) self.emit('U', id, &.{});
    }
};
