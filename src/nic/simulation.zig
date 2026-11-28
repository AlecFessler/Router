//! Each worker owns one RX cursor. A buffer carries its egress across ARP handoffs.
const std = @import("std");
const Router = @import("router");

const Api = Router.Nic.Api.Api;
const IFace = Router.Nic.Api.IFace;
pub threadlocal var phase: u64 = 0;

const header = "\xd4\xc3\xb2\xa1\x02\x00\x04\x00" ++ "\x00" ** 8 ++ "\xff\xff\x00\x00\x01\x00\x00\x00";

pub const Capture = struct {
    input: []const u8,
    endian: std.builtin.Endian,
    nano: bool,

    pub fn init(data: []const u8) !Capture {
        if (data.len < 24) return error.TruncatedPcap;
        const magic = std.mem.readInt(u32, data[0..4], .little);
        const endian: std.builtin.Endian = switch (magic) {
            0xa1b2c3d4, 0xa1b23c4d => .little,
            0xd4c3b2a1, 0x4d3cb2a1 => .big,
            else => return error.UnsupportedPcap,
        };
        if (std.mem.readInt(u16, data[4..6], endian) != 2 or
            std.mem.readInt(u16, data[6..8], endian) != 4 or
            std.mem.readInt(u32, data[20..24], endian) != 1) return error.ExpectedEthernetPcap;
        return .{
            .input = data[24..],
            .endian = endian,
            .nano = magic == 0xa1b23c4d or magic == 0x4d3cb2a1,
        };
    }

    pub fn checkedPhase(self: Capture) !?u64 {
        if (self.input.len > 0 and self.input.len < 16) return error.TruncatedPcap;
        return self.nextPhase();
    }

    pub fn nextPhase(self: Capture) ?u64 {
        if (self.input.len == 0) return null;
        return @as(u64, std.mem.readInt(u32, self.input[0..4], self.endian)) * 1000 + std.mem.readInt(u32, self.input[4..8], self.endian) / @as(u32, if (self.nano) 1_000_000 else 1000);
    }

    pub fn pop(self: *Capture) ![]const u8 {
        if (self.input.len < 16) return error.TruncatedPcap;
        const n = std.mem.readInt(u32, self.input[8..12], self.endian);
        if (n != std.mem.readInt(u32, self.input[12..16], self.endian) or
            n > self.input.len - 16 or n > 65535) return error.InvalidCapturedLength;
        const frame = self.input[16..][0..n];
        self.input = self.input[16 + n ..];
        return frame;
    }
};

pub const Output = struct {
    file: std.Io.File,
    writer: std.Io.File.Writer,
    buffer: [65536]u8,
    mutex: std.Io.Mutex = .init,
    failed: bool = false,

    pub fn open(self: *Output, io: std.Io, dir: std.Io.Dir, name: []const u8) !void {
        self.file = try dir.createFile(io, name, .{});
        errdefer self.file.close(io);
        self.writer = self.file.writerStreaming(io, &self.buffer);
        try self.writer.interface.writeAll(header);
    }

    pub fn frame(self: *Output, io: std.Io, bytes: []const u8) void {
        var record: [16]u8 = @splat(0);
        std.mem.writeInt(u32, record[0..4], @intCast(phase / 1000), .little);
        std.mem.writeInt(u32, record[4..8], @intCast(phase % 1000 * 1000), .little);
        for ([_]usize{ 8, 12 }) |i| std.mem.writeInt(u32, record[i..][0..4], @intCast(bytes.len), .little);
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        if (self.failed) return;
        var parts = [_][]const u8{ &record, bytes };
        self.writer.interface.writeVecAll(&parts) catch {
            self.failed = true;
        };
    }
};

pub const Observation = struct {
    frames: std.ArrayList(struct { iface: IFace, start: usize, len: usize }) = .empty,
    bytes: std.ArrayList(u8) = .empty,
    count: usize = 0,

    pub fn deinit(self: *Observation, alloc: std.mem.Allocator) void {
        self.frames.deinit(alloc);
        self.bytes.deinit(alloc);
    }

    fn record(self: *Observation, alloc: std.mem.Allocator, iface: IFace, buffer: []const u8) void {
        if (self.count == 0) {
            self.frames.clearRetainingCapacity();
            self.bytes.clearRetainingCapacity();
        }
        self.frames.append(alloc, .{
            .iface = iface,
            .start = self.bytes.items.len,
            .len = buffer.len,
        }) catch @panic("mock NIC out of memory");
        self.bytes.appendSlice(alloc, buffer) catch @panic("mock NIC out of memory");
        self.count += 1;
    }

    pub fn take(self: *Observation, index: usize, iface: IFace) ![]u8 {
        if (index >= self.count) return error.WrongTxCount;
        const frame = self.frames.items[index];
        if (frame.iface != iface) return error.UnexpectedTx;
        return self.bytes.items[frame.start..][0..frame.len];
    }
};

pub threadlocal var observation: ?*Observation = null;
threadlocal var injected: ?[]const u8 = null;

pub const Mock = struct {
    alloc: std.mem.Allocator,
    io: std.Io,
    captures: ?[2]Capture = null,
    outputs: ?*[2]Output = null,
    rx_outputs: ?*[2]Output = null,
    outstanding: std.atomic.Value(usize) = .init(0),

    pub fn inject(self: *Mock, iface: IFace, bytes: []const u8) []u8 {
        injected = bytes;
        return self.api().receive(iface).?;
    }

    pub fn api(self: *Mock) Api {
        return .{
            .ptr = self,
            .vtable = &.{
                .receive = receive,
                .release = release,
                .transmit = transmit,
                .nextTxBuffer = nextTxBuffer,
                .macAddress = macAddress,
            },
        };
    }

    fn allocate(self: *Mock, iface: IFace, n: usize) []u8 {
        const allocation = self.alloc.alloc(u8, n + 5) catch @panic("mock NIC out of memory");
        allocation[0] = @intFromEnum(iface);
        std.mem.writeInt(u32, allocation[1..5], @intCast(n), .little);
        _ = self.outstanding.fetchAdd(1, .monotonic);
        return allocation[5..];
    }

    fn receive(ctx: *anyopaque, iface: IFace) ?[]u8 {
        const self: *Mock = @ptrCast(@alignCast(ctx));
        const bytes = if (injected) |input| blk: {
            injected = null;
            if (self.rx_outputs) |outputs| outputs[@intFromEnum(iface)].frame(self.io, input);
            break :blk input;
        } else blk: {
            const capture = &self.captures.?[@intFromEnum(iface)];
            if (capture.nextPhase() != phase) return null;
            break :blk capture.pop() catch unreachable;
        };
        const frame = self.allocate(if (iface == .lan) .wan else .lan, bytes.len);
        @memcpy(frame, bytes);
        return frame;
    }

    fn nextTxBuffer(ctx: *anyopaque, iface: IFace) []u8 {
        const self: *Mock = @ptrCast(@alignCast(ctx));
        return self.allocate(iface, 16384);
    }

    fn macAddress(_: *anyopaque, iface: IFace) [6]u8 {
        return .{ 2, 0, 0, 0, 0, if (iface == .lan) 1 else 2 };
    }

    fn transmit(ctx: *anyopaque, buffer: []u8) void {
        const self: *Mock = @ptrCast(@alignCast(ctx));
        const prefix = buffer.ptr - 5;
        if (self.outputs) |outputs| outputs[prefix[0]].frame(self.io, buffer);
        if (observation) |obs| obs.record(self.alloc, @enumFromInt(prefix[0]), buffer);
        release(ctx, buffer);
    }

    fn release(ctx: *anyopaque, buffer: []u8) void {
        const self: *Mock = @ptrCast(@alignCast(ctx));
        const prefix = buffer.ptr - 5;
        const n = std.mem.readInt(u32, prefix[1..5], .little);
        std.debug.assert(n >= buffer.len);
        self.alloc.free(prefix[0 .. 5 + @as(usize, n)]);
        _ = self.outstanding.fetchSub(1, .monotonic);
    }
};
