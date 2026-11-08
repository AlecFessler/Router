const std = @import("std");
const Router = @import("router");

const Api = Router.Nic.Api.Api;
const Cli = Router.Debug.Cli;
const IFace = Router.Nic.Api.IFace;
const PcapParser = Router.TestFixtures.PcapParser;
const ParsedPCAP = Router.TestFixtures.PcapParser.ParsedPCAP;

pub const Mock = struct {
    const MAX_PACKET_SIZE = 16384;

    const Origin = enum { rx_lan, rx_wan, tx_lan, tx_wan };
    const Outstanding = struct {
        allocation: []u8,
        origin: Origin,
    };

    alloc: std.mem.Allocator,
    index: usize = 0,
    outstanding: std.ArrayList(Outstanding) = .empty,
    pcap: ParsedPCAP,

    pub fn api(self: *Mock) Api {
        return .{
            .ptr = self,
            .vtable = &.{
                .receive = receive,
                .nextTxBuffer = nextTxBuffer,
                .release = release,
                .transmit = transmit,
            },
        };
    }

    pub fn init(
        file: []const u8,
        alloc: std.mem.Allocator,
    ) !Mock {
        return .{
            .pcap = try PcapParser.parse(file, alloc),
            .alloc = alloc,
        };
    }

    pub fn deinit(self: *Mock) void {
        std.debug.assert(self.outstanding.items.len == 0);
        self.outstanding.deinit(self.alloc);
        self.pcap.deinit(self.alloc);
    }

    fn track(self: *Mock, allocation: []u8, origin: Origin) void {
        self.outstanding.append(self.alloc, .{
            .allocation = allocation,
            .origin = origin,
        }) catch unreachable;
    }

    fn take(self: *Mock, buffer: []u8) Outstanding {
        for (self.outstanding.items, 0..) |entry, i| {
            if (entry.allocation.ptr == buffer.ptr) {
                return self.outstanding.swapRemove(i);
            }
        }
        @panic("mock NIC: buffer is not outstanding");
    }

    fn receive(ctx: *anyopaque, iface: IFace) ?[]u8 {
        const self: *Mock = @ptrCast(@alignCast(ctx));
        if (self.index == self.pcap.packet_bytes.len) return null;
        const packet = self.pcap.packet_bytes[self.index];
        std.debug.assert(packet.len <= MAX_PACKET_SIZE);
        const buffer = self.alloc.alloc(u8, MAX_PACKET_SIZE) catch unreachable;
        self.track(buffer, switch (iface) {
            .lan => .rx_lan,
            .wan => .rx_wan,
        });
        self.index += 1;
        @memcpy(buffer[0..packet.len], packet);
        Cli.enter(.rx, buffer[0..packet.len]);
        return buffer[0..packet.len];
    }

    fn nextTxBuffer(ctx: *anyopaque, iface: IFace) []u8 {
        const self: *Mock = @ptrCast(@alignCast(ctx));
        const buffer = self.alloc.alloc(u8, MAX_PACKET_SIZE) catch unreachable;
        self.track(buffer, switch (iface) {
            .lan => .tx_lan,
            .wan => .tx_wan,
        });
        return buffer;
    }

    fn release(ctx: *anyopaque, buffer: []u8) void {
        const self: *Mock = @ptrCast(@alignCast(ctx));
        const entry = self.take(buffer);
        Cli.enter(.release, buffer);
        switch (entry.origin) {
            .rx_lan => std.debug.print("Released received buffer to lan interface\n", .{}),
            .rx_wan => std.debug.print("Released received buffer to wan interface\n", .{}),
            .tx_lan => std.debug.print("Released transmit buffer to lan interface\n", .{}),
            .tx_wan => std.debug.print("Released transmit buffer to wan interface\n", .{}),
        }
        self.alloc.free(entry.allocation);
    }

    fn transmit(ctx: *anyopaque, buffer: []u8) void {
        const self: *Mock = @ptrCast(@alignCast(ctx));
        const entry = self.take(buffer);
        Cli.enter(.tx, buffer);
        const destination: IFace = switch (entry.origin) {
            .rx_lan, .tx_wan => .wan,
            .rx_wan, .tx_lan => .lan,
        };
        std.debug.print("Transmitted buffer on {s} interface\n", .{@tagName(destination)});
        self.alloc.free(entry.allocation);
    }
};
