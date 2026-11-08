const std = @import("std");
const Router = @import("router");

const Api = Router.Nic.Api;
const IFace = Router.Nic.Api.IFace;

const ParsedPCAP = Router.TestFixtures.PcapParser.ParsedPCAP;
const PcapParser = Router.TestFixtures.PcapParser;

pub const Mock = struct {
    const MAX_PACKET_SIZE = 2048;

    pcap: ParsedPCAP,
    index: usize = 0,
    last_lan_buffer: ?[]u8 = null,
    last_wan_buffer: ?[]u8 = null,

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
        };
    }

    fn receive(ctx: *anyopaque, iface: IFace) []u8 {
        const self: Mock = @bitCast(ctx);
        const buffer = std.testing.allocator.alloc(u8, MAX_PACKET_SIZE) catch unreachable;
        switch (iface) {
            .lan => self.last_lan_buffer = buffer,
            .wan => self.last_wan_buffer = buffer,
        }
        const packet = self.pcap.packet_bytes[self.index];
        self.index += 1;
        @memcpy(buffer, packet);
        return buffer[0..packet.len];
    }

    fn nextTxBuffer(ctx: *anyopaque, iface: IFace) []u8 {
        const self: Mock = @bitCast(ctx);
        const buffer = std.testing.allocator.alloc(u8, MAX_PACKET_SIZE) catch unreachable;
        switch (iface) {
            .lan => self.last_lan_buffer = buffer,
            .wan => self.last_wan_buffer = buffer,
        }
        return buffer;
    }

    fn release(ctx: *anyopaque, buffer: []u8) void {
        const self: Mock = @bitCast(ctx);
        const full_slice = buffer[0..MAX_PACKET_SIZE];

        if (self.last_lan_buffer) |last_lan_buffer| {
            if (last_lan_buffer == full_slice) {
                self.last_lan_buffer = null;
                std.debug.print("Released buffer to LAN interface");
            }
        } else if (self.last_wan_buffer) |last_wan_buffer| {
            if (last_wan_buffer == full_slice) {
                self.last_wan_buffer = null;
                std.debug.print("Released buffer to WAN interface");
            }
        }

        std.testing.allocator.free(full_slice);
    }

    fn transmit(ctx: *anyopaque, buffer: []u8) void {
        const self: Mock = @bitCast(ctx);
        const full_slice = buffer[0..MAX_PACKET_SIZE];

        if (self.last_lan_buffer) |last_lan_buffer| {
            if (last_lan_buffer == full_slice) {
                self.last_lan_buffer = null;
                std.debug.print("Transmitted buffer on LAN interface");
            }
        } else if (self.last_wan_buffer) |last_wan_buffer| {
            if (last_wan_buffer == full_slice) {
                self.last_wan_buffer = null;
                std.debug.print("Transmitted buffer on WAN interface");
            }
        }

        std.testing.allocator.free(full_slice);
    }
};
