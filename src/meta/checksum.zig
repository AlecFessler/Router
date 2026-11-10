const std = @import("std");
const Router = @import("router");

const ViewModule = Router.Meta.View;
const View = ViewModule.View;
const IPv4 = Router.Protocols.IPv4;

fn rangeIsByteAligned(comptime V: type, comptime start: V.Field, comptime inclusive_end: V.Field) bool {
    if (@intFromEnum(start) > @intFromEnum(inclusive_end)) return false;
    const first = ViewModule.bitInfo(V.BaseType, @intFromEnum(start));
    const last = ViewModule.bitInfo(V.BaseType, @intFromEnum(inclusive_end));
    return (first == null or first.?.first) and
        (last == null or last.?.end == @intFromEnum(inclusive_end) + 1);
}

pub fn Checksum(comptime V: type) type {
    return struct {
        view: V,
        sum: u64 = 0,
        pending_byte: ?u8 = null,

        const Self = @This();

        fn addBytes(self: *Self, bytes: []const u8) void {
            for (bytes) |byte| {
                if (self.pending_byte) |high| {
                    self.sum += (@as(u16, high) << 8) | byte;
                    self.pending_byte = null;
                } else {
                    self.pending_byte = byte;
                }
            }
        }

        fn addWord(self: *Self, word: u16) void {
            self.addBytes(&.{ @intCast(word >> 8), @intCast(word & 0xff) });
        }

        pub fn addFields(self: *Self, comptime start: V.Field, comptime inclusive_end: V.Field) void {
            if (comptime !rangeIsByteAligned(V, start, inclusive_end))
                @compileError("Checksum field ranges must contain whole bytes");

            inline for (@as(usize, @intFromEnum(start))..@as(usize, @intFromEnum(inclusive_end)) + 1) |index| {
                if (self.view.wireBytes(@enumFromInt(index))) |bytes| self.addBytes(bytes);
            }
        }

        pub fn addPseudoheader(self: *Self, ip_view: anytype) error{InvalidField}!void {
            const IpView = @TypeOf(ip_view);
            const IPv4View = IPv4.IPv4PacketView;

            if (comptime IpView == IPv4View) {
                const header_bytes: u16 = @as(u16, ip_view.get(.ihl)) * 4;
                const total_length = ip_view.get(.total_length);
                if (total_length < header_bytes) return error.InvalidField;
                const length = total_length - header_bytes;
                const src = ip_view.get(.src);
                const dst = ip_view.get(.dst);
                self.addBytes(&src);
                self.addBytes(&dst);
                self.addBytes(&.{ 0, @intFromEnum(ip_view.get(.protocol)) });
                self.addWord(length);
            } else {
                @compileError("addPseudoheader() requires an IPv4 packet view");
            }
        }

        pub fn validate(self: *const Self) error{BadChecksum}!void {
            var sum = self.sum;
            if (self.pending_byte) |byte| sum += @as(u16, byte) << 8;
            while (sum >> 16 != 0) sum = (sum & 0xffff) + (sum >> 16);
            if (sum != 0xffff) return error.BadChecksum;
        }
    };
}

test "Checksum adds field ranges across odd byte boundaries" {
    const TestPacket = struct {
        first: [1]u8,
        second: [1]u8,
        checksum: u16,
    };
    const TestView = View(TestPacket);
    var bytes = [_]u8{ 0x12, 0x34, 0xed, 0xcb };
    var reader: std.Io.Reader = .fixed(&bytes);
    var view: TestView = undefined;
    try view.takeFields(.first, .checksum, &reader);

    var checksum = view.checksum();
    checksum.addFields(.first, .first);
    checksum.addFields(.second, .checksum);
    try checksum.validate();

    bytes[1] = 0x35;
    var bad_checksum = view.checksum();
    bad_checksum.addFields(.first, .checksum);
    try std.testing.expectError(error.BadChecksum, bad_checksum.validate());
}

test "Checksum adds an IPv4 pseudoheader" {
    const ip_bytes = [_]u8{
        0x45, 0x00, 0x00, 0x18, 0x12, 0x34, 0x40, 0x00,
        0x40, 0x11, 0xa5, 0x4d, 0xc0, 0xa8, 0x01, 0x01,
        0xc0, 0xa8, 0x01, 0x02, 0xde, 0xad, 0xbe, 0xef,
    };
    const ip_view = try IPv4.parse(&ip_bytes);

    const TestPacket = struct { bytes: [4]u8 };
    const TestView = View(TestPacket);
    var transport_bytes = [_]u8{ 0x12, 0x34, 0x6a, 0x62 };
    var reader: std.Io.Reader = .fixed(&transport_bytes);
    var transport_view: TestView = undefined;
    try transport_view.takeField(.bytes, &reader);

    var checksum = transport_view.checksum();
    try checksum.addPseudoheader(ip_view);
    checksum.addFields(.bytes, .bytes);
    try checksum.validate();
}
