const std = @import("std");
const Router = @import("router");

const ChecksumModule = Router.Meta.Checksum;
const EchoMsg = Router.Protocols.ICMPv4Messages.Echo.EchoMsg;
const ICMPv4Protocol = Router.Protocols.ICMPv4;
const IPv4Packet = Router.Protocols.IPv4.IPv4Packet;
const IPv4Protocol = Router.Protocols.IPv4;
const TcpProtocol = Router.Protocols.Tcp;
const UdpPacket = Router.Protocols.Udp.UdpPacket;
const UdpProtocol = Router.Protocols.Udp;
const ViewStack = Router.Protocols.ViewStack;

fn FieldType(
    comptime Base: type,
    comptime field: std.meta.FieldEnum(Base),
) type {
    @setEvalBranchQuota(10000);
    return @FieldType(Base, @tagName(field));
}

fn UnderlyingType(comptime T: type) type {
    return switch (@typeInfo(T)) {
        .optional => |info| info.child,
        else => T,
    };
}

fn Validation(comptime FieldT: type) type {
    const T = UnderlyingType(FieldT);
    return switch (@typeInfo(T)) {
        .int => union(enum) {
            lt: T,
            gt: T,
            lte: T,
            gte: T,
            multiple_of: T,
            eq: FieldT,
        },
        .@"enum" => |info| union(enum) {
            lt: info.tag_type,
            gt: info.tag_type,
            lte: info.tag_type,
            gte: info.tag_type,
            eq: FieldT,
            any,
        },
        else => union(enum) {
            eq: FieldT,
        },
    };
}

fn isBitField(comptime T: type) bool {
    return switch (@typeInfo(UnderlyingType(T))) {
        .int => @bitSizeOf(UnderlyingType(T)) % 8 != 0,
        .bool => true,
        else => false,
    };
}

pub const BitInfo = struct {
    first: bool,
    start: usize,
    width: usize,
    bytes: usize,
    offset: usize,
    end: usize,
};

pub fn bitInfo(comptime Base: type, comptime index: usize) ?BitInfo {
    @setEvalBranchQuota(10000);
    return comptime blk: {
        const fields = @typeInfo(Base).@"struct".fields;
        if (!isBitField(fields[index].type)) break :blk null;

        var cursor: usize = 0;
        while (cursor < fields.len) {
            if (!isBitField(fields[cursor].type)) {
                cursor += 1;
                continue;
            }
            const first = cursor;
            var total: usize = 0;
            while (cursor < fields.len and isBitField(fields[cursor].type)) {
                total += @bitSizeOf(UnderlyingType(fields[cursor].type));
                cursor += 1;
                if (total % 8 == 0) break;
            }
            if (total % 8 != 0) @compileError("Adjacent bit fields must fill whole bytes");
            if (total > 64) @compileError("A bit field group cannot exceed 64 bits");
            if (index >= first and index < cursor) {
                var start: usize = 0;
                for (fields[first..index]) |field| {
                    start += @bitSizeOf(UnderlyingType(field.type));
                }
                const width = @bitSizeOf(UnderlyingType(fields[index].type));
                break :blk .{
                    .first = first == index,
                    .start = start,
                    .width = width,
                    .bytes = total / 8,
                    .offset = total - start - width,
                    .end = cursor,
                };
            }
        }
        unreachable;
    };
}

fn readBits(bytes: [*]const u8, start: usize, width: usize) u64 {
    var value: u64 = 0;
    for (start..start + width) |bit| {
        value = (value << 1) | ((bytes[bit / 8] >> @intCast(7 - bit % 8)) & 1);
    }
    return value;
}

fn writeBits(bytes: [*]u8, start: usize, width: usize, value: u64) void {
    for (start..start + width) |bit| {
        const shift: u6 = @intCast(width - 1 - (bit - start));
        const mask: u8 = @as(u8, 1) << @intCast(7 - bit % 8);
        if ((value >> shift) & 1 != 0) {
            bytes[bit / 8] |= mask;
        } else {
            bytes[bit / 8] &= ~mask;
        }
    }
}

pub fn View(Base: type) type {
    @setEvalBranchQuota(5000);
    const base_info = @typeInfo(Base).@"struct";
    const fields = base_info.fields;
    var field_names: [fields.len][:0]const u8 = undefined;
    var field_types: [fields.len]type = undefined;
    const attributes = [_]std.builtin.Type.StructField.Attributes{.{}} ** fields.len;

    inline for (fields, 0..) |field, i| {
        field_names[i] = field.name;

        const T = UnderlyingType(field.type);
        switch (@typeInfo(T)) {
            .int, .bool => {},
            .@"enum" => |info| {
                if (@bitSizeOf(info.tag_type) % 8 != 0)
                    @compileError("Enum backing integers must be whole-byte sized");
            },
            .array => |info| {
                if (info.child != u8)
                    @compileError("Only byte arrays are supported");
            },
            .pointer => |info| {
                if (info.size != .slice or info.child != u8)
                    @compileError("Only byte slices are supported");
            },
            else => @compileError("Unsupported field type"),
        }

        const StorageType = switch (@typeInfo(T)) {
            .@"enum" => |info| info.tag_type,
            else => T,
        };

        const ViewType = if (bitInfo(Base, i)) |bit|
            *align(1:bit.offset:bit.bytes) StorageType
        else switch (@typeInfo(T)) {
            .pointer => T,
            else => @Pointer(
                .one,
                .{ .@"align" = 1 },
                StorageType,
                null,
            ),
        };

        field_types[i] = switch (@typeInfo(field.type)) {
            .optional => ?ViewType,
            else => ViewType,
        };
    }

    const ViewFields = @Struct(
        .auto,
        null,
        &field_names,
        &field_types,
        &attributes,
    );

    const FieldEnum = std.meta.FieldEnum(Base);

    return struct {
        pub const BaseType = Base;
        pub const Field = FieldEnum;

        fields: ViewFields,
        bit_group: []u8 = undefined,

        pub fn takeField(
            self: *@This(),
            comptime field: FieldEnum,
            reader: *std.Io.Reader,
        ) !void {
            const T = UnderlyingType(FieldType(Base, field));
            const PtrType = UnderlyingType(@FieldType(ViewFields, @tagName(field)));
            const index = @intFromEnum(field);

            switch (@typeInfo(T)) {
                .pointer => @compileError("Use takeBytes() for slices"),
                else => {},
            }

            if (comptime bitInfo(Base, index)) |bit| {
                if (bit.first) self.bit_group = try reader.take(bit.bytes);
                @field(self.fields, @tagName(field)) = @ptrCast(&self.bit_group[0]);
                return;
            }

            @field(self.fields, @tagName(field)) =
                @ptrCast(try reader.takeArray(@sizeOf(@typeInfo(PtrType).pointer.child)));
        }

        pub fn takeFields(
            self: *@This(),
            comptime start: FieldEnum,
            comptime inclusive_end: FieldEnum,
            reader: *std.Io.Reader,
        ) !void {
            if (@intFromEnum(start) > @intFromEnum(inclusive_end))
                @compileError("takeFields() start must not follow its end");

            inline for (@as(usize, @intFromEnum(start))..@as(usize, @intFromEnum(inclusive_end)) + 1) |index| {
                try self.takeField(@enumFromInt(index), reader);
            }
        }

        pub fn takeBytes(
            self: *@This(),
            comptime field: FieldEnum,
            len: usize,
            reader: *std.Io.Reader,
        ) !void {
            const T = UnderlyingType(FieldType(Base, field));
            switch (@typeInfo(T)) {
                .pointer => {},
                else => @compileError("Use takeField() for non-slices"),
            }

            @field(self.fields, @tagName(field)) = try reader.take(len);
        }

        pub fn checksum(self: @This()) ChecksumModule.Checksum(@This()) {
            return .{ .view = self };
        }

        pub fn wireBytes(self: *const @This(), comptime field: FieldEnum) ?[]const u8 {
            const T = UnderlyingType(FieldType(Base, field));
            const storage = @field(self.fields, @tagName(field));
            const ptr = if (comptime @typeInfo(FieldType(Base, field)) == .optional)
                storage orelse return null
            else
                storage;

            if (comptime bitInfo(Base, @intFromEnum(field))) |bit| {
                if (!bit.first) return &.{};
                const bytes: [*]const u8 = @ptrCast(ptr);
                return bytes[0..bit.bytes];
            }

            if (comptime @typeInfo(T) == .pointer) return ptr;
            const bytes: [*]const u8 = @ptrCast(ptr);
            return bytes[0..@sizeOf(T)];
        }

        pub fn serialize(
            base: Base,
            writer: *std.Io.Writer,
        ) !void {
            inline for (fields, 0..) |field, index| {
                if (comptime bitInfo(Base, index)) |bit| {
                    if (bit.first) {
                        var bytes: [bit.bytes]u8 = .{0} ** bit.bytes;
                        var present: ?bool = null;
                        inline for (fields, 0..) |group_field, group_index| {
                            if (group_index >= index and group_index < bit.end) {
                                const group_value = @field(base, group_field.name);
                                const is_present = if (@typeInfo(group_field.type) == .optional)
                                    group_value != null
                                else
                                    true;
                                if (present) |previous| {
                                    if (previous != is_present) return error.InvalidField;
                                } else {
                                    present = is_present;
                                }
                                if (is_present) {
                                    const value = if (@typeInfo(group_field.type) == .optional)
                                        group_value.?
                                    else
                                        group_value;
                                    const raw: u64 = if (@TypeOf(value) == bool) @intFromBool(value) else value;
                                    const info = bitInfo(Base, group_index).?;
                                    writeBits(&bytes, info.start, info.width, raw);
                                }
                            }
                        }
                        if (present.?) try writer.writeAll(&bytes);
                    }
                    continue;
                }
                field_value: {
                    const T = UnderlyingType(field.type);
                    const storage = @field(base, field.name);
                    const value = if (@typeInfo(field.type) == .optional)
                        storage orelse break :field_value
                    else
                        storage;

                    switch (@typeInfo(T)) {
                        .int => {
                            try writer.writeInt(T, value, .big);
                        },
                        .@"enum" => |info| {
                            try writer.writeInt(info.tag_type, @intFromEnum(value), .big);
                        },
                        .array => {
                            try writer.writeAll(&value);
                        },
                        .pointer => {
                            try writer.writeAll(value);
                        },
                        else => unreachable,
                    }
                }
            }
        }

        pub fn fieldCmp(
            self: *const @This(),
            comptime field: FieldEnum,
            condition: Validation(FieldType(Base, field)),
        ) bool {
            const FieldT = FieldType(Base, field);
            const T = UnderlyingType(FieldT);
            const storage = @field(self.fields, @tagName(field));

            if (comptime @typeInfo(FieldT) == .optional) {
                if (condition == .eq and condition.eq == null) {
                    return storage == null;
                }
                if (storage == null) return false;
            }

            const actual: T = if (comptime @typeInfo(T) == .@"enum") blk: {
                const ptr = if (comptime @typeInfo(FieldT) == .optional) storage.? else storage;
                const raw = std.mem.bigToNative(@typeInfo(T).@"enum".tag_type, ptr.*);
                break :blk std.enums.fromInt(T, raw) orelse return false;
            } else if (comptime @typeInfo(FieldT) == .optional)
                self.get(field).?
            else
                self.get(field);

            if (condition == .eq) {
                const value: T = if (comptime @typeInfo(FieldT) == .optional)
                    condition.eq.?
                else
                    condition.eq;
                const matches = if (comptime @typeInfo(T) == .pointer)
                    std.mem.eql(u8, actual, value)
                else
                    std.meta.eql(actual, value);
                return matches;
            }

            return switch (@typeInfo(T)) {
                .int => switch (condition) {
                    .lt => |value| actual < value,
                    .gt => |value| actual > value,
                    .lte => |value| actual <= value,
                    .gte => |value| actual >= value,
                    .multiple_of => |value| value != 0 and @rem(actual, value) == 0,
                    .eq => unreachable,
                },
                .@"enum" => switch (condition) {
                    .any => true,
                    .lt => |value| @intFromEnum(actual) < value,
                    .gt => |value| @intFromEnum(actual) > value,
                    .lte => |value| @intFromEnum(actual) <= value,
                    .gte => |value| @intFromEnum(actual) >= value,
                    .eq => unreachable,
                },
                else => unreachable,
            };
        }

        pub fn validate(
            self: *const @This(),
            comptime field: FieldEnum,
            condition: Validation(FieldType(Base, field)),
        ) error{InvalidField}!void {
            if (!self.fieldCmp(field, condition)) return error.InvalidField;
        }

        pub fn get(
            self: *const @This(),
            comptime field: FieldEnum,
        ) FieldType(Base, field) {
            const T = UnderlyingType(FieldType(Base, field));
            const storage = @field(self.fields, @tagName(field));

            const ptr = if (comptime @typeInfo(FieldType(Base, field)) == .optional)
                storage orelse return null
            else
                storage;

            if (comptime bitInfo(Base, @intFromEnum(field))) |bit| {
                const raw = readBits(@ptrCast(ptr), bit.start, bit.width);
                return if (T == bool) raw != 0 else @intCast(raw);
            }

            switch (@typeInfo(T)) {
                .@"enum" => |info| {
                    return @enumFromInt(std.mem.bigToNative(info.tag_type, ptr.*));
                },

                .int => {
                    return std.mem.bigToNative(T, ptr.*);
                },

                .pointer => |info| {
                    if (info.size == .slice) {
                        return ptr;
                    }
                    return ptr.*;
                },

                else => {
                    return ptr.*;
                },
            }
        }

        pub fn set(
            self: *@This(),
            comptime field: FieldEnum,
            value: FieldType(Base, field),
        ) void {
            const T = UnderlyingType(FieldType(Base, field));

            if (@typeInfo(FieldType(Base, field)) == .optional) {
                if (value == null) {
                    @field(self.fields, @tagName(field)) = null;
                    return;
                }
            }

            const storage = @field(self.fields, @tagName(field));

            const ptr = if (comptime @typeInfo(FieldType(Base, field)) == .optional)
                storage orelse @panic("Cannot set absent field")
            else
                storage;

            const actual_value = if (comptime @typeInfo(FieldType(Base, field)) == .optional)
                value.?
            else
                value;

            if (comptime bitInfo(Base, @intFromEnum(field))) |bit| {
                const raw: u64 = if (T == bool) @intFromBool(actual_value) else actual_value;
                writeBits(@ptrCast(ptr), bit.start, bit.width, raw);
                return;
            }

            switch (@typeInfo(T)) {
                .@"enum" => |info| {
                    ptr.* = std.mem.nativeToBig(info.tag_type, @intFromEnum(actual_value));
                },

                .int => {
                    ptr.* = std.mem.nativeToBig(T, actual_value);
                },

                .pointer => |info| {
                    if (info.size == .slice) {
                        @field(self.fields, @tagName(field)) = actual_value;
                    } else {
                        ptr.* = actual_value;
                    }
                },

                else => {
                    ptr.* = actual_value;
                },
            }
        }

        fn checksumAffectedBytes(self: *const @This(), comptime field: FieldEnum) []u8 {
            const FieldT = FieldType(Base, field);
            const T = UnderlyingType(FieldT);
            if (comptime @typeInfo(FieldT) == .optional or @typeInfo(T) == .pointer)
                @compileError("setUpdateChecksum() requires a fixed-size, present field");

            const first_storage = @field(self.fields, fields[0].name);
            const field_storage = @field(self.fields, @tagName(field));
            const first: [*]u8 = @ptrCast(first_storage);
            const current: [*]u8 = @ptrCast(field_storage);
            const offset = @intFromPtr(current) - @intFromPtr(first);
            const field_bytes = if (comptime bitInfo(Base, @intFromEnum(field))) |bit|
                bit.bytes
            else
                @sizeOf(T);
            const start = offset & ~@as(usize, 1);
            const end = (offset + field_bytes + 1) & ~@as(usize, 1);
            return first[start..end];
        }

        pub fn setUpdateChecksum(
            self: *@This(),
            comptime field: FieldEnum,
            value: FieldType(Base, field),
            views: *ViewStack,
        ) void {
            const checksum_view = if (comptime Base == EchoMsg) views.getView(.icmpv4) else self;
            const ChecksumView = @TypeOf(checksum_view.*);
            const ChecksumBase = ChecksumView.BaseType;
            const checksum_field: ChecksumView.Field = if (comptime @hasField(ChecksumBase, "header_checksum"))
                .header_checksum
            else if (comptime @hasField(ChecksumBase, "checksum"))
                .checksum
            else
                @compileError("setUpdateChecksum() requires a checksum field");
            if (comptime ChecksumView == @This() and field == checksum_field)
                @compileError("setUpdateChecksum() cannot set the checksum field itself");
            if (comptime @FieldType(ChecksumBase, @tagName(checksum_field)) != u16)
                @compileError("setUpdateChecksum() requires a u16 checksum field");
            if (comptime Base == IPv4Packet) {
                if (comptime field == .ihl or field == .total_length or field == .protocol)
                    @compileError("setUpdateChecksum() cannot change IPv4 pseudoheader length or protocol");
            }

            const old_checksum = checksum_view.get(checksum_field);
            const affected = self.checksumAffectedBytes(field);
            const old_sum = ChecksumModule.checksumContribution(affected);
            self.set(field, value);
            const new_sum = ChecksumModule.checksumContribution(affected);
            if (old_sum == new_sum) return;

            if (comptime Base == UdpPacket) {
                if (old_checksum == 0) return; // IPv4 UDP checksum disabled.
            }

            var new_checksum = ChecksumModule.update(old_checksum, old_sum, new_sum, affected.len / 2);
            if (comptime Base == UdpPacket) {
                if (new_checksum == 0) new_checksum = 0xffff;
            }
            checksum_view.set(checksum_field, new_checksum);

            if (comptime Base == IPv4Packet) {
                if (comptime field == .src or field == .dst) {
                    // Later fragments do not contain a TCP or UDP checksum field.
                    if (self.get(.fragment_offset) != 0) return;
                    std.debug.assert(affected.len == 4);
                    switch (self.get(.protocol)) {
                        .tcp => {
                            const tcp_view = views.getView(.tcp);
                            const updated = ChecksumModule.update(tcp_view.get(.checksum), old_sum, new_sum, 2);
                            tcp_view.set(.checksum, updated);
                        },
                        .udp => {
                            const udp_view = views.getView(.udp);
                            const old_udp_checksum = udp_view.get(.checksum);
                            if (old_udp_checksum != 0) {
                                var updated = ChecksumModule.update(old_udp_checksum, old_sum, new_sum, 2);
                                if (updated == 0) updated = 0xffff;
                                udp_view.set(.checksum, updated);
                            }
                        },
                        else => {},
                    }
                }
            }
        }

        fn printValue(comptime T: type, value: T, left_pad: usize) void {
            switch (@typeInfo(T)) {
                .optional => |info| {
                    if (value) |present| {
                        printValue(info.child, present, left_pad);
                    } else {
                        std.debug.print("null", .{});
                    }
                },
                .int => std.debug.print("0x{x}", .{value}),
                .bool => std.debug.print("{}", .{value}),
                .@"enum" => {
                    if (std.enums.tagName(T, value)) |name| {
                        std.debug.print("{s}", .{name});
                    } else {
                        std.debug.print("0x{x}", .{@intFromEnum(value)});
                    }
                },
                .array => |info| {
                    switch (info.len) {
                        4 => {
                            inline for (0..4) |i| {
                                if (i != 0) std.debug.print(".", .{});
                                std.debug.print("{}", .{value[i]});
                            }
                        },
                        6 => {
                            inline for (0..6) |i| {
                                if (i != 0) std.debug.print(":", .{});
                                std.debug.print("{x:0>2}", .{value[i]});
                            }
                        },
                        16 => {
                            var groups: [8]u16 = undefined;
                            inline for (0..8) |i| {
                                groups[i] = (@as(u16, value[i * 2]) << 8) |
                                    @as(u16, value[i * 2 + 1]);
                            }
                            var best_start: usize = 0;
                            var best_len: usize = 0;
                            var i: usize = 0;
                            while (i < groups.len) {
                                if (groups[i] != 0) {
                                    i += 1;
                                    continue;
                                }
                                const start = i;
                                while (i < groups.len and groups[i] == 0) : (i += 1) {}
                                const len = i - start;
                                if (len >= 2 and len > best_len) {
                                    best_start = start;
                                    best_len = len;
                                }
                            }
                            i = 0;
                            while (i < groups.len) {
                                if (best_len >= 2 and i == best_start) {
                                    std.debug.print("::", .{});
                                    i += best_len;
                                    continue;
                                }
                                if (i != 0 and i != best_start + best_len)
                                    std.debug.print(":", .{});
                                std.debug.print("{x}", .{groups[i]});
                                i += 1;
                            }
                        },
                        else => {
                            if (info.child == u8 and info.len >= 32) {
                                for (value, 0..) |byte, i| {
                                    if (i % 16 == 0) {
                                        std.debug.print("\n", .{});
                                        for (0..left_pad + 2) |_| std.debug.print(" ", .{});
                                        std.debug.print("{x:0>4}: ", .{i});
                                    } else {
                                        std.debug.print(" ", .{});
                                    }
                                    std.debug.print("{x:0>2}", .{byte});
                                }
                            } else {
                                inline for (0..info.len) |i| {
                                    if (i != 0) std.debug.print(" ", .{});
                                    std.debug.print("{x:0>2}", .{value[i]});
                                }
                            }
                        },
                    }
                },
                .pointer => |info| {
                    if (info.size == .slice) {
                        std.debug.print("0x{x} ({} bytes)", .{
                            @intFromPtr(value.ptr),
                            value.len,
                        });
                    }
                },
                else => unreachable,
            }
        }

        pub fn print(self: *const @This(), left_pad: usize) void {
            inline for (fields) |field| {
                const field_enum = @field(FieldEnum, field.name);
                for (0..left_pad) |_| std.debug.print(" ", .{});
                std.debug.print("{s}: ", .{field.name});
                printValue(field.type, self.get(field_enum), left_pad);
                std.debug.print("\n", .{});
            }
        }

        pub fn copy(self: *@This()) Base {
            var result: Base = undefined;
            inline for (fields) |field| {
                @field(result, field.name) = self.get(@field(FieldEnum, field.name));
            }
            return result;
        }
    };
}

const TestEnum = enum(u16) {
    first = 0xABCD,
    second = 0x1234,
};

const TestBase = struct {
    test_int: u16 = 0x0806,
    test_enum: TestEnum = .first,
    test_high_nibble: u4 = 9,
    test_low_twelve: u12 = 0xABC,
    test_array: [4]u8 = .{ 1, 2, 3, 4 },
    test_slice: []const u8 = &.{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF },
    test_optional_int: ?u16 = 0x8100,
    test_absent_int: ?u16 = null,
    test_optional_slice: ?[]const u8 = &.{ 0x11, 0x22, 0x33 },
    test_absent_slice: ?[]const u8 = null,
};

const TestView = View(TestBase);

const test_buffer = [_]u8{
    0x08, 0x06,
    0xAB, 0xCD,
    0x9A, 0xBC,
    0x01, 0x02,
    0x03, 0x04,
    0xAA, 0xBB,
    0xCC, 0xDD,
    0xEE, 0xFF,
    0x81, 0x00,
    0x11, 0x22,
    0x33,
};

fn parseTestBuffer(buffer: []u8) TestView {
    const default = TestBase{};
    var output: TestView = undefined;
    var reader: std.Io.Reader = .fixed(buffer);

    output.takeFields(.test_int, .test_array, &reader) catch unreachable;
    output.takeBytes(.test_slice, default.test_slice.len, &reader) catch unreachable;
    output.takeField(.test_optional_int, &reader) catch unreachable;
    output.fields.test_absent_int = null;
    output.takeBytes(.test_optional_slice, default.test_optional_slice.?.len, &reader) catch unreachable;
    output.fields.test_absent_slice = null;

    return output;
}

test "View() generates a struct with the expected field types" {
    var mutable = test_buffer;
    const test_view = parseTestBuffer(&mutable);

    try std.testing.expectEqual(
        *align(1) u16,
        @TypeOf(test_view.fields.test_int),
    );
    try std.testing.expectEqual(
        *align(1) @typeInfo(TestEnum).@"enum".tag_type,
        @TypeOf(test_view.fields.test_enum),
    );
    try std.testing.expectEqual(
        *align(1:12:2) u4,
        @TypeOf(test_view.fields.test_high_nibble),
    );
    try std.testing.expectEqual(
        *align(1:0:2) u12,
        @TypeOf(test_view.fields.test_low_twelve),
    );
    try std.testing.expectEqual(
        *align(1) [4]u8,
        @TypeOf(test_view.fields.test_array),
    );
    try std.testing.expectEqual(
        []const u8,
        @TypeOf(test_view.fields.test_slice),
    );
    try std.testing.expectEqual(
        ?*align(1) u16,
        @TypeOf(test_view.fields.test_optional_int),
    );
    try std.testing.expectEqual(
        ?*align(1) u16,
        @TypeOf(test_view.fields.test_absent_int),
    );
    try std.testing.expectEqual(
        ?[]const u8,
        @TypeOf(test_view.fields.test_optional_slice),
    );
    try std.testing.expectEqual(
        ?[]const u8,
        @TypeOf(test_view.fields.test_absent_slice),
    );
}

test "View.takeField() binds fields to the wire buffer" {
    var buffer = test_buffer;
    var reader: std.Io.Reader = .fixed(&buffer);
    var view: TestView = undefined;

    try view.takeField(.test_int, &reader);
    try view.takeField(.test_enum, &reader);
    try view.takeField(.test_high_nibble, &reader);
    try view.takeField(.test_low_twelve, &reader);
    try view.takeField(.test_array, &reader);

    try std.testing.expectEqual(
        @intFromPtr(&buffer[0]),
        @intFromPtr(view.fields.test_int),
    );
    try std.testing.expectEqual(
        @intFromPtr(&buffer[2]),
        @intFromPtr(view.fields.test_enum),
    );
    try std.testing.expectEqual(
        @intFromPtr(&buffer[4]),
        @intFromPtr(view.fields.test_high_nibble),
    );
    try std.testing.expectEqual(
        @intFromPtr(&buffer[6]),
        @intFromPtr(view.fields.test_array),
    );

    try std.testing.expectEqual(@as(u16, 0x0806), view.get(.test_int));
    try std.testing.expectEqual(TestEnum.first, view.get(.test_enum));
    try std.testing.expectEqual(@as(u4, 9), view.get(.test_high_nibble));
    try std.testing.expectEqual(@as(u12, 0xABC), view.get(.test_low_twelve));
    try std.testing.expectEqualDeep([4]u8{ 1, 2, 3, 4 }, view.get(.test_array));

    var optional_reader: std.Io.Reader = .fixed(buffer[16..]);
    try view.takeField(.test_optional_int, &optional_reader);

    try std.testing.expectEqual(
        @intFromPtr(&buffer[16]),
        @intFromPtr(view.fields.test_optional_int.?),
    );
    try std.testing.expectEqual(
        @as(?u16, 0x8100),
        view.get(.test_optional_int),
    );

    view.fields.test_absent_int = null;

    try std.testing.expectEqual(
        @as(?u16, null),
        view.get(.test_absent_int),
    );
}

test "View.takeBytes() binds slices to the wire buffer" {
    var buffer = test_buffer;
    var view: TestView = undefined;
    var reader: std.Io.Reader = .fixed(buffer[10..]);

    try view.takeBytes(.test_slice, 6, &reader);

    const slice = view.get(.test_slice);
    try std.testing.expectEqualSlices(
        u8,
        buffer[10..16],
        slice,
    );
    try std.testing.expectEqual(
        @intFromPtr(&buffer[10]),
        @intFromPtr(slice.ptr),
    );
    try std.testing.expectEqual(@as(usize, 6), slice.len);

    var optional_reader: std.Io.Reader = .fixed(buffer[18..]);
    try view.takeBytes(.test_optional_slice, 3, &optional_reader);

    const optional_slice = view.get(.test_optional_slice).?;
    try std.testing.expectEqualSlices(
        u8,
        buffer[18..21],
        optional_slice,
    );
    try std.testing.expectEqual(
        @intFromPtr(&buffer[18]),
        @intFromPtr(optional_slice.ptr),
    );
    try std.testing.expectEqual(@as(usize, 3), optional_slice.len);

    view.fields.test_absent_slice = null;

    try std.testing.expectEqual(
        @as(?[]const u8, null),
        view.get(.test_absent_slice),
    );
}

test "View.serialize() writes all field types correctly" {
    const value = TestBase{};
    var buffer: [test_buffer.len]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);

    try TestView.serialize(value, &writer);

    try std.testing.expectEqualSlices(
        u8,
        &test_buffer,
        &buffer,
    );
}

test "View.serialize() skips absent optional fields" {
    var value = TestBase{};
    value.test_optional_int = null;
    value.test_optional_slice = null;

    var buffer: [16]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);

    try TestView.serialize(value, &writer);

    try std.testing.expectEqualSlices(
        u8,
        test_buffer[0..16],
        &buffer,
    );

    value.test_optional_slice = &.{ 0x11, 0x22, 0x33 };

    var partial_buffer: [19]u8 = undefined;
    var partial_writer: std.Io.Writer = .fixed(&partial_buffer);

    try TestView.serialize(value, &partial_writer);

    try std.testing.expectEqualSlices(
        u8,
        test_buffer[0..16],
        partial_buffer[0..16],
    );
    try std.testing.expectEqualSlices(
        u8,
        test_buffer[18..21],
        partial_buffer[16..19],
    );
}

test "View.get() reads all field types correctly" {
    const expected = TestBase{};
    var buffer = test_buffer;
    var view = parseTestBuffer(&buffer);

    try std.testing.expectEqual(
        expected.test_int,
        view.get(.test_int),
    );
    try std.testing.expectEqual(
        expected.test_enum,
        view.get(.test_enum),
    );
    try std.testing.expectEqual(expected.test_high_nibble, view.get(.test_high_nibble));
    try std.testing.expectEqual(expected.test_low_twelve, view.get(.test_low_twelve));
    try std.testing.expectEqualDeep(
        expected.test_array,
        view.get(.test_array),
    );
    try std.testing.expectEqualSlices(
        u8,
        expected.test_slice,
        view.get(.test_slice),
    );
    try std.testing.expectEqual(
        expected.test_optional_int,
        view.get(.test_optional_int),
    );
    try std.testing.expectEqual(
        expected.test_absent_int,
        view.get(.test_absent_int),
    );
    try std.testing.expectEqualSlices(
        u8,
        expected.test_optional_slice.?,
        view.get(.test_optional_slice).?,
    );
    try std.testing.expectEqual(
        expected.test_absent_slice,
        view.get(.test_absent_slice),
    );
}

test "View.set() writes all field types correctly" {
    const expected = TestBase{};
    var buffer: [test_buffer.len]u8 = .{0} ** test_buffer.len;
    var view = parseTestBuffer(&buffer);

    view.set(.test_int, expected.test_int);
    view.set(.test_enum, expected.test_enum);
    view.set(.test_high_nibble, expected.test_high_nibble);
    view.set(.test_low_twelve, expected.test_low_twelve);
    view.set(.test_array, expected.test_array);
    view.set(.test_slice, expected.test_slice);
    view.set(.test_optional_int, expected.test_optional_int);
    view.set(.test_optional_slice, expected.test_optional_slice);

    try std.testing.expectEqualSlices(
        u8,
        test_buffer[0..10],
        buffer[0..10],
    );
    try std.testing.expectEqualSlices(
        u8,
        test_buffer[16..18],
        buffer[16..18],
    );
    try std.testing.expectEqual(
        expected.test_optional_int,
        view.get(.test_optional_int),
    );

    const actual_slice = view.get(.test_slice);
    try std.testing.expectEqual(
        @intFromPtr(expected.test_slice.ptr),
        @intFromPtr(actual_slice.ptr),
    );
    try std.testing.expectEqual(
        expected.test_slice.len,
        actual_slice.len,
    );

    const actual_optional_slice = view.get(.test_optional_slice).?;
    try std.testing.expectEqual(
        @intFromPtr(expected.test_optional_slice.?.ptr),
        @intFromPtr(actual_optional_slice.ptr),
    );
    try std.testing.expectEqual(
        expected.test_optional_slice.?.len,
        actual_optional_slice.len,
    );

    try std.testing.expectEqual(
        @as(?u16, null),
        view.get(.test_absent_int),
    );
    try std.testing.expectEqual(
        @as(?[]const u8, null),
        view.get(.test_absent_slice),
    );
}

test "View.set() clears optional fields without changing the wire buffer" {
    var buffer = test_buffer;
    var view = parseTestBuffer(&buffer);

    view.set(.test_optional_int, null);
    view.set(.test_optional_slice, null);
    view.set(.test_absent_int, null);
    view.set(.test_absent_slice, null);

    try std.testing.expectEqual(@as(?u16, null), view.get(.test_optional_int));
    try std.testing.expectEqual(@as(?[]const u8, null), view.get(.test_optional_slice));
    try std.testing.expectEqual(@as(?u16, null), view.get(.test_absent_int));
    try std.testing.expectEqual(@as(?[]const u8, null), view.get(.test_absent_slice));
    try std.testing.expectEqualSlices(u8, &test_buffer, &buffer);
}

test "View.validate() handles optional field presence and values" {
    const default = TestBase{};
    var buffer = test_buffer;
    var view = parseTestBuffer(&buffer);

    try view.validate(.test_int, .{ .eq = 0x0806 });
    try view.validate(.test_enum, .any);
    try view.validate(.test_enum, .{ .eq = .first });
    try view.validate(.test_high_nibble, .{ .eq = 9 });
    try view.validate(.test_low_twelve, .{ .eq = 0xABC });
    try view.validate(.test_array, .{ .eq = .{ 1, 2, 3, 4 } });
    try view.validate(.test_slice, .{ .eq = default.test_slice });
    try view.validate(.test_optional_int, .{ .eq = 0x8100 });
    try view.validate(.test_absent_int, .{ .eq = null });
    try view.validate(.test_optional_slice, .{ .eq = default.test_optional_slice });
    try view.validate(.test_absent_slice, .{ .eq = null });

    try std.testing.expectError(
        error.InvalidField,
        view.validate(.test_int, .{ .eq = 0x1234 }),
    );
    try std.testing.expectError(
        error.InvalidField,
        view.validate(.test_enum, .{ .eq = .second }),
    );
    try std.testing.expectError(
        error.InvalidField,
        view.validate(.test_slice, .{ .eq = &.{ 0xAA, 0xBB } }),
    );
    try std.testing.expectError(
        error.InvalidField,
        view.validate(.test_optional_int, .{ .eq = 0x1234 }),
    );
    try std.testing.expectError(
        error.InvalidField,
        view.validate(.test_optional_int, .{ .eq = null }),
    );
    try std.testing.expectError(
        error.InvalidField,
        view.validate(.test_absent_int, .{ .eq = 0x8100 }),
    );
    try std.testing.expectError(
        error.InvalidField,
        view.validate(.test_optional_slice, .{ .eq = &.{ 0x11, 0x22 } }),
    );
    try std.testing.expectError(
        error.InvalidField,
        view.validate(.test_absent_slice, .{ .eq = &.{0x11} }),
    );

    buffer[2] = 0xFF;
    buffer[3] = 0xFF;

    try std.testing.expectError(
        error.InvalidField,
        view.validate(.test_enum, .any),
    );
}

test "View.fieldCmp() compares fields without raising validation errors" {
    var buffer = test_buffer;
    const view = parseTestBuffer(&buffer);

    try std.testing.expect(view.fieldCmp(.test_int, .{ .eq = 0x0806 }));
    try std.testing.expect(!view.fieldCmp(.test_int, .{ .eq = 0x1234 }));
    try std.testing.expect(view.fieldCmp(.test_int, .{ .multiple_of = 2 }));
    try std.testing.expect(!view.fieldCmp(.test_int, .{ .multiple_of = 0 }));
    try std.testing.expect(view.fieldCmp(.test_enum, .any));
    try std.testing.expect(view.fieldCmp(.test_enum, .{ .lt = 0xFFFF }));
    try std.testing.expect(!view.fieldCmp(.test_enum, .{ .lt = 0xABCD }));
    try std.testing.expect(view.fieldCmp(.test_array, .{ .eq = .{ 1, 2, 3, 4 } }));
    try std.testing.expect(view.fieldCmp(.test_absent_int, .{ .eq = null }));
    try std.testing.expect(!view.fieldCmp(.test_absent_int, .{ .eq = 0 }));

    buffer[2] = 0xFF;
    buffer[3] = 0xFF;
    try std.testing.expect(!view.fieldCmp(.test_enum, .any));
}

test "setUpdateChecksum updates IPv4 and TCP checksums after address and port changes" {
    var packet = [_]u8{
        0x45, 0x00, 0x00, 0x2c, 0x12, 0x34, 0x40, 0x00,
        0x40, 0x06, 0xa5, 0x44, 0xc0, 0xa8, 0x01, 0x01,
        0xc0, 0xa8, 0x01, 0x02, 0x04, 0xd2, 0x01, 0xbb,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x50, 0x18, 0x10, 0x00, 0x3f, 0xcc, 0x00, 0x00,
        0x61, 0x62, 0x63, 0x64,
    };
    var ip_view = try IPv4Protocol.parse(&packet);
    var tcp_view = try TcpProtocol.parse(ip_view.get(.payload), ip_view);
    var views: ViewStack = .{};
    views.setView(.ipv4, &ip_view);
    views.setView(.tcp, &tcp_view);

    ip_view.setUpdateChecksum(.src, .{ 198, 51, 100, 10 }, &views);
    ip_view.setUpdateChecksum(.dst, .{ 203, 0, 113, 20 }, &views);
    ip_view.setUpdateChecksum(.ttl, 63, &views);
    ip_view.setUpdateChecksum(.dont_fragment, false, &views);
    tcp_view.setUpdateChecksum(.src_port, 40_000, &views);
    tcp_view.setUpdateChecksum(.dst_port, 8080, &views);

    const reparsed_ip = try IPv4Protocol.parse(&packet);
    const reparsed_tcp = try TcpProtocol.parse(reparsed_ip.get(.payload), reparsed_ip);
    try std.testing.expectEqualDeep(IPv4Protocol.IPv4{ 198, 51, 100, 10 }, reparsed_ip.get(.src));
    try std.testing.expectEqualDeep(IPv4Protocol.IPv4{ 203, 0, 113, 20 }, reparsed_ip.get(.dst));
    try std.testing.expectEqual(@as(u8, 63), reparsed_ip.get(.ttl));
    try std.testing.expect(!reparsed_ip.get(.dont_fragment));
    try std.testing.expectEqual(@as(u16, 40_000), reparsed_tcp.get(.src_port));
    try std.testing.expectEqual(@as(u16, 8080), reparsed_tcp.get(.dst_port));
}

test "setUpdateChecksum updates UDP pseudoheader and preserves disabled UDP checksum" {
    const original = [_]u8{
        0x45, 0x00, 0x00, 0x20, 0x12, 0x34, 0x40, 0x00,
        0x40, 0x11, 0xa5, 0x45, 0xc0, 0xa8, 0x01, 0x01,
        0xc0, 0xa8, 0x01, 0x02, 0x04, 0xd2, 0x00, 0x35,
        0x00, 0x0c, 0xb2, 0xb4, 0x61, 0x62, 0x63, 0x64,
    };
    for ([_]bool{ false, true }) |disabled| {
        var packet = original;
        if (disabled) {
            packet[26] = 0;
            packet[27] = 0;
        }
        var ip_view = try IPv4Protocol.parse(&packet);
        var udp_view = try UdpProtocol.parse(ip_view.get(.payload), ip_view);
        var views: ViewStack = .{};
        views.setView(.ipv4, &ip_view);
        views.setView(.udp, &udp_view);

        ip_view.setUpdateChecksum(.dst, .{ 203, 0, 113, 20 }, &views);
        udp_view.setUpdateChecksum(.dst_port, 5300, &views);

        const reparsed_ip = try IPv4Protocol.parse(&packet);
        const reparsed_udp = try UdpProtocol.parse(reparsed_ip.get(.payload), reparsed_ip);
        try std.testing.expectEqual(@as(u16, 5300), reparsed_udp.get(.dst_port));
        if (disabled) try std.testing.expectEqual(@as(u16, 0), reparsed_udp.get(.checksum));
    }

    // A computed UDP checksum of zero must be transmitted as all ones.
    var zero_packet = original;
    const zero_ip = try IPv4Protocol.parse(&zero_packet);
    var zero_udp = try UdpProtocol.parse(zero_ip.get(.payload), zero_ip);
    var zero_views: ViewStack = .{};
    zero_views.setView(.udp, &zero_udp);
    zero_udp.setUpdateChecksum(.dst_port, 0xb2e9, &zero_views);
    try std.testing.expectEqual(@as(u16, 0xffff), zero_udp.get(.checksum));
    _ = try UdpProtocol.parse(zero_ip.get(.payload), zero_ip);
}

test "setUpdateChecksum updates ICMPv4 checksum" {
    var packet = [_]u8{ 0x08, 0x00, 0x21, 0x68, 0x12, 0x34, 0x00, 0x01, 0x61, 0x62, 0x63 };
    var view = try ICMPv4Protocol.parse(&packet);
    var views: ViewStack = .{};
    view.setUpdateChecksum(.code, 1, &views);
    const reparsed = try ICMPv4Protocol.parse(&packet);
    try std.testing.expectEqual(@as(u8, 1), reparsed.get(.code));
}

test "View.validate() compares integer fields at boundaries" {
    var buffer = test_buffer;
    var view = parseTestBuffer(&buffer);

    try view.validate(.test_int, .{ .lt = 0x0807 });
    try view.validate(.test_int, .{ .lte = 0x0806 });
    try view.validate(.test_int, .{ .gt = 0x0805 });
    try view.validate(.test_int, .{ .gte = 0x0806 });
    try view.validate(.test_int, .{ .multiple_of = 2 });
    try view.validate(.test_high_nibble, .{ .gte = 9 });
    try view.validate(.test_high_nibble, .{ .multiple_of = 3 });
    try view.validate(.test_optional_int, .{ .gte = 0x8100 });

    try std.testing.expectError(error.InvalidField, view.validate(.test_int, .{ .lt = 0x0806 }));
    try std.testing.expectError(error.InvalidField, view.validate(.test_int, .{ .lte = 0x0805 }));
    try std.testing.expectError(error.InvalidField, view.validate(.test_int, .{ .gt = 0x0806 }));
    try std.testing.expectError(error.InvalidField, view.validate(.test_int, .{ .gte = 0x0807 }));
    try std.testing.expectError(error.InvalidField, view.validate(.test_int, .{ .multiple_of = 4 }));
    try std.testing.expectError(error.InvalidField, view.validate(.test_int, .{ .multiple_of = 0 }));
    try std.testing.expectError(error.InvalidField, view.validate(.test_absent_int, .{ .gte = 0 }));
}

test "View.validate() checks enum values with any" {
    const OptionalEnum = struct { value: ?TestEnum };
    const OptionalEnumView = View(OptionalEnum);
    var buffer = [_]u8{ 0xAB, 0xCD };
    var reader: std.Io.Reader = .fixed(&buffer);
    var view: OptionalEnumView = undefined;
    try view.takeField(.value, &reader);

    try view.validate(.value, .any);
    try std.testing.expectError(error.InvalidField, view.validate(.value, .{ .eq = .second }));
    view.set(.value, null);
    try view.validate(.value, .{ .eq = null });
    try std.testing.expectError(error.InvalidField, view.validate(.value, .any));
}

test "View() generated copy() copies non-owned slices" {
    const expected = TestBase{};
    var buffer = test_buffer;
    var view = parseTestBuffer(&buffer);

    const copied = view.copy();

    try std.testing.expectEqualDeep(expected, copied);
    try std.testing.expectEqual(
        @intFromPtr(view.get(.test_slice).ptr),
        @intFromPtr(copied.test_slice.ptr),
    );
    try std.testing.expectEqual(
        @intFromPtr(view.get(.test_optional_slice).?.ptr),
        @intFromPtr(copied.test_optional_slice.?.ptr),
    );
    try std.testing.expectEqual(
        @as(?u16, null),
        copied.test_absent_int,
    );
    try std.testing.expectEqual(
        @as(?[]const u8, null),
        copied.test_absent_slice,
    );
}

const TestBitFields = struct {
    version: u4,
    ihl: u4,
    dscp: u6,
    ecn: u2,
    reserved: u1,
    dont_fragment: bool,
    more_fragments: bool,
    fragment_offset: u13,
};

const TestBitFieldsView = View(TestBitFields);

test "View() binds bit fields to wire bytes" {
    var buffer = [_]u8{ 0x45, 0xab, 0x75, 0x12 };
    var reader: std.Io.Reader = .fixed(&buffer);
    var view: TestBitFieldsView = undefined;
    try view.takeFields(.version, .fragment_offset, &reader);

    try std.testing.expectEqual(*align(1:4:1) u4, @TypeOf(view.fields.version));
    try std.testing.expectEqual(*align(1:0:1) u4, @TypeOf(view.fields.ihl));
    try std.testing.expectEqual(*align(1:0:2) u13, @TypeOf(view.fields.fragment_offset));
    try std.testing.expectEqual(@intFromPtr(&buffer[0]), @intFromPtr(view.fields.version));
    try std.testing.expectEqual(@intFromPtr(&buffer[2]), @intFromPtr(view.fields.fragment_offset));
    try std.testing.expectEqual(@as(u4, 4), view.get(.version));
    try std.testing.expectEqual(@as(u4, 5), view.get(.ihl));
    try std.testing.expectEqual(@as(u6, 42), view.get(.dscp));
    try std.testing.expectEqual(@as(u2, 3), view.get(.ecn));
    try std.testing.expectEqual(@as(u1, 0), view.get(.reserved));
    try std.testing.expect(view.get(.dont_fragment));
    try std.testing.expect(view.get(.more_fragments));
    try std.testing.expectEqual(@as(u13, 0x1512), view.get(.fragment_offset));

    view.set(.version, 6);
    view.set(.fragment_offset, 0x1234);
    try std.testing.expectEqualSlices(u8, &.{ 0x65, 0xab, 0x72, 0x34 }, &buffer);

    var serialized: [buffer.len]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&serialized);
    try TestBitFieldsView.serialize(view.copy(), &writer);
    try std.testing.expectEqualSlices(u8, &buffer, &serialized);
}

const TestOptionalBitFields = struct {
    pcp: ?u3,
    dei: ?bool,
    vid: ?u12,
};

const TestOptionalBitFieldsView = View(TestOptionalBitFields);

test "View() skips absent bit groups and rejects partial groups" {
    var buffer = [_]u8{ 0x60, 0x64 };
    var reader: std.Io.Reader = .fixed(&buffer);
    var view: TestOptionalBitFieldsView = undefined;
    try view.takeFields(.pcp, .vid, &reader);
    try std.testing.expectEqual(@as(?u3, 3), view.get(.pcp));
    try std.testing.expectEqual(@as(?bool, false), view.get(.dei));
    try std.testing.expectEqual(@as(?u12, 100), view.get(.vid));

    view.set(.pcp, 5);
    try std.testing.expectEqualSlices(u8, &.{ 0xa0, 0x64 }, &buffer);

    var serialized: [2]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&serialized);
    try TestOptionalBitFieldsView.serialize(view.copy(), &writer);
    try std.testing.expectEqualSlices(u8, &buffer, &serialized);

    view.set(.dei, null);
    try std.testing.expectError(error.InvalidField, TestOptionalBitFieldsView.serialize(view.copy(), &writer));

    const absent = TestOptionalBitFields{ .pcp = null, .dei = null, .vid = null };
    var empty_writer: std.Io.Writer = .fixed(&serialized);
    try TestOptionalBitFieldsView.serialize(absent, &empty_writer);
    try std.testing.expectEqual(@as(usize, 0), empty_writer.end);
}
