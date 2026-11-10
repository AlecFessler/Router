const std = @import("std");
const StructField = std.builtin.Type.StructField;

fn FieldType(
    comptime Base: type,
    comptime field: std.meta.FieldEnum(Base),
) type {
    return @FieldType(Base, @tagName(field));
}

fn UnderlyingType(comptime T: type) type {
    return switch (@typeInfo(T)) {
        .optional => |info| info.child,
        else => T,
    };
}

fn isBitField(comptime T: type) bool {
    return switch (@typeInfo(UnderlyingType(T))) {
        .int => @bitSizeOf(UnderlyingType(T)) % 8 != 0,
        .bool => true,
        else => false,
    };
}

const BitInfo = struct {
    first: bool,
    start: usize,
    width: usize,
    bytes: usize,
    offset: usize,
    end: usize,
};

fn bitInfo(comptime Base: type, comptime index: usize) ?BitInfo {
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
            .@"struct" => |info| {
                if (info.layout != .@"packed")
                    @compileError("Only packed structs are supported");
                if (@bitSizeOf(T) % 8 != 0)
                    @compileError("Packed structs must be whole-byte sized");
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
        fields: ViewFields,
        bit_group: []u8 = undefined,

        pub const EqualityMode = enum {
            shallow,
            deep,
            ignore_slices,
        };

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
                        .@"struct" => {
                            const IntType = std.meta.Int(.unsigned, @bitSizeOf(T));
                            try writer.writeInt(IntType, @bitCast(value), .big);
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

        pub fn validate(
            self: *const @This(),
            comptime field: FieldEnum,
            expected: ?UnderlyingType(FieldType(Base, field)),
        ) error{InvalidField}!void {
            const FieldT = FieldType(Base, field);
            const T = UnderlyingType(FieldT);
            const storage = @field(self.fields, @tagName(field));

            if (@typeInfo(FieldT) == .optional) {
                if (expected == null) {
                    if (storage != null) return error.InvalidField;
                    return;
                }

                if (storage == null) return error.InvalidField;
            }

            switch (@typeInfo(T)) {
                .@"enum" => |info| {
                    const ptr = if (@typeInfo(FieldT) == .optional)
                        storage.?
                    else
                        storage;

                    const raw = std.mem.bigToNative(info.tag_type, ptr.*);
                    const actual = std.enums.fromInt(T, raw) orelse
                        return error.InvalidField;

                    if (expected) |value| {
                        if (actual != value) return error.InvalidField;
                    }
                },

                .pointer => {
                    const value = expected orelse return error.InvalidField;
                    const actual = if (@typeInfo(FieldT) == .optional)
                        self.get(field).?
                    else
                        self.get(field);

                    if (!std.mem.eql(u8, actual, value))
                        return error.InvalidField;
                },

                else => {
                    const value = expected orelse return error.InvalidField;
                    if (!std.meta.eql(self.get(field), value))
                        return error.InvalidField;
                },
            }
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

                .@"struct" => |info| {
                    if (info.layout == .@"packed") {
                        const IntType = std.meta.Int(.unsigned, @bitSizeOf(T));
                        const bits: IntType = @bitCast(ptr.*);
                        return @bitCast(std.mem.bigToNative(IntType, bits));
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

                .@"struct" => |info| {
                    if (info.layout == .@"packed") {
                        const IntType = std.meta.Int(.unsigned, @bitSizeOf(T));
                        const bits: IntType = @bitCast(actual_value);
                        ptr.* = @bitCast(std.mem.nativeToBig(IntType, bits));
                    } else {
                        ptr.* = actual_value;
                    }
                },

                else => {
                    ptr.* = actual_value;
                },
            }
        }

        fn readField(source: anytype, comptime field: FieldEnum) FieldType(Base, field) {
            const T = @TypeOf(source);
            const name = @tagName(field);

            if (T == Base) return @field(source, name);
            if (T == *Base or T == *const Base) return @field(source.*, name);
            if (T == @This()) return source.get(field);
            if (T == *@This() or T == *const @This()) return source.get(field);

            @compileError("Expected Base or View(Base)");
        }

        pub fn compare(a: anytype, b: anytype, comptime mode: EqualityMode) bool {
            @setEvalBranchQuota(10000);
            inline for (fields) |field| {
                field_check: {
                    const T = UnderlyingType(field.type);
                    const field_enum = @field(FieldEnum, field.name);

                    if (mode == .ignore_slices and @typeInfo(T) == .pointer)
                        break :field_check;

                    const left_value = readField(a, field_enum);
                    const right_value = readField(b, field_enum);

                    if (@typeInfo(field.type) == .optional) {
                        if (left_value == null and right_value == null)
                            break :field_check;
                        if (left_value == null or right_value == null)
                            return false;
                    }

                    const left = if (@typeInfo(field.type) == .optional)
                        left_value.?
                    else
                        left_value;
                    const right = if (@typeInfo(field.type) == .optional)
                        right_value.?
                    else
                        right_value;

                    switch (@typeInfo(T)) {
                        .pointer => {
                            if (mode == .deep) {
                                if (!std.mem.eql(u8, left, right)) return false;
                            } else {
                                if (left.ptr != right.ptr or left.len != right.len)
                                    return false;
                            }
                        },
                        else => {
                            if (!std.meta.eql(left, right)) return false;
                        },
                    }
                }
            }
            return true;
        }

        pub fn isEqual(self: *const @This(), other: anytype) bool {
            return compare(self, other, .shallow);
        }

        pub fn isDeepEqual(self: *const @This(), other: anytype) bool {
            return compare(self, other, .deep);
        }

        pub fn isEqualIgnoringSlices(self: *const @This(), other: anytype) bool {
            return compare(self, other, .ignore_slices);
        }

        fn printValue(comptime T: type, value: T) void {
            switch (@typeInfo(T)) {
                .optional => |info| {
                    if (value) |present| {
                        printValue(info.child, present);
                    } else {
                        std.debug.print("null", .{});
                    }
                },
                .int => std.debug.print("0x{x}", .{value}),
                .bool => std.debug.print("{}", .{value}),
                .@"enum" => std.debug.print("{s}", .{@tagName(value)}),
                .@"struct" => |info| {
                    std.debug.print("{{ ", .{});
                    inline for (info.fields, 0..) |field, i| {
                        if (i != 0) std.debug.print(", ", .{});
                        std.debug.print("{s}: ", .{field.name});
                        const field_value = @field(value, field.name);
                        switch (@typeInfo(field.type)) {
                            .int => std.debug.print("{}", .{field_value}),
                            else => printValue(field.type, field_value),
                        }
                    }
                    std.debug.print(" }}", .{});
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
                            inline for (0..info.len) |i| {
                                if (i != 0) std.debug.print(" ", .{});
                                std.debug.print("{x:0>2}", .{value[i]});
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
                printValue(field.type, self.get(field_enum));
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

        pub fn deepCopy(
            self: *@This(),
            alloc: std.mem.Allocator,
        ) !Base {
            var result: Base = undefined;
            var initialized: usize = 0;

            errdefer {
                inline for (fields, 0..) |field, i| {
                    const T = UnderlyingType(field.type);
                    const is_slice = switch (@typeInfo(T)) {
                        .pointer => |info| info.size == .slice,
                        else => false,
                    };

                    if (is_slice and i < initialized) {
                        const slice = @field(result, field.name);

                        if (@typeInfo(field.type) == .optional) {
                            if (slice) |present| alloc.free(present);
                        } else {
                            alloc.free(slice);
                        }
                    }
                }
            }

            inline for (fields) |field| {
                const T = UnderlyingType(field.type);
                const value = self.get(@field(FieldEnum, field.name));

                if (@typeInfo(T) == .pointer and @typeInfo(T).pointer.size == .slice) {
                    if (comptime @typeInfo(field.type) == .optional) {
                        @field(result, field.name) = if (value) |slice|
                            try alloc.dupe(u8, slice)
                        else
                            null;
                    } else {
                        @field(result, field.name) = try alloc.dupe(u8, value);
                    }
                } else {
                    @field(result, field.name) = value;
                }

                initialized += 1;
            }

            return result;
        }
    };
}

const TestPackedStruct = packed struct {
    field1: u12 = 0xABC,
    field2: bool = true,
    field3: u3 = 4,
};

const TestEnum = enum(u16) {
    first = 0xABCD,
    second = 0x1234,
};

const TestBase = struct {
    test_int: u16 = 0x0806,
    test_enum: TestEnum = .first,
    test_packed_struct: TestPackedStruct = .{},
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

    output.takeField(.test_int, &reader) catch unreachable;
    output.takeField(.test_enum, &reader) catch unreachable;
    output.takeField(.test_packed_struct, &reader) catch unreachable;
    output.takeField(.test_array, &reader) catch unreachable;
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
        *align(1) TestPackedStruct,
        @TypeOf(test_view.fields.test_packed_struct),
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
    try view.takeField(.test_packed_struct, &reader);
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
        @intFromPtr(view.fields.test_packed_struct),
    );
    try std.testing.expectEqual(
        @intFromPtr(&buffer[6]),
        @intFromPtr(view.fields.test_array),
    );

    try std.testing.expectEqual(@as(u16, 0x0806), view.get(.test_int));
    try std.testing.expectEqual(TestEnum.first, view.get(.test_enum));
    try std.testing.expectEqualDeep(TestPackedStruct{}, view.get(.test_packed_struct));
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
    try std.testing.expectEqualDeep(
        expected.test_packed_struct,
        view.get(.test_packed_struct),
    );
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
    view.set(.test_packed_struct, expected.test_packed_struct);
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

test "View.compare() supports views, bases, and all equality modes" {
    var first_buffer = test_buffer;
    var second_buffer = test_buffer;
    var first = parseTestBuffer(&first_buffer);
    var second = parseTestBuffer(&second_buffer);
    const base = first.copy();

    try std.testing.expect(first.isEqual(&first));
    try std.testing.expect(!first.isEqual(&second));
    try std.testing.expect(first.isDeepEqual(&second));
    try std.testing.expect(first.isEqualIgnoringSlices(&second));
    try std.testing.expect(first.isEqual(&base));
    try std.testing.expect(TestView.compare(base, first, .shallow));
    try std.testing.expect(TestView.compare(&base, &second, .deep));
    try std.testing.expect(TestView.compare(base, base, .shallow));
    try std.testing.expect(TestView.compare(&first, base, .ignore_slices));

    second.set(.test_slice, &.{ 0xAA, 0xBB });
    second.set(.test_optional_slice, null);
    try std.testing.expect(!first.isDeepEqual(second));
    try std.testing.expect(!first.isEqual(second));
    try std.testing.expect(first.isEqualIgnoringSlices(second));

    second.set(.test_int, 0x1234);
    try std.testing.expect(!first.isEqualIgnoringSlices(second));

    var changed_base = base;
    changed_base.test_array[0] = 0xFF;
    try std.testing.expect(!TestView.compare(base, changed_base, .deep));

    changed_base = base;
    changed_base.test_optional_int = null;
    try std.testing.expect(!TestView.compare(&first, &changed_base, .ignore_slices));

    changed_base = base;
    changed_base.test_slice = second.get(.test_slice);
    try std.testing.expect(!TestView.compare(base, changed_base, .shallow));
    try std.testing.expect(!TestView.compare(base, changed_base, .deep));
    try std.testing.expect(TestView.compare(base, changed_base, .ignore_slices));
}

test "View.validate() handles optional field presence and values" {
    const default = TestBase{};
    var buffer = test_buffer;
    var view = parseTestBuffer(&buffer);

    try view.validate(.test_int, 0x0806);
    try view.validate(.test_enum, null);
    try view.validate(.test_enum, .first);
    try view.validate(.test_packed_struct, .{});
    try view.validate(.test_array, .{ 1, 2, 3, 4 });
    try view.validate(.test_slice, default.test_slice);
    try view.validate(.test_optional_int, 0x8100);
    try view.validate(.test_absent_int, null);
    try view.validate(.test_optional_slice, default.test_optional_slice);
    try view.validate(.test_absent_slice, null);

    try std.testing.expectError(
        error.InvalidField,
        view.validate(.test_int, 0x1234),
    );
    try std.testing.expectError(
        error.InvalidField,
        view.validate(.test_enum, .second),
    );
    try std.testing.expectError(
        error.InvalidField,
        view.validate(.test_slice, &.{ 0xAA, 0xBB }),
    );
    try std.testing.expectError(
        error.InvalidField,
        view.validate(.test_optional_int, 0x1234),
    );
    try std.testing.expectError(
        error.InvalidField,
        view.validate(.test_optional_int, null),
    );
    try std.testing.expectError(
        error.InvalidField,
        view.validate(.test_absent_int, 0x8100),
    );
    try std.testing.expectError(
        error.InvalidField,
        view.validate(.test_optional_slice, &.{ 0x11, 0x22 }),
    );
    try std.testing.expectError(
        error.InvalidField,
        view.validate(.test_absent_slice, &.{0x11}),
    );

    buffer[2] = 0xFF;
    buffer[3] = 0xFF;

    try std.testing.expectError(
        error.InvalidField,
        view.validate(.test_enum, null),
    );
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

test "View() generated deepCopy() copies into owned slices" {
    const expected = TestBase{};
    var buffer = test_buffer;
    var view = parseTestBuffer(&buffer);

    const copied = try view.deepCopy(std.testing.allocator);
    defer std.testing.allocator.free(copied.test_slice);
    defer std.testing.allocator.free(copied.test_optional_slice.?);

    try std.testing.expectEqualDeep(expected, copied);

    try std.testing.expect(
        @intFromPtr(view.get(.test_slice).ptr) !=
            @intFromPtr(copied.test_slice.ptr),
    );
    try std.testing.expect(
        @intFromPtr(view.get(.test_optional_slice).?.ptr) !=
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
    try view.takeField(.version, &reader);
    try view.takeField(.ihl, &reader);
    try view.takeField(.dscp, &reader);
    try view.takeField(.ecn, &reader);
    try view.takeField(.reserved, &reader);
    try view.takeField(.dont_fragment, &reader);
    try view.takeField(.more_fragments, &reader);
    try view.takeField(.fragment_offset, &reader);

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
    try view.takeField(.pcp, &reader);
    try view.takeField(.dei, &reader);
    try view.takeField(.vid, &reader);
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
