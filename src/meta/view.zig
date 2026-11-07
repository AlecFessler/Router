const std = @import("std");
const StructField = std.builtin.Type.StructField;

fn FieldType(
    comptime Base: type,
    comptime field: std.meta.FieldEnum(Base),
) type {
    return @FieldType(Base, @tagName(field));
}

pub fn View(Base: type) type {
    const base_info = @typeInfo(Base).@"struct";
    const fields = base_info.fields;
    var field_names: [fields.len][:0]const u8 = undefined;
    var field_types: [fields.len]type = undefined;
    const attributes = [_]std.builtin.Type.StructField.Attributes{.{}} ** fields.len;

    inline for (fields, 0..) |field, i| {
        field_names[i] = field.name;

        switch (@typeInfo(field.type)) {
            .int => {
                if (@bitSizeOf(field.type) % 8 != 0)
                    @compileError("Integer fields must be whole-byte sized");
            },
            .@"enum" => |info| {
                if (@bitSizeOf(info.tag_type) % 8 != 0)
                    @compileError("Enum backing integers must be whole-byte sized");
            },
            .@"struct" => |info| {
                if (info.layout != .@"packed")
                    @compileError("Only packed structs are supported");
                if (@bitSizeOf(field.type) % 8 != 0)
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

        const StorageType = switch (@typeInfo(field.type)) {
            .@"enum" => |info| info.tag_type,
            else => field.type,
        };

        field_types[i] = switch (@typeInfo(field.type)) {
            .pointer => field.type,
            else => @Pointer(
                .one,
                .{ .@"align" = 1 },
                StorageType,
                null,
            ),
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

        pub fn parse(
            self: *@This(),
            comptime field: FieldEnum,
            reader: *std.Io.Reader,
        ) !void {
            const T = @FieldType(ViewFields, @tagName(field));

            switch (@typeInfo(FieldType(Base, field))) {
                .pointer => @compileError("Use take() for slices"),
                else => {},
            }

            @field(self.fields, @tagName(field)) =
                @ptrCast(try reader.takeArray(@sizeOf(@typeInfo(T).pointer.child)));
        }

        pub fn take(
            self: *@This(),
            comptime field: FieldEnum,
            len: usize,
            reader: *std.Io.Reader,
        ) !void {
            switch (@typeInfo(FieldType(Base, field))) {
                .pointer => {},
                else => @compileError("Use parse() for non-slices"),
            }

            @field(self.fields, @tagName(field)) = try reader.take(len);
        }

        pub fn serialize(
            base: Base,
            comptime field: FieldEnum,
            writer: *std.Io.Writer,
        ) !void {
            const value = @field(base, @tagName(field));
            const T = FieldType(Base, field);

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

        pub fn validate(
            self: *const @This(),
            comptime field: FieldEnum,
            expected: ?FieldType(Base, field),
        ) error{InvalidField}!void {
            const T = FieldType(Base, field);

            switch (@typeInfo(T)) {
                .@"enum" => |info| {
                    const ptr = @field(self.fields, @tagName(field));
                    const raw = std.mem.bigToNative(info.tag_type, ptr.*);
                    const actual = std.enums.fromInt(T, raw) orelse
                        return error.InvalidField;

                    if (expected) |value| {
                        if (actual != value) return error.InvalidField;
                    }
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
            const ptr = @field(self.fields, @tagName(field));
            switch (@typeInfo(FieldType(Base, field))) {
                .@"enum" => |info| {
                    return @enumFromInt(std.mem.bigToNative(info.tag_type, ptr.*));
                },

                .int => {
                    return std.mem.bigToNative(FieldType(Base, field), ptr.*);
                },

                .pointer => |info| {
                    if (info.size == .slice) {
                        return ptr;
                    }
                    return ptr.*;
                },

                .@"struct" => |info| {
                    if (info.layout == .@"packed") {
                        const IntType = std.meta.Int(.unsigned, @bitSizeOf(FieldType(Base, field)));
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
            const ptr = @field(self.fields, @tagName(field));
            switch (@typeInfo(FieldType(Base, field))) {
                .@"enum" => |info| {
                    ptr.* = std.mem.nativeToBig(info.tag_type, @intFromEnum(value));
                },

                .int => {
                    ptr.* = std.mem.nativeToBig(@TypeOf(value), value);
                },

                .pointer => |info| {
                    if (info.size == .slice) {
                        @field(self.fields, @tagName(field)) = value;
                    } else {
                        ptr.* = value;
                    }
                },

                .@"struct" => |info| {
                    if (info.layout == .@"packed") {
                        const IntType = std.meta.Int(.unsigned, @bitSizeOf(FieldType(Base, field)));
                        const bits: IntType = @bitCast(value);
                        ptr.* = @bitCast(std.mem.nativeToBig(IntType, bits));
                    } else {
                        ptr.* = value;
                    }
                },

                else => {
                    ptr.* = value;
                },
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
                    if (i < initialized) {
                        switch (@typeInfo(field.type)) {
                            .pointer => |info| {
                                if (info.size != .slice) continue;
                                alloc.free(@field(result, field.name));
                            },

                            else => {},
                        }
                    }
                }
            }

            inline for (fields) |field| {
                switch (@typeInfo(field.type)) {
                    .pointer => |info| {
                        if (info.size == .slice) {
                            const original = self.get(@field(FieldEnum, field.name));
                            const copied = try alloc.alloc(info.child, original.len);
                            @memcpy(copied, original);
                            @field(result, field.name) = copied;
                        } else {
                            @field(result, field.name) = self.get(@field(FieldEnum, field.name));
                        }
                    },

                    else => @field(result, field.name) = self.get(@field(FieldEnum, field.name)),
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
};

const TestView = View(TestBase);

const test_buffer = result: {
    const default = TestBase{};
    var buffer: [18]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    TestView.serialize(default, .test_int, &writer) catch unreachable;
    TestView.serialize(default, .test_enum, &writer) catch unreachable;
    TestView.serialize(default, .test_packed_struct, &writer) catch unreachable;
    TestView.serialize(default, .test_array, &writer) catch unreachable;
    TestView.serialize(default, .test_slice, &writer) catch unreachable;
    break :result buffer;
};

fn parseTestBuffer(buffer: []u8) TestView {
    const default = TestBase{};
    var output: TestView = undefined;
    var reader: std.Io.Reader = .fixed(buffer);
    output.parse(.test_int, &reader) catch unreachable;
    output.parse(.test_enum, &reader) catch unreachable;
    output.parse(.test_packed_struct, &reader) catch unreachable;
    output.parse(.test_array, &reader) catch unreachable;
    output.take(.test_slice, default.test_slice.len, &reader) catch unreachable;
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
    try std.testing.expectEqualSlices(
        u8,
        test_buffer[0..10],
        buffer[0..10],
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
}

test "View() generated deepCopy() copies into owned slices" {
    const expected = TestBase{};
    var buffer = test_buffer;
    var view = parseTestBuffer(&buffer);

    const copied = try view.deepCopy(std.testing.allocator);
    defer std.testing.allocator.free(copied.test_slice);

    try std.testing.expectEqualDeep(expected, copied);
    try std.testing.expect(@intFromPtr(view.get(.test_slice).ptr) != @intFromPtr(copied.test_slice.ptr));
}
