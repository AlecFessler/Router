//! Debug CLI entry points and packet printing.
//!
//! To add a protocol:
//! 1. Add its module alias below.
//! 2. Add an `EntryPoint` value and call `Cli.enter(.protocol, view)` in its handler.
//! 3. Add its display name to `printData` so printing its View has a header.
//! 4. Extend `printFrame` at the parent protocol's dispatch field to parse and
//!    print the payload, then continue into any supported child protocol.
//!    Keep a clear "No parser" message for unmatched values.

const std = @import("std");
const Router = @import("router");

const Arp = Router.Protocols.Arp;
const Ethernet = Router.Protocols.Ethernet;

pub const EntryPoint = enum {
    rx,
    tx,
    release,
    ethernet,
    arp,
};

const StepTarget = union(enum) {
    pause,
    next_entry,
    next_rx,
    rx_number: usize,
    outcome: usize,
};

var target: StepTarget = .pause;
var rx_count: usize = 0;
var current_rx_ptr: usize = 0;
var input_closed = false;

fn dataPointer(data: anytype) usize {
    const T = @TypeOf(data);
    if (comptime @typeInfo(T) == .pointer and
        @typeInfo(T).pointer.size == .slice and
        @typeInfo(T).pointer.child == u8)
    {
        return @intFromPtr(data.ptr);
    }
    return 0;
}

fn readLine(buffer: []u8) ?[]const u8 {
    var len: usize = 0;
    var too_long = false;
    while (true) {
        var byte: [1]u8 = undefined;
        const n = std.posix.read(std.posix.STDIN_FILENO, &byte) catch {
            input_closed = true;
            return null;
        };
        if (n == 0) {
            input_closed = true;
            return null;
        }
        if (byte[0] == '\n') break;
        if (len < buffer.len) {
            buffer[len] = byte[0];
            len += 1;
        } else {
            too_long = true;
        }
    }
    if (too_long) {
        std.debug.print("Command too long\n", .{});
        return "";
    }
    return std.mem.trim(u8, buffer[0..len], " \t\r");
}

fn printFrame(frame: []const u8) void {
    var ethernet = Ethernet.parse(frame) catch |err| {
        std.debug.print("Ethernet parse failed: {}\n", .{err});
        return;
    };
    std.debug.print("Ethernet:\n", .{});
    ethernet.print(2);
    std.debug.print("\n", .{});

    const ethertype = ethernet.get(.ethertype);
    switch (ethertype) {
        0x0806 => {
            var arp = Arp.parse(ethernet.get(.payload)) catch |err| {
                std.debug.print("ARP parse failed: {}\n", .{err});
                return;
            };
            std.debug.print("ARP:\n", .{});
            arp.print(2);
            std.debug.print("\n", .{});
        },
        else => std.debug.print("No parser for EtherType 0x{x:0>4}\n", .{ethertype}),
    }
}

fn printData(entrypoint: EntryPoint, data: anytype) void {
    const T = @TypeOf(data);
    if (comptime @typeInfo(T) == .pointer and
        @typeInfo(T).pointer.size == .slice and
        @typeInfo(T).pointer.child == u8)
    {
        printFrame(data);
    } else if (comptime @hasDecl(T, "print")) {
        var view = data;
        const label: []const u8 = switch (entrypoint) {
            .ethernet => "Ethernet",
            .arp => "ARP",
            else => @tagName(entrypoint),
        };
        std.debug.print("{s}:\n", .{label});
        view.print(2);
        std.debug.print("\n", .{});
    } else {
        @compileError("Cli.enter expects a byte slice or a protocol View");
    }
}

fn shouldPause(entrypoint: EntryPoint, ptr: usize) bool {
    return switch (target) {
        .pause, .next_entry => true,
        .next_rx => entrypoint == .rx,
        .rx_number => |number| entrypoint == .rx and rx_count == number,
        .outcome => |expected_ptr| (entrypoint == .tx or entrypoint == .release) and
            expected_ptr != 0 and ptr == expected_ptr,
    };
}

pub fn enter(entrypoint: EntryPoint, data: anytype) void {
    const ptr = dataPointer(data);
    if (entrypoint == .rx) {
        rx_count += 1;
        current_rx_ptr = ptr;
        if (target == .outcome and target.outcome == 0) {
            target.outcome = ptr;
        }
    }
    const pause = shouldPause(entrypoint, ptr);
    if ((entrypoint == .tx or entrypoint == .release) and ptr == current_rx_ptr) {
        current_rx_ptr = 0;
    }
    if (input_closed or !pause) return;
    target = .pause;

    if (entrypoint == .release) {
        std.debug.print("\nPacket was not transmitted; its buffer was released.\n\n", .{});
    }

    while (true) {
        if (entrypoint == .rx) {
            std.debug.print("cli[rx #{}]> ", .{rx_count});
        } else {
            std.debug.print("cli[{s}]> ", .{@tagName(entrypoint)});
        }
        var buffer: [256]u8 = undefined;
        const line = readLine(&buffer) orelse {
            std.debug.print("\n", .{});
            return;
        };
        std.debug.print("\n", .{});
        if (std.mem.eql(u8, line, "print")) {
            printData(entrypoint, data);
        } else if (std.mem.eql(u8, line, "step")) {
            target = .next_entry;
            return;
        } else if (std.mem.eql(u8, line, "step n")) {
            target = .next_rx;
            return;
        } else if (std.mem.eql(u8, line, "step tx")) {
            target = .{ .outcome = current_rx_ptr };
            return;
        } else if (std.mem.startsWith(u8, line, "step #")) {
            const number = std.fmt.parseInt(usize, line[6..], 10) catch {
                std.debug.print("Expected a packet number after #\n", .{});
                continue;
            };
            target = .{ .rx_number = number };
            return;
        } else {
            std.debug.print("Commands: print | step | step #n | step n | step tx\n\n", .{});
        }
    }
}
