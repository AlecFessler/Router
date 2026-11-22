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
const DHCPv4 = Router.Protocols.DHCPv4;
const DestinationUnreachable = @import("../protocols/icmpv4/destination_unreachable.zig");
const Ethernet = Router.Protocols.Ethernet;
const Echo = @import("../protocols/icmpv4/echo.zig");
const Format = Router.Meta.Format;
const ICMPv4 = Router.Protocols.ICMPv4;
const IPv4 = Router.Protocols.IPv4;
const ParameterProblem = @import("../protocols/icmpv4/parameter_problem.zig");
const Tcp = Router.Protocols.Tcp;
const TimeExceeded = @import("../protocols/icmpv4/time_exceeded.zig");
const Udp = Router.Protocols.Udp;

pub const EntryPoint = enum {
    rx,
    tx,
    release,
    ethernet,
    arp,
    dhcpv4,
    icmpv4,
    echo,
    destination_unreachable,
    time_exceeded,
    parameter_problem,
    ipv4,
    tcp,
    udp,
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

fn printVlanTags(tags: []const u8) void {
    if (tags.len == 0) return;
    if (tags.len % 4 != 0) {
        std.debug.print("VLAN tag stack has {} bytes (expected a multiple of 4)\n", .{tags.len});
        return;
    }

    std.debug.print("VLAN tag stack ({} tags):\n", .{tags.len / 4});
    for (0..tags.len / 4) |index| {
        const bytes = tags[index * 4 ..][0..4];
        var reader: std.Io.Reader = .fixed(bytes);
        var tag = Ethernet.parseVlanTag(&reader) catch |err| {
            std.debug.print("  tag #{}: parse failed: {}\n", .{ index + 1, err });
            continue;
        };
        std.debug.print("  tag #{}:\n", .{index + 1});
        tag.print(4);
    }
}

fn printDhcpIp(ip: IPv4.IPv4) void {
    std.debug.print("{}.{}.{}.{}", .{ ip[0], ip[1], ip[2], ip[3] });
}

fn printDhcpOptions(options: []const u8) void {
    var reader: std.Io.Reader = .fixed(options);
    std.debug.print("DHCPv4 options:\n", .{});
    while (true) {
        const offset = reader.seek;
        const option = DHCPv4.parseOption(&reader) catch |err| {
            std.debug.print("  parse failed at byte {}: {}\n", .{ offset, err });
            return;
        } orelse break;

        switch (option) {
            inline .subnet_mask, .broadcast_address, .requested_ip_address, .server_id => |ip, tag| {
                std.debug.print("  {s}: ", .{@tagName(tag)});
                printDhcpIp(ip);
                std.debug.print("\n", .{});
            },
            inline .router, .dns_servers => |addresses, tag| {
                std.debug.print("  {s}: ", .{@tagName(tag)});
                for (addresses, 0..) |ip, i| {
                    if (i != 0) std.debug.print(", ", .{});
                    printDhcpIp(ip);
                }
                std.debug.print("\n", .{});
            },
            inline .host_name, .domain_name => |name, tag| {
                std.debug.print("  {s}: {s}\n", .{ @tagName(tag), name });
            },
            .interface_mtu => |mtu| std.debug.print("  interface_mtu: {} bytes\n", .{mtu}),
            .static_route => |routes| {
                std.debug.print("  static_route:\n", .{});
                for (routes) |route| {
                    std.debug.print("    ", .{});
                    printDhcpIp(route.destination);
                    std.debug.print(" via ", .{});
                    printDhcpIp(route.router);
                    std.debug.print("\n", .{});
                }
            },
            inline .lease_time, .renewal_time, .rebinding_time => |duration, tag| {
                std.debug.print("  {s}: {} seconds\n", .{ @tagName(tag), duration.toSeconds() });
            },
            .message_type => |message_type| {
                std.debug.print("  message_type: {f}\n", .{Format.enumLabel(message_type)});
            },
            .parameter_request_list => |codes| {
                std.debug.print("  parameter_request_list:\n", .{});
                for (codes) |code| {
                    const name = std.enums.tagName(DHCPv4.OptionType, code) orelse "unknown";
                    std.debug.print("    {} {s}\n", .{ @intFromEnum(code), name });
                }
            },
            .max_message_size => |size| std.debug.print("  max_message_size: {} bytes\n", .{size}),
            .client_id => |bytes| {
                std.debug.print("  client_id: ", .{});
                for (bytes) |byte| std.debug.print("{x:0>2}", .{byte});
                std.debug.print("\n", .{});
            },
            inline .domain_search, .classless_static_route => |bytes, tag| {
                std.debug.print("  {s} (encoded): ", .{@tagName(tag)});
                for (bytes) |byte| std.debug.print("{x:0>2}", .{byte});
                std.debug.print("\n", .{});
            },
        }
    }
}

fn printDhcpPacket(bytes: []const u8) void {
    var view = DHCPv4.parse(bytes) catch |err| {
        std.debug.print("DHCPv4 parse failed: {}\n", .{err});
        return;
    };
    std.debug.print("DHCPv4:\n", .{});
    view.print(2);
    printDhcpOptions(view.get(.options));
    std.debug.print("\n", .{});
}

fn printChild(comptime Packet: type, comptime Parser: type, name: []const u8, bytes: []const u8) void {
    if (comptime @typeInfo(Packet).@"struct".fields.len == 0) {
        std.debug.print("{s} parser not implemented\n", .{name});
    } else {
        var view = Parser.parse(bytes) catch |err| {
            std.debug.print("{s} parse failed: {}\n", .{ name, err });
            return;
        };
        std.debug.print("{s}:\n", .{name});
        view.print(2);
        std.debug.print("\n", .{});
    }
}

fn printFrame(frame: []const u8) void {
    var ethernet = Ethernet.parse(frame) catch |err| {
        std.debug.print("Ethernet parse failed: {}\n", .{err});
        return;
    };
    std.debug.print("Ethernet:\n", .{});
    ethernet.print(2);
    printVlanTags(ethernet.get(.vlan_tags));
    std.debug.print("\n", .{});

    const ethertype = ethernet.get(.ethertype);
    switch (ethertype) {
        .ipv4 => {
            var ipv4 = IPv4.parse(ethernet.get(.payload)) catch |err| {
                std.debug.print("IPv4 parse failed: {}\n", .{err});
                return;
            };
            std.debug.print("IPv4:\n", .{});
            ipv4.print(2);
            std.debug.print("\n", .{});

            const protocol = ipv4.get(.protocol);
            switch (protocol) {
                .icmp => {
                    var icmpv4 = ICMPv4.parse(ipv4.get(.payload)) catch |err| {
                        std.debug.print("ICMPv4 parse failed: {}\n", .{err});
                        return;
                    };
                    std.debug.print("ICMPv4:\n", .{});
                    icmpv4.print(2);
                    std.debug.print("\n", .{});

                    const message = icmpv4.get(.payload);
                    switch (icmpv4.get(.msg_type)) {
                        .echo_request, .echo_reply => printChild(Echo.EchoMsg, Echo, "Echo", message),
                        .destination_unreachable => printChild(DestinationUnreachable.DestinationUnreachableMsg, DestinationUnreachable, "Destination Unreachable", message),
                        .time_exceeded => printChild(TimeExceeded.TimeExceeddedMsg, TimeExceeded, "Time Exceeded", message),
                        .parameter_problem => printChild(ParameterProblem.ParameterProblemMsg, ParameterProblem, "Parameter Problem", message),
                        else => std.debug.print("No parser for ICMPv4 type {}\n", .{@intFromEnum(icmpv4.get(.msg_type))}),
                    }
                },
                .tcp => {
                    var tcp = Tcp.parse(ipv4.get(.payload), ipv4) catch |err| {
                        std.debug.print("TCP parse failed: {}\n", .{err});
                        return;
                    };
                    std.debug.print("TCP:\n", .{});
                    tcp.print(2);
                    std.debug.print("\n", .{});
                },
                .udp => {
                    var udp = Udp.parse(ipv4.get(.payload), ipv4) catch |err| {
                        std.debug.print("UDP parse failed: {}\n", .{err});
                        return;
                    };
                    std.debug.print("UDP:\n", .{});
                    udp.print(2);
                    std.debug.print("\n", .{});

                    const src_port = udp.get(.src_port);
                    const dst_port = udp.get(.dst_port);
                    if ((src_port == 67 and dst_port == 68) or
                        (src_port == 68 and dst_port == 67))
                    {
                        printDhcpPacket(udp.get(.payload));
                    } else {
                        std.debug.print("No parser for UDP ports {} -> {}\n", .{ src_port, dst_port });
                    }
                },
                else => std.debug.print("No parser for IP protocol {}\n", .{@intFromEnum(protocol)}),
            }
        },
        .arp => {
            var arp = Arp.parse(ethernet.get(.payload)) catch |err| {
                std.debug.print("ARP parse failed: {}\n", .{err});
                return;
            };
            std.debug.print("ARP:\n", .{});
            arp.print(2);
            std.debug.print("\n", .{});
        },
        else => std.debug.print("No parser for EtherType 0x{x:0>4}\n", .{@intFromEnum(ethertype)}),
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
            .dhcpv4 => "DHCPv4",
            .icmpv4 => "ICMPv4",
            .echo => "Echo",
            .destination_unreachable => "Destination Unreachable",
            .time_exceeded => "Time Exceeded",
            .parameter_problem => "Parameter Problem",
            .ipv4 => "IPv4",
            .tcp => "TCP",
            .udp => "UDP",
            else => @tagName(entrypoint),
        };
        std.debug.print("{s}:\n", .{label});
        view.print(2);
        if (comptime T == Ethernet.EthernetFrameView) {
            if (entrypoint == .ethernet) printVlanTags(view.get(.vlan_tags));
        }
        if (comptime T == DHCPv4.DHCPv4PacketView) {
            if (entrypoint == .dhcpv4) printDhcpOptions(view.get(.options));
        }
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
