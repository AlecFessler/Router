//! Streaming router process. Input and output share an ID space with the oracle.
//! All integers are big endian. Each command ends with a 'D' response.
//! L/W: id:u64, size:u16, frame. A: interface byte, IPv4, MAC. T: idle tick.
//! N: id:u64, IPv4 protocol:u8, inside IPv4, inside port:u16.
//! F/R/X/U/E/N: id:u64, size:u16, bytes (forward/reply/release/unhandled/error/NAT port).
const std = @import("std");
const Router = @import("router");
const Runtime = @import("debug/runtime.zig");

const Mock = Router.Nic.Shadow.Mock;
const IFace = Router.Nic.Api.IFace;
const Ethernet = Router.Protocols.Ethernet;
const Log = Router.Debug.Unhandled;
const State = Router.State;

fn readArgument(args: *std.process.Args.Iterator) ![]const u8 {
    return args.next() orelse error.InvalidArguments;
}

fn parseIp(args: *std.process.Args.Iterator) ![4]u8 {
    return (try std.Io.net.Ip4Address.parse(try readArgument(args), 0)).bytes;
}

fn parseMac(args: *std.process.Args.Iterator) !Ethernet.Mac {
    var mac: Ethernet.Mac = undefined;
    if ((try std.fmt.hexToBytes(&mac, try readArgument(args))).len != mac.len) return error.InvalidArguments;
    return mac;
}

fn parseIface(value: u8) !IFace {
    return switch (value) {
        'L' => .lan,
        'W' => .wan,
        else => error.InvalidInterface,
    };
}

pub fn main(init: std.process.Init) !void {
    var args = try std.process.Args.Iterator.initAllocator(init.minimal.args, init.gpa);
    defer args.deinit();
    _ = args.skip();
    const log_dir = try readArgument(&args);
    const lan_ip = try parseIp(&args);
    const wan_ip = try parseIp(&args);
    const wan_mask = try parseIp(&args);
    const gateway = try parseIp(&args);
    const lan_mac = try parseMac(&args);
    const wan_mac = try parseMac(&args);
    if (args.next() != null) return error.InvalidArguments;

    var log_sink = try Log.Sink.open(init.io, log_dir);
    defer log_sink.close();
    Log.sink = &log_sink;
    defer Log.sink = null;
    Router.Debug.Cli.enabled = false;

    var read_buffer: [32768]u8 = undefined;
    var write_buffer: [32768]u8 = undefined;
    var input = std.Io.File.stdin().readerStreaming(init.io, &read_buffer);
    var output = std.Io.File.stdout().writerStreaming(init.io, &write_buffer);
    var mock = Mock{
        .alloc = init.gpa,
        .out = &output.interface,
        .macs = .{ lan_mac, wan_mac },
    };
    defer mock.deinit();
    const nic = mock.api();
    try Runtime.setup(init.gpa, init.io, nic, lan_ip, .{ 255, 255, 255, 0 });
    defer {
        mock.ending = true;
        Runtime.teardown(init.gpa, nic);
    }

    const stationary = std.Io.Timestamp.fromNanoseconds(std.math.maxInt(i96));
    State.wan_lease = .{
        .ip = wan_ip,
        .subnet_mask = wan_mask,
        .router = gateway,
        .server_id = .{0} ** 4,
        .renewal_deadline = stationary,
        .rebinding_deadline = stationary,
        .expiration_deadline = stationary,
    };

    const reader = &input.interface;
    while (true) {
        const kind = reader.takeByte() catch |err| switch (err) {
            error.EndOfStream => break,
            else => return err,
        };
        State.arp_waiters_table.expire(nic);
        switch (kind) {
            'L', 'W' => {
                var id: [8]u8 = undefined;
                try reader.readSliceAll(&id);
                try mock.replay(try parseIface(kind), std.mem.readInt(u64, &id, .big), reader);
            },
            'A' => {
                const iface = try parseIface(try reader.takeByte());
                var address: [4]u8 = undefined;
                var mac: Ethernet.Mac = undefined;
                try reader.readSliceAll(&address);
                try reader.readSliceAll(&mac);
                switch (iface) {
                    .lan => State.lan_arp_table.cache(address, mac),
                    .wan => State.wan_arp_table.cache(address, mac),
                }
            },
            'N' => {
                var query: [15]u8 = undefined;
                try reader.readSliceAll(&query);
                const id = std.mem.readInt(u64, query[0..8], .big);
                const protocol: Router.Protocols.IPv4.Protocol = @enumFromInt(query[8]);
                const inside = query[9..13].*;
                const port = std.mem.readInt(u16, query[13..15], .big);
                if (State.wan_lease) |lease| {
                    if (State.nat_table.outboundEntry(.{ .protocol = protocol, .ip = inside, .port = port }, lease.ip)) |entry| {
                        var translated: [2]u8 = undefined;
                        std.mem.writeInt(u16, &translated, entry.outside.port, .big);
                        mock.emit('N', id, &translated);
                    }
                }
            },
            'T' => {},
            else => return error.InvalidCommand,
        }
        State.dhcp_table.tickReclaim(nic) catch |err| {
            std.log.scoped(.dhcp).warn("LAN address reclaim failed: {t}", .{err});
        };
        if (mock.failed) return error.WriteFailed;
        if (log_sink.failed) return error.UnhandledLogWriteFailed;
        try output.interface.writeByte('D');
        try output.interface.flush();
    }
}
