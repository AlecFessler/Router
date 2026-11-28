pub const trace_router_handlers = true;
const std = @import("std");
const Router = @import("router");

const Runtime = Router.Debug.Runtime;
const Sim = Router.Nic.Simulation;
const Network = Router.Debug.NetworkSimulation;
const IFace = Router.Nic.Api.IFace;

const Clock = Router.Debug.SimulationClock;

const Replay = struct {
    mock: *Sim.Mock,
    io: std.Io,
    phases: []const u64,
    barrier: Network.Barrier,
    failures: [2]usize = .{ 0, 0 },

    fn failure(self: *Replay, iface: IFace, err: anyerror) void {
        const count = &self.failures[@intFromEnum(iface)];
        if (count.* < 3) std.log.err("{t} phase {d}: {t}", .{ iface, Sim.phase, err });
        count.* += 1;
    }

    fn worker(self: *Replay, iface: IFace) void {
        Clock.resetWorker();
        const nic = self.mock.api();
        for (self.phases) |t| {
            self.barrier.wait();
            Sim.phase = t;
            if (iface == .wan) {
                Router.State.arp_waiters_table.expire(nic);
                Router.Protocols.DHCPv4.tickWan(self.io, nic) catch |err| self.failure(iface, err);
            } else {
                Clock.tickReclaim(self.io, nic) catch |err| self.failure(iface, err);
            }
            while (nic.receive(iface)) |packet| {
                if (iface == .wan) Router.Protocols.DHCPv4.tickWan(self.io, nic) catch |err| self.failure(iface, err);
                var views: Router.Protocols.ViewStack = .{};
                Router.Protocols.Ethernet.handle(packet, nic, iface, &views) catch |err| {
                    self.failure(iface, err);
                    nic.release(packet);
                };
            }
        }
    }
};

fn readWeights(init: std.process.Init, filename: []const u8) !Network.Scenarios.Weights {
    const json = try std.Io.Dir.cwd().readFileAlloc(init.io, filename, init.gpa, .limited(65536));
    defer init.gpa.free(json);
    const parsed = try std.json.parseFromSlice(Network.Scenarios.Weights, init.gpa, json, .{});
    defer parsed.deinit();
    try Network.Scenarios.validate(parsed.value);
    return parsed.value;
}

pub fn main(init: std.process.Init) !void {
    var args = try std.process.Args.Iterator.initAllocator(init.minimal.args, init.gpa);
    defer args.deinit();
    _ = args.skip();
    const command = args.next() orelse return error.ExpectedRunOrReplay;
    if (std.mem.eql(u8, command, "weights")) {
        const weights = try readWeights(init, args.next() orelse return error.ExpectedWeightsFile);
        if (args.next() != null) return error.TooManyArguments;
        var buffer: [512]u8 = undefined;
        var stdout = std.Io.File.stdout().writerStreaming(init.io, &buffer);
        try std.json.Stringify.value(weights, .{}, &stdout.interface);
        try stdout.interface.writeByte('\n');
        try stdout.interface.flush();
        return;
    }
    const raw_smith = std.mem.eql(u8, command, "smith");
    const synthetic = raw_smith or std.mem.eql(u8, command, "run");
    const checking = std.mem.eql(u8, command, "check");
    if (!synthetic and !checking and !std.mem.eql(u8, command, "replay")) return error.ExpectedRunOrReplay;
    const path = args.next() orelse return error.ExpectedCaptureDirectory;
    var input: Router.Debug.SimulationFuzzInput = undefined;
    var workload: Network.Workload = .{};
    var seed: u64 = 1;
    var frames: usize = 100000;
    const smith_file = if (raw_smith) args.next() orelse return error.ExpectedSmithInput else null;
    if (synthetic and !raw_smith) {
        if (args.next()) |v| seed = try std.fmt.parseInt(u64, v, 0);
        if (args.next()) |v| frames = try std.fmt.parseInt(usize, v, 10);
    }
    var weights: Network.Scenarios.Weights = .{};
    var extended: ?usize = null;
    var full_size: usize = 100000;
    while (args.next()) |flag| {
        if (synthetic and std.mem.eql(u8, flag, "--weights")) {
            weights = try readWeights(init, args.next() orelse return error.ExpectedWeightsFile);
        } else if (raw_smith and std.mem.eql(u8, flag, "--frames")) {
            extended = try std.fmt.parseInt(usize, args.next() orelse return error.ExpectedFrameCount, 10);
        } else if (raw_smith and std.mem.eql(u8, flag, "--full-size")) {
            full_size = try std.fmt.parseInt(usize, args.next() orelse return error.ExpectedFrameCount, 10);
        } else return error.InvalidArguments;
    }
    if (smith_file) |filename| {
        const bytes = try std.Io.Dir.cwd().readFileAlloc(init.io, filename, init.gpa, .unlimited);
        defer init.gpa.free(bytes);
        var smith: std.testing.Smith = .{ .in = bytes };
        input.read(&smith, weights);
        seed = input.seed;
        workload = input.workload();
        frames = extended orelse if (input.full_size) full_size else input.length;
        if (extended != null) workload.burst_width = 128;
    }
    const dir = if (synthetic) try std.Io.Dir.cwd().createDirPathOpen(init.io, path, .{}) else try std.Io.Dir.cwd().openDir(init.io, path, .{});
    defer dir.close(init.io);
    if (raw_smith and extended == null) {
        var canonical: [Router.Debug.SimulationFuzzInput.encoded_max]u8 = undefined;
        try dir.writeFile(init.io, .{ .sub_path = "normalized.smith", .data = input.encode(&canonical) });
    }
    if (checking) {
        try checkFiles(init, dir);
        std.debug.print("Both egress captures match.\n", .{});
        return;
    }
    var outputs: [6]Sim.Output = undefined;
    const names = [_][]const u8{ "lan-tx.pcap", "wan-tx.pcap", "lan-rx.pcap", "wan-rx.pcap", "lan-expected.pcap", "wan-expected.pcap" };
    var opened: usize = 0;
    defer for (outputs[0..opened]) |*out| out.file.close(init.io);
    for (names[0..@as(usize, if (synthetic) 6 else 2)]) |name| {
        const out = &outputs[opened];
        out.* = .{ .file = undefined, .writer = undefined, .buffer = undefined };
        try out.open(init.io, dir, name);
        opened += 1;
    }
    var clock = Clock.vtable(init.io);
    const io: std.Io = .{ .vtable = &clock, .userdata = init.io.userdata };
    var mock = Sim.Mock{ .io = init.io, .alloc = std.heap.smp_allocator, .outputs = outputs[0..2] };
    const result = if (synthetic) blk: {
        mock.rx_outputs = outputs[2..4];
        break :blk Network.run(io, &mock, seed, frames, workload, outputs[4..6], weights);
    } else replayFiles(init, dir, io, &mock);
    for (outputs[0..opened]) |*out| {
        if (out.failed) return error.WriteFailed;
        try out.writer.interface.flush();
    }
    result catch |err| {
        if (synthetic) std.log.err("simulation failed: seed {d}, frames {d}, captures {s}", .{ seed, frames, path });
        return err;
    };
}

fn replayFiles(init: std.process.Init, dir: std.Io.Dir, io: std.Io, mock: *Sim.Mock) !void {
    mock.captures = @as([2]Sim.Capture, undefined);
    var phases: std.ArrayList(u64) = .empty;
    defer phases.deinit(init.gpa);
    const lan = try dir.readFileAlloc(init.io, "lan-rx.pcap", init.gpa, .unlimited);
    defer init.gpa.free(lan);
    const wan = try dir.readFileAlloc(init.io, "wan-rx.pcap", init.gpa, .unlimited);
    defer init.gpa.free(wan);
    for ([_][]const u8{ lan, wan }, &mock.captures.?) |data, *capture| {
        capture.* = try .init(data);
        var cursor = capture.*;
        var prev: ?u64 = null;
        while (cursor.input.len > 0) {
            const t = (try cursor.checkedPhase()).?;
            if (prev) |p| if (t < p) return error.UnsortedPcap;
            if (t != prev) try phases.append(init.gpa, t);
            _ = try cursor.pop();
            prev = t;
        }
    }
    std.mem.sort(u64, phases.items, {}, std.sort.asc(u64));
    var count: usize = 0;
    for (phases.items) |t| {
        if (count > 0 and phases.items[count - 1] == t) continue;
        phases.items[count] = t;
        count += 1;
    }
    Router.Debug.Cli.enabled = false;
    try Runtime.setup(init.gpa, io, mock.api(), .{ 192, 168, 86, 1 }, .{ 255, 255, 255, 0 });
    var replay = Replay{ .mock = mock, .io = io, .barrier = .{ .io = io }, .phases = phases.items[0..count] };
    {
        defer Runtime.teardown(init.gpa, mock.api());
        const thread = try std.Thread.spawn(.{}, Replay.worker, .{ &replay, IFace.wan });
        replay.worker(.lan);
        thread.join();
    }
    if (mock.outstanding.load(.monotonic) != 0) return error.UnreleasedNicBuffers;
    if (replay.failures[0] + replay.failures[1] != 0) return error.PacketHandlerFailed;
}

fn checkFiles(init: std.process.Init, dir: std.Io.Dir) !void {
    for ([_]IFace{ .lan, .wan }) |side| {
        const expected = try dir.readFileAlloc(init.io, if (side == .lan) "lan-expected.pcap" else "wan-expected.pcap", init.gpa, .unlimited);
        defer init.gpa.free(expected);
        const actual = try dir.readFileAlloc(init.io, if (side == .lan) "lan-tx.pcap" else "wan-tx.pcap", init.gpa, .unlimited);
        defer init.gpa.free(actual);
        try compare(side, init.gpa, expected, actual);
    }
}

fn compare(side: IFace, alloc: std.mem.Allocator, expected: []const u8, actual: []const u8) !void {
    var want = try Sim.Capture.init(expected);
    var got = try Sim.Capture.init(actual);
    var counts: std.StringHashMapUnmanaged(usize) = .empty;
    defer counts.deinit(alloc);
    while (want.input.len != 0) {
        const t = (try want.checkedPhase()).?;
        while (try want.checkedPhase() == t) {
            const entry = try counts.getOrPut(alloc, try want.pop());
            if (!entry.found_existing) entry.value_ptr.* = 0;
            entry.value_ptr.* += 1;
        }
        while (try got.checkedPhase() == t) {
            const frame = try got.pop();
            const n = counts.getPtr(frame) orelse {
                std.log.err("unexpected {t} TX at {d} ms: {x}", .{ side, t, frame });
                return error.UnexpectedTx;
            };
            n.* -= 1;
            if (n.* == 0) _ = counts.remove(frame);
        }
        if (counts.count() != 0) {
            var it = counts.keyIterator();
            std.log.err("missing {t} TX at {d} ms: {x}", .{ side, t, it.next().?.* });
            return error.MissingTx;
        }
    }
    if (got.input.len != 0) return error.ExtraTx;
}
