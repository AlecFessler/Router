const std = @import("std");
const Io = std.Io;
const Dir = Io.Dir;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Json = std.json.Value;
const linux = std.os.linux;
const cwd = Dir.cwd();

const Options = struct {
    output: []const u8,
    weights: ?[]const u8 = null,
    frames: ?usize = null,
    seed: ?u64 = null,
    runs: ?usize = null,
    fuzz_batch: usize = 128,
    timeout: u32 = 120,
    keep_all: bool = false,
};

const Coverage = struct {
    runs: usize = 0,
    unique: usize = 0,
    sites: usize = 0,
    instrumented_sites: usize = 0,
    corpus_inputs: usize = 0,
};

const Status = struct {
    seed: u64 = 0,
    next_seed: ?u64 = null,
    last_passed: ?u64 = null,
    passed: usize = 0,
    failed: usize = 0,
    last_failure: ?[]const u8 = null,
    previous_seeded: ?Json = null,
    catalog_dispatches: Json = .{ .object = .empty },
    engine: []const u8 = "",
    source: []const u8 = "",
    sha256: []const u8 = "",
    workspace: []const u8 = "",
    zig: []const u8 = "",
    weights: Json = .{ .object = .empty },
    frames: usize = 100000,
    checked_full_size_input: bool = false,
    fuzz: ?Coverage = null,
    stage: []const u8 = "starting",
    updated: f64 = 0,
};

var stopping = std.atomic.Value(bool).init(false);

fn onSignal(_: std.posix.SIG) callconv(.c) void {
    stopping.store(true, .monotonic);
}

fn same(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

fn hex(bytes: []const u8) [64]u8 {
    var hash: [32]u8 = undefined;
    Sha256.hash(bytes, &hash, .{});
    return std.fmt.bytesToHex(hash, .lower);
}

const Files = struct {
    io: Io,
    alloc: std.mem.Allocator,

    fn path(f: Files, parts: []const []const u8) ![]const u8 {
        return std.fs.path.join(f.alloc, parts);
    }

    fn fmt(f: Files, comptime format: []const u8, args: anytype) ![]const u8 {
        return std.fmt.allocPrint(f.alloc, format, args);
    }

    fn exists(f: Files, name: []const u8) !bool {
        cwd.access(f.io, name, .{}) catch |err| switch (err) {
            error.FileNotFound => return false,
            else => return err,
        };
        return true;
    }

    fn read(f: Files, name: []const u8) ![]const u8 {
        return cwd.readFileAlloc(f.io, name, f.alloc, .unlimited);
    }

    fn write(f: Files, name: []const u8, bytes: []const u8) !void {
        var file = try cwd.createFileAtomic(f.io, name, .{ .replace = true, .make_path = true });
        defer file.deinit(f.io);
        try file.file.writeStreamingAll(f.io, bytes);
        try file.replace(f.io);
    }

    fn json(f: Files, value: anytype) ![]const u8 {
        return std.json.Stringify.valueAlloc(f.alloc, value, .{});
    }

    fn parse(f: Files, comptime T: type, bytes: []const u8) !T {
        return std.json.parseFromSliceLeaky(T, f.alloc, bytes, .{ .ignore_unknown_fields = true, .allocate = .alloc_always });
    }

    fn copy(f: Files, from: []const u8, to: []const u8) !void {
        try cwd.copyFile(from, cwd, to, f.io, .{ .make_path = true });
    }

    fn link(f: Files, from: []const u8, to: []const u8) !void {
        cwd.hardLink(from, cwd, to, f.io, .{}) catch |err| switch (err) {
            error.CrossDevice => try f.copy(from, to),
            else => return err,
        };
    }

    fn remove(f: Files, name: []const u8) !void {
        cwd.deleteFile(f.io, name) catch |err| if (err != error.FileNotFound) return err;
    }

    fn output(f: Files, argv: []const []const u8) ![]const u8 {
        const result = try std.process.run(f.alloc, f.io, .{ .argv = argv });
        if (result.term != .exited or result.term.exited != 0) {
            std.debug.print("{s}", .{result.stderr});
            return error.CommandFailed;
        }
        return std.mem.trim(u8, result.stdout, " \t\r\n");
    }
};

fn options(f: Files, init: std.process.Init, argv: []const [:0]const u8) !Options {
    const home = init.minimal.environ.getPosix("HOME") orelse return error.MissingHome;
    var o: Options = .{ .output = try f.path(&.{ home, ".local/state/router-sim" }) };
    var i: usize = 0;
    while (i < argv.len) : (i += 1) {
        const flag = argv[i];
        if (same(flag, "--keep-all")) {
            o.keep_all = true;
            continue;
        }
        if (i == 0 and !std.mem.startsWith(u8, flag, "--")) {
            o.output = flag;
            continue;
        }
        i += 1;
        if (i == argv.len) return error.MissingOptionValue;
        const value = argv[i];
        if (same(flag, "--weights")) o.weights = value else if (same(flag, "--seed")) {
            o.seed = try std.fmt.parseInt(u64, value, 0);
        } else {
            const n = try std.fmt.parseInt(u32, value, 10);
            if (n == 0) return error.ExpectedPositiveNumber;
            if (same(flag, "--frames")) o.frames = n else if (same(flag, "--runs")) o.runs = n else if (same(flag, "--timeout")) o.timeout = n else if (same(flag, "--fuzz-batch")) o.fuzz_batch = n else return error.UnknownOption;
        }
    }
    try cwd.createDirPath(f.io, o.output);
    o.output = try cwd.realPathFileAlloc(f.io, o.output, f.alloc);
    return o;
}

// The build system supplies a content-addressed, immutable directory. Keep a copy
// in campaign storage so clearing the compiler cache cannot invalidate evidence.
fn pin(f: Files, snapshot: []const u8, output: []const u8) ![]const u8 {
    const build = try f.path(&.{ output, "versions", std.fs.path.basename(snapshot) });
    const dest = try f.path(&.{ build, "source" });
    if (try f.exists(dest)) return build;
    const staging = try f.path(&.{ build, "source.tmp" });
    try linkTree(f, snapshot, staging);
    try cwd.rename(staging, cwd, dest, f.io);
    return build;
}

fn linkTree(f: Files, source: []const u8, destination: []const u8) !void {
    try cwd.deleteTree(f.io, destination);
    try cwd.createDirPath(f.io, destination);
    var dir = try cwd.openDir(f.io, source, .{ .iterate = true });
    defer dir.close(f.io);
    var walk = try dir.walk(f.alloc);
    defer walk.deinit();
    while (try walk.next(f.io)) |entry| {
        const local = try f.path(&.{ destination, entry.path });
        switch (entry.kind) {
            .directory => try cwd.createDirPath(f.io, local),
            .file => try f.link(try f.path(&.{ source, entry.path }), local),
            else => return error.UnexpectedSnapshotEntry,
        }
    }
}

const ChildResult = enum { passed, failed, timeout };

fn runChild(f: Files, argv: []const []const u8, dir: []const u8, log: Io.File, timeout: u32, heartbeat: ?[2][]const u8) !ChildResult {
    var proc = try std.process.spawn(f.io, .{ .argv = argv, .cwd = .{ .path = dir }, .pgid = 0, .stdin = .ignore, .stdout = .{ .file = log }, .stderr = .{ .file = log } });
    const pid = proc.id.?;
    defer if (proc.id != null) {
        std.posix.kill(-pid, .KILL) catch {};
        _ = proc.wait(f.io) catch {};
    };
    var last = Io.Timestamp.now(f.io, .awake).toSeconds();
    var report = last;
    var mtime: i96 = 0;
    while (!stopping.load(.monotonic)) {
        var status: u32 = 0;
        const rc = linux.waitpid(pid, &status, linux.W.NOHANG);
        switch (linux.errno(rc)) {
            .SUCCESS => if (rc != 0) {
                proc.id = null;
                return if (linux.W.IFEXITED(status) and linux.W.EXITSTATUS(status) == 0) .passed else .failed;
            },
            .INTR => continue,
            else => return error.WaitFailed,
        }
        const now = Io.Timestamp.now(f.io, .awake).toSeconds();
        if (heartbeat) |paths| for (paths) |name| {
            const stat = cwd.statFile(f.io, name, .{}) catch |err| if (err == error.FileNotFound) continue else return err;
            if (stat.mtime.nanoseconds > mtime) {
                mtime = stat.mtime.nanoseconds;
                last = now;
            }
        };
        if (now - last >= (if (heartbeat != null and mtime == 0) @max(timeout, 120) else timeout)) return .timeout;
        if (now - report >= 60) {
            std.debug.print("Running {s}, {d}s since the last input began or completed.\n", .{ argv[1], now - last });
            report = now;
        }
        try Io.sleep(f.io, .fromMilliseconds(100), .awake);
    }
    return error.Interrupted;
}

fn coverage(log: []const u8) !Coverage {
    var c: Coverage = .{};
    var lines = std.mem.tokenizeScalar(u8, log, '\n');
    while (lines.next()) |line| {
        const arrow = std.mem.indexOf(u8, line, " -> ") orelse continue;
        var numbers = std.mem.tokenizeAny(u8, line[arrow + 4 ..], "/ (");
        const first = numbers.next() orelse continue;
        if (std.mem.startsWith(u8, line, "Runs:")) c.runs = try std.fmt.parseInt(usize, first, 10) else if (std.mem.startsWith(u8, line, "Unique runs:")) c.unique = try std.fmt.parseInt(usize, first, 10) else if (std.mem.startsWith(u8, line, "Coverage:")) {
            c.sites = try std.fmt.parseInt(usize, first, 10);
            c.instrumented_sites = try std.fmt.parseInt(usize, numbers.next() orelse return error.MissingCoverage, 10);
        }
    }
    if (c.instrumented_sites == 0) return error.MissingCoverage;
    return c;
}

fn hexName(name: []const u8) bool {
    if (name.len == 0) return false;
    for (name) |c| if (!(std.ascii.isDigit(c) or (c >= 'a' and c <= 'f'))) return false;
    return true;
}

fn corpus(f: Files, folder: []const u8) ![][]const u8 {
    var root = try cwd.openDir(f.io, folder, .{ .iterate = true });
    defer root.close(f.io);
    var items: std.ArrayList([]const u8) = .empty;
    var walker = try root.walk(f.alloc);
    defer walker.deinit();
    while (try walker.next(f.io)) |e| {
        if (e.kind != .file or !hexName(e.basename)) continue;
        const parent = std.fs.path.dirname(e.path) orelse continue;
        if (parent.len == 16 and hexName(parent)) try items.append(f.alloc, try f.path(&.{ folder, e.path }));
    }
    if (items.items.len == 0) return error.EmptyCoverageCorpus;
    std.mem.sort([]const u8, items.items, {}, struct {
        fn less(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.order(u8, a, b) == .lt;
        }
    }.less);
    return items.items;
}

fn dispatches(f: Files, totals: *Json, log: []const u8) !void {
    var lines = std.mem.tokenizeScalar(u8, log, '\n');
    while (lines.next()) |line| {
        const marker = " catalog dispatches ";
        const i = std.mem.indexOf(u8, line, marker) orelse continue;
        const group = try totals.object.getOrPut(f.alloc, line[0..i]);
        if (!group.found_existing) group.value_ptr.* = .{ .object = .empty };
        var fields = std.mem.tokenizeScalar(u8, line[i + marker.len ..], ' ');
        while (fields.next()) |item| {
            const k = std.mem.indexOfScalar(u8, item, '=') orelse return error.InvalidDispatchCount;
            const entry = try group.value_ptr.object.getOrPut(f.alloc, item[0..k]);
            if (!entry.found_existing) entry.value_ptr.* = .{ .integer = 0 };
            entry.value_ptr.integer += try std.fmt.parseInt(i64, item[k + 1 ..], 10);
        }
    }
}

const Batch = struct {
    f: Files,
    o: Options,
    s: *Status,
    root: []const u8,
    work: []const u8,

    fn stage(b: Batch, name: []const u8) !void {
        b.s.stage = name;
        b.s.updated = @floatFromInt(Io.Timestamp.now(b.f.io, .real).toSeconds());
        try b.f.write(try b.f.path(&.{ b.root, "status.json" }), try b.f.json(b.s.*));
    }

    fn inWork(b: Batch, name: []const u8) ![]const u8 {
        return b.f.path(&.{ b.work, name });
    }

    fn inProfile(b: Batch, name: []const u8) ![]const u8 {
        return b.f.path(&.{ b.s.workspace, name });
    }

    fn capture(b: Batch, exact: bool) !ChildResult {
        const f = b.f;
        const log = try cwd.createFile(f.io, try b.inWork("run.log"), .{});
        defer log.close(f.io);
        const frames = try f.fmt("{d}", .{b.s.frames});
        const replay = try b.inWork("replay");
        for ([_][]const []const u8{
            &.{ b.s.engine, "smith", b.work, try b.inWork("input.smith"), "--weights", try b.inProfile("weights.json"), if (exact) "--full-size" else "--frames", frames },
            &.{ b.s.engine, "check", b.work },
            &.{ b.s.engine, "replay", replay },
            &.{ b.s.engine, "check", replay },
        }, [_][]const u8{ "generate", "check", "replay", "check replay" }) |argv, name| {
            if (same(name, "replay")) {
                try cwd.createDirPath(f.io, replay);
                for ([_][]const u8{ "lan-rx.pcap", "lan-expected.pcap", "wan-rx.pcap", "wan-expected.pcap" }) |pcap| {
                    try f.link(try b.inWork(pcap), try f.path(&.{ replay, pcap }));
                }
            }
            if (!exact) try b.stage(name);
            const result = try runChild(f, argv, b.s.source, log, b.o.timeout, null);
            if (result != .passed) return result;
        }
        return .passed;
    }

    fn explore(b: Batch, zig: []const u8) !ChildResult {
        const f = b.f;
        const cache = try b.inProfile("zig-cache");
        const active = try b.inProfile("active.smith");
        const last = try b.inProfile("last.smith");
        try f.remove(active);
        try f.remove(last);
        try b.stage("coverage-guided fuzz");
        const report = try b.inProfile("fuzz.log");
        const result = blk: {
            const log = try cwd.createFile(f.io, report, .{});
            defer log.close(f.io);
            break :blk try runChild(f, &.{
                zig,      "build",                                              "sim-fuzz",    "-j1", try f.fmt("--fuzz={d}", .{b.o.fuzz_batch}),
                "--seed", try f.fmt("0x{x}", .{@as(u32, @truncate(b.s.seed))}), "--cache-dir", cache, "--color",
                "off",    try f.fmt("-Dsim-campaign={s}", .{b.s.workspace}),
            }, b.s.source, log, b.o.timeout, .{ active, last });
        };
        // The bounded 0.16 runner can write a crash and exit successfully.
        const crash = try b.inProfile("zig-cache/f/crash");
        if (try f.exists(crash)) return if (result == .timeout) .timeout else .failed;
        if (result != .passed) {
            if (!try f.exists(active)) {
                std.debug.print("Coverage worker stopped without an active input. Inspect {s}\n", .{report});
                return error.WorkerStartupFailed;
            }
            try f.copy(active, crash);
            return result;
        }
        b.s.fuzz = try coverage(try f.read(report));
        const inputs = try corpus(f, try f.path(&.{ cache, "f" }));
        b.s.fuzz.?.corpus_inputs = inputs.len;
        b.s.checked_full_size_input = try f.exists(try b.inProfile("last-full.smith"));
        var prng = std.Random.DefaultPrng.init(b.s.seed);
        try f.copy(inputs[prng.random().uintLessThan(usize, inputs.len)], try b.inWork("input.smith"));
        return b.capture(false);
    }

    const Failure = struct {
        stage: []const u8,
        result: ChildResult,
        timeout_seconds: ?u32 = null,
    };

    fn archive(b: Batch, failure: Failure) !void {
        const f = b.f;
        const exact = same(failure.stage, "coverage-guided fuzz");
        const root = try f.path(&.{ b.root, "failures" });
        const raw = try b.inWork("input.smith");
        var reproduced: ?ChildResult = null;
        if (exact) {
            // Keep Zig's original failure across interrupts, even during reproduction.
            try cwd.deleteTree(f.io, b.work);
            try cwd.createDirPath(f.io, b.work);
            try f.copy(try b.inProfile("zig-cache/f/crash"), raw);
            const report = try b.inProfile("fuzz.log");
            if (try f.exists(report)) try f.copy(report, try b.inWork("fuzz.log"));
            reproduced = try b.capture(true);
        }
        const key = hex(try f.read(raw));
        const input = try f.path(&.{ root, "inputs", &key });
        if (!try f.exists(input)) try f.copy(raw, input);
        const reason = try diagnostic(f, if (exact and reproduced != .failed) try b.inWork("fuzz.log") else try b.inWork("run.log"), &key);
        const digest = hex(try f.json(.{ b.s.workspace, failure, reason }));
        const id = if (b.o.keep_all) try f.fmt("{s}-{d}", .{ digest[0..24], b.s.seed }) else digest[0..24];
        const dest = try f.path(&.{ root, id });
        const record = try f.json(.{
            .seed = b.s.seed,
            .frames = b.s.frames,
            .sha256 = b.s.sha256,
            .engine = b.s.engine,
            .source = b.s.source,
            .zig = b.s.zig,
            .weights = b.s.weights,
            .stage = failure.stage,
            .result = failure.result,
            .timeout_seconds = failure.timeout_seconds,
            .workload = if (exact) "exact" else "extended",
            .capture_replay = reproduced,
            .input = input,
            .evidence = dest,
            .time = Io.Timestamp.now(f.io, .real).toSeconds(),
        });
        const normalized = try b.inWork("normalized.smith");
        const canonical = if (exact) hex(try f.read(if (try f.exists(normalized)) normalized else try b.inProfile("active.smith"))) else null;
        if (!try f.exists(dest)) {
            const staging = try f.path(&.{ root, "evidence.tmp" });
            try linkTree(f, b.work, staging);
            try f.link(b.s.engine, try f.path(&.{ staging, "router-sim" }));
            try f.write(try f.path(&.{ staging, "weights.json" }), try f.json(b.s.weights));
            try f.write(try f.path(&.{ staging, "case.json" }), record);
            try cwd.rename(staging, cwd, dest, f.io);
        }
        const ledger = try cwd.createFile(f.io, try f.path(&.{ b.root, "failures.jsonl" }), .{ .truncate = false });
        defer ledger.close(f.io);
        const ready: Archived = .{
            .evidence = dest,
            .ledger_offset = (try ledger.stat(f.io)).size,
            .record = try f.fmt("{s}\n", .{record}),
            .known = if (canonical) |hash| try f.path(&.{ b.s.workspace, "known", &hash }) else null,
        };
        try f.write(try b.inProfile("archive.ready"), try f.json(ready));
        try b.finishArchive(ready);
        std.debug.print("FAIL {s} during {s}. Evidence in {s}\n", .{ @tagName(failure.result), failure.stage, dest });
    }

    const Archived = struct {
        evidence: []const u8,
        ledger_offset: u64,
        record: []const u8,
        known: ?[]const u8,
    };

    fn finishArchive(b: Batch, ready: Archived) !void {
        const f = b.f;
        const ledger = try cwd.openFile(f.io, try f.path(&.{ b.root, "failures.jsonl" }), .{ .mode = .write_only });
        defer ledger.close(f.io);
        // Repeating this write after an interrupt commits the same record once.
        try ledger.writePositionalAll(f.io, ready.record, ready.ledger_offset);
        if (ready.known) |known| try f.write(known, "");
        if (!same(b.s.stage, "failed")) {
            b.s.failed += 1;
            b.s.next_seed = b.s.seed +% 1;
            b.s.last_failure = ready.evidence;
            try b.stage("failed");
        }
        try f.remove(try b.inProfile("zig-cache/f/crash"));
        try f.remove(try b.inProfile("failure.pending"));
        try f.remove(try b.inProfile("archive.ready"));
    }

    fn recover(b: Batch) !void {
        const f = b.f;
        if (b.s.workspace.len == 0) {
            // An earlier supervisor did not persist its profile path. Recover its
            // crash using the profile that produced it before changing builds.
            const base = std.fs.path.dirname(b.s.source) orelse return;
            var dir = try cwd.openDir(f.io, base, .{ .iterate = true });
            defer dir.close(f.io);
            var it = dir.iterate();
            while (try it.next(f.io)) |e| {
                if (e.kind != .directory or !std.mem.startsWith(u8, e.name, "profile-")) continue;
                const ws = try f.path(&.{ base, e.name });
                if (!try f.exists(try f.path(&.{ ws, "zig-cache/f/crash" }))) continue;
                b.s.workspace = ws;
                b.s.weights = try f.parse(Json, try f.read(try b.inProfile("weights.json")));
                b.s.frames = try std.fmt.parseInt(usize, try f.read(try b.inProfile("frames")), 10);
                break;
            }
            if (b.s.workspace.len == 0) return;
        }
        const ready = try b.inProfile("archive.ready");
        if (try f.exists(ready)) return b.finishArchive(try f.parse(Archived, try f.read(ready)));
        const pending = try b.inProfile("failure.pending");
        if (try f.exists(pending) or try f.exists(try b.inProfile("zig-cache/f/crash"))) {
            const failure: Failure = if (try f.exists(pending)) try f.parse(Failure, try f.read(pending)) else .{ .stage = "coverage-guided fuzz", .result = .failed };
            if (same(b.s.stage, "failed") and !try f.exists(pending)) {
                // A prior successful archive may have been interrupted before cleanup.
                try f.remove(try b.inProfile("zig-cache/f/crash"));
            } else try b.archive(failure);
        }
    }
};

fn diagnostic(f: Files, logfile: []const u8, fallback: []const u8) ![]const u8 {
    if (!try f.exists(logfile)) return fallback;
    var lines = std.mem.tokenizeScalar(u8, try f.read(logfile), '\n');
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, "error: scenario ")) {
            if (std.mem.indexOf(u8, line, " (round ")) |i| return line[0..i];
        }
    }
    lines.reset();
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, "error:") and std.mem.indexOf(u8, line, "simulation failed: seed") == null) return line;
        if (std.mem.startsWith(u8, line, "failed with error.")) return line;
    }
    return fallback;
}

fn campaign(init: std.process.Init) !usize {
    const f: Files = .{ .io = init.io, .alloc = init.arena.allocator() };
    const args = try init.minimal.args.toSlice(f.alloc);
    if (args.len == 4 and same(args[3], "--help")) {
        std.debug.print(
            \\Usage: zig build sim -- [output_dir] [options]
            \\  --runs N          Stop after N batches (default: continuous)
            \\  --fuzz-batch N    Coverage-guided iterations per batch (default: 128)
            \\  --frames N        Bulk inputs per interface (default: 100000)
            \\  --seed N          Set the starting seed (default: resume)
            \\  --weights FILE    Select a traffic profile (default: resume)
            \\  --timeout SEC     Time limit per active input or capture stage (default: 120)
            \\  --keep-all        Retain full captures for repeated diagnostics
            \\
        , .{});
        return 0;
    }
    const zig = args[1];
    const o = try options(f, init, args[3..]);
    const lock = try cwd.createFile(f.io, try f.path(&.{ o.output, "soak.lock" }), .{ .truncate = false });
    defer lock.close(f.io);
    if (!try lock.tryLock(f.io, .exclusive)) return error.CampaignAlreadyRunning;
    const file = try f.path(&.{ o.output, "status.json" });
    var initial: Status = if (try f.exists(file)) try f.parse(Status, try f.read(file)) else .{};
    const work = try f.path(&.{ o.output, "work" });
    const original_failures = initial.failed;
    var batch: Batch = .{ .f = f, .o = o, .s = &initial, .root = o.output, .work = work };
    try batch.recover();
    const build = try pin(f, args[2], o.output);
    const source = try f.path(&.{ build, "source" });
    const engine = try f.path(&.{ build, "bin/router-sim" });
    if (!try f.exists(engine)) {
        std.debug.print("Building the pinned simulation in {s}\n", .{build});
        var child = try std.process.spawn(f.io, .{ .argv = &.{ zig, "build", "sim-engine", "-Doptimize=ReleaseSafe", "--prefix", build }, .cwd = .{ .path = source } });
        const term = try child.wait(f.io);
        if (term != .exited or term.exited != 0) return error.BuildFailed;
    }
    const requested = try f.path(&.{ build, "requested-weights.json" });
    try f.write(requested, try f.json(initial.weights));
    const weights = try f.output(&.{ engine, "weights", o.weights orelse requested });
    const frames = o.frames orelse initial.frames;
    const profile = hex(try f.fmt("{s}\n{d}", .{ weights, frames }));
    const ws = try f.path(&.{ build, try f.fmt("profile-{s}", .{profile[0..16]}) });
    if (!same(initial.workspace, ws)) {
        initial.fuzz = null;
        initial.checked_full_size_input = false;
    }
    initial.frames = frames;
    initial.workspace = ws;
    initial.source = source;
    initial.engine = engine;
    initial.zig = @import("builtin").zig_version_string;
    initial.sha256 = try f.alloc.dupe(u8, &hex(try f.read(engine)));
    initial.weights = try f.parse(Json, weights);
    const source_rng: std.Random.IoSource = .{ .io = f.io };
    initial.seed = o.seed orelse initial.next_seed orelse source_rng.interface().int(u64);
    initial.next_seed = initial.seed;
    try cwd.createDirPath(f.io, try batch.inProfile("known"));
    try f.write(try batch.inProfile("weights.json"), weights);
    try f.write(try batch.inProfile("frames"), try f.fmt("{d}", .{frames}));
    try batch.stage("ready");
    std.debug.print("Campaign {s}\nBuild {s}. Requesting {d} fuzz iterations then {d} inputs per interface. Ctrl+C stops and saves the cursor.\n", .{ o.output, std.fs.path.basename(build), o.fuzz_batch, frames });
    var done: usize = 0;
    while (o.runs == null or done < o.runs.?) : (done += 1) {
        var arena: std.heap.ArenaAllocator = .init(init.gpa);
        defer arena.deinit();
        const bf: Files = .{ .io = f.io, .alloc = arena.allocator() };
        var s = try bf.parse(Status, try bf.read(file));
        s.seed = s.next_seed.?;
        batch = .{ .f = bf, .o = o, .s = &s, .root = o.output, .work = work };
        if (stopping.load(.monotonic)) return error.Interrupted;
        try cwd.deleteTree(f.io, work);
        try cwd.createDirPath(f.io, work);
        const result = batch.explore(zig) catch |err| {
            if (err == error.Interrupted) try batch.stage("interrupted");
            return err;
        };
        if (result == .passed) {
            try dispatches(bf, &s.catalog_dispatches, try bf.read(try batch.inWork("run.log")));
            s.passed += 1;
            s.last_passed = s.seed;
            s.next_seed = s.seed +% 1;
            try batch.stage("passed");
        } else {
            const failure: Batch.Failure = .{ .stage = s.stage, .result = result, .timeout_seconds = if (result == .timeout) o.timeout else null };
            try bf.write(try batch.inProfile("failure.pending"), try bf.json(failure));
            try batch.archive(failure);
        }
        try cwd.deleteTree(f.io, work);
        const c = s.fuzz orelse Coverage{};
        std.debug.print("{d} passed, {d} failed batches. {d} fuzz iterations, {d}/{d} sites, {d} corpus inputs. Next batch {d}.\n", .{ s.passed, s.failed, c.runs, c.sites, c.instrumented_sites, c.corpus_inputs, s.next_seed.? });
        if (o.runs != null and done + 1 == o.runs.?) return s.failed - original_failures;
    }
    return 0;
}

pub fn main(init: std.process.Init) !void {
    const sig: std.posix.Sigaction = .{ .handler = .{ .handler = onSignal }, .mask = std.posix.sigemptyset(), .flags = 0 };
    std.posix.sigaction(.INT, &sig, null);
    std.posix.sigaction(.TERM, &sig, null);
    const failures = campaign(init) catch |err| {
        if (err == error.Interrupted) {
            std.debug.print("Stopped. The next run resumes the campaign.\n", .{});
            std.process.exit(130);
        }
        return err;
    };
    if (failures != 0) std.process.exit(1);
}

test "coverage-selected inputs exclude Zig's index and lock files" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const f: Files = .{ .io = io, .alloc = arena.allocator() };
    const path = try tmp.dir.realPathFileAlloc(io, ".", f.alloc);
    const dir = try f.path(&.{ path, "48b9039d53ab4901" });
    for ([_][]const u8{ "0", "1f", "readlock", "synclock" }) |name| try f.write(try f.path(&.{ dir, name }), "");
    try f.write(try f.path(&.{ path, "crash" }), "");
    const cases = try corpus(f, path);
    try std.testing.expectEqual(@as(usize, 2), cases.len);
    try std.testing.expectEqualStrings("0", std.fs.path.basename(cases[0]));
    try std.testing.expectEqualStrings("1f", std.fs.path.basename(cases[1]));
}

test "an interrupted failure archive commits its ledger and counter once across restart" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const f: Files = .{ .io = io, .alloc = arena.allocator() };
    const root = try tmp.dir.realPathFileAlloc(io, ".", f.alloc);
    var state: Status = .{ .workspace = try f.path(&.{ root, "version/profile" }), .seed = 42 };
    const b: Batch = .{ .f = f, .o = .{ .output = root }, .s = &state, .root = root, .work = try f.path(&.{ root, "work" }) };
    const ledger = try f.path(&.{ root, "failures.jsonl" });
    const start = "{}\n";
    try f.write(ledger, start ++ "{");
    const ready: Batch.Archived = .{ .evidence = "/evidence", .ledger_offset = start.len, .record = "{\"seed\":42}\n", .known = try b.inProfile("known/hash") };
    try f.write(try b.inProfile("archive.ready"), try f.json(ready));
    try b.recover();
    try std.testing.expectEqual(@as(?u64, 43), state.next_seed);
    try std.testing.expect(try f.exists(ready.known.?));
    // A restart just after status was committed can see the same journal again.
    try f.write(try b.inProfile("archive.ready"), try f.json(ready));
    try b.recover();
    try std.testing.expectEqual(@as(usize, 1), state.failed);
    try std.testing.expectEqualStrings(start ++ "{\"seed\":42}\n", try f.read(ledger));
}
