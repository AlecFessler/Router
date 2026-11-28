const std = @import("std");
const IFace = @import("../nic/api.zig").IFace;

const log = std.log.scoped(.unhandled);
const max_bytes = 4 * 1024 * 1024;

pub const Sink = struct {
    io: std.Io,
    dir: std.Io.Dir,
    file: ?std.Io.File = null,
    size: usize = 0,
    mutex: std.Io.Mutex = .init,
    failed: bool = false,

    pub fn open(io: std.Io, path: []const u8) !Sink {
        const dir = try std.Io.Dir.cwd().openDir(io, path, .{});
        errdefer dir.close(io);
        return .{ .io = io, .dir = dir, .file = try create(dir, io) };
    }

    fn create(dir: std.Io.Dir, io: std.Io) !std.Io.File {
        return dir.createFile(io, "unhandled.log", .{ .permissions = .fromMode(0o600), .exclusive = true });
    }

    pub fn close(self: *Sink) void {
        if (self.file) |file| file.close(self.io);
        self.dir.close(self.io);
    }

    fn write(self: *Sink, line: []const u8) !void {
        if (self.size + line.len > max_bytes) {
            self.file.?.close(self.io);
            self.file = null;
            try self.dir.rename("unhandled.log", self.dir, "unhandled.log.1", self.io);
            self.file = try create(self.dir, self.io);
            self.size = 0;
        }
        try self.file.?.writeStreamingAll(self.io, line);
        self.size += line.len;
    }
};

pub var sink: ?*Sink = null;
pub threadlocal var packet_id: ?u64 = null;
pub threadlocal var seen: bool = false;

pub const Observation = struct {
    count: usize = 0,
    line: [256]u8 = undefined,
    len: usize = 0,
};
pub threadlocal var observation: ?*Observation = null;

fn warn(comptime format: []const u8, args: anytype) void {
    if (comptime @import("builtin").is_test or @hasDecl(@import("root"), "trace_router_handlers")) {
        if (observation) |report_line| {
            report_line.count += 1;
            const line = std.fmt.bufPrint(&report_line.line, format, args) catch report_line.line[0..0];
            report_line.len = line.len;
            return;
        }
    }
    log.warn(format, args);
}

pub fn report(iface: IFace, comptime format: []const u8, args: anytype) void {
    seen = true;
    if (packet_id) |id| {
        warn("packet={} ingress={s} " ++ format, .{ id, @tagName(iface) } ++ args);
    } else {
        warn("ingress={s} " ++ format, .{@tagName(iface)} ++ args);
    }
    if (sink) |output| {
        const now = std.Io.Timestamp.now(output.io, .real).toMilliseconds();
        var buffer: [1024]u8 = undefined;
        const line = std.fmt.bufPrint(
            &buffer,
            "unix_ms={} packet={?d} ingress={s} " ++ format ++ "\n",
            .{ now, packet_id, @tagName(iface) } ++ args,
        ) catch unreachable;
        output.mutex.lockUncancelable(output.io);
        defer output.mutex.unlock(output.io);
        if (output.failed) return;
        output.write(line) catch |err| {
            output.failed = true;
            log.err("file write failed: {t}", .{err});
        };
    }
}
