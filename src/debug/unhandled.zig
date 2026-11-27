const std = @import("std");
const IFace = @import("../nic/api.zig").IFace;

const log = std.log.scoped(.unhandled);
const max_bytes = 4 * 1024 * 1024;

pub const Sink = struct {
    io: std.Io,
    dir: std.Io.Dir,
    file: ?std.Io.File = null,
    size: usize = 0,
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
pub var packet_id: ?u64 = null;
pub var seen: bool = false;

pub fn report(iface: IFace, comptime format: []const u8, args: anytype) void {
    seen = true;
    if (packet_id) |id| {
        log.warn("packet={} ingress={s} " ++ format, .{ id, @tagName(iface) } ++ args);
    } else {
        log.warn("ingress={s} " ++ format, .{@tagName(iface)} ++ args);
    }
    if (sink) |output| {
        if (output.failed) return;
        const now = std.Io.Timestamp.now(output.io, .real).toMilliseconds();
        var buffer: [1024]u8 = undefined;
        const line = std.fmt.bufPrint(
            &buffer,
            "unix_ms={} packet={?d} ingress={s} " ++ format ++ "\n",
            .{ now, packet_id, @tagName(iface) } ++ args,
        ) catch unreachable;
        output.write(line) catch |err| {
            output.failed = true;
            log.err("file write failed: {t}", .{err});
        };
    }
}
