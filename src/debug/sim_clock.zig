const std = @import("std");
const Router = @import("router");

const Sim = Router.Nic.Simulation;
pub const Entropy = struct {
    word: u32 = 0x12345678,

    pub fn fill(self: *Entropy, buffer: []u8) void {
        for (buffer, 0..) |*byte, i| byte.* = std.mem.asBytes(&self.word)[i % 4];
        self.word +%= 1;
    }
};
threadlocal var entropy: Entropy = .{};

pub fn resetWorker() void {
    entropy = .{};
}

fn random(_: ?*anyopaque, buffer: []u8) void {
    // Each worker has its own deterministic source of DHCP transaction IDs and probe jitter.
    entropy.fill(buffer);
}

fn now(_: ?*anyopaque, _: std.Io.Clock) std.Io.Timestamp {
    return .fromNanoseconds(100 * std.time.ns_per_s + @as(i96, Sim.phase) * std.time.ns_per_ms);
}

// The DHCP timer task publishes its requested deadline before signaling probe_due.
var probe_deadline: std.Io.Timestamp = .zero;
fn timerSleep(_: ?*anyopaque, timeout: std.Io.Timeout) std.Io.Cancelable!void {
    probe_deadline = timeout.deadline.raw;
}

pub fn vtable(io: std.Io) std.Io.VTable {
    var v = io.vtable.*;
    v.now = now;
    v.random = random;
    v.sleep = timerSleep;
    return v;
}

pub fn tickReclaim(io: std.Io, nic: Router.Nic.Api.Api) !void {
    const table = &Router.State.dhcp_table;
    if (table.reclaim == null) return;
    table.probe_due.waitUncancelable(io);
    if (probe_deadline.toNanoseconds() <= now(null, .boot).toNanoseconds()) try table.tickReclaim(nic);
}
