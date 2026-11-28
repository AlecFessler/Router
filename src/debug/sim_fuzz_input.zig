//! Structured Smith input shared by the coverage-guided fixture and capture reproducer.
const std = @import("std");
const Router = @import("router");
const Simulation = Router.Debug.NetworkSimulation;

seed: u64,
length: usize,
full_size: bool,
width: u8,
lag: u8,
download: Simulation.Scenarios.Download,
conversation: Simulation.Scenarios.Conversation,
choices: [64]Simulation.Choice,

pub fn read(self: *@This(), smith: *std.testing.Smith, profile: Simulation.Scenarios.Weights) void {
    const scenarios = Simulation.Scenarios;
    const seed = smith.value(u64);
    const width = smith.valueRangeAtMost(u8, 1, 32);
    const reply_lag = smith.valueRangeAtMost(u8, 1, Simulation.max_reply_lag);
    const download: scenarios.Download = .{
        .client = smith.value(u4),
        .client_seq = smith.value(u32),
        .server_seq = smith.value(u32),
        .segments = smith.valueRangeAtMost(u8, 2, 6),
        .retransmit = smith.value(bool),
        .reset = smith.value(bool),
    };
    const conversation = weighted(smith, scenarios.conversations, profile);
    const length = smith.valueRangeAtMost(u8, 1, self.choices.len);
    for (self.choices[0..length]) |*choice| {
        choice.* = .{
            .kind = .udp,
            .scenario = weighted(smith, scenarios.clients, profile),
            .outcome = smith.value(@FieldType(Simulation.Choice, "outcome")),
            .host = smith.value(u4),
            .socket = smith.value(u5),
            .token = smith.value(u32),
            .size = smith.value(u8),
            .payload_prefix = smith.value([8]u8),
            .ttl = smith.valueRangeAtMost(u8, 2, 255),
        };
    }
    self.full_size = smith.valueWeighted(bool, &.{
        .value(bool, false, 127),
        .value(bool, true, 1),
    });
    self.seed = seed;
    self.length = length;
    self.width = width;
    self.lag = reply_lag;
    self.download = download;
    self.conversation = conversation;
}

fn weighted(smith: *std.testing.Smith, comptime catalog: anytype, profile: Simulation.Scenarios.Weights) std.meta.FieldEnum(@TypeOf(catalog)) {
    const Tag = std.meta.FieldEnum(@TypeOf(catalog));
    var weights: [std.meta.fields(Tag).len]std.testing.Smith.Weight = undefined;
    var n: usize = 0;
    inline for (comptime std.meta.tags(Tag)) |scenario| {
        if (comptime @field(catalog, @tagName(scenario)).weight != null) {
            const weight = @field(profile, @tagName(scenario));
            if (weight != 0) {
                weights[n] = .value(u8, @intFromEnum(scenario), weight);
                n += 1;
            }
        }
    }
    return smith.valueWeighted(Tag, weights[0..n]);
}

pub fn workload(self: *const @This()) Simulation.Workload {
    return .{
        .choices = self.choices[0..self.length],
        .download = self.download,
        .conversations = @as(*const [1]Simulation.Scenarios.Conversation, &self.conversation),
        .burst_width = if (self.full_size) 128 else self.width,
        .reply_lag = self.lag,
    };
}

// Zig 0.16 Smith replays each scalar from a little-endian u64 and each byte block verbatim.
pub const encoded_max = (12 + 8 * 64) * 8;

pub fn encode(self: *const @This(), buffer: *[encoded_max]u8) []const u8 {
    var out: std.Io.Writer = .fixed(buffer);
    const d = self.download;
    for ([_]u64{ self.seed, self.width, self.lag, d.client, d.client_seq, d.server_seq, d.segments, @intFromBool(d.retransmit), @intFromBool(d.reset), @intFromEnum(self.conversation), self.length }) |word| {
        out.writeInt(u64, word, .little) catch unreachable;
    }
    for (self.choices[0..self.length]) |choice| {
        for ([_]u64{ @intFromEnum(choice.scenario.?), @intFromEnum(choice.outcome), choice.host, choice.socket, choice.token, choice.size }) |word| {
            out.writeInt(u64, word, .little) catch unreachable;
        }
        out.writeAll(&choice.payload_prefix.?) catch unreachable;
        out.writeInt(u64, choice.ttl, .little) catch unreachable;
    }
    out.writeInt(u64, @intFromBool(self.full_size), .little) catch unreachable;
    return out.buffered();
}
