const std = @import("std");
const Router = @import("router");
const Simulation = Router.Debug.NetworkSimulation;

test "correlated LAN and WAN conversations" {
    const corpus = comptime blk: {
        const scenarios = Simulation.Scenarios;
        // Short raw Smith inputs replay in ordinary tests as well as seeding the fuzzer.
        var cases: [3][21 * 8]u8 = undefined;
        for (&cases, [_]scenarios.Conversation{ .download, .peer_rotation, .path_mtu }, [_]scenarios.ClientScenario{ .dns_udp, .fragmented_echo, .udp }, 0..) |*bytes, conversation, client, mode| {
            const words = [_]u64{
                42,                   4,                                     3, 15, 0xfffffffe, 0xfffffff0, 5,                  1,   0, @intFromEnum(conversation), 1,
                @intFromEnum(client), @intFromEnum(scenarios.Outcome.reply), 2, 7,  0xa8,       63,         0x7766554433221100, 128, 0,
            };
            for (words, 0..) |word, i| std.mem.writeInt(u64, bytes[i * 8 ..][0..8], word, .little);
            std.mem.writeInt(u64, bytes[20 * 8 ..][0..8], mode, .little);
            if (@import("sim_settings").campaign_dir != null and conversation == .download)
                std.mem.writeInt(u64, bytes[19 * 8 ..][0..8], 1, .little);
        }
        break :blk cases;
    };
    try std.testing.fuzz({}, exercise, .{ .corpus = &.{ &.{}, &corpus[0], &corpus[1], &corpus[2] } });
}

fn exercise(_: void, smith: *std.testing.Smith) !void {
    const campaign = @import("sim_settings").campaign_dir;
    // Zig discovers this test before launching the instrumented worker.
    if (campaign != null and !@import("builtin").fuzz) return;
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const base = threaded.io();
    var clock = Router.Debug.SimulationClock.vtable(base);
    const io: std.Io = .{ .vtable = &clock, .userdata = base.userdata };
    var mock = Router.Nic.Simulation.Mock{ .io = io, .alloc = std.testing.allocator };
    var input: Router.Debug.SimulationFuzzInput = undefined;
    if (campaign) |path| {
        var dir = try std.Io.Dir.openDirAbsolute(base, path, .{});
        defer dir.close(base);
        const raw = try dir.readFileAlloc(base, "weights.json", std.testing.allocator, .limited(65536));
        defer std.testing.allocator.free(raw);
        const weights = try std.json.parseFromSlice(Simulation.Scenarios.Weights, std.testing.allocator, raw, .{});
        defer weights.deinit();
        input.read(smith, weights.value);
        var buffer: [Router.Debug.SimulationFuzzInput.encoded_max]u8 = undefined;
        const bytes = input.encode(&buffer);
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
        const known = "known/" ++ std.fmt.bytesToHex(digest, .lower);
        if (dir.access(base, known, .{})) |_| return error.SkipZigTest else |err| switch (err) {
            error.FileNotFound => {},
            else => return err,
        }
        try dir.writeFile(base, .{ .sub_path = "active.tmp", .data = bytes });
        try dir.rename("active.tmp", dir, "active.smith", base);
        const budget = if (input.full_size) blk: {
            const n = try dir.readFileAlloc(base, "frames", std.testing.allocator, .limited(32));
            defer std.testing.allocator.free(n);
            break :blk try std.fmt.parseInt(usize, n, 10);
        } else input.length;
        try Simulation.run(io, &mock, input.seed, budget, input.workload(), null, weights.value);
        if (input.full_size) try dir.writeFile(base, .{ .sub_path = "last-full.smith", .data = bytes });
        try dir.rename("active.smith", dir, "last.smith", base);
    } else {
        input.read(smith, .{});
        try Simulation.run(io, &mock, input.seed, if (input.full_size) 100000 else input.length, input.workload(), null, .{});
    }
}

test "DNS over TCP can reuse a socket number still mapped for a cancelled download" {
    const scenarios = Simulation.Scenarios;
    // The cancelled transfer uses private port 38000 + twice its episode index.
    // DNS at twice that index asks for the same port while the TCP mapping is live.
    const first = scenarios.mandatory_conversations.len;
    var episodes: [first + 1]scenarios.Conversation = @splat(.download);
    episodes[0] = .cancelled_download;
    episodes[first] = .dns_fallback;

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const base = threaded.io();
    var clock = Router.Debug.SimulationClock.vtable(base);
    const io: std.Io = .{ .vtable = &clock, .userdata = base.userdata };
    var mock = Router.Nic.Simulation.Mock{ .io = io, .alloc = std.testing.allocator };
    try Simulation.run(io, &mock, 1, 128, .{ .conversations = &episodes }, null, .{});
}

test "the TCP client retransmitting its FIN remains bound through another client's DHCPDECLINE" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const base = threaded.io();
    var clock = Router.Debug.SimulationClock.vtable(base);
    const io: std.Io = .{ .vtable = &clock, .userdata = base.userdata };
    var mock = Router.Nic.Simulation.Mock{ .io = io, .alloc = std.testing.allocator };
    try Simulation.run(io, &mock, 701, 128, .{ .conversations = &.{.download} }, null, .{});
}

test "UDP media from alternate ports and participants follows the configured NAT filter" {
    try std.testing.expect(Simulation.Scenarios.conversations.udp_filtering.mandatory);
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const base = threaded.io();
    var clock = Router.Debug.SimulationClock.vtable(base);
    const io: std.Io = .{ .vtable = &clock, .userdata = base.userdata };
    var mock = Router.Nic.Simulation.Mock{ .io = io, .alloc = std.testing.allocator };
    for (std.meta.tags(Simulation.FilteringMode)) |mode| {
        try Simulation.run(io, &mock, 42, 128, .{ .filtering_mode = mode }, null, .{});
    }
}

test "peer state gates DHCP, ARP, forwarding and upstream replies" {
    const scenarios = Simulation.Scenarios;
    var client: scenarios.Client = .{};
    const initial = client.available(.bound, true, true);
    try std.testing.expectEqual(@as(usize, 1), initial.count());
    try std.testing.expect(initial.contains(.discover));
    client.lease = .offered;
    try std.testing.expect(client.available(.bound, true, true).contains(.request_lease));
    client.lease = .bound;
    const cold = client.available(.bound, true, true);
    try std.testing.expectEqual(@as(usize, 1), cold.count());
    try std.testing.expect(cold.contains(.resolve_gateway));
    client.knows_gateway = true;
    const offline = client.available(.unconfigured, true, true);
    try std.testing.expect(offline.contains(.fragmented_echo));
    try std.testing.expect(!offline.contains(.udp));
    const online = client.available(.bound, false, true);
    try std.testing.expect(online.contains(.udp) and online.contains(.dns_tcp) and !online.contains(.tcp));
    var rng = std.Random.DefaultPrng.init(42);
    const random = rng.random();
    try std.testing.expectEqual(null, scenarios.gatewayScenario(.unconfigured, .flow, .{}, random));
    try std.testing.expectEqual(scenarios.WanScenario.offer_lease, scenarios.gatewayScenario(.unconfigured, .discover, .{}, random));
    try std.testing.expectEqual(null, scenarios.gatewayScenario(.offered, .idle, .{}, random));
    try std.testing.expectEqual(scenarios.WanScenario.acknowledge_lease, scenarios.gatewayScenario(.offered, .request, .{}, random));
    try std.testing.expectEqual(scenarios.WanScenario.answer_flow, scenarios.gatewayScenario(.bound, .flow, .{}, random));
}

test "weight selection skips zero-weight scenarios and validates each independent pool" {
    const scenarios = Simulation.Scenarios;
    var weights: scenarios.Weights = .{};
    inline for (std.meta.fields(scenarios.Weights)) |field| @field(weights, field.name) = 0;
    weights.udp = 100;
    weights.peer_rotation = 1;
    weights.wan_arp_refresh = 1;
    const client: scenarios.Client = .{ .lease = .bound, .knows_gateway = true };
    var rng = std.Random.DefaultPrng.init(5);
    for (0..50) |_| {
        try std.testing.expectEqual(scenarios.ClientScenario.udp, scenarios.choose(client.available(.bound, true, true), weights, rng.random()));
        try std.testing.expectEqual(scenarios.Conversation.peer_rotation, scenarios.chooseConversation(.bound, weights, rng.random()));
    }
    weights.udp = 0;
    try std.testing.expectError(error.EmptyScenarioWeights, scenarios.validate(weights));
    weights.udp = 1;
    weights.peer_rotation = 0;
    try std.testing.expectError(error.EmptyConversationWeights, scenarios.validate(weights));
    weights.download = 1;
    weights.wan_fragmented_echo = 0;
    weights.wan_arp_refresh = 0;
    try std.testing.expectError(error.EmptyGatewayWeights, scenarios.validate(weights));
}

test "a recorded campaign input replays the same structured Smith choices" {
    var random = std.Random.DefaultPrng.init(43);
    var raw: [5000]u8 = undefined;
    random.random().bytes(&raw);
    var in: std.testing.Smith = .{ .in = &raw };
    var original: Router.Debug.SimulationFuzzInput = undefined;
    original.read(&in, .{});
    var buffer: [Router.Debug.SimulationFuzzInput.encoded_max]u8 = undefined;
    var replay: std.testing.Smith = .{ .in = original.encode(&buffer) };
    var copy: Router.Debug.SimulationFuzzInput = undefined;
    copy.read(&replay, .{});
    try std.testing.expectEqual(original.seed, copy.seed);
    try std.testing.expectEqual(original.full_size, copy.full_size);
    try std.testing.expectEqualDeep(original.workload(), copy.workload());
}
