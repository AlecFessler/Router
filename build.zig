const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const campaign = b.option([]const u8, "sim-campaign", "Working directory for the foreground coverage campaign");
    const router, const test_fixtures = modules(b, target, optimize, null, null);

    const exe = b.addExecutable(.{
        .name = "router",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    exe.root_module.addImport("router", router);
    b.installArtifact(exe);

    const shadow = b.addExecutable(.{
        .name = "router-shadow",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/shadow_main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    shadow.root_module.addImport("router", router);
    b.installArtifact(shadow);

    const sim = b.addExecutable(.{
        .name = "router-sim",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/sim_main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    sim.root_module.addImport("router", router);
    const install_sim = b.addInstallArtifact(sim, .{});
    b.getInstallStep().dependOn(&install_sim.step);
    b.step("sim-engine", "Build the simulation capture and replay executable").dependOn(&install_sim.step);

    const supervisor = b.addExecutable(.{
        .name = "router-campaign",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/debug/campaign.zig"),
            .target = b.graph.host,
            .optimize = .ReleaseSafe,
        }),
    });
    const snapshot = b.addWriteFiles();
    _ = snapshot.addCopyFile(b.path("build.zig"), "build.zig");
    _ = snapshot.addCopyDirectory(b.path("src"), "src", .{ .include_extensions = &.{".zig"} });
    _ = snapshot.addCopyDirectory(b.path("test_fixtures"), "test_fixtures", .{ .include_extensions = &.{ ".zig", ".csv", ".pcap" } });
    const soak = b.addRunArtifact(supervisor);
    soak.addArg(b.graph.zig_exe);
    soak.addDirectoryArg(snapshot.getDirectory());
    if (b.args) |args| soak.addArgs(args);
    soak.stdio = .inherit;
    b.step("sim", "Continuously fuzz, check and replay the two-interface router").dependOn(&soak.step);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const tests = b.addTest(.{
        .root_module = router,
    });

    const run_tests = b.addRunArtifact(tests);

    const fixture_tests = b.addTest(.{ .root_module = test_fixtures });
    const run_fixture_tests = b.addRunArtifact(fixture_tests);

    // Zig 0.16's LLVM fuzz runner cannot format an error-return trace.
    _, const fuzz_fixtures = modules(b, target, .Debug, false, campaign);
    const fuzz = b.addTest(.{
        .root_module = fuzz_fixtures,
        .filters = &.{"correlated LAN and WAN conversations"},
        .use_llvm = true,
    });
    b.step("sim-fuzz", "Exercise the two-interface network model").dependOn(&b.addRunArtifact(fuzz).step);

    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_tests.step);
    test_step.dependOn(&run_fixture_tests.step);
}

fn modules(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode, error_tracing: ?bool, campaign: ?[]const u8) struct { *std.Build.Module, *std.Build.Module } {
    const router = b.createModule(.{
        .root_source_file = b.path("src/router.zig"),
        .target = target,
        .optimize = optimize,
    });
    const test_fixtures = b.createModule(.{
        .root_source_file = b.path("test_fixtures/test_fixtures.zig"),
        .error_tracing = error_tracing,
        .target = target,
        .optimize = optimize,
    });
    const settings = b.addOptions();
    settings.addOption(?[]const u8, "campaign_dir", campaign);
    test_fixtures.addOptions("sim_settings", settings);
    test_fixtures.addImport("router", router);
    router.addImport("router", router);
    router.addImport("test_fixtures", test_fixtures);
    return .{ router, test_fixtures };
}
