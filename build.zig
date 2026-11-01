const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const exe = b.addExecutable(.{
        .name = "router",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    b.installArtifact(exe);

    const run_step = b.step("run", "Run the app");

    const run_cmd = b.addRunArtifact(exe);
    run_step.dependOn(&run_cmd.step);
    run_cmd.step.dependOn(b.getInstallStep());

    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const exe_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/test.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    const ethernet = b.createModule(.{
        .root_source_file = b.path("src/protocols/ethernet.zig"),
    });
    const ethernet_csv_parser = b.createModule(.{
        .root_source_file = b.path("test_fixtures/ethernet_csv_parser.zig"),
    });
    ethernet_csv_parser.addImport("ethernet", ethernet);
    const pcap_parser = b.createModule(.{
        .root_source_file = b.path("test_fixtures/pcap_parser.zig"),
    });

    exe_tests.root_module.addImport("ethernet_csv_parser", ethernet_csv_parser);
    exe_tests.root_module.addAnonymousImport("ethernet_test_csv", .{
        .root_source_file = b.path("test_fixtures/ethernet_test.csv"),
    });
    exe_tests.root_module.addImport("pcap_parser", pcap_parser);
    exe_tests.root_module.addAnonymousImport("ethernet_test_pcap", .{
        .root_source_file = b.path("test_fixtures/ethernet_test.pcap"),
    });

    const run_exe_tests = b.addRunArtifact(exe_tests);
    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_exe_tests.step);
}
