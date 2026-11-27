const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const router = b.createModule(.{
        .root_source_file = b.path("src/router.zig"),
        .target = target,
        .optimize = optimize,
    });
    const test_fixtures = b.createModule(.{
        .root_source_file = b.path("test_fixtures/test_fixtures.zig"),
        .target = target,
        .optimize = optimize,
    });
    test_fixtures.addImport("router", router);
    router.addImport("test_fixtures", test_fixtures);

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
    tests.root_module.addImport("router", router);

    const run_tests = b.addRunArtifact(tests);

    // Cross-cutting regression tests live in their own binary so audit branches can
    // add failing reproductions without touching the production test modules.
    const regression_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("test_fixtures/regression_tests.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    regression_tests.root_module.addImport("router", router);
    regression_tests.root_module.addImport("test_fixtures", test_fixtures);
    const run_regression_tests = b.addRunArtifact(regression_tests);

    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_tests.step);
    test_step.dependOn(&run_regression_tests.step);
}
