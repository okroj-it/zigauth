const std = @import("std");

pub fn build(b: *std.Build) void {
    const t = b.standardTargetOptions(.{});
    const o = b.standardOptimizeOption(.{});

    // Library module
    const zigauth_mod = b.createModule(.{
        .root_source_file = b.path("src/zigauth.zig"),
        .target = t,
        .optimize = o,
    });

    // Tests
    const lib_unit_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/zigauth.zig"),
            .target = t,
            .optimize = o,
        }),
    });
    const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);

    const auth_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/auth_test.zig"),
            .target = t,
            .optimize = o,
            .imports = &.{
                .{ .name = "zigauth", .module = zigauth_mod },
            },
        }),
    });
    const run_auth_tests = b.addRunArtifact(auth_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_lib_unit_tests.step);
    test_step.dependOn(&run_auth_tests.step);

    // Example executable
    const example = b.addExecutable(.{
        .name = "basic_password",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/basic_password.zig"),
            .target = t,
            .optimize = o,
            .imports = &.{
                .{ .name = "zigauth", .module = zigauth_mod },
            },
        }),
    });
    b.installArtifact(example);

    const run_example = b.addRunArtifact(example);
    const example_step = b.step("example", "Run basic password example");
    example_step.dependOn(&run_example.step);
}
