const std = @import("std");

pub fn build(b: *std.Build) void {
    const t = b.standardTargetOptions(.{});
    const o = b.standardOptimizeOption(.{});

    // Library module - framework-agnostic core
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

    const jwt_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/jwt_test.zig"),
            .target = t,
            .optimize = o,
            .imports = &.{
                .{ .name = "zigauth", .module = zigauth_mod },
            },
        }),
    });
    const run_jwt_tests = b.addRunArtifact(jwt_tests);

    const session_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/session_test.zig"),
            .target = t,
            .optimize = o,
            .imports = &.{
                .{ .name = "zigauth", .module = zigauth_mod },
            },
        }),
    });
    const run_session_tests = b.addRunArtifact(session_tests);

    const rbac_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/rbac_test.zig"),
            .target = t,
            .optimize = o,
            .imports = &.{
                .{ .name = "zigauth", .module = zigauth_mod },
            },
        }),
    });
    const run_rbac_tests = b.addRunArtifact(rbac_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_lib_unit_tests.step);
    test_step.dependOn(&run_auth_tests.step);
    test_step.dependOn(&run_jwt_tests.step);
    test_step.dependOn(&run_session_tests.step);
    test_step.dependOn(&run_rbac_tests.step);

    // Example executables
    const password_example = b.addExecutable(.{
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
    b.installArtifact(password_example);

    const jwt_example = b.addExecutable(.{
        .name = "basic_jwt",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/basic_jwt.zig"),
            .target = t,
            .optimize = o,
            .imports = &.{
                .{ .name = "zigauth", .module = zigauth_mod },
            },
        }),
    });
    b.installArtifact(jwt_example);

    const session_example = b.addExecutable(.{
        .name = "basic_session",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/basic_session.zig"),
            .target = t,
            .optimize = o,
            .imports = &.{
                .{ .name = "zigauth", .module = zigauth_mod },
            },
        }),
    });
    b.installArtifact(session_example);

    const rbac_example = b.addExecutable(.{
        .name = "basic_rbac",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/basic_rbac.zig"),
            .target = t,
            .optimize = o,
            .imports = &.{
                .{ .name = "zigauth", .module = zigauth_mod },
            },
        }),
    });
    b.installArtifact(rbac_example);

    const run_password_example = b.addRunArtifact(password_example);
    const password_example_step = b.step("example-password", "Run basic password example");
    password_example_step.dependOn(&run_password_example.step);

    const run_jwt_example = b.addRunArtifact(jwt_example);
    const jwt_example_step = b.step("example-jwt", "Run basic JWT example");
    jwt_example_step.dependOn(&run_jwt_example.step);

    const run_session_example = b.addRunArtifact(session_example);
    const session_example_step = b.step("example-session", "Run basic session example");
    session_example_step.dependOn(&run_session_example.step);

    const run_rbac_example = b.addRunArtifact(rbac_example);
    const rbac_example_step = b.step("example-rbac", "Run basic RBAC example");
    rbac_example_step.dependOn(&run_rbac_example.step);

    // Run all core examples (no framework dependencies required)
    const example_step = b.step("example", "Run all core examples");
    example_step.dependOn(&run_password_example.step);
    example_step.dependOn(&run_jwt_example.step);
    example_step.dependOn(&run_session_example.step);
    example_step.dependOn(&run_rbac_example.step);
}
