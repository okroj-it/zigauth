const std = @import("std");
const zigauth = @import("zigauth");
const expect = std.testing.expect;
const expectEqual = std.testing.expectEqual;
const expectError = std.testing.expectError;
const expectEqualStrings = std.testing.expectEqualStrings;

const Role = zigauth.authz.rbac.Role;
const RBAC = zigauth.authz.rbac.RBAC;
const permissions = zigauth.authz.permissions;

// Permission matching tests
test "permissions - exact match" {
    try expect(permissions.matches("users:read", "users:read"));
    try expect(!permissions.matches("users:read", "users:write"));
    try expect(!permissions.matches("users:read", "posts:read"));
}

test "permissions - full wildcard" {
    try expect(permissions.matches("*", "users:read"));
    try expect(permissions.matches("*", "posts:write"));
    try expect(permissions.matches("*", "admin:delete"));
}

test "permissions - resource wildcard" {
    try expect(permissions.matches("users:*", "users:read"));
    try expect(permissions.matches("users:*", "users:write"));
    try expect(permissions.matches("users:*", "users:delete"));
    try expect(!permissions.matches("users:*", "posts:read"));
    try expect(!permissions.matches("users:*", "admin:access"));
}

test "permissions - parse permission" {
    const perm = permissions.Permission.parse("users:read").?;
    try expectEqualStrings("users", perm.resource);
    try expectEqualStrings("read", perm.action);

    const perm2 = permissions.Permission.parse("posts:write").?;
    try expectEqualStrings("posts", perm2.resource);
    try expectEqualStrings("write", perm2.action);

    const invalid = permissions.Permission.parse("invalid");
    try expect(invalid == null);
}

// Role tests
test "role - basic permission checking" {
    const role = Role{
        .name = "user",
        .permissions = &[_][]const u8{ "posts:read", "profile:edit" },
    };

    try expect(role.hasPermission("posts:read"));
    try expect(role.hasPermission("profile:edit"));
    try expect(!role.hasPermission("users:delete"));
}

test "role - wildcard permissions" {
    const admin = Role{
        .name = "admin",
        .permissions = &[_][]const u8{"*"},
    };

    try expect(admin.hasPermission("users:create"));
    try expect(admin.hasPermission("posts:delete"));
    try expect(admin.hasPermission("anything:anything"));

    const moderator = Role{
        .name = "moderator",
        .permissions = &[_][]const u8{"posts:*"},
    };

    try expect(moderator.hasPermission("posts:read"));
    try expect(moderator.hasPermission("posts:write"));
    try expect(moderator.hasPermission("posts:delete"));
    try expect(!moderator.hasPermission("users:read"));
}

test "role - any permission" {
    const role = Role{
        .name = "editor",
        .permissions = &[_][]const u8{ "posts:read", "posts:write" },
    };

    const required1 = [_][]const u8{ "posts:read", "users:delete" };
    try expect(role.hasAnyPermission(&required1)); // Has posts:read

    const required2 = [_][]const u8{ "users:read", "admin:access" };
    try expect(!role.hasAnyPermission(&required2)); // Has neither
}

test "role - all permissions" {
    const role = Role{
        .name = "editor",
        .permissions = &[_][]const u8{ "posts:read", "posts:write", "posts:edit" },
    };

    const required1 = [_][]const u8{ "posts:read", "posts:write" };
    try expect(role.hasAllPermissions(&required1));

    const required2 = [_][]const u8{ "posts:read", "posts:delete" };
    try expect(!role.hasAllPermissions(&required2)); // Missing posts:delete
}

// RBAC manager tests
test "rbac - define and get role" {
    const allocator = std.testing.allocator;

    var rbac = RBAC.init(allocator);
    defer rbac.deinit();

    const user_role = Role{
        .name = "user",
        .permissions = &[_][]const u8{ "posts:read", "profile:edit" },
        .description = "Basic user role",
    };

    try rbac.defineRole(user_role);

    const retrieved = rbac.getRole("user").?;
    try expectEqualStrings("user", retrieved.name);
    try expect(retrieved.hasPermission("posts:read"));
    try expectEqualStrings("Basic user role", retrieved.description.?);

    // Non-existent role
    const none = rbac.getRole("nonexistent");
    try expect(none == null);
}

test "rbac - multiple roles" {
    const allocator = std.testing.allocator;

    var rbac = RBAC.init(allocator);
    defer rbac.deinit();

    const user = Role{
        .name = "user",
        .permissions = &[_][]const u8{ "posts:read", "profile:edit" },
    };

    const editor = Role{
        .name = "editor",
        .permissions = &[_][]const u8{ "posts:read", "posts:write", "posts:edit" },
    };

    const admin = Role{
        .name = "admin",
        .permissions = &[_][]const u8{"*"},
    };

    try rbac.defineRole(user);
    try rbac.defineRole(editor);
    try rbac.defineRole(admin);

    // Verify all roles
    try expect(rbac.getRole("user") != null);
    try expect(rbac.getRole("editor") != null);
    try expect(rbac.getRole("admin") != null);
}

test "rbac - assign role to user" {
    const allocator = std.testing.allocator;

    var rbac = RBAC.init(allocator);
    defer rbac.deinit();

    const editor = Role{
        .name = "editor",
        .permissions = &[_][]const u8{ "posts:write", "posts:edit" },
    };

    try rbac.defineRole(editor);
    try rbac.assignRole("user_123", "editor");

    const roles = rbac.getUserRoles("user_123").?;
    try expectEqual(@as(usize, 1), roles.len);
    try expectEqualStrings("editor", roles[0]);
}

test "rbac - assign nonexistent role" {
    const allocator = std.testing.allocator;

    var rbac = RBAC.init(allocator);
    defer rbac.deinit();

    const result = rbac.assignRole("user_123", "nonexistent");
    try expectError(error.RoleNotFound, result);
}

test "rbac - assign multiple roles" {
    const allocator = std.testing.allocator;

    var rbac = RBAC.init(allocator);
    defer rbac.deinit();

    const user = Role{
        .name = "user",
        .permissions = &[_][]const u8{"posts:read"},
    };

    const editor = Role{
        .name = "editor",
        .permissions = &[_][]const u8{"posts:write"},
    };

    try rbac.defineRole(user);
    try rbac.defineRole(editor);

    try rbac.assignRole("user_123", "user");
    try rbac.assignRole("user_123", "editor");

    const roles = rbac.getUserRoles("user_123").?;
    try expectEqual(@as(usize, 2), roles.len);
}

test "rbac - remove role from user" {
    const allocator = std.testing.allocator;

    var rbac = RBAC.init(allocator);
    defer rbac.deinit();

    const editor = Role{
        .name = "editor",
        .permissions = &[_][]const u8{"posts:write"},
    };

    try rbac.defineRole(editor);
    try rbac.assignRole("user_123", "editor");

    // Verify assigned
    const roles_before = rbac.getUserRoles("user_123").?;
    try expectEqual(@as(usize, 1), roles_before.len);

    // Remove role
    try rbac.removeRole("user_123", "editor");

    // Verify removed
    const roles_after = rbac.getUserRoles("user_123").?;
    try expectEqual(@as(usize, 0), roles_after.len);
}

test "rbac - remove role errors" {
    const allocator = std.testing.allocator;

    var rbac = RBAC.init(allocator);
    defer rbac.deinit();

    // User not found
    const result1 = rbac.removeRole("nonexistent", "editor");
    try expectError(error.UserNotFound, result1);

    const role = Role{
        .name = "editor",
        .permissions = &[_][]const u8{"posts:write"},
    };
    try rbac.defineRole(role);
    try rbac.assignRole("user_123", "editor");

    // Role not assigned
    const result2 = rbac.removeRole("user_123", "admin");
    try expectError(error.RoleNotAssigned, result2);
}

test "rbac - user permission checking" {
    const allocator = std.testing.allocator;

    var rbac = RBAC.init(allocator);
    defer rbac.deinit();

    const editor = Role{
        .name = "editor",
        .permissions = &[_][]const u8{ "posts:read", "posts:write", "posts:edit" },
    };

    try rbac.defineRole(editor);
    try rbac.assignRole("user_123", "editor");

    // Has permissions
    try expect(rbac.userHasPermission("user_123", "posts:read"));
    try expect(rbac.userHasPermission("user_123", "posts:write"));
    try expect(rbac.userHasPermission("user_123", "posts:edit"));

    // Doesn't have permission
    try expect(!rbac.userHasPermission("user_123", "posts:delete"));
    try expect(!rbac.userHasPermission("user_123", "users:read"));

    // Non-existent user
    try expect(!rbac.userHasPermission("nonexistent", "posts:read"));
}

test "rbac - user with admin wildcard" {
    const allocator = std.testing.allocator;

    var rbac = RBAC.init(allocator);
    defer rbac.deinit();

    const admin = Role{
        .name = "admin",
        .permissions = &[_][]const u8{"*"},
    };

    try rbac.defineRole(admin);
    try rbac.assignRole("admin_user", "admin");

    // Admin has all permissions
    try expect(rbac.userHasPermission("admin_user", "users:create"));
    try expect(rbac.userHasPermission("admin_user", "posts:delete"));
    try expect(rbac.userHasPermission("admin_user", "anything:anything"));
}

test "rbac - user with multiple roles" {
    const allocator = std.testing.allocator;

    var rbac = RBAC.init(allocator);
    defer rbac.deinit();

    const user = Role{
        .name = "user",
        .permissions = &[_][]const u8{"posts:read"},
    };

    const editor = Role{
        .name = "editor",
        .permissions = &[_][]const u8{"posts:write"},
    };

    try rbac.defineRole(user);
    try rbac.defineRole(editor);

    try rbac.assignRole("user_123", "user");
    try rbac.assignRole("user_123", "editor");

    // Has permissions from both roles
    try expect(rbac.userHasPermission("user_123", "posts:read"));
    try expect(rbac.userHasPermission("user_123", "posts:write"));
    try expect(!rbac.userHasPermission("user_123", "posts:delete"));
}

test "rbac - user any permission" {
    const allocator = std.testing.allocator;

    var rbac = RBAC.init(allocator);
    defer rbac.deinit();

    const moderator = Role{
        .name = "moderator",
        .permissions = &[_][]const u8{ "posts:read", "posts:edit", "comments:delete" },
    };

    try rbac.defineRole(moderator);
    try rbac.assignRole("mod_user", "moderator");

    const required1 = [_][]const u8{ "posts:delete", "posts:read" };
    try expect(rbac.userHasAnyPermission("mod_user", &required1)); // Has posts:read

    const required2 = [_][]const u8{ "users:read", "admin:access" };
    try expect(!rbac.userHasAnyPermission("mod_user", &required2)); // Has neither
}

test "rbac - user all permissions" {
    const allocator = std.testing.allocator;

    var rbac = RBAC.init(allocator);
    defer rbac.deinit();

    const moderator = Role{
        .name = "moderator",
        .permissions = &[_][]const u8{ "posts:read", "posts:edit", "comments:delete" },
    };

    try rbac.defineRole(moderator);
    try rbac.assignRole("mod_user", "moderator");

    const required1 = [_][]const u8{ "posts:read", "posts:edit" };
    try expect(rbac.userHasAllPermissions("mod_user", &required1));

    const required2 = [_][]const u8{ "posts:read", "admin:access" };
    try expect(!rbac.userHasAllPermissions("mod_user", &required2)); // Missing admin:access
}
