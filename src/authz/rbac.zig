const std = @import("std");
const mem = std.mem;
const permissions_mod = @import("permissions.zig");

/// Role with associated permissions
pub const Role = struct {
    name: []const u8,
    permissions: []const []const u8,
    description: ?[]const u8 = null,

    /// Check if role has a specific permission
    pub fn hasPermission(self: Role, permission: []const u8) bool {
        return permissions_mod.matchesAny(self.permissions, permission);
    }

    /// Check if role has any of the specified permissions
    pub fn hasAnyPermission(self: Role, required: []const []const u8) bool {
        for (required) |perm| {
            if (self.hasPermission(perm)) return true;
        }
        return false;
    }

    /// Check if role has all of the specified permissions
    pub fn hasAllPermissions(self: Role, required: []const []const u8) bool {
        return permissions_mod.matchesAll(self.permissions, required);
    }

    /// Create a copy of the role with owned memory
    pub fn clone(self: Role, allocator: mem.Allocator) !Role {
        const name_copy = try allocator.dupe(u8, self.name);
        errdefer allocator.free(name_copy);

        var perms_copy = try allocator.alloc([]const u8, self.permissions.len);
        errdefer allocator.free(perms_copy);

        var i: usize = 0;
        errdefer {
            for (perms_copy[0..i]) |perm| {
                allocator.free(perm);
            }
        }

        for (self.permissions, 0..) |perm, idx| {
            perms_copy[idx] = try allocator.dupe(u8, perm);
            i = idx + 1;
        }

        const desc_copy = if (self.description) |desc|
            try allocator.dupe(u8, desc)
        else
            null;

        return .{
            .name = name_copy,
            .permissions = perms_copy,
            .description = desc_copy,
        };
    }

    /// Free role memory
    pub fn deinit(self: *Role, allocator: mem.Allocator) void {
        allocator.free(self.name);
        for (self.permissions) |perm| {
            allocator.free(perm);
        }
        allocator.free(self.permissions);
        if (self.description) |desc| {
            allocator.free(desc);
        }
    }
};

/// RBAC manager for role definitions and user assignments
pub const RBAC = struct {
    allocator: mem.Allocator,
    roles: std.StringHashMap(Role),
    user_roles: std.StringHashMap(std.ArrayListUnmanaged([]const u8)),

    pub fn init(allocator: mem.Allocator) RBAC {
        return .{
            .allocator = allocator,
            .roles = std.StringHashMap(Role).init(allocator),
            .user_roles = std.StringHashMap(std.ArrayListUnmanaged([]const u8)).init(allocator),
        };
    }

    pub fn deinit(self: *RBAC) void {
        // Free roles
        var role_iter = self.roles.iterator();
        while (role_iter.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            var role = entry.value_ptr.*;
            role.deinit(self.allocator);
        }
        self.roles.deinit();

        // Free user roles
        var user_iter = self.user_roles.iterator();
        while (user_iter.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            for (entry.value_ptr.items) |role_name| {
                self.allocator.free(role_name);
            }
            entry.value_ptr.deinit(self.allocator);
        }
        self.user_roles.deinit();
    }

    /// Define a new role
    pub fn defineRole(self: *RBAC, role: Role) !void {
        const role_copy = try role.clone(self.allocator);
        errdefer {
            var r = role_copy;
            r.deinit(self.allocator);
        }

        const key = try self.allocator.dupe(u8, role.name);
        try self.roles.put(key, role_copy);
    }

    /// Get a role by name
    pub fn getRole(self: *RBAC, name: []const u8) ?Role {
        return self.roles.get(name);
    }

    /// Assign a role to a user
    pub fn assignRole(self: *RBAC, user_id: []const u8, role_name: []const u8) !void {
        // Verify role exists
        if (!self.roles.contains(role_name)) {
            return error.RoleNotFound;
        }

        const entry = try self.user_roles.getOrPut(user_id);
        if (!entry.found_existing) {
            entry.key_ptr.* = try self.allocator.dupe(u8, user_id);
            entry.value_ptr.* = .empty;
        }

        // SECURITY: Check for duplicate before adding to prevent memory leaks
        // and performance degradation from duplicate role entries
        for (entry.value_ptr.items) |existing_role| {
            if (mem.eql(u8, existing_role, role_name)) {
                return; // Already assigned, no-op
            }
        }

        const role_copy = try self.allocator.dupe(u8, role_name);
        try entry.value_ptr.append(self.allocator, role_copy);
    }

    /// Remove a role from a user
    pub fn removeRole(self: *RBAC, user_id: []const u8, role_name: []const u8) !void {
        const roles = self.user_roles.getPtr(user_id) orelse return error.UserNotFound;

        var i: usize = 0;
        while (i < roles.items.len) {
            if (mem.eql(u8, roles.items[i], role_name)) {
                const removed = roles.orderedRemove(i);
                self.allocator.free(removed);
                return;
            }
            i += 1;
        }

        return error.RoleNotAssigned;
    }

    /// Get all roles assigned to a user
    pub fn getUserRoles(self: *RBAC, user_id: []const u8) ?[]const []const u8 {
        const roles = self.user_roles.get(user_id) orelse return null;
        return roles.items;
    }

    /// Check if user has a specific permission
    pub fn userHasPermission(self: *RBAC, user_id: []const u8, permission: []const u8) bool {
        const role_names = self.getUserRoles(user_id) orelse return false;

        for (role_names) |role_name| {
            if (self.getRole(role_name)) |role| {
                if (role.hasPermission(permission)) return true;
            }
        }

        return false;
    }

    /// Check if user has any of the specified permissions
    pub fn userHasAnyPermission(self: *RBAC, user_id: []const u8, required: []const []const u8) bool {
        const role_names = self.getUserRoles(user_id) orelse return false;

        for (role_names) |role_name| {
            if (self.getRole(role_name)) |role| {
                if (role.hasAnyPermission(required)) return true;
            }
        }

        return false;
    }

    /// Check if user has all of the specified permissions
    pub fn userHasAllPermissions(self: *RBAC, user_id: []const u8, required: []const []const u8) bool {
        for (required) |perm| {
            if (!self.userHasPermission(user_id, perm)) return false;
        }
        return true;
    }
};

// Tests
test "rbac - role permission checking" {
    const testing = std.testing;

    const role = Role{
        .name = "editor",
        .permissions = &[_][]const u8{ "posts:read", "posts:write", "posts:edit" },
    };

    try testing.expect(role.hasPermission("posts:read"));
    try testing.expect(role.hasPermission("posts:write"));
    try testing.expect(!role.hasPermission("posts:delete"));
}

test "rbac - role wildcard permissions" {
    const testing = std.testing;

    const role = Role{
        .name = "admin",
        .permissions = &[_][]const u8{"*"},
    };

    try testing.expect(role.hasPermission("users:read"));
    try testing.expect(role.hasPermission("posts:delete"));
    try testing.expect(role.hasPermission("anything:anything"));
}

test "rbac - role any/all permissions" {
    const testing = std.testing;

    const role = Role{
        .name = "moderator",
        .permissions = &[_][]const u8{ "posts:read", "posts:edit", "comments:delete" },
    };

    const any_required = [_][]const u8{ "posts:delete", "posts:read" };
    try testing.expect(role.hasAnyPermission(&any_required));

    const all_required = [_][]const u8{ "posts:read", "posts:edit" };
    try testing.expect(role.hasAllPermissions(&all_required));

    const missing = [_][]const u8{ "posts:read", "admin:access" };
    try testing.expect(!role.hasAllPermissions(&missing));
}

test "rbac - define and get role" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var rbac = RBAC.init(allocator);
    defer rbac.deinit();

    const role = Role{
        .name = "user",
        .permissions = &[_][]const u8{ "posts:read", "profile:edit" },
        .description = "Basic user role",
    };

    try rbac.defineRole(role);

    const retrieved = rbac.getRole("user").?;
    try testing.expectEqualStrings("user", retrieved.name);
    try testing.expect(retrieved.hasPermission("posts:read"));
}

test "rbac - assign and remove roles" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var rbac = RBAC.init(allocator);
    defer rbac.deinit();

    const role = Role{
        .name = "editor",
        .permissions = &[_][]const u8{ "posts:write", "posts:edit" },
    };

    try rbac.defineRole(role);
    try rbac.assignRole("user_123", "editor");

    const roles = rbac.getUserRoles("user_123").?;
    try testing.expectEqual(@as(usize, 1), roles.len);
    try testing.expectEqualStrings("editor", roles[0]);

    try rbac.removeRole("user_123", "editor");
    const roles_after = rbac.getUserRoles("user_123").?;
    try testing.expectEqual(@as(usize, 0), roles_after.len);
}

test "rbac - user permission checking" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var rbac = RBAC.init(allocator);
    defer rbac.deinit();

    const editor = Role{
        .name = "editor",
        .permissions = &[_][]const u8{ "posts:write", "posts:edit" },
    };

    const admin = Role{
        .name = "admin",
        .permissions = &[_][]const u8{"*"},
    };

    try rbac.defineRole(editor);
    try rbac.defineRole(admin);

    try rbac.assignRole("user_123", "editor");
    try rbac.assignRole("user_456", "admin");

    // Editor permissions
    try testing.expect(rbac.userHasPermission("user_123", "posts:write"));
    try testing.expect(!rbac.userHasPermission("user_123", "users:delete"));

    // Admin permissions
    try testing.expect(rbac.userHasPermission("user_456", "anything:anything"));
}

test "rbac - user any/all permissions" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var rbac = RBAC.init(allocator);
    defer rbac.deinit();

    const role = Role{
        .name = "moderator",
        .permissions = &[_][]const u8{ "posts:read", "posts:edit", "comments:delete" },
    };

    try rbac.defineRole(role);
    try rbac.assignRole("user_789", "moderator");

    const any_required = [_][]const u8{ "posts:delete", "posts:read" };
    try testing.expect(rbac.userHasAnyPermission("user_789", &any_required));

    const all_required = [_][]const u8{ "posts:read", "posts:edit" };
    try testing.expect(rbac.userHasAllPermissions("user_789", &all_required));

    const missing = [_][]const u8{ "posts:read", "admin:access" };
    try testing.expect(!rbac.userHasAllPermissions("user_789", &missing));
}
