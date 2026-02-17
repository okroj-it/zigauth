const std = @import("std");
const mem = std.mem;

/// Permission format: "resource:action"
/// Examples: "users:read", "posts:write", "admin:*"
/// Wildcards: "*" matches all, "users:*" matches all user actions

/// Check if a permission matches a required permission
/// Supports wildcard matching
pub fn matches(has: []const u8, required: []const u8) bool {
    // Exact match
    if (mem.eql(u8, has, required)) return true;

    // Full wildcard
    if (mem.eql(u8, has, "*")) return true;

    // Resource wildcard (e.g., "users:*" matches "users:read")
    if (mem.endsWith(u8, has, ":*")) {
        const resource = has[0 .. has.len - 2]; // Remove ":*"
        if (mem.startsWith(u8, required, resource) and required.len > resource.len and required[resource.len] == ':') {
            return true;
        }
    }

    return false;
}

/// Check if any of the provided permissions match the required permission
pub fn matchesAny(has_permissions: []const []const u8, required: []const u8) bool {
    for (has_permissions) |perm| {
        if (matches(perm, required)) return true;
    }
    return false;
}

/// Check if all required permissions are satisfied by the provided permissions
pub fn matchesAll(has_permissions: []const []const u8, required_permissions: []const []const u8) bool {
    for (required_permissions) |required| {
        if (!matchesAny(has_permissions, required)) return false;
    }
    return true;
}

/// Parse permission into resource and action
pub const Permission = struct {
    resource: []const u8,
    action: []const u8,

    pub fn parse(permission: []const u8) ?Permission {
        const colon_idx = mem.indexOf(u8, permission, ":") orelse return null;

        const resource = permission[0..colon_idx];
        const action = permission[colon_idx + 1 ..];

        // Reject empty resource or action (e.g., ":", "resource:", ":action")
        if (resource.len == 0 or action.len == 0) return null;

        return .{ .resource = resource, .action = action };
    }

    pub fn toString(self: Permission, allocator: mem.Allocator) ![]u8 {
        return std.fmt.allocPrint(allocator, "{s}:{s}", .{ self.resource, self.action });
    }
};

// Tests
test "permissions - exact match" {
    const testing = std.testing;
    try testing.expect(matches("users:read", "users:read"));
    try testing.expect(!matches("users:read", "users:write"));
}

test "permissions - wildcard match" {
    const testing = std.testing;
    try testing.expect(matches("*", "users:read"));
    try testing.expect(matches("*", "posts:write"));
    try testing.expect(matches("users:*", "users:read"));
    try testing.expect(matches("users:*", "users:write"));
    try testing.expect(!matches("users:*", "posts:read"));
}

test "permissions - matches any" {
    const testing = std.testing;
    const perms = [_][]const u8{ "users:read", "posts:write" };
    try testing.expect(matchesAny(&perms, "users:read"));
    try testing.expect(matchesAny(&perms, "posts:write"));
    try testing.expect(!matchesAny(&perms, "admin:delete"));
}

test "permissions - matches all" {
    const testing = std.testing;
    const has = [_][]const u8{ "users:read", "users:write", "posts:read" };
    const required1 = [_][]const u8{ "users:read", "posts:read" };
    const required2 = [_][]const u8{ "users:read", "admin:delete" };

    try testing.expect(matchesAll(&has, &required1));
    try testing.expect(!matchesAll(&has, &required2));
}

test "permissions - parse" {
    const testing = std.testing;

    const perm = Permission.parse("users:read").?;
    try testing.expectEqualStrings("users", perm.resource);
    try testing.expectEqualStrings("read", perm.action);

    const invalid = Permission.parse("invalid");
    try testing.expect(invalid == null);

    // Empty resource or action should be rejected
    try testing.expect(Permission.parse(":read") == null);
    try testing.expect(Permission.parse("users:") == null);
    try testing.expect(Permission.parse(":") == null);
}

test "permissions - to string" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const perm = Permission{ .resource = "users", .action = "read" };
    const str = try perm.toString(allocator);
    defer allocator.free(str);

    try testing.expectEqualStrings("users:read", str);
}
