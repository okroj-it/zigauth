const std = @import("std");

// Core modules
pub const auth = struct {
    pub const password = @import("auth/password.zig");
    pub const session = @import("auth/session.zig");
    pub const jwt = @import("auth/jwt.zig");
    pub const csrf = @import("auth/csrf.zig");
};

pub const authz = struct {
    pub const rbac = @import("authz/rbac.zig");
    pub const permissions = @import("authz/permissions.zig");
};

pub const adapters = struct {
    pub const zigzap = @import("adapters/zigzap.zig");
    pub const httpz = @import("adapters/httpz.zig");
    pub const jetzig = @import("adapters/jetzig.zig");
    pub const tokamak = @import("adapters/tokamak.zig");
};

pub const security = struct {
    // TODO: Implement security modules
};

pub const storage = struct {
    pub const memory = @import("storage/memory.zig");
};

// Core types
pub const User = struct {
    id: []const u8,
    email: []const u8,
    password_hash: []const u8,
    roles: []const []const u8,
    created_at: i64,
    updated_at: i64,
};

pub const Session = struct {
    id: []const u8,
    user_id: []const u8,
    expires_at: i64,
    data: std.json.Value,
};

pub const Claims = struct {
    sub: []const u8, // Subject (user ID)
    exp: i64, // Expiration time
    iat: i64, // Issued at
    iss: []const u8, // Issuer
    roles: []const []const u8, // User roles
};

test "zigauth core types" {
    const testing = std.testing;

    const user = User{
        .id = "user_123",
        .email = "test@example.com",
        .password_hash = "hashed_password",
        .roles = &[_][]const u8{"user"},
        .created_at = 1234567890,
        .updated_at = 1234567890,
    };

    try testing.expectEqualStrings("user_123", user.id);
    try testing.expectEqualStrings("test@example.com", user.email);
}
