const std = @import("std");
const testing = std.testing;
const zigauth = @import("zigauth");

test "password hashing - basic functionality" {
    const password = "my_secure_password_123!";
    const hashed = try zigauth.auth.password.hashFast(testing.allocator, password);
    defer testing.allocator.free(hashed);

    try testing.expect(hashed.len > 0);
    try testing.expect(std.mem.startsWith(u8, hashed, "$argon2id$"));
}

test "password verification - correct password" {
    const password = "correct_password_789";
    const hashed = try zigauth.auth.password.hashFast(testing.allocator, password);
    defer testing.allocator.free(hashed);

    const valid = try zigauth.auth.password.verify(testing.allocator, password, hashed);
    try testing.expect(valid);
}

test "password verification - incorrect password" {
    const password = "correct_password";
    const wrong_password = "wrong_password";

    const hashed = try zigauth.auth.password.hashFast(testing.allocator, password);
    defer testing.allocator.free(hashed);

    const valid = try zigauth.auth.password.verify(testing.allocator, wrong_password, hashed);
    try testing.expect(!valid);
}

test "password hashing - empty password rejected" {
    const result = zigauth.auth.password.hash(
        testing.allocator,
        "",
        zigauth.auth.password.default_config,
    );
    try testing.expectError(zigauth.auth.password.Error.InvalidPassword, result);
}

test "password hashing - unique salts" {
    const password = "same_password";

    const hash1 = try zigauth.auth.password.hashFast(testing.allocator, password);
    defer testing.allocator.free(hash1);

    const hash2 = try zigauth.auth.password.hashFast(testing.allocator, password);
    defer testing.allocator.free(hash2);

    try testing.expect(!std.mem.eql(u8, hash1, hash2));
    try testing.expect(try zigauth.auth.password.verify(testing.allocator, password, hash1));
    try testing.expect(try zigauth.auth.password.verify(testing.allocator, password, hash2));
}

test "password hashing - special characters" {
    const passwords = [_][]const u8{
        "p@ssw0rd!",
        "test#123$",
        "user_name+123",
        "spaces in password",
    };

    for (passwords) |password| {
        const hashed = try zigauth.auth.password.hashFast(testing.allocator, password);
        defer testing.allocator.free(hashed);

        const valid = try zigauth.auth.password.verify(testing.allocator, password, hashed);
        try testing.expect(valid);
    }
}

test "password hashing - long passwords" {
    var long_password: [1024]u8 = undefined;
    @memset(&long_password, 'a');

    const hashed = try zigauth.auth.password.hashFast(testing.allocator, &long_password);
    defer testing.allocator.free(hashed);

    const valid = try zigauth.auth.password.verify(testing.allocator, &long_password, hashed);
    try testing.expect(valid);
}

test "core types - User struct" {
    const user = zigauth.User{
        .id = "user_123",
        .email = "test@example.com",
        .password_hash = "hashed_password",
        .roles = &[_][]const u8{ "user", "admin" },
        .created_at = 1234567890,
        .updated_at = 1234567890,
    };

    try testing.expectEqualStrings("user_123", user.id);
    try testing.expectEqualStrings("test@example.com", user.email);
    try testing.expect(user.roles.len == 2);
}

test "core types - Session struct" {
    const session = zigauth.Session{
        .id = "session_abc",
        .user_id = "user_123",
        .expires_at = 1234567890,
        .data = .null,
    };

    try testing.expectEqualStrings("session_abc", session.id);
    try testing.expectEqualStrings("user_123", session.user_id);
}

test "core types - Claims struct" {
    const claims = zigauth.Claims{
        .sub = "user_123",
        .exp = 1234567890,
        .iat = 1234567000,
        .iss = "zigauth",
        .roles = &[_][]const u8{"user"},
    };

    try testing.expectEqualStrings("user_123", claims.sub);
    try testing.expectEqualStrings("zigauth", claims.iss);
}
