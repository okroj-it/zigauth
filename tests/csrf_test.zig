const std = @import("std");
const zigauth = @import("zigauth");
const csrf = zigauth.auth.csrf;

test "CSRF: generateToken creates unique tokens" {
    const allocator = std.testing.allocator;

    const token1 = try csrf.generateToken(allocator);
    defer allocator.free(token1);

    const token2 = try csrf.generateToken(allocator);
    defer allocator.free(token2);

    // Tokens should be different
    try std.testing.expect(!std.mem.eql(u8, token1, token2));

    // Tokens should be non-empty
    try std.testing.expect(token1.len > 0);
    try std.testing.expect(token2.len > 0);
}

test "CSRF: validateToken accepts matching tokens" {
    const allocator = std.testing.allocator;

    const token = try csrf.generateToken(allocator);
    defer allocator.free(token);

    // Same token should validate
    try std.testing.expect(csrf.validateToken(token, token));

    // Copy should also validate
    const token_copy = try allocator.dupe(u8, token);
    defer allocator.free(token_copy);
    try std.testing.expect(csrf.validateToken(token, token_copy));
}

test "CSRF: validateToken rejects different tokens" {
    const allocator = std.testing.allocator;

    const token1 = try csrf.generateToken(allocator);
    defer allocator.free(token1);

    const token2 = try csrf.generateToken(allocator);
    defer allocator.free(token2);

    // Different tokens should not validate
    try std.testing.expect(!csrf.validateToken(token1, token2));
}

test "CSRF: validateToken rejects different lengths" {
    const token1 = "shorttoken";
    const token2 = "verylongtoken";

    try std.testing.expect(!csrf.validateToken(token1, token2));
}

test "CSRF: validateTokenOrError returns correct errors" {
    const allocator = std.testing.allocator;

    const token = try csrf.generateToken(allocator);
    defer allocator.free(token);

    // Valid token should succeed
    try csrf.validateTokenOrError(token, token);

    // Missing token should error
    try std.testing.expectError(error.MissingCsrfToken, csrf.validateTokenOrError(token, null));

    // Invalid token should error
    const wrong_token = "wrong_token";
    try std.testing.expectError(error.InvalidCsrfToken, csrf.validateTokenOrError(token, wrong_token));
}

test "CSRF: generateTokenWithConfig respects token_bytes" {
    const allocator = std.testing.allocator;

    const config = csrf.Config{
        .token_bytes = 16, // 16 bytes = 128 bits
    };

    const token = try csrf.generateTokenWithConfig(allocator, config);
    defer allocator.free(token);

    // Base64url encoding should expand 16 bytes to ~22 characters
    const base64 = std.base64.url_safe_no_pad;
    const expected_len = base64.Encoder.calcSize(16);
    try std.testing.expectEqual(expected_len, token.len);
}

test "CSRF: extractTokenFromParams finds token in common field names" {
    const allocator = std.testing.allocator;

    var params = std.StringHashMap([]const u8).init(allocator);
    defer params.deinit();

    // Test csrf_token field
    try params.put("csrf_token", "token123");
    try std.testing.expectEqualStrings("token123", csrf.extractTokenFromParams(params).?);
    _ = params.remove("csrf_token");

    // Test _csrf field
    try params.put("_csrf", "token456");
    try std.testing.expectEqualStrings("token456", csrf.extractTokenFromParams(params).?);
    _ = params.remove("_csrf");

    // Test csrf field
    try params.put("csrf", "token789");
    try std.testing.expectEqualStrings("token789", csrf.extractTokenFromParams(params).?);

    // Test missing token
    params.clearRetainingCapacity();
    try std.testing.expect(csrf.extractTokenFromParams(params) == null);
}

test "CSRF: session integration - token is generated on session creation" {
    const allocator = std.testing.allocator;

    var store = zigauth.storage.memory.MemoryStore.init(allocator);
    defer store.deinit();

    const store_interface = store.store();

    // Create session
    const session = try store_interface.create(allocator, "user_123", 3600);
    defer {
        var s = session;
        s.deinit(allocator);
    }

    // Session should have a CSRF token
    try std.testing.expect(session.csrf_token != null);
    const token = session.csrf_token.?;
    try std.testing.expect(token.len > 0);
}

test "CSRF: session integration - token persists across get" {
    const allocator = std.testing.allocator;

    var store = zigauth.storage.memory.MemoryStore.init(allocator);
    defer store.deinit();

    const store_interface = store.store();

    // Create session
    const session = try store_interface.create(allocator, "user_123", 3600);
    const session_id = try allocator.dupe(u8, session.id);
    defer allocator.free(session_id);

    const original_token = try allocator.dupe(u8, session.csrf_token.?);
    defer allocator.free(original_token);

    var s = session;
    s.deinit(allocator);

    // Retrieve session
    const retrieved = try store_interface.get(allocator, session_id);
    defer {
        var r = retrieved;
        r.deinit(allocator);
    }

    // CSRF token should match
    try std.testing.expect(retrieved.csrf_token != null);
    try std.testing.expectEqualStrings(original_token, retrieved.csrf_token.?);
}
