const std = @import("std");
const testing = std.testing;
const zigauth = @import("zigauth");
const jwt = zigauth.auth.jwt;

test "jwt sign and verify - basic" {
    const secret = "my-secret-key";
    const claims = jwt.Claims{
        .sub = "user_123",
        .exp = std.time.timestamp() + 3600, // 1 hour from now
        .iat = std.time.timestamp(),
        .iss = "zigauth",
    };

    // Sign token
    const token = try jwt.sign(testing.allocator, claims, secret, .hs256);
    defer token.deinit(testing.allocator);

    // Token should be non-empty
    try testing.expect(token.raw.len > 0);

    // Verify token
    const verified = try jwt.verify(testing.allocator, token.raw, secret);
    defer jwt.freeClaims(testing.allocator, verified);

    try testing.expectEqualStrings(claims.sub, verified.sub);
    try testing.expectEqual(claims.exp, verified.exp);
    try testing.expectEqual(claims.iat, verified.iat);
}

test "jwt verify fails with wrong secret" {
    const secret = "correct-secret";
    const wrong_secret = "wrong-secret";

    const claims = jwt.Claims{
        .sub = "user_123",
        .exp = std.time.timestamp() + 3600,
        .iat = std.time.timestamp(),
    };

    const token = try jwt.sign(testing.allocator, claims, secret, .hs256);
    defer token.deinit(testing.allocator);

    const result = jwt.verify(testing.allocator, token.raw, wrong_secret);
    try testing.expectError(jwt.Error.InvalidSignature, result);
}

test "jwt verify detects expired token" {
    const secret = "my-secret";
    const claims = jwt.Claims{
        .sub = "user_123",
        .exp = std.time.timestamp() - 1, // Already expired
        .iat = std.time.timestamp() - 3600,
    };

    const token = try jwt.sign(testing.allocator, claims, secret, .hs256);
    defer token.deinit(testing.allocator);

    const result = jwt.verify(testing.allocator, token.raw, secret);
    try testing.expectError(jwt.Error.TokenExpired, result);
}

test "jwt token format - three parts" {
    const secret = "test-secret";
    const claims = jwt.Claims{
        .sub = "user_123",
        .exp = std.time.timestamp() + 3600,
        .iat = std.time.timestamp(),
    };

    const token = try jwt.sign(testing.allocator, claims, secret, .hs256);
    defer token.deinit(testing.allocator);

    // Token should have format: header.payload.signature
    var parts = std.mem.splitSequence(u8, token.raw, ".");
    try testing.expect(parts.next() != null); // header
    try testing.expect(parts.next() != null); // payload
    try testing.expect(parts.next() != null); // signature
    try testing.expect(parts.next() == null); // no more parts
}

test "jwt refresh token generation" {
    const token1 = try jwt.generateRefreshToken(testing.allocator);
    defer testing.allocator.free(token1);

    const token2 = try jwt.generateRefreshToken(testing.allocator);
    defer testing.allocator.free(token2);

    // Tokens should be different
    try testing.expect(!std.mem.eql(u8, token1, token2));

    // Tokens should be base64url encoded (no padding, URL-safe)
    try testing.expect(std.mem.indexOf(u8, token1, "=") == null);
    try testing.expect(std.mem.indexOf(u8, token2, "=") == null);

    // Tokens should have reasonable length (32 bytes -> ~43 chars base64url)
    try testing.expect(token1.len > 40);
    try testing.expect(token2.len > 40);
}

test "jwt claims validation - is valid" {
    const now = std.time.timestamp();

    // Valid token (not expired, issued in past)
    const valid = jwt.Claims{
        .sub = "user",
        .exp = now + 3600,
        .iat = now,
    };
    try testing.expect(valid.isValid());
    try testing.expect(!valid.isExpired());
}

test "jwt claims validation - is expired" {
    const now = std.time.timestamp();

    // Expired token
    const expired = jwt.Claims{
        .sub = "user",
        .exp = now - 1,
        .iat = now - 3600,
    };
    try testing.expect(!expired.isValid());
    try testing.expect(expired.isExpired());
}

test "jwt with optional claims" {
    const secret = "test-secret";
    const claims = jwt.Claims{
        .sub = "user_123",
        .exp = std.time.timestamp() + 3600,
        .iat = std.time.timestamp(),
        .iss = "zigauth",
        .aud = "myapp",
        .jti = "token_id_123",
    };

    const token = try jwt.sign(testing.allocator, claims, secret, .hs256);
    defer token.deinit(testing.allocator);

    const verified = try jwt.verify(testing.allocator, token.raw, secret);
    defer jwt.freeClaims(testing.allocator, verified);

    try testing.expectEqualStrings("user_123", verified.sub);
    try testing.expectEqualStrings("zigauth", verified.iss.?);
    try testing.expectEqualStrings("myapp", verified.aud.?);
    try testing.expectEqualStrings("token_id_123", verified.jti.?);
}

test "jwt invalid format - missing parts" {
    const secret = "secret";

    // Token with only 2 parts (should have 3)
    const invalid_token = "header.payload";
    const result = jwt.verify(testing.allocator, invalid_token, secret);
    try testing.expectError(jwt.Error.InvalidFormat, result);
}

test "jwt invalid format - too many parts" {
    const secret = "secret";

    // Token with 4 parts (should have 3)
    const invalid_token = "header.payload.signature.extra";
    const result = jwt.verify(testing.allocator, invalid_token, secret);
    try testing.expectError(jwt.Error.InvalidFormat, result);
}
