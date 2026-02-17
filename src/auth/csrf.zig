//! CSRF (Cross-Site Request Forgery) Protection
//!
//! Provides cryptographically secure CSRF token generation and validation
//! to protect against CSRF attacks on state-changing requests.
//!
//! Features:
//! - Secure random token generation (32 bytes)
//! - Constant-time token comparison (timing-attack resistant)
//! - Base64url encoding for URL safety
//! - Integration with session-based and stateless patterns
//!
//! Example usage:
//!
//! ```zig
//! const csrf = @import("zigauth").auth.csrf;
//!
//! // Generate token for session
//! const token = try csrf.generateToken(allocator);
//! defer allocator.free(token);
//!
//! // Validate token (constant-time comparison)
//! const valid = csrf.validateToken(expected, provided);
//! if (!valid) return error.InvalidCsrfToken;
//! ```

const std = @import("std");
const base64 = std.base64.url_safe_no_pad;

/// CSRF token configuration
pub const Config = struct {
    /// Token length in bytes (before base64 encoding)
    /// Default: 32 bytes (256 bits)
    token_bytes: usize = 32,

    /// Whether to enforce token validation on all state-changing methods
    /// (POST, PUT, DELETE, PATCH)
    enforce_on_mutations: bool = true,

    /// HTTP header name for CSRF token (for double-submit cookie pattern)
    header_name: []const u8 = "X-CSRF-Token",
};

/// Default CSRF configuration
pub const default_config = Config{};

/// Generate a cryptographically secure CSRF token
///
/// Returns a base64url-encoded token that should be stored in the session
/// and included in forms/requests for validation.
///
/// Caller owns the returned memory and must free it.
pub fn generateToken(allocator: std.mem.Allocator) ![]u8 {
    return generateTokenWithConfig(allocator, default_config);
}

/// Generate a CSRF token with custom configuration
pub fn generateTokenWithConfig(allocator: std.mem.Allocator, config: Config) ![]u8 {
    // Generate random bytes
    const random_bytes = try allocator.alloc(u8, config.token_bytes);
    defer allocator.free(random_bytes);

    std.crypto.random.bytes(random_bytes);

    // Encode to base64url (URL-safe, no padding)
    const encoded_len = base64.Encoder.calcSize(random_bytes.len);
    const token = try allocator.alloc(u8, encoded_len);
    errdefer allocator.free(token);

    _ = base64.Encoder.encode(token, random_bytes);

    return token;
}

/// Validate CSRF token using constant-time comparison
///
/// Compares expected token (from session/cookie) with provided token
/// (from form/header) using constant-time comparison to prevent timing attacks.
///
/// Returns true if tokens match, false otherwise.
pub fn validateToken(expected: []const u8, provided: []const u8) bool {
    // Length must match
    if (expected.len != provided.len) {
        return false;
    }

    // Constant-time comparison (timing-attack resistant)
    // Compare byte-by-byte using XOR accumulator
    var diff: u8 = 0;
    for (expected, provided) |e, p| {
        diff |= e ^ p;
    }
    return diff == 0;
}

/// CSRF token validation error
pub const CsrfError = error{
    MissingCsrfToken,
    InvalidCsrfToken,
    TokenLengthMismatch,
};

/// Validate CSRF token and return error on failure
///
/// Convenience function that returns specific error instead of bool
pub fn validateTokenOrError(expected: []const u8, provided: ?[]const u8) CsrfError!void {
    const provided_token = provided orelse return error.MissingCsrfToken;

    if (!validateToken(expected, provided_token)) {
        return error.InvalidCsrfToken;
    }
}

/// Extract CSRF token from form data or query parameters
///
/// Looks for token in common field names: csrf_token, _csrf, csrf
pub fn extractTokenFromParams(params: std.StringHashMap([]const u8)) ?[]const u8 {
    // Try common field names
    if (params.get("csrf_token")) |token| return token;
    if (params.get("_csrf")) |token| return token;
    if (params.get("csrf")) |token| return token;
    return null;
}

test "generateToken creates unique tokens" {
    const allocator = std.testing.allocator;

    const token1 = try generateToken(allocator);
    defer allocator.free(token1);

    const token2 = try generateToken(allocator);
    defer allocator.free(token2);

    // Tokens should be different
    try std.testing.expect(!std.mem.eql(u8, token1, token2));

    // Tokens should be non-empty
    try std.testing.expect(token1.len > 0);
    try std.testing.expect(token2.len > 0);
}

test "validateToken accepts matching tokens" {
    const allocator = std.testing.allocator;

    const token = try generateToken(allocator);
    defer allocator.free(token);

    // Same token should validate
    try std.testing.expect(validateToken(token, token));

    // Copy should also validate
    const token_copy = try allocator.dupe(u8, token);
    defer allocator.free(token_copy);
    try std.testing.expect(validateToken(token, token_copy));
}

test "validateToken rejects different tokens" {
    const allocator = std.testing.allocator;

    const token1 = try generateToken(allocator);
    defer allocator.free(token1);

    const token2 = try generateToken(allocator);
    defer allocator.free(token2);

    // Different tokens should not validate
    try std.testing.expect(!validateToken(token1, token2));
}

test "validateToken rejects different lengths" {
    const token1 = "shorttoken";
    const token2 = "verylongtoken";

    try std.testing.expect(!validateToken(token1, token2));
}

test "validateTokenOrError returns correct errors" {
    const allocator = std.testing.allocator;

    const token = try generateToken(allocator);
    defer allocator.free(token);

    // Valid token should succeed
    try validateTokenOrError(token, token);

    // Missing token should error
    try std.testing.expectError(error.MissingCsrfToken, validateTokenOrError(token, null));

    // Invalid token should error
    const wrong_token = "wrong_token";
    try std.testing.expectError(error.InvalidCsrfToken, validateTokenOrError(token, wrong_token));
}

test "generateTokenWithConfig respects token_bytes" {
    const allocator = std.testing.allocator;

    const config = Config{
        .token_bytes = 16, // 16 bytes = 128 bits
    };

    const token = try generateTokenWithConfig(allocator, config);
    defer allocator.free(token);

    // Base64url encoding should expand 16 bytes to ~22 characters
    const expected_len = base64.Encoder.calcSize(16);
    try std.testing.expectEqual(expected_len, token.len);
}

test "extractTokenFromParams finds token in common field names" {
    const allocator = std.testing.allocator;

    var params = std.StringHashMap([]const u8).init(allocator);
    defer params.deinit();

    // Test csrf_token field
    try params.put("csrf_token", "token123");
    try std.testing.expectEqualStrings("token123", extractTokenFromParams(params).?);
    _ = params.remove("csrf_token");

    // Test _csrf field
    try params.put("_csrf", "token456");
    try std.testing.expectEqualStrings("token456", extractTokenFromParams(params).?);
    _ = params.remove("_csrf");

    // Test csrf field
    try params.put("csrf", "token789");
    try std.testing.expectEqualStrings("token789", extractTokenFromParams(params).?);

    // Test missing token
    params.clearRetainingCapacity();
    try std.testing.expect(extractTokenFromParams(params) == null);
}
