const std = @import("std");
const crypto = std.crypto;
const mem = std.mem;
const base64 = std.base64;

/// JWT signing algorithms
pub const Algorithm = enum {
    hs256, // HMAC-SHA256

    pub fn toString(self: Algorithm) []const u8 {
        return switch (self) {
            .hs256 => "HS256",
        };
    }
};

/// JWT header
pub const Header = struct {
    alg: []const u8 = "HS256",
    typ: []const u8 = "JWT",
};

/// JWT claims
pub const Claims = struct {
    sub: []const u8, // Subject (user ID)
    exp: i64, // Expiration time (Unix timestamp)
    iat: i64, // Issued at (Unix timestamp)
    iss: ?[]const u8 = null, // Issuer (optional)
    aud: ?[]const u8 = null, // Audience (optional)
    jti: ?[]const u8 = null, // JWT ID (optional)

    /// Check if token is expired
    pub fn isExpired(self: Claims) bool {
        const now = std.time.timestamp();
        return now >= self.exp;
    }

    /// Check if token is valid (not expired, issued in past)
    pub fn isValid(self: Claims) bool {
        const now = std.time.timestamp();
        return now < self.exp and self.iat <= now;
    }
};

/// JWT token (opaque type)
pub const Token = struct {
    raw: []const u8,

    pub fn deinit(self: Token, allocator: mem.Allocator) void {
        allocator.free(self.raw);
    }
};

/// JWT errors
pub const Error = error{
    InvalidToken,
    InvalidFormat,
    InvalidSignature,
    TokenExpired,
    InvalidClaims,
    InvalidAlgorithm,
    OutOfMemory,
    // Base64 errors
    InvalidCharacter,
    InvalidPadding,
    NoSpaceLeft,
    // JSON errors
    Overflow,
    UnexpectedToken,
    InvalidNumber,
    InvalidEnumTag,
    DuplicateField,
    UnknownField,
    MissingField,
    LengthMismatch,
    SyntaxError,
    UnexpectedEndOfInput,
    BufferUnderrun,
    ValueTooLong,
};

/// Sign claims and create a JWT token
pub fn sign(
    allocator: mem.Allocator,
    claims: Claims,
    secret: []const u8,
    algorithm: Algorithm,
) Error!Token {
    // Create header
    const header = Header{
        .alg = algorithm.toString(),
        .typ = "JWT",
    };

    // Serialize header to JSON using fmt.allocPrint
    const header_json = try std.fmt.allocPrint(
        allocator,
        "{{\"alg\":\"{s}\",\"typ\":\"{s}\"}}",
        .{ header.alg, header.typ },
    );
    defer allocator.free(header_json);

    // SECURITY FIX: Serialize claims to JSON using incremental building
    // instead of deeply nested if/else blocks (LLM anti-pattern)
    const claims_json = blk: {
        var buf: std.ArrayListUnmanaged(u8) = .empty;
        defer buf.deinit(allocator);
        const writer = buf.writer(allocator);

        // Start JSON object with required fields
        try writer.print("{{\"sub\":\"{s}\",\"exp\":{d},\"iat\":{d}", .{
            claims.sub,
            claims.exp,
            claims.iat,
        });

        // Append optional fields if present
        if (claims.iss) |iss| {
            try writer.print(",\"iss\":\"{s}\"", .{iss});
        }
        if (claims.aud) |aud| {
            try writer.print(",\"aud\":\"{s}\"", .{aud});
        }
        if (claims.jti) |jti| {
            try writer.print(",\"jti\":\"{s}\"", .{jti});
        }

        // Close JSON object
        try writer.writeByte('}');

        break :blk try buf.toOwnedSlice(allocator);
    };
    defer allocator.free(claims_json);

    // Base64url encode header and claims
    const header_b64 = try base64url.encode(allocator, header_json);
    defer allocator.free(header_b64);

    const claims_b64 = try base64url.encode(allocator, claims_json);
    defer allocator.free(claims_b64);

    // Create signing input: header.claims
    const signing_input = try std.fmt.allocPrint(
        allocator,
        "{s}.{s}",
        .{ header_b64, claims_b64 },
    );
    defer allocator.free(signing_input);

    // Sign with HMAC-SHA256
    const signature = try signHmacSha256(allocator, signing_input, secret);
    defer allocator.free(signature);

    // Create final token: header.claims.signature
    const token = try std.fmt.allocPrint(
        allocator,
        "{s}.{s}",
        .{ signing_input, signature },
    );

    return Token{ .raw = token };
}

/// Verify and decode a JWT token
pub fn verify(
    allocator: mem.Allocator,
    token: []const u8,
    secret: []const u8,
) Error!Claims {
    // Split token into parts
    var parts_iter = mem.splitSequence(u8, token, ".");

    const header_b64 = parts_iter.next() orelse return Error.InvalidFormat;
    const claims_b64 = parts_iter.next() orelse return Error.InvalidFormat;
    const signature_b64 = parts_iter.next() orelse return Error.InvalidFormat;

    // Check no extra parts
    if (parts_iter.next() != null) return Error.InvalidFormat;

    // SECURITY: Decode and validate header algorithm.
    // Reject tokens with "alg": "none" or unsupported algorithms.
    const header_json = try base64url.decode(allocator, header_b64);
    defer allocator.free(header_json);

    const parsed_header = std.json.parseFromSlice(Header, allocator, header_json, .{}) catch {
        return Error.InvalidFormat;
    };
    defer parsed_header.deinit();

    if (!mem.eql(u8, parsed_header.value.alg, "HS256")) {
        return Error.InvalidAlgorithm;
    }

    // Verify signature
    const signing_input = try std.fmt.allocPrint(
        allocator,
        "{s}.{s}",
        .{ header_b64, claims_b64 },
    );
    defer allocator.free(signing_input);

    const expected_signature = try signHmacSha256(allocator, signing_input, secret);
    defer allocator.free(expected_signature);

    // SECURITY: Constant-time comparison to prevent timing attacks
    // Using same pattern as CSRF validation
    const length_match: u8 = if (signature_b64.len == expected_signature.len) 0 else 1;
    const min_len = @min(signature_b64.len, expected_signature.len);

    var diff: u8 = 0;
    for (0..min_len) |i| {
        diff |= signature_b64[i] ^ expected_signature[i];
    }

    // XOR remaining bytes to maintain constant time
    if (signature_b64.len > min_len) {
        for (min_len..signature_b64.len) |i| {
            diff |= signature_b64[i] ^ signature_b64[i];
        }
    }
    if (expected_signature.len > min_len) {
        for (min_len..expected_signature.len) |i| {
            diff |= expected_signature[i] ^ expected_signature[i];
        }
    }

    if ((length_match | diff) != 0) {
        return Error.InvalidSignature;
    }

    // Decode and parse claims
    const claims_json = try base64url.decode(allocator, claims_b64);
    defer allocator.free(claims_json);

    const parsed = try std.json.parseFromSlice(Claims, allocator, claims_json, .{});
    defer parsed.deinit();

    const claims = parsed.value;

    // Check expiration
    if (claims.isExpired()) {
        return Error.TokenExpired;
    }

    // Allocate claims with owned strings
    return Claims{
        .sub = try allocator.dupe(u8, claims.sub),
        .exp = claims.exp,
        .iat = claims.iat,
        .iss = if (claims.iss) |iss| try allocator.dupe(u8, iss) else null,
        .aud = if (claims.aud) |aud| try allocator.dupe(u8, aud) else null,
        .jti = if (claims.jti) |jti| try allocator.dupe(u8, jti) else null,
    };
}

/// Free claims allocated by verify()
pub fn freeClaims(allocator: mem.Allocator, claims: Claims) void {
    allocator.free(claims.sub);
    if (claims.iss) |iss| allocator.free(iss);
    if (claims.aud) |aud| allocator.free(aud);
    if (claims.jti) |jti| allocator.free(jti);
}

/// Generate a refresh token (random string)
pub fn generateRefreshToken(allocator: mem.Allocator) Error![]u8 {
    var random_bytes: [32]u8 = undefined;
    crypto.random.bytes(&random_bytes);

    return base64url.encode(allocator, &random_bytes);
}

// Internal: Base64url encoding (URL-safe, no padding)
const base64url = struct {
    const encoder = base64.url_safe_no_pad.Encoder;
    const decoder = base64.url_safe_no_pad.Decoder;

    fn encode(allocator: mem.Allocator, data: []const u8) Error![]u8 {
        const encoded_len = encoder.calcSize(data.len);
        const result = try allocator.alloc(u8, encoded_len);
        _ = encoder.encode(result, data);
        return result;
    }

    fn decode(allocator: mem.Allocator, data: []const u8) Error![]u8 {
        const decoded_len = try decoder.calcSizeForSlice(data);
        const result = try allocator.alloc(u8, decoded_len);
        try decoder.decode(result, data);
        return result;
    }
};

// Internal: HMAC-SHA256 signing and base64url encoding
fn signHmacSha256(
    allocator: mem.Allocator,
    data: []const u8,
    secret: []const u8,
) Error![]u8 {
    var mac_buf: [32]u8 = undefined;
    crypto.auth.hmac.sha2.HmacSha256.create(&mac_buf, data, secret);

    return base64url.encode(allocator, &mac_buf);
}

// Tests
test "jwt sign and verify" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const secret = "my-secret-key";
    const claims = Claims{
        .sub = "user_123",
        .exp = std.time.timestamp() + 3600, // 1 hour from now
        .iat = std.time.timestamp(),
        .iss = "zigauth",
    };

    // Sign token
    const token = try sign(allocator, claims, secret, .hs256);
    defer token.deinit(allocator);

    // Verify token
    const verified = try verify(allocator, token.raw, secret);
    defer freeClaims(allocator, verified);

    try testing.expectEqualStrings(claims.sub, verified.sub);
    try testing.expectEqual(claims.exp, verified.exp);
    try testing.expectEqual(claims.iat, verified.iat);
}

test "jwt verify fails with wrong secret" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const secret = "correct-secret";
    const wrong_secret = "wrong-secret";

    const claims = Claims{
        .sub = "user_123",
        .exp = std.time.timestamp() + 3600,
        .iat = std.time.timestamp(),
    };

    const token = try sign(allocator, claims, secret, .hs256);
    defer token.deinit(allocator);

    const result = verify(allocator, token.raw, wrong_secret);
    try testing.expectError(Error.InvalidSignature, result);
}

test "jwt verify detects expired token" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const secret = "my-secret";
    const claims = Claims{
        .sub = "user_123",
        .exp = std.time.timestamp() - 1, // Already expired
        .iat = std.time.timestamp() - 3600,
    };

    const token = try sign(allocator, claims, secret, .hs256);
    defer token.deinit(allocator);

    const result = verify(allocator, token.raw, secret);
    try testing.expectError(Error.TokenExpired, result);
}

test "jwt token format" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const secret = "test-secret";
    const claims = Claims{
        .sub = "user_123",
        .exp = std.time.timestamp() + 3600,
        .iat = std.time.timestamp(),
    };

    const token = try sign(allocator, claims, secret, .hs256);
    defer token.deinit(allocator);

    // Token should have format: header.payload.signature
    var parts = mem.splitSequence(u8, token.raw, ".");
    try testing.expect(parts.next() != null); // header
    try testing.expect(parts.next() != null); // payload
    try testing.expect(parts.next() != null); // signature
    try testing.expect(parts.next() == null); // no more parts
}

test "jwt refresh token generation" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const token1 = try generateRefreshToken(allocator);
    defer allocator.free(token1);

    const token2 = try generateRefreshToken(allocator);
    defer allocator.free(token2);

    // Tokens should be different
    try testing.expect(!mem.eql(u8, token1, token2));

    // Tokens should be base64url encoded (no padding, URL-safe)
    try testing.expect(mem.indexOf(u8, token1, "=") == null);
    try testing.expect(mem.indexOf(u8, token2, "=") == null);
}

test "jwt claims validation" {
    const testing = std.testing;

    const now = std.time.timestamp();

    // Valid token
    const valid = Claims{
        .sub = "user",
        .exp = now + 3600,
        .iat = now,
    };
    try testing.expect(valid.isValid());
    try testing.expect(!valid.isExpired());

    // Expired token
    const expired = Claims{
        .sub = "user",
        .exp = now - 1,
        .iat = now - 3600,
    };
    try testing.expect(!expired.isValid());
    try testing.expect(expired.isExpired());
}
