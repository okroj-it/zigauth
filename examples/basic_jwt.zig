const std = @import("std");
const zigauth = @import("zigauth");
const jwt = zigauth.auth.jwt;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer {
        const status = gpa.deinit();
        if (status == .leak) @panic("Memory leak detected!");
    }
    const allocator = gpa.allocator();

    std.debug.print("=== ZigAuth JWT Example ===\n\n", .{});

    // Secret key for signing (in production, use env var)
    const secret = "your-256-bit-secret-key-change-this";

    // 1. Create claims
    std.debug.print("1. Creating JWT claims...\n", .{});
    const now = std.time.timestamp();
    const claims = jwt.Claims{
        .sub = "user_12345",
        .exp = now + 3600, // Expires in 1 hour
        .iat = now,
        .iss = "zigauth-demo",
        .aud = "myapp",
    };
    std.debug.print("   Subject: {s}\n", .{claims.sub});
    std.debug.print("   Expires: {d} (in 1 hour)\n", .{claims.exp});
    std.debug.print("   Issuer: {s}\n\n", .{claims.iss.?});

    // 2. Sign and generate token
    std.debug.print("2. Signing JWT token...\n", .{});
    const token = try jwt.sign(allocator, claims, secret, .hs256);
    defer token.deinit(allocator);
    std.debug.print("   Token: {s}\n\n", .{token.raw});

    // 3. Verify and decode token
    std.debug.print("3. Verifying JWT token...\n", .{});
    const verified = try jwt.verify(allocator, token.raw, secret);
    defer jwt.freeClaims(allocator, verified);
    std.debug.print("   ✅ Signature valid!\n", .{});
    std.debug.print("   Subject: {s}\n", .{verified.sub});
    std.debug.print("   Issuer: {s}\n", .{verified.iss.?});
    std.debug.print("   Audience: {s}\n\n", .{verified.aud.?});

    // 4. Check token validation
    std.debug.print("4. Checking token validity...\n", .{});
    if (verified.isValid()) {
        std.debug.print("   ✅ Token is valid (not expired)\n\n", .{});
    } else {
        std.debug.print("   ❌ Token is invalid or expired\n\n", .{});
    }

    // 5. Generate refresh token
    std.debug.print("5. Generating refresh token...\n", .{});
    const refresh_token = try jwt.generateRefreshToken(allocator);
    defer allocator.free(refresh_token);
    std.debug.print("   Refresh token: {s}\n\n", .{refresh_token});

    // 6. Try verifying with wrong secret (should fail)
    std.debug.print("6. Testing wrong secret...\n", .{});
    const wrong_secret = "wrong-secret-key";
    const result = jwt.verify(allocator, token.raw, wrong_secret);
    if (result) |_| {
        std.debug.print("   ❌ Unexpected: Verification succeeded with wrong secret!\n", .{});
    } else |err| {
        std.debug.print("   ✅ Correctly rejected: {s}\n\n", .{@errorName(err)});
    }

    std.debug.print("=== JWT Demo Complete! ===\n", .{});
}
