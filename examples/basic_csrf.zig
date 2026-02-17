const std = @import("std");
const zigauth = @import("zigauth");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("\n=== ZigAuth CSRF Protection Example ===\n\n", .{});

    // 1. Generate CSRF Token
    std.debug.print("1. Generating CSRF token...\n", .{});
    const token = try zigauth.auth.csrf.generateToken(allocator);
    defer allocator.free(token);
    std.debug.print("   Generated token: {s}\n", .{token});
    std.debug.print("   Token length: {d} characters\n\n", .{token.len});

    // 2. Validate Matching Tokens
    std.debug.print("2. Validating matching tokens...\n", .{});
    const valid = zigauth.auth.csrf.validateToken(token, token);
    std.debug.print("   Token validates: {}\n\n", .{valid});

    // 3. Reject Different Tokens
    std.debug.print("3. Testing token rejection...\n", .{});
    const wrong_token = "wrong_token_value";
    const invalid = zigauth.auth.csrf.validateToken(token, wrong_token);
    std.debug.print("   Wrong token validates: {}\n\n", .{invalid});

    // 4. Session Integration
    std.debug.print("4. Creating session with CSRF token...\n", .{});
    var store = zigauth.storage.memory.MemoryStore.init(allocator);
    defer store.deinit();

    const store_interface = store.store();

    const session = try store_interface.create(allocator, "user_123", 3600);
    defer {
        var s = session;
        s.deinit(allocator);
    }

    if (session.csrf_token) |csrf_token| {
        std.debug.print("   Session ID: {s}\n", .{session.id});
        std.debug.print("   User ID: {s}\n", .{session.user_id});
        std.debug.print("   CSRF Token: {s}\n", .{csrf_token});
        std.debug.print("   Token automatically generated: ✓\n\n", .{});
    } else {
        std.debug.print("   ERROR: Session missing CSRF token\n\n", .{});
    }

    // 5. Validate Token from Form Submission
    std.debug.print("5. Simulating form submission with CSRF token...\n", .{});

    // Simulate user submitting a form with the token
    const submitted_token = session.csrf_token.?;

    // Validate using the helper function
    zigauth.auth.csrf.validateTokenOrError(
        session.csrf_token.?,
        submitted_token,
    ) catch |err| {
        std.debug.print("   Validation failed: {}\n", .{err});
        return err;
    };
    std.debug.print("   Form submission validated: ✓\n\n", .{});

    // 6. Custom Token Configuration
    std.debug.print("6. Generating shorter token (16 bytes)...\n", .{});
    const config = zigauth.auth.csrf.Config{
        .token_bytes = 16, // 16 bytes = 128 bits
    };
    const short_token = try zigauth.auth.csrf.generateTokenWithConfig(allocator, config);
    defer allocator.free(short_token);
    std.debug.print("   Short token: {s}\n", .{short_token});
    std.debug.print("   Short token length: {d} characters\n\n", .{short_token.len});

    // 7. Extract Token from Form Parameters
    std.debug.print("7. Extracting token from form parameters...\n", .{});
    var params = std.StringHashMap([]const u8).init(allocator);
    defer params.deinit();

    try params.put("username", "john");
    try params.put("csrf_token", token);
    try params.put("email", "john@example.com");

    if (zigauth.auth.csrf.extractTokenFromParams(params)) |extracted| {
        std.debug.print("   Extracted token: {s}\n", .{extracted});
        std.debug.print("   Matches original: {}\n\n", .{std.mem.eql(u8, token, extracted)});
    }

    std.debug.print("=== CSRF Protection Implementation Guide ===\n\n", .{});
    std.debug.print("Synchronizer Token Pattern (Session-Based):\n", .{});
    std.debug.print("1. Generate token on session creation (done automatically)\n", .{});
    std.debug.print("2. Include token in forms: <input type=\"hidden\" name=\"csrf_token\" value=\"{{{{token}}}}\">\n", .{});
    std.debug.print("3. Validate on POST/PUT/DELETE requests\n", .{});
    std.debug.print("4. Return 403 Forbidden if validation fails\n\n", .{});

    std.debug.print("Double-Submit Cookie Pattern (Stateless):\n", .{});
    std.debug.print("1. Generate token and set as cookie\n", .{});
    std.debug.print("2. Require token in request header: X-CSRF-Token\n", .{});
    std.debug.print("3. Compare cookie value with header value\n", .{});
    std.debug.print("4. Tokens must match for validation to succeed\n\n", .{});

    std.debug.print("Framework Integration:\n", .{});
    std.debug.print("- Zigzap: Use CSRF middleware (coming soon)\n", .{});
    std.debug.print("- http.zig: Use validateCsrfToken() helper\n", .{});
    std.debug.print("- Jetzig: Use getCsrfToken() in templates\n", .{});
    std.debug.print("- Tokamak: Use CsrfMiddleware with DI\n\n", .{});

    std.debug.print("✓ CSRF protection is now enabled for all sessions!\n", .{});
}
