const std = @import("std");
const zigauth = @import("../zigauth.zig");

/// Jetzig authentication helpers
/// Note: Jetzig is built on http.zig and supports middleware chains
/// These helpers integrate with Jetzig's request/response system

/// Authentication result for Jetzig handlers
pub const AuthResult = struct {
    authenticated: bool,
    user_id: ?[]const u8 = null,
    error_message: ?[]const u8 = null,
};

/// Session authentication helper for Jetzig
/// Returns authentication result that handlers can check
pub fn validateSession(
    allocator: std.mem.Allocator,
    store: *zigauth.storage.memory.MemoryStore.Store,
    cookie_header: ?[]const u8,
    cookie_name: []const u8,
) !AuthResult {
    const cookies = cookie_header orelse {
        return .{
            .authenticated = false,
            .error_message = "No cookies provided",
        };
    };

    // Extract session cookie
    const session_id = extractCookie(cookies, cookie_name) orelse {
        return .{
            .authenticated = false,
            .error_message = "Session cookie not found",
        };
    };

    // Validate session
    const session = store.get(allocator, session_id) catch {
        return .{
            .authenticated = false,
            .error_message = "Invalid session",
        };
    };
    defer {
        var s = session;
        s.deinit(allocator);
    }

    if (!session.isValid()) {
        return .{
            .authenticated = false,
            .error_message = "Session expired",
        };
    }

    return .{
        .authenticated = true,
        .user_id = session.user_id,
    };
}

/// JWT authentication helper for Jetzig
pub fn validateJWT(
    allocator: std.mem.Allocator,
    auth_header: ?[]const u8,
    secret: []const u8,
) !AuthResult {
    const header = auth_header orelse {
        return .{
            .authenticated = false,
            .error_message = "No authorization header",
        };
    };

    const token = if (std.mem.startsWith(u8, header, "Bearer "))
        header[7..]
    else {
        return .{
            .authenticated = false,
            .error_message = "Invalid authorization format",
        };
    };

    const claims = zigauth.auth.jwt.verify(allocator, token, secret) catch {
        return .{
            .authenticated = false,
            .error_message = "Invalid JWT token",
        };
    };
    defer zigauth.auth.jwt.freeClaims(allocator, claims);

    return .{
        .authenticated = true,
        .user_id = claims.sub,
    };
}

/// RBAC authorization helper for Jetzig
pub fn checkPermissions(
    rbac: *zigauth.authz.rbac.RBAC,
    user_id: []const u8,
    required_permissions: []const []const u8,
) bool {
    return rbac.userHasAllPermissions(user_id, required_permissions);
}

/// Helper: Extract cookie value by name
fn extractCookie(cookies: []const u8, name: []const u8) ?[]const u8 {
    var it = std.mem.splitSequence(u8, cookies, "; ");
    while (it.next()) |cookie| {
        if (std.mem.indexOf(u8, cookie, "=")) |eq_pos| {
            const cookie_name = cookie[0..eq_pos];
            const cookie_value = cookie[eq_pos + 1 ..];
            if (std.mem.eql(u8, cookie_name, name)) {
                return cookie_value;
            }
        }
    }
    return null;
}

/// Helper: Build Set-Cookie header value
pub fn buildSetCookie(
    allocator: std.mem.Allocator,
    name: []const u8,
    value: []const u8,
    max_age: ?i64,
    http_only: bool,
    secure: bool,
    same_site: []const u8,
) ![]const u8 {
    var buf = std.ArrayList(u8).init(allocator);
    const writer = buf.writer();

    try writer.print("{s}={s}", .{ name, value });

    if (max_age) |age| {
        try writer.print("; Max-Age={d}", .{age});
    }

    if (http_only) {
        try writer.writeAll("; HttpOnly");
    }

    if (secure) {
        try writer.writeAll("; Secure");
    }

    try writer.print("; SameSite={s}", .{same_site});
    try writer.writeAll("; Path=/");

    return buf.toOwnedSlice();
}

/// Create login response with session cookie
pub fn createLoginResponse(
    allocator: std.mem.Allocator,
    store: *zigauth.storage.memory.MemoryStore.Store,
    user_id: []const u8,
    session_duration: i64,
    cookie_name: []const u8,
) !struct { session_id: []const u8, cookie: []const u8 } {
    const session = try store.create(allocator, user_id, session_duration);
    defer {
        var s = session;
        s.deinit(allocator);
    }

    const cookie = try buildSetCookie(
        allocator,
        cookie_name,
        session.id,
        session_duration,
        true, // HttpOnly
        false, // Secure (set to true in production with HTTPS)
        "Lax",
    );

    return .{
        .session_id = try allocator.dupe(u8, session.id),
        .cookie = cookie,
    };
}

/// Destroy session and create logout cookie
pub fn createLogoutResponse(
    allocator: std.mem.Allocator,
    store: *zigauth.storage.memory.MemoryStore.Store,
    session_id: ?[]const u8,
    cookie_name: []const u8,
) ![]const u8 {
    if (session_id) |sid| {
        store.destroy(sid) catch {};
    }

    return try buildSetCookie(
        allocator,
        cookie_name,
        "",
        0, // Max-Age=0 to delete
        true,
        false,
        "Lax",
    );
}

/// Get CSRF token from session for use in templates
///
/// Returns the CSRF token that should be included in forms.
/// Caller owns returned memory and must free it.
pub fn getCsrfToken(
    allocator: std.mem.Allocator,
    store: *zigauth.storage.memory.MemoryStore.Store,
    cookie_header: ?[]const u8,
    cookie_name: []const u8,
) !?[]const u8 {
    const cookies = cookie_header orelse return null;

    const session_id = extractCookie(cookies, cookie_name) orelse return null;

    const session = store.get(allocator, session_id) catch return null;
    defer {
        var s = session;
        s.deinit(allocator);
    }

    if (session.csrf_token) |token| {
        return try allocator.dupe(u8, token);
    }

    return null;
}

/// Validate CSRF token from form submission
///
/// Compares provided token against session's CSRF token.
/// Returns error if token is missing or invalid.
pub fn validateCsrfToken(
    allocator: std.mem.Allocator,
    store: *zigauth.storage.memory.MemoryStore.Store,
    cookie_header: ?[]const u8,
    cookie_name: []const u8,
    provided_token: ?[]const u8,
) !void {
    const cookies = cookie_header orelse return error.NoCookies;

    const session_id = extractCookie(cookies, cookie_name) orelse
        return error.SessionNotFound;

    const session = try store.get(allocator, session_id);
    defer {
        var s = session;
        s.deinit(allocator);
    }

    const expected_token = session.csrf_token orelse
        return error.MissingCsrfToken;

    const csrf = zigauth.auth.csrf;
    try csrf.validateTokenOrError(expected_token, provided_token);
}

/// CSRF validation result for templates
pub const CsrfValidation = struct {
    valid: bool,
    error_message: ?[]const u8 = null,
};

/// Validate CSRF and return result (for use in handlers)
pub fn checkCsrfToken(
    allocator: std.mem.Allocator,
    store: *zigauth.storage.memory.MemoryStore.Store,
    cookie_header: ?[]const u8,
    cookie_name: []const u8,
    provided_token: ?[]const u8,
) CsrfValidation {
    validateCsrfToken(allocator, store, cookie_header, cookie_name, provided_token) catch |err| {
        const message = switch (err) {
            error.NoCookies => "No cookies provided",
            error.SessionNotFound => "Session not found",
            error.MissingCsrfToken => "CSRF token missing",
            error.InvalidCsrfToken => "Invalid CSRF token",
            else => "CSRF validation failed",
        };
        return .{ .valid = false, .error_message = message };
    };

    return .{ .valid = true };
}
