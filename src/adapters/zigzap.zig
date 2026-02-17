const std = @import("std");
const zap = @import("zap");
const zigauth = @import("../zigauth.zig");

/// Authentication context attached to requests
pub const AuthContext = struct {
    /// Authenticated user ID (null if not authenticated)
    user_id: ?[]const u8 = null,

    /// Session ID if using session-based auth
    session_id: ?[]const u8 = null,

    /// JWT claims if using token-based auth
    claims: ?zigauth.auth.jwt.Claims = null,

    /// User roles for RBAC
    roles: std.ArrayList([]const u8),

    /// Allocator for memory management
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) AuthContext {
        return .{
            .roles = std.ArrayList([]const u8).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *AuthContext) void {
        self.roles.deinit();
    }

    /// Check if user is authenticated
    pub fn isAuthenticated(self: AuthContext) bool {
        return self.user_id != null;
    }
};

/// Configuration for session middleware
pub const SessionConfig = struct {
    /// Session store interface
    store: *zigauth.storage.memory.MemoryStore.Store,

    /// Cookie name for session ID (default: "session_id")
    cookie_name: []const u8 = "session_id",

    /// Whether authentication is required (401 if not authenticated)
    required: bool = true,
};

/// Configuration for JWT middleware
pub const JWTConfig = struct {
    /// Secret key for JWT verification
    secret: []const u8,

    /// Whether authentication is required (401 if not authenticated)
    required: bool = true,
};

/// Configuration for RBAC middleware
pub const RBACConfig = struct {
    /// RBAC manager instance
    rbac: *zigauth.authz.rbac.RBAC,

    /// Required permissions (user must have ALL of these)
    required_permissions: []const []const u8,
};

/// Session authentication middleware
pub const SessionMiddleware = struct {
    handler: zap.Middleware.Handler,
    config: SessionConfig,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, config: SessionConfig, _: zap.Middleware.Handler) SessionMiddleware {
        return .{
            .handler = .{
                .handleRequestFn = handleRequest,
            },
            .config = config,
            .allocator = allocator,
        };
    }

    fn handleRequest(handler: *zap.Middleware.Handler, r: zap.Request, context: anytype) void {
        const self: *SessionMiddleware = @fieldParentPtr("handler", handler);

        // Extract session cookie
        const session_id = extractCookie(r, self.config.cookie_name) orelse {
            if (self.config.required) {
                r.setStatus(.unauthorized);
                r.sendBody("Unauthorized: No session") catch {};
                return;
            }
            handler.handleOther(r, context);
            return;
        };

        // Validate session
        const session = self.config.store.get(self.allocator, session_id) catch {
            if (self.config.required) {
                r.setStatus(.unauthorized);
                r.sendBody("Unauthorized: Invalid session") catch {};
                return;
            }
            handler.handleOther(r, context);
            return;
        };
        defer {
            var s = session;
            s.deinit(self.allocator);
        }

        if (!session.isValid()) {
            if (self.config.required) {
                r.setStatus(.unauthorized);
                r.sendBody("Unauthorized: Session expired") catch {};
                return;
            }
            handler.handleOther(r, context);
            return;
        }

        // Update context with session info
        var new_context = context;
        new_context.user_id = session.user_id;
        new_context.session_id = session.id;

        handler.handleOther(r, new_context);
    }
};

/// JWT authentication middleware
pub const JWTMiddleware = struct {
    handler: zap.Middleware.Handler,
    config: JWTConfig,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, config: JWTConfig, _: zap.Middleware.Handler) JWTMiddleware {
        return .{
            .handler = .{
                .handleRequestFn = handleRequest,
            },
            .config = config,
            .allocator = allocator,
        };
    }

    fn handleRequest(handler: *zap.Middleware.Handler, r: zap.Request, context: anytype) void {
        const self: *JWTMiddleware = @fieldParentPtr("handler", handler);

        // Extract Bearer token
        const token = extractBearerToken(r) orelse {
            if (self.config.required) {
                r.setStatus(.unauthorized);
                r.sendBody("Unauthorized: No token provided") catch {};
                return;
            }
            handler.handleOther(r, context);
            return;
        };

        // Verify JWT
        const claims = zigauth.auth.jwt.verify(self.allocator, token, self.config.secret) catch {
            if (self.config.required) {
                r.setStatus(.unauthorized);
                r.sendBody("Unauthorized: Invalid token") catch {};
                return;
            }
            handler.handleOther(r, context);
            return;
        };
        defer zigauth.auth.jwt.freeClaims(self.allocator, claims);

        // Update context with JWT claims
        var new_context = context;
        new_context.user_id = claims.sub;
        new_context.claims = claims;

        handler.handleOther(r, new_context);
    }
};

/// RBAC authorization middleware
pub const RBACMiddleware = struct {
    handler: zap.Middleware.Handler,
    config: RBACConfig,

    pub fn init(config: RBACConfig, _: zap.Middleware.Handler) RBACMiddleware {
        return .{
            .handler = .{
                .handleRequestFn = handleRequest,
            },
            .config = config,
        };
    }

    fn handleRequest(handler: *zap.Middleware.Handler, r: zap.Request, context: anytype) void {
        const self: *RBACMiddleware = @fieldParentPtr("handler", handler);

        // Check if user is authenticated
        const user_id = context.user_id orelse {
            r.setStatus(.unauthorized);
            r.sendBody("Unauthorized: Authentication required") catch {};
            return;
        };

        // Check permissions
        if (!self.config.rbac.userHasAllPermissions(user_id, self.config.required_permissions)) {
            r.setStatus(.forbidden);
            r.sendBody("Forbidden: Insufficient permissions") catch {};
            return;
        }

        handler.handleOther(r, context);
    }
};

/// Configuration for CSRF middleware
pub const CsrfConfig = struct {
    /// Session store interface (to retrieve CSRF tokens from sessions)
    store: *zigauth.storage.memory.MemoryStore.Store,

    /// Cookie name for session ID (default: "session_id")
    session_cookie_name: []const u8 = "session_id",

    /// HTTP header name for CSRF token (default: "X-CSRF-Token")
    header_name: []const u8 = "X-CSRF-Token",

    /// Form field names to check for CSRF token
    form_field_names: []const []const u8 = &[_][]const u8{ "csrf_token", "_csrf", "csrf" },

    /// Whether to validate on all state-changing methods (POST, PUT, DELETE, PATCH)
    /// If false, only validates when explicitly called
    auto_validate_mutations: bool = true,
};

/// CSRF protection middleware
///
/// Validates CSRF tokens on state-changing requests (POST, PUT, DELETE, PATCH).
/// Expects the CSRF token in either:
/// - HTTP header (X-CSRF-Token by default)
/// - Form field (csrf_token, _csrf, or csrf)
///
/// The token is compared against the session's CSRF token.
pub const CsrfMiddleware = struct {
    config: CsrfConfig,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, config: CsrfConfig) CsrfMiddleware {
        return .{
            .config = config,
            .allocator = allocator,
        };
    }

    pub fn handleRequest(
        self: *CsrfMiddleware,
        r: zap.Request,
        context: *AuthContext,
        handler: anytype,
    ) void {
        // Only validate on state-changing methods if auto_validate is enabled
        const method = r.method orelse {
            handler.handleOther(r, context);
            return;
        };

        const should_validate = self.config.auto_validate_mutations and
            (std.mem.eql(u8, method, "POST") or
            std.mem.eql(u8, method, "PUT") or
            std.mem.eql(u8, method, "DELETE") or
            std.mem.eql(u8, method, "PATCH"));

        if (!should_validate) {
            handler.handleOther(r, context);
            return;
        }

        // Validate CSRF token
        self.validateCsrf(r, context) catch {
            r.setStatus(.forbidden);
            r.sendBody("Forbidden: Invalid or missing CSRF token") catch {};
            return;
        };

        handler.handleOther(r, context);
    }

    /// Validate CSRF token from request
    fn validateCsrf(
        self: *CsrfMiddleware,
        r: zap.Request,
        context: *AuthContext,
    ) !void {
        _ = context; // Context not needed for CSRF validation

        // Extract session ID from cookie
        const session_id = extractCookie(r, self.config.session_cookie_name) orelse
            return error.SessionNotFound;

        // Get session from store
        const session = try self.config.store.get(self.allocator, session_id);
        defer {
            var s = session;
            s.deinit(self.allocator);
        }

        // Get expected CSRF token from session
        const expected_token = session.csrf_token orelse
            return error.MissingCsrfToken;

        // Try to extract CSRF token from request header
        const provided_token: ?[]const u8 = r.getHeader(self.config.header_name);

        // If not in header, try form fields (requires parsing body)
        if (provided_token == null) {
            // Try to get from query parameters or form data
            // Note: Zigzap doesn't provide easy body parsing, so this is a placeholder
            // In practice, you'd parse the request body here
            // For now, we only support header-based CSRF validation
            return error.MissingCsrfToken;
        }

        // Validate token using constant-time comparison
        const csrf = zigauth.auth.csrf;
        try csrf.validateTokenOrError(expected_token, provided_token);
    }
};

/// Helper: Extract cookie value by name
fn extractCookie(r: zap.Request, name: []const u8) ?[]const u8 {
    const cookie_header = r.getHeader("cookie") orelse return null;

    // Parse cookies (format: "name1=value1; name2=value2")
    var it = std.mem.splitSequence(u8, cookie_header, "; ");
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

/// Helper: Extract Bearer token from Authorization header
fn extractBearerToken(r: zap.Request) ?[]const u8 {
    const auth_header = r.getHeader("authorization") orelse return null;

    if (std.mem.startsWith(u8, auth_header, "Bearer ")) {
        return auth_header[7..];
    }
    return null;
}

/// Helper: Build Set-Cookie header value
/// Caller owns returned memory and must free it
pub fn buildSetCookie(
    allocator: std.mem.Allocator,
    name: []const u8,
    value: []const u8,
    max_age: ?i64,
    http_only: bool,
    secure: bool,
    same_site: []const u8,
) ![]u8 {
    // SECURITY FIX: Use dynamic allocation instead of fixed buffer
    // to prevent buffer overflow and use-after-free bugs

    // Validate input sizes to prevent excessive allocation
    const MAX_COOKIE_NAME_LEN = 256;
    const MAX_COOKIE_VALUE_LEN = 4096;
    const MAX_SAME_SITE_LEN = 16;

    if (name.len > MAX_COOKIE_NAME_LEN) return error.CookieNameTooLong;
    if (value.len > MAX_COOKIE_VALUE_LEN) return error.CookieValueTooLong;
    if (same_site.len > MAX_SAME_SITE_LEN) return error.SameSiteTooLong;

    var parts = std.ArrayList(u8).init(allocator);
    defer parts.deinit();

    const writer = parts.writer();

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

    return parts.toOwnedSlice();
}
