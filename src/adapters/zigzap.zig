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
pub fn buildSetCookie(
    name: []const u8,
    value: []const u8,
    max_age: ?i64,
    http_only: bool,
    secure: bool,
    same_site: []const u8,
) ![]const u8 {
    var buf: [4096]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    const writer = stream.writer();

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

    return stream.getWritten();
}
