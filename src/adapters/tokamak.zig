const std = @import("std");
const zigauth = @import("../zigauth.zig");

/// Tokamak authentication helpers
/// Note: Tokamak uses dependency injection and Context-based middleware
/// These helpers integrate with Tokamak's DI container and routing system

/// Authentication context that can be injected into handlers
pub const AuthContext = struct {
    user_id: ?[]const u8 = null,
    session_id: ?[]const u8 = null,
    authenticated: bool = false,
    roles: std.ArrayList([]const u8),
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

    pub fn isAuthenticated(self: AuthContext) bool {
        return self.authenticated;
    }
};

/// Session authentication middleware for Tokamak
/// Use with ctx.nextScoped() to inject AuthContext into downstream handlers
pub fn sessionAuthMiddleware(
    store: *zigauth.storage.memory.MemoryStore.Store,
    cookie_name: []const u8,
    required: bool,
) type {
    return struct {
        store: *zigauth.storage.memory.MemoryStore.Store,
        cookie_name: []const u8,
        required: bool,

        const Self = @This();

        pub fn init() Self {
            return .{
                .store = store,
                .cookie_name = cookie_name,
                .required = required,
            };
        }

        /// Middleware handler for Tokamak Context
        pub fn handle(self: *Self, ctx: anytype) !void {
            const allocator = ctx.arena;

            // Extract cookies from request
            const cookie_header = ctx.req.header("cookie");

            var auth_context = AuthContext.init(allocator);

            if (cookie_header) |cookies| {
                if (extractCookie(cookies, self.cookie_name)) |session_id| {
                    // Validate session
                    if (self.store.get(allocator, session_id)) |session| {
                        defer {
                            var s = session;
                            s.deinit(allocator);
                        }

                        if (session.isValid()) {
                            auth_context.authenticated = true;
                            auth_context.user_id = session.user_id;
                            auth_context.session_id = session.id;
                        }
                    } else |_| {}
                }
            }

            if (self.required and !auth_context.authenticated) {
                ctx.res.status = 401;
                ctx.res.body = "Unauthorized";
                return;
            }

            // Inject auth context for downstream handlers
            return ctx.nextScoped(auth_context);
        }
    };
}

/// JWT authentication middleware for Tokamak
pub fn jwtAuthMiddleware(
    secret: []const u8,
    required: bool,
) type {
    return struct {
        secret: []const u8,
        required: bool,

        const Self = @This();

        pub fn init() Self {
            return .{
                .secret = secret,
                .required = required,
            };
        }

        pub fn handle(self: *Self, ctx: anytype) !void {
            const allocator = ctx.arena;

            var auth_context = AuthContext.init(allocator);

            // Extract Authorization header
            if (ctx.req.header("authorization")) |auth_header| {
                if (std.mem.startsWith(u8, auth_header, "Bearer ")) {
                    const token = auth_header[7..];

                    if (zigauth.auth.jwt.verify(allocator, token, self.secret)) |claims| {
                        defer zigauth.auth.jwt.freeClaims(allocator, claims);

                        auth_context.authenticated = true;
                        auth_context.user_id = claims.sub;
                    } else |_| {}
                }
            }

            if (self.required and !auth_context.authenticated) {
                ctx.res.status = 401;
                ctx.res.body = "Unauthorized";
                return;
            }

            return ctx.nextScoped(auth_context);
        }
    };
}

/// RBAC authorization middleware for Tokamak
pub fn rbacAuthMiddleware(
    rbac: *zigauth.authz.rbac.RBAC,
    required_permissions: []const []const u8,
) type {
    return struct {
        rbac: *zigauth.authz.rbac.RBAC,
        required_permissions: []const []const u8,

        const Self = @This();

        pub fn init() Self {
            return .{
                .rbac = rbac,
                .required_permissions = required_permissions,
            };
        }

        pub fn handle(self: *Self, ctx: anytype, auth: AuthContext) !void {
            if (!auth.authenticated) {
                ctx.res.status = 401;
                ctx.res.body = "Unauthorized: Authentication required";
                return;
            }

            const user_id = auth.user_id orelse {
                ctx.res.status = 401;
                ctx.res.body = "Unauthorized: No user ID";
                return;
            };

            if (!self.rbac.userHasAllPermissions(user_id, self.required_permissions)) {
                ctx.res.status = 403;
                ctx.res.body = "Forbidden: Insufficient permissions";
                return;
            }

            return ctx.next();
        }
    };
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

/// Helper: Validate session from request and return user ID
pub fn getUserIdFromSession(
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

    if (!session.isValid()) {
        return null;
    }

    return session.user_id;
}

/// Create session and return Set-Cookie header
pub fn createSessionCookie(
    allocator: std.mem.Allocator,
    store: *zigauth.storage.memory.MemoryStore.Store,
    user_id: []const u8,
    duration: i64,
    cookie_name: []const u8,
) ![]const u8 {
    const session = try store.create(allocator, user_id, duration);
    defer {
        var s = session;
        s.deinit(allocator);
    }

    return try buildSetCookie(
        allocator,
        cookie_name,
        session.id,
        duration,
        true, // HttpOnly
        false, // Secure (use true in production)
        "Lax",
    );
}
