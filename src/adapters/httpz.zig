const std = @import("std");
const httpz = @import("httpz");
const zigauth = @import("../zigauth.zig");

/// Authentication context for http.zig requests
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

/// Session authentication middleware
pub fn sessionAuth(
    allocator: std.mem.Allocator,
    store: *zigauth.storage.memory.MemoryStore,
    cookie_name: []const u8,
    required: bool,
) type {
    return struct {
        const Self = @This();

        allocator: std.mem.Allocator,
        store: *zigauth.storage.memory.MemoryStore,
        cookie_name: []const u8,
        required: bool,

        pub fn init() Self {
            return .{
                .allocator = allocator,
                .store = store,
                .cookie_name = cookie_name,
                .required = required,
            };
        }

        pub fn dispatch(
            self: *Self,
            action: httpz.Action(*Self),
            req: *httpz.Request,
            res: *httpz.Response,
        ) !void {
            // Extract session cookie
            const session_id = extractCookie(req, self.cookie_name) orelse {
                if (self.required) {
                    res.status = 401;
                    res.body = "Unauthorized: No session";
                    return;
                }
                return action(self, req, res);
            };

            // Validate session
            const store_interface = self.store.store();
            const session = store_interface.get(self.allocator, session_id) catch {
                if (self.required) {
                    res.status = 401;
                    res.body = "Unauthorized: Invalid session";
                    return;
                }
                return action(self, req, res);
            };
            defer {
                var s = session;
                s.deinit(self.allocator);
            }

            if (!session.isValid()) {
                if (self.required) {
                    res.status = 401;
                    res.body = "Unauthorized: Session expired";
                    return;
                }
                return action(self, req, res);
            }

            // Store user_id in request for downstream handlers
            // Note: http.zig doesn't have built-in context storage,
            // so handlers need to extract from session again or use custom App state
            return action(self, req, res);
        }
    };
}

/// JWT authentication middleware
pub fn jwtAuth(
    allocator: std.mem.Allocator,
    secret: []const u8,
    required: bool,
) type {
    return struct {
        const Self = @This();

        allocator: std.mem.Allocator,
        secret: []const u8,
        required: bool,

        pub fn init() Self {
            return .{
                .allocator = allocator,
                .secret = secret,
                .required = required,
            };
        }

        pub fn dispatch(
            self: *Self,
            action: httpz.Action(*Self),
            req: *httpz.Request,
            res: *httpz.Response,
        ) !void {
            // Extract Bearer token
            const token = extractBearerToken(req) orelse {
                if (self.required) {
                    res.status = 401;
                    res.body = "Unauthorized: No token provided";
                    return;
                }
                return action(self, req, res);
            };

            // Verify JWT
            const claims = zigauth.auth.jwt.verify(self.allocator, token, self.secret) catch {
                if (self.required) {
                    res.status = 401;
                    res.body = "Unauthorized: Invalid token";
                    return;
                }
                return action(self, req, res);
            };
            defer zigauth.auth.jwt.freeClaims(self.allocator, claims);

            return action(self, req, res);
        }
    };
}

/// RBAC authorization middleware
pub fn rbacAuth(
    rbac: *zigauth.authz.rbac.RBAC,
    required_permissions: []const []const u8,
    user_id_extractor: fn (*httpz.Request) ?[]const u8,
) type {
    return struct {
        const Self = @This();

        rbac: *zigauth.authz.rbac.RBAC,
        required_permissions: []const []const u8,
        user_id_extractor: fn (*httpz.Request) ?[]const u8,

        pub fn init() Self {
            return .{
                .rbac = rbac,
                .required_permissions = required_permissions,
                .user_id_extractor = user_id_extractor,
            };
        }

        pub fn dispatch(
            self: *Self,
            action: httpz.Action(*Self),
            req: *httpz.Request,
            res: *httpz.Response,
        ) !void {
            // Extract user ID from request
            const user_id = self.user_id_extractor(req) orelse {
                res.status = 401;
                res.body = "Unauthorized: Authentication required";
                return;
            };

            // Check permissions
            if (!self.rbac.userHasAllPermissions(user_id, self.required_permissions)) {
                res.status = 403;
                res.body = "Forbidden: Insufficient permissions";
                return;
            }

            return action(self, req, res);
        }
    };
}

/// Helper: Extract cookie value by name
pub fn extractCookie(req: *httpz.Request, name: []const u8) ?[]const u8 {
    const cookie_header = req.header("cookie") orelse return null;

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
pub fn extractBearerToken(req: *httpz.Request) ?[]const u8 {
    const auth_header = req.header("authorization") orelse return null;

    if (std.mem.startsWith(u8, auth_header, "Bearer ")) {
        return auth_header[7..];
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

/// Helper: Validate session and return user ID
pub fn validateSessionCookie(
    allocator: std.mem.Allocator,
    store: *zigauth.storage.memory.MemoryStore,
    req: *httpz.Request,
    cookie_name: []const u8,
)  !?[]const u8 {
    const session_id = extractCookie(req, cookie_name) orelse return null;

    const store_interface = store.store();
    const session = store_interface.get(allocator, session_id) catch return null;
    defer {
        var s = session;
        s.deinit(allocator);
    }

    if (!session.isValid()) {
        return null;
    }

    // IMPORTANT: Return a copy since the session will be freed by defer
    return try allocator.dupe(u8, session.user_id);
}
