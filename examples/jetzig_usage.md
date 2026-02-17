# ZigAuth + Jetzig Integration Example

This document shows how to use ZigAuth with the Jetzig web framework.

## Setup

```zig
const std = @import("std");
const jetzig = @import("jetzig");
const zigauth = @import("zigauth");

// Global session store and RBAC
var global_session_store: zigauth.storage.memory.MemoryStore = undefined;
var global_rbac: zigauth.authz.rbac.RBAC = undefined;
```

## Login Handler

```zig
pub fn login(request: *jetzig.http.Request, response: *jetzig.http.Response) !void {
    const allocator = request.allocator;

    // Parse credentials from request body
    const username = request.body.get("username") orelse return error.MissingUsername;
    const password = request.body.get("password") orelse return error.MissingPassword;

    // Find and verify user (your user lookup logic)
    const user = lookupUser(username) orelse {
        response.status = 401;
        try response.json(.{ .error = "Invalid credentials" });
        return;
    };

    const valid = try zigauth.auth.password.verify(allocator, password, user.password_hash);
    if (!valid) {
        response.status = 401;
        try response.json(.{ .error = "Invalid credentials" });
        return;
    }

    // Create session and set cookie
    const login_response = try zigauth.adapters.jetzig.createLoginResponse(
        allocator,
        &global_session_store,
        user.id,
        3600 * 24, // 24 hours
        "session_id",
    );
    defer allocator.free(login_response.session_id);
    defer allocator.free(login_response.cookie);

    response.header("Set-Cookie", login_response.cookie);
    try response.json(.{ .success = true, .message = "Login successful" });
}
```

## Protected Handler with Session Auth

```zig
pub fn profile(request: *jetzig.http.Request, response: *jetzig.http.Response) !void {
    const allocator = request.allocator;

    // Validate session
    const auth = try zigauth.adapters.jetzig.validateSession(
        allocator,
        &global_session_store,
        request.header("cookie"),
        "session_id",
    );

    if (!auth.authenticated) {
        response.status = 401;
        try response.json(.{ .error = auth.error_message orelse "Unauthorized" });
        return;
    }

    // User is authenticated - fetch profile
    const user_id = auth.user_id.?;
    const user = getUserById(user_id) orelse return error.UserNotFound;

    try response.json(.{
        .user_id = user.id,
        .username = user.username,
        .email = user.email,
    });
}
```

## Protected Handler with RBAC

```zig
pub fn adminPanel(request: *jetzig.http.Request, response: *jetzig.http.Response) !void {
    const allocator = request.allocator;

    // Validate session
    const auth = try zigauth.adapters.jetzig.validateSession(
        allocator,
        &global_session_store,
        request.header("cookie"),
        "session_id",
    );

    if (!auth.authenticated) {
        response.status = 401;
        try response.json(.{ .error = "Unauthorized" });
        return;
    }

    // Check admin permissions
    const user_id = auth.user_id.?;
    if (!zigauth.adapters.jetzig.checkPermissions(&global_rbac, user_id, &[_][]const u8{"*"})) {
        response.status = 403;
        try response.json(.{ .error = "Forbidden: Admin access required" });
        return;
    }

    // User has admin permissions
    try response.render("admin/panel.html");
}
```

## JWT Authentication

```zig
pub fn apiEndpoint(request: *jetzig.http.Request, response: *jetzig.http.Response) !void {
    const allocator = request.allocator;

    // Validate JWT
    const auth = try zigauth.adapters.jetzig.validateJWT(
        allocator,
        request.header("authorization"),
        "your-secret-key",
    );

    if (!auth.authenticated) {
        response.status = 401;
        try response.json(.{ .error = auth.error_message orelse "Unauthorized" });
        return;
    }

    // JWT is valid
    const user_id = auth.user_id.?;
    try response.json(.{ .message = "API access granted", .user_id = user_id });
}
```

## Logout Handler

```zig
pub fn logout(request: *jetzig.http.Request, response: *jetzig.http.Response) !void {
    const allocator = request.allocator;

    // Extract session ID from cookie
    const cookies = request.header("cookie");
    var session_id: ?[]const u8 = null;

    if (cookies) |cookie_header| {
        // Simple cookie parsing (you might use a helper)
        var it = std.mem.splitSequence(u8, cookie_header, "; ");
        while (it.next()) |cookie| {
            if (std.mem.startsWith(u8, cookie, "session_id=")) {
                session_id = cookie[11..];
                break;
            }
        }
    }

    // Create logout response
    const logout_cookie = try zigauth.adapters.jetzig.createLogoutResponse(
        allocator,
        &global_session_store,
        session_id,
        "session_id",
    );
    defer allocator.free(logout_cookie);

    response.header("Set-Cookie", logout_cookie);
    try response.json(.{ .success = true, .message = "Logged out" });
}
```

## Initialization

```zig
pub fn main() !void {
    const allocator = std.heap.page_allocator;

    // Initialize stores
    global_session_store = zigauth.storage.memory.MemoryStore.init(allocator);
    global_rbac = zigauth.authz.rbac.RBAC.init(allocator);

    // Define roles
    try global_rbac.defineRole(.{
        .name = "admin",
        .permissions = &[_][]const u8{"*"},
    });

    try global_rbac.defineRole(.{
        .name = "editor",
        .permissions = &[_][]const u8{ "posts:read", "posts:write" },
    });

    // Start Jetzig server (framework-specific code)
    // ...
}
```

## Features

- ✅ Session-based authentication with cookies
- ✅ JWT token authentication
- ✅ RBAC permission checking
- ✅ Login/logout helpers
- ✅ Clean AuthResult pattern for handlers
