# ZigAuth + Tokamak Integration Example

This document shows how to use ZigAuth with the Tokamak web framework using dependency injection.

## Setup

```zig
const std = @import("std");
const tk = @import("tokamak");
const zigauth = @import("zigauth");

// Global session store and RBAC
var global_session_store: zigauth.storage.memory.MemoryStore = undefined;
var global_rbac: zigauth.authz.rbac.RBAC = undefined;
```

## Session Authentication Middleware

```zig
// Create session auth middleware
const SessionAuth = zigauth.adapters.tokamak.sessionAuthMiddleware(
    &global_session_store,
    "session_id",
    true, // required
);

var session_auth = SessionAuth.init();
```

## JWT Authentication Middleware

```zig
// Create JWT auth middleware
const JWTAuth = zigauth.adapters.tokamak.jwtAuthMiddleware(
    "your-secret-key",
    true, // required
);

var jwt_auth = JWTAuth.init();
```

## RBAC Authorization Middleware

```zig
// Create RBAC middleware for specific permissions
const AdminAuth = zigauth.adapters.tokamak.rbacAuthMiddleware(
    &global_rbac,
    &[_][]const u8{"*"}, // admin requires all permissions
);

var admin_auth = AdminAuth.init();
```

## Routes with Middleware

```zig
const routes: []const tk.Route = &.{
    // Public routes
    .post("/login", login),
    .post("/logout", logout),

    // Protected routes with session auth - AuthContext injected
    tk.group(.{
        .middleware = &session_auth.handle,
        .children = &.{
            .get("/profile", profile),
            .get("/dashboard", dashboard),
        },
    }),

    // Admin routes with session + RBAC
    tk.group(.{
        .middleware = &session_auth.handle,
        .children = &.{
            tk.group(.{
                .middleware = &admin_auth.handle,
                .children = &.{
                    .get("/admin", adminPanel),
                    .post("/admin/users", createUser),
                },
            }),
        },
    }),

    // API routes with JWT auth
    tk.group(.{
        .middleware = &jwt_auth.handle,
        .children = &.{
            .get("/api/data", apiData),
            .post("/api/submit", apiSubmit),
        },
    }),
};
```

## Login Handler

```zig
fn login(ctx: *tk.Context) !void {
    const allocator = ctx.arena;

    // Parse request body
    const body = try ctx.req.body();
    const credentials = try std.json.parseFromSlice(
        struct { username: []const u8, password: []const u8 },
        allocator,
        body,
        .{},
    );
    defer credentials.deinit();

    // Verify user (your user lookup logic)
    const user = lookupUser(credentials.value.username) orelse {
        ctx.res.status = 401;
        return ctx.res.json(.{ .error = "Invalid credentials" });
    };

    const valid = try zigauth.auth.password.verify(
        allocator,
        credentials.value.password,
        user.password_hash,
    );

    if (!valid) {
        ctx.res.status = 401;
        return ctx.res.json(.{ .error = "Invalid credentials" });
    }

    // Create session cookie
    const cookie = try zigauth.adapters.tokamak.createSessionCookie(
        allocator,
        &global_session_store,
        user.id,
        3600 * 24, // 24 hours
        "session_id",
    );
    defer allocator.free(cookie);

    ctx.res.header("Set-Cookie", cookie);
    return ctx.res.json(.{ .success = true });
}
```

## Protected Handler with Injected AuthContext

```zig
fn profile(ctx: *tk.Context, auth: zigauth.adapters.tokamak.AuthContext) !void {
    // AuthContext is automatically injected by middleware
    if (!auth.isAuthenticated()) {
        ctx.res.status = 401;
        return ctx.res.json(.{ .error = "Unauthorized" });
    }

    const user_id = auth.user_id.?;
    const user = getUserById(user_id) orelse {
        ctx.res.status = 404;
        return ctx.res.json(.{ .error = "User not found" });
    };

    return ctx.res.json(.{
        .user_id = user.id,
        .username = user.username,
        .email = user.email,
    });
}
```

## Admin Handler with RBAC

```zig
fn adminPanel(ctx: *tk.Context, auth: zigauth.adapters.tokamak.AuthContext) !void {
    // RBAC middleware already checked permissions
    // This handler only runs if user has admin permissions

    const user_id = auth.user_id.?;

    return ctx.res.json(.{
        .message = "Welcome to admin panel",
        .user_id = user_id,
    });
}
```

## API Handler with JWT

```zig
fn apiData(ctx: *tk.Context, auth: zigauth.adapters.tokamak.AuthContext) !void {
    // JWT middleware already validated token
    // auth contains claims from JWT

    const user_id = auth.user_id.?;

    const data = fetchUserData(user_id);
    return ctx.res.json(data);
}
```

## Logout Handler

```zig
fn logout(ctx: *tk.Context) !void {
    const allocator = ctx.arena;

    // Extract session ID
    const user_id = try zigauth.adapters.tokamak.getUserIdFromSession(
        allocator,
        &global_session_store,
        ctx.req.header("cookie"),
        "session_id",
    );

    // Destroy session
    if (user_id) |_| {
        const cookies = ctx.req.header("cookie") orelse return;
        // Extract session_id from cookies
        var it = std.mem.splitSequence(u8, cookies, "; ");
        while (it.next()) |cookie| {
            if (std.mem.startsWith(u8, cookie, "session_id=")) {
                const session_id = cookie[11..];
                const store = global_session_store.store();
                store.destroy(session_id) catch {};
                break;
            }
        }
    }

    // Clear cookie
    const cookie = try zigauth.adapters.tokamak.buildSetCookie(
        allocator,
        "session_id",
        "",
        0, // Max-Age=0 to delete
        true,
        false,
        "Lax",
    );
    defer allocator.free(cookie);

    ctx.res.header("Set-Cookie", cookie);
    return ctx.res.json(.{ .success = true });
}
```

## Custom Middleware with AuthContext

```zig
// Create custom middleware that uses AuthContext
fn logUserActivity(ctx: *tk.Context, auth: zigauth.adapters.tokamak.AuthContext) !void {
    if (auth.isAuthenticated()) {
        std.debug.print("User {s} accessed: {s}\n", .{
            auth.user_id.?,
            ctx.req.url,
        });
    }

    return ctx.next();
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

    try global_rbac.defineRole(.{
        .name = "viewer",
        .permissions = &[_][]const u8{"posts:read"},
    });

    // Start Tokamak server
    try tk.serve(.{
        .port = 3000,
        .routes = routes,
    });
}
```

## Features

- ✅ **Dependency Injection**: AuthContext automatically injected into handlers
- ✅ **Middleware Chaining**: Stack multiple middleware (session + RBAC)
- ✅ **Type Safety**: Tokamak's DI ensures correct types
- ✅ **ctx.nextScoped()**: Inject auth context for downstream handlers
- ✅ **Clean Separation**: Auth logic separated from business logic

## Advantages of Tokamak Integration

1. **Automatic Injection**: No manual auth context passing
2. **Middleware Composition**: Easy to chain auth + RBAC
3. **Type Safety**: Compiler ensures correct handler signatures
4. **Scoped Dependencies**: Auth context scoped per-request
5. **Clean Handlers**: Handlers receive exactly what they need
