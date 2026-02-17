const std = @import("std");
const httpz = @import("httpz");
const zigauth = @import("zigauth");

// Demo user database
const User = struct {
    id: []const u8,
    username: []const u8,
    password_hash: []const u8,
};

var users: std.StringHashMap(User) = undefined;
var global_session_store: zigauth.storage.memory.MemoryStore = undefined;
var global_rbac: zigauth.authz.rbac.RBAC = undefined;

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    // Initialize data structures
    users = std.StringHashMap(User).init(allocator);
    global_session_store = zigauth.storage.memory.MemoryStore.init(allocator);
    global_rbac = zigauth.authz.rbac.RBAC.init(allocator);

    // Define roles
    const admin_role = zigauth.authz.rbac.Role{
        .name = "admin",
        .permissions = &[_][]const u8{"*"},
    };

    const editor_role = zigauth.authz.rbac.Role{
        .name = "editor",
        .permissions = &[_][]const u8{ "posts:read", "posts:write" },
    };

    try global_rbac.defineRole(admin_role);
    try global_rbac.defineRole(editor_role);

    // Create demo users
    const admin_hash = try zigauth.auth.password.hash(allocator, "admin123", zigauth.auth.password.default_config);
    defer allocator.free(admin_hash);

    const editor_hash = try zigauth.auth.password.hash(allocator, "editor123", zigauth.auth.password.default_config);
    defer allocator.free(editor_hash);

    try users.put("admin", .{
        .id = "user_admin",
        .username = "admin",
        .password_hash = try allocator.dupe(u8, admin_hash),
    });

    try users.put("editor", .{
        .id = "user_editor",
        .username = "editor",
        .password_hash = try allocator.dupe(u8, editor_hash),
    });

    // Assign roles
    try global_rbac.assignRole("user_admin", "admin");
    try global_rbac.assignRole("user_editor", "editor");

    std.debug.print("\n🚀 ZigAuth + http.zig Demo Server\n", .{});
    std.debug.print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n", .{});
    std.debug.print("📍 Server: http://localhost:3001\n\n", .{});
    std.debug.print("📝 Test Accounts:\n", .{});
    std.debug.print("   Admin:  username=admin,  password=admin123\n", .{});
    std.debug.print("   Editor: username=editor, password=editor123\n\n", .{});
    std.debug.print("🔗 Endpoints:\n", .{});
    std.debug.print("   POST /login        - Login\n", .{});
    std.debug.print("   GET  /profile      - View profile (requires auth)\n", .{});
    std.debug.print("   GET  /admin        - Admin panel (requires admin role)\n", .{});
    std.debug.print("   POST /logout       - Logout\n", .{});
    std.debug.print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n", .{});

    // Start server
    var server = try httpz.Server(void).init(
        allocator,
        .{ .address = .{ .tcp = .{ .host = "0.0.0.0", .port = 3001 } } },
        {},
    );
    defer {
        server.stop();
        server.deinit();
    }

    var router = try server.router(.{});
    router.get("/", handleRoot, .{});
    router.post("/login", handleLogin, .{});
    router.get("/profile", handleProfile, .{});
    router.get("/admin", handleAdmin, .{});
    router.post("/logout", handleLogout, .{});

    std.debug.print("✅ Server running. Press Ctrl+C to stop.\n\n", .{});
    try server.listen();
}

fn handleRoot(_: *httpz.Request, res: *httpz.Response) !void {
    const html =
        \\<!DOCTYPE html>
        \\<html>
        \\<head><title>ZigAuth + http.zig Demo</title></head>
        \\<body>
        \\  <h1>🔐 ZigAuth + http.zig Demo</h1>
        \\  <h2>Welcome!</h2>
        \\  <p>This demo shows ZigAuth's integration with http.zig.</p>
        \\
        \\  <h3>Test Accounts:</h3>
        \\  <ul>
        \\    <li><strong>Admin:</strong> username=admin, password=admin123</li>
        \\    <li><strong>Editor:</strong> username=editor, password=editor123</li>
        \\  </ul>
        \\
        \\  <h3>Try these curl commands:</h3>
        \\  <pre>
        \\# Login
        \\curl -X POST http://localhost:3001/login \
        \\  -H "Content-Type: application/json" \
        \\  -d '{"username":"admin","password":"admin123"}' \
        \\  -c cookies.txt
        \\
        \\# View profile
        \\curl http://localhost:3001/profile -b cookies.txt
        \\
        \\# Admin panel
        \\curl http://localhost:3001/admin -b cookies.txt
        \\  </pre>
        \\</body>
        \\</html>
    ;

    res.status = 200;
    res.header("Content-Type", "text/html");
    res.body = html;
}

fn handleLogin(req: *httpz.Request, res: *httpz.Response) !void {
    const allocator = req.arena;

    const body = req.body() orelse {
        res.status = 400;
        res.body = "Missing request body";
        return;
    };

    // Simple JSON parsing
    const username_start = std.mem.indexOf(u8, body, "\"username\":\"") orelse {
        res.status = 400;
        res.body = "Invalid JSON";
        return;
    };
    const username_value_start = username_start + 12;
    const username_end = std.mem.indexOfPos(u8, body, username_value_start, "\"") orelse {
        res.status = 400;
        res.body = "Invalid JSON";
        return;
    };
    const username = body[username_value_start..username_end];

    const password_start = std.mem.indexOf(u8, body, "\"password\":\"") orelse {
        res.status = 400;
        res.body = "Invalid JSON";
        return;
    };
    const password_value_start = password_start + 12;
    const password_end = std.mem.indexOfPos(u8, body, password_value_start, "\"") orelse {
        res.status = 400;
        res.body = "Invalid JSON";
        return;
    };
    const password = body[password_value_start..password_end];

    // Find user
    const user = users.get(username) orelse {
        res.status = 401;
        res.body = "Invalid credentials";
        return;
    };

    // Verify password
    const valid = try zigauth.auth.password.verify(allocator, password, user.password_hash);
    if (!valid) {
        res.status = 401;
        res.body = "Invalid credentials";
        return;
    }

    // Create session
    const store = global_session_store.store();
    const session = try store.create(allocator, user.id, 3600 * 24);
    defer {
        var s = session;
        s.deinit(allocator);
    }

    // Build cookie
    const cookie = try std.fmt.allocPrint(allocator, "session_id={s}; HttpOnly; SameSite=Lax; Path=/; Max-Age=86400", .{session.id});

    res.status = 200;
    res.header("Set-Cookie", cookie);
    res.header("Content-Type", "application/json");
    res.body = "{\"success\":true,\"message\":\"Login successful\"}";

    std.debug.print("✅ User '{s}' logged in\n", .{username});
}

fn handleProfile(req: *httpz.Request, res: *httpz.Response) !void {
    const allocator = req.arena;

    // Validate session
    const store = global_session_store.store();
    const user_id = try zigauth.adapters.httpz.validateSessionCookie(
        allocator,
        &store,
        req,
        "session_id",
    ) orelse {
        res.status = 401;
        res.body = "Unauthorized: Invalid session";
        return;
    };

    // Find user
    const user = blk: {
        var it = users.iterator();
        while (it.next()) |entry| {
            if (std.mem.eql(u8, entry.value_ptr.id, user_id)) {
                break :blk entry.value_ptr.*;
            }
        }
        res.status = 404;
        res.body = "User not found";
        return;
    };

    const response = try std.fmt.allocPrint(allocator, "{{\"user_id\":\"{s}\",\"username\":\"{s}\"}}", .{ user.id, user.username });

    res.status = 200;
    res.header("Content-Type", "application/json");
    res.body = response;
}

fn handleAdmin(req: *httpz.Request, res: *httpz.Response) !void {
    const allocator = req.arena;

    // Validate session
    const store = global_session_store.store();
    const user_id = try zigauth.adapters.httpz.validateSessionCookie(
        allocator,
        &store,
        req,
        "session_id",
    ) orelse {
        res.status = 401;
        res.body = "Unauthorized: Authentication required";
        return;
    };

    // Check admin permissions
    if (!global_rbac.userHasPermission(user_id, "*")) {
        res.status = 403;
        res.body = "Forbidden: Admin access required";
        return;
    }

    res.status = 200;
    res.header("Content-Type", "text/html");
    res.body = "<h1>Admin Panel</h1><p>Welcome, admin!</p>";
}

fn handleLogout(req: *httpz.Request, res: *httpz.Response) !void {
    // Extract and destroy session
    const session_id = zigauth.adapters.httpz.extractCookie(req, "session_id");
    if (session_id) |sid| {
        const store = global_session_store.store();
        store.destroy(sid) catch {};
    }

    res.status = 200;
    res.header("Set-Cookie", "session_id=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0");
    res.header("Content-Type", "application/json");
    res.body = "{\"success\":true,\"message\":\"Logged out\"}";
}
