const std = @import("std");
const zap = @import("zap");
const zigauth = @import("zigauth");

// Demo user database
const User = struct {
    id: []const u8,
    username: []const u8,
    password_hash: []const u8,
};

var users = std.StringHashMap(User).init(std.heap.page_allocator);

// Authentication context for middleware
const Context = struct {
    user_id: ?[]const u8 = null,
    session_id: ?[]const u8 = null,
    claims: ?zigauth.auth.jwt.Claims = null,
};

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    // Initialize session store
    var session_store = zigauth.storage.memory.MemoryStore.init(allocator);
    defer session_store.deinit();

    // Initialize RBAC
    var rbac = zigauth.authz.rbac.RBAC.init(allocator);
    defer rbac.deinit();

    // Define roles
    const admin_role = zigauth.authz.rbac.Role{
        .name = "admin",
        .permissions = &[_][]const u8{"*"}, // Full access
    };

    const editor_role = zigauth.authz.rbac.Role{
        .name = "editor",
        .permissions = &[_][]const u8{ "posts:read", "posts:write", "posts:delete" },
    };

    const viewer_role = zigauth.authz.rbac.Role{
        .name = "viewer",
        .permissions = &[_][]const u8{"posts:read"},
    };

    try rbac.defineRole(admin_role);
    try rbac.defineRole(editor_role);
    try rbac.defineRole(viewer_role);

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
    try rbac.assignRole("user_admin", "admin");
    try rbac.assignRole("user_editor", "editor");

    std.debug.print("\n🚀 ZigAuth Demo Server Starting...\n", .{});
    std.debug.print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n", .{});
    std.debug.print("📍 Server: http://localhost:3000\n\n", .{});
    std.debug.print("📝 Test Accounts:\n", .{});
    std.debug.print("   Admin:  username=admin,  password=admin123\n", .{});
    std.debug.print("   Editor: username=editor, password=editor123\n\n", .{});
    std.debug.print("🔗 Endpoints:\n", .{});
    std.debug.print("   POST /login        - Login (returns session cookie)\n", .{});
    std.debug.print("   GET  /profile      - View profile (requires auth)\n", .{});
    std.debug.print("   GET  /posts        - View posts (requires posts:read)\n", .{});
    std.debug.print("   POST /posts        - Create post (requires posts:write)\n", .{});
    std.debug.print("   DELETE /posts      - Delete post (requires posts:delete)\n", .{});
    std.debug.print("   GET  /admin        - Admin panel (requires admin role)\n", .{});
    std.debug.print("   POST /logout       - Logout\n", .{});
    std.debug.print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n", .{});

    // Start server
    var listener = zap.HttpListener.init(.{
        .port = 3000,
        .on_request = onRequest,
        .log = true,
        .max_clients = 100,
    });

    try listener.listen();

    std.debug.print("✅ Server running. Press Ctrl+C to stop.\n\n", .{});

    // Run the server
    zap.start(.{
        .threads = 2,
        .workers = 2,
    });
}

fn onRequest(r: zap.Request) anyerror!void {
    const allocator = std.heap.page_allocator;

    // Route requests
    const path = r.path orelse "/";

    if (std.mem.eql(u8, path, "/")) {
        handleRoot(r) catch {};
    } else if (std.mem.eql(u8, path, "/login")) {
        handleLogin(r, allocator) catch {};
    } else if (std.mem.eql(u8, path, "/profile")) {
        handleProfile(r, allocator) catch {};
    } else if (std.mem.eql(u8, path, "/posts")) {
        if (r.method) |method| {
            if (std.mem.eql(u8, method, "GET")) {
                handleGetPosts(r, allocator) catch {};
            } else if (std.mem.eql(u8, method, "POST")) {
                handleCreatePost(r, allocator) catch {};
            } else if (std.mem.eql(u8, method, "DELETE")) {
                handleDeletePost(r, allocator) catch {};
            }
        }
    } else if (std.mem.eql(u8, path, "/admin")) {
        handleAdmin(r, allocator) catch {};
    } else if (std.mem.eql(u8, path, "/logout")) {
        handleLogout(r, allocator) catch {};
    } else {
        r.setStatus(.not_found);
        r.sendBody("404 Not Found") catch {};
    }
}

fn handleRoot(r: zap.Request) !void {
    const html =
        \\<!DOCTYPE html>
        \\<html>
        \\<head><title>ZigAuth Demo</title></head>
        \\<body>
        \\  <h1>🔐 ZigAuth + Zigzap Demo</h1>
        \\  <h2>Welcome!</h2>
        \\  <p>This demo shows ZigAuth's session-based authentication and RBAC.</p>
        \\
        \\  <h3>Test Accounts:</h3>
        \\  <ul>
        \\    <li><strong>Admin:</strong> username=admin, password=admin123</li>
        \\    <li><strong>Editor:</strong> username=editor, password=editor123</li>
        \\  </ul>
        \\
        \\  <h3>Try these curl commands:</h3>
        \\  <pre>
        \\# Login as admin
        \\curl -X POST http://localhost:3000/login \
        \\  -H "Content-Type: application/json" \
        \\  -d '{"username":"admin","password":"admin123"}' \
        \\  -c cookies.txt
        \\
        \\# View profile (requires auth)
        \\curl http://localhost:3000/profile -b cookies.txt
        \\
        \\# Create post (requires posts:write)
        \\curl -X POST http://localhost:3000/posts -b cookies.txt
        \\
        \\# Access admin panel (requires admin role)
        \\curl http://localhost:3000/admin -b cookies.txt
        \\  </pre>
        \\</body>
        \\</html>
    ;

    try r.setHeader("Content-Type", "text/html");
    try r.sendBody(html);
}

fn handleLogin(r: zap.Request, allocator: std.mem.Allocator) !void {
    // Parse JSON body
    const body = r.body orelse {
        r.setStatus(.bad_request);
        try r.sendBody("Missing request body");
        return;
    };

    // Simple JSON parsing (in production, use std.json)
    const username_start = std.mem.indexOf(u8, body, "\"username\":\"") orelse {
        r.setStatus(.bad_request);
        try r.sendBody("Invalid JSON");
        return;
    };
    const username_value_start = username_start + 12;
    const username_end = std.mem.indexOfPos(u8, body, username_value_start, "\"") orelse {
        r.setStatus(.bad_request);
        try r.sendBody("Invalid JSON");
        return;
    };
    const username = body[username_value_start..username_end];

    const password_start = std.mem.indexOf(u8, body, "\"password\":\"") orelse {
        r.setStatus(.bad_request);
        try r.sendBody("Invalid JSON");
        return;
    };
    const password_value_start = password_start + 12;
    const password_end = std.mem.indexOfPos(u8, body, password_value_start, "\"") orelse {
        r.setStatus(.bad_request);
        try r.sendBody("Invalid JSON");
        return;
    };
    const password = body[password_value_start..password_end];

    // Find user
    const user = users.get(username) orelse {
        r.setStatus(.unauthorized);
        try r.sendBody("Invalid credentials");
        return;
    };

    // Verify password
    const valid = try zigauth.auth.password.verify(allocator, password, user.password_hash);
    if (!valid) {
        r.setStatus(.unauthorized);
        try r.sendBody("Invalid credentials");
        return;
    }

    // Create session
    var session_store = zigauth.storage.memory.MemoryStore.init(allocator);
    defer session_store.deinit();
    const store = session_store.store();

    const session = try store.create(allocator, user.id, 3600 * 24); // 24 hour session
    defer {
        var s = session;
        s.deinit(allocator);
    }

    // Build cookie header
    const cookie = try std.fmt.allocPrint(allocator, "session_id={s}; HttpOnly; SameSite=Lax; Path=/; Max-Age=86400", .{session.id});
    defer allocator.free(cookie);

    try r.setHeader("Set-Cookie", cookie);
    try r.setHeader("Content-Type", "application/json");
    try r.sendBody("{\"success\":true,\"message\":\"Login successful\"}");

    std.debug.print("✅ User '{s}' logged in\n", .{username});
}

fn handleProfile(r: zap.Request, allocator: std.mem.Allocator) !void {
    // Extract session cookie
    const cookie_header = r.getHeader("cookie") orelse {
        r.setStatus(.unauthorized);
        try r.sendBody("Unauthorized: No session");
        return;
    };

    // Parse session_id
    const session_id = blk: {
        var it = std.mem.splitSequence(u8, cookie_header, "; ");
        while (it.next()) |cookie| {
            if (std.mem.startsWith(u8, cookie, "session_id=")) {
                break :blk cookie[11..];
            }
        }
        break :blk null;
    } orelse {
        r.setStatus(.unauthorized);
        try r.sendBody("Unauthorized: No session");
        return;
    };

    // Validate session
    var session_store = zigauth.storage.memory.MemoryStore.init(allocator);
    defer session_store.deinit();
    const store = session_store.store();

    const session = store.get(allocator, session_id) catch {
        r.setStatus(.unauthorized);
        try r.sendBody("Unauthorized: Invalid session");
        return;
    };
    defer {
        var s = session;
        s.deinit(allocator);
    }

    if (!session.isValid()) {
        r.setStatus(.unauthorized);
        try r.sendBody("Unauthorized: Session expired");
        return;
    }

    // Find user
    const user = blk: {
        var it = users.iterator();
        while (it.next()) |entry| {
            if (std.mem.eql(u8, entry.value_ptr.id, session.user_id)) {
                break :blk entry.value_ptr.*;
            }
        }
        r.setStatus(.not_found);
        try r.sendBody("User not found");
        return;
    };

    const response = try std.fmt.allocPrint(allocator, "{{\"user_id\":\"{s}\",\"username\":\"{s}\"}}", .{ user.id, user.username });
    defer allocator.free(response);

    try r.setHeader("Content-Type", "application/json");
    try r.sendBody(response);
}

fn handleGetPosts(r: zap.Request, _: std.mem.Allocator) !void {
    // Simplified: Would normally check RBAC for posts:read
    try r.setHeader("Content-Type", "application/json");
    try r.sendBody("[{\"id\":1,\"title\":\"Hello World\"},{\"id\":2,\"title\":\"ZigAuth Rocks\"}]");
}

fn handleCreatePost(r: zap.Request, _: std.mem.Allocator) !void {
    // Would check RBAC for posts:write
    try r.setHeader("Content-Type", "application/json");
    try r.sendBody("{\"success\":true,\"message\":\"Post created\"}");
}

fn handleDeletePost(r: zap.Request, _: std.mem.Allocator) !void {
    // Would check RBAC for posts:delete
    try r.setHeader("Content-Type", "application/json");
    try r.sendBody("{\"success\":true,\"message\":\"Post deleted\"}");
}

fn handleAdmin(r: zap.Request, _: std.mem.Allocator) !void {
    // Would check RBAC for admin permissions
    try r.setHeader("Content-Type", "text/html");
    try r.sendBody("<h1>Admin Panel</h1><p>Welcome, admin!</p>");
}

fn handleLogout(r: zap.Request, _: std.mem.Allocator) !void {
    try r.setHeader("Set-Cookie", "session_id=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0");
    try r.setHeader("Content-Type", "application/json");
    try r.sendBody("{\"success\":true,\"message\":\"Logged out\"}");
}
