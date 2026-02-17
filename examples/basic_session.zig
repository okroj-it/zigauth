const std = @import("std");
const zigauth = @import("zigauth");

pub fn main() !void {
    // Setup allocator
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer {
        const status = gpa.deinit();
        if (status == .leak) @panic("Memory leak detected!");
    }
    const allocator = gpa.allocator();

    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout: *std.Io.Writer = &stdout_writer.interface;

    try stdout.writeAll("=== ZigAuth Session Management Example ===\n\n");

    // Initialize session store
    var store = zigauth.storage.memory.MemoryStore.init(allocator);
    defer store.deinit();

    const store_interface = store.store();

    // Configuration
    const config = zigauth.auth.session.Config{
        .default_ttl = 3600 * 24, // 24 hours
        .cookie_name = "session_id",
        .cookie_path = "/",
        .http_only = true,
        .secure = true,
        .same_site = .lax,
    };

    try stdout.writeAll("1. Creating session for user...\n");
    var session = try store_interface.create(allocator, "user_12345", config.default_ttl);
    defer session.deinit(allocator);

    try stdout.print("   Session ID: {s}\n", .{session.id});
    try stdout.print("   User ID: {s}\n", .{session.user_id});
    try stdout.print("   Expires in: {d} seconds\n\n", .{config.default_ttl});

    try stdout.writeAll("2. Building Set-Cookie header...\n");
    const cookie = zigauth.auth.session.Cookie.fromSession(session.id, config, config.default_ttl);
    const cookie_header = try cookie.toString(allocator);
    defer allocator.free(cookie_header);

    try stdout.print("   Set-Cookie: {s}\n\n", .{cookie_header});

    try stdout.writeAll("3. Verifying session is valid...\n");
    if (session.isValid()) {
        try stdout.writeAll("   ✅ Session is valid (not expired)\n\n");
    } else {
        try stdout.writeAll("   ❌ Session is invalid or expired\n\n");
    }

    try stdout.writeAll("4. Retrieving session from store...\n");
    const retrieved = try store_interface.get(allocator, session.id);
    defer {
        var s = retrieved;
        s.deinit(allocator);
    }

    try stdout.print("   Retrieved session ID: {s}\n", .{retrieved.id});
    try stdout.print("   User ID: {s}\n\n", .{retrieved.user_id});

    try stdout.writeAll("5. Updating last accessed time...\n");
    session.touch();
    try store_interface.update(session);
    try stdout.writeAll("   ✅ Session updated\n\n");

    try stdout.writeAll("6. Parsing session ID from cookie header...\n");
    const cookie_header_from_client = "session_id=test123; other=value";
    const parsed_id = try zigauth.auth.session.parseSessionId(
        cookie_header_from_client,
        config.cookie_name,
        allocator,
    );

    if (parsed_id) |id| {
        defer allocator.free(id);
        try stdout.print("   Parsed session ID: {s}\n\n", .{id});
    }

    try stdout.writeAll("7. Creating delete cookie...\n");
    const delete_cookie = zigauth.auth.session.Cookie.deleteSession(config);
    const delete_header = try delete_cookie.toString(allocator);
    defer allocator.free(delete_header);

    try stdout.print("   Set-Cookie (delete): {s}\n\n", .{delete_header});

    try stdout.writeAll("8. Destroying session...\n");
    try store_interface.destroy(session.id);
    try stdout.writeAll("   ✅ Session destroyed\n\n");

    try stdout.writeAll("9. Verifying session is gone...\n");
    const result = store_interface.get(allocator, session.id);
    if (result) |_| {
        try stdout.writeAll("   ❌ Session still exists\n");
    } else |err| {
        try stdout.print("   ✅ Session not found: {s}\n\n", .{@errorName(err)});
    }

    try stdout.writeAll("=== Session Management Demo Complete! ===\n");
}
