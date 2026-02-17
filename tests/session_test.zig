const std = @import("std");
const zigauth = @import("zigauth");
const expect = std.testing.expect;
const expectEqual = std.testing.expectEqual;
const expectError = std.testing.expectError;
const expectEqualStrings = std.testing.expectEqualStrings;

const Session = zigauth.auth.session.Session;
const SessionError = zigauth.auth.session.Error;
const Config = zigauth.auth.session.Config;
const Cookie = zigauth.auth.session.Cookie;
const MemoryStore = zigauth.storage.memory.MemoryStore;

test "session - create and validate" {
    const allocator = std.testing.allocator;

    var store = MemoryStore.init(allocator);
    defer store.deinit();

    const store_interface = store.store();
    const session = try store_interface.create(allocator, "user_123", 3600);
    defer {
        var s = session;
        s.deinit(allocator);
    }

    try expectEqualStrings("user_123", session.user_id);
    try expect(session.id.len > 0);
    try expect(session.isValid());
}

test "session - expired session" {
    const allocator = std.testing.allocator;

    var store = MemoryStore.init(allocator);
    defer store.deinit();

    const store_interface = store.store();
    // Create session with -1 TTL (already expired)
    const session = try store_interface.create(allocator, "user_expired", -1);
    defer {
        var s = session;
        s.deinit(allocator);
    }

    try expect(!session.isValid());
    try expect(session.isExpired());
}

test "session - touch updates last_accessed" {
    const allocator = std.testing.allocator;

    var store = MemoryStore.init(allocator);
    defer store.deinit();

    const store_interface = store.store();
    var session = try store_interface.create(allocator, "user_touch", 3600);
    defer session.deinit(allocator);

    // Manually set old timestamp
    session.last_accessed = 1000;
    const old_accessed = session.last_accessed;

    // Touch should update to current timestamp
    session.touch();

    try expect(session.last_accessed >= old_accessed);
    try expect(session.last_accessed > 1000);
}

test "session - get existing session" {
    const allocator = std.testing.allocator;

    var store = MemoryStore.init(allocator);
    defer store.deinit();

    const store_interface = store.store();

    // Create session
    const created = try store_interface.create(allocator, "user_get", 3600);
    const session_id = try allocator.dupe(u8, created.id);
    defer allocator.free(session_id);
    defer {
        var s = created;
        s.deinit(allocator);
    }

    // Get session
    const retrieved = try store_interface.get(allocator, session_id);
    defer {
        var s = retrieved;
        s.deinit(allocator);
    }

    try expectEqualStrings(created.id, retrieved.id);
    try expectEqualStrings(created.user_id, retrieved.user_id);
}

test "session - get nonexistent session" {
    const allocator = std.testing.allocator;

    var store = MemoryStore.init(allocator);
    defer store.deinit();

    const store_interface = store.store();
    const result = store_interface.get(allocator, "nonexistent_id");

    try expectError(SessionError.SessionNotFound, result);
}

test "session - get expired session" {
    const allocator = std.testing.allocator;

    var store = MemoryStore.init(allocator);
    defer store.deinit();

    const store_interface = store.store();

    // Create expired session
    const created = try store_interface.create(allocator, "user_expired", -1);
    const session_id = try allocator.dupe(u8, created.id);
    defer allocator.free(session_id);
    defer {
        var s = created;
        s.deinit(allocator);
    }

    // Try to get expired session
    const result = store_interface.get(allocator, session_id);
    try expectError(SessionError.SessionExpired, result);
}

test "session - update session" {
    const allocator = std.testing.allocator;

    var store = MemoryStore.init(allocator);
    defer store.deinit();

    const store_interface = store.store();

    // Create session
    var session = try store_interface.create(allocator, "user_update", 3600);
    defer session.deinit(allocator);

    const old_accessed = session.last_accessed;

    // Update session
    std.Thread.sleep(1_000_000_000); // Sleep 1 second
    session.touch();
    try store_interface.update(session);

    // Get updated session
    const retrieved = try store_interface.get(allocator, session.id);
    defer {
        var s = retrieved;
        s.deinit(allocator);
    }

    try expect(retrieved.last_accessed > old_accessed);
}

test "session - destroy session" {
    const allocator = std.testing.allocator;

    var store = MemoryStore.init(allocator);
    defer store.deinit();

    const store_interface = store.store();

    // Create session
    const session = try store_interface.create(allocator, "user_destroy", 3600);
    const session_id = try allocator.dupe(u8, session.id);
    defer allocator.free(session_id);
    defer {
        var s = session;
        s.deinit(allocator);
    }

    try expect(store.count() == 1);

    // Destroy session
    try store_interface.destroy(session_id);

    try expect(store.count() == 0);

    // Try to get destroyed session
    const result = store_interface.get(allocator, session_id);
    try expectError(SessionError.SessionNotFound, result);
}

test "session - destroy nonexistent session" {
    const allocator = std.testing.allocator;

    var store = MemoryStore.init(allocator);
    defer store.deinit();

    const store_interface = store.store();
    const result = store_interface.destroy("nonexistent_id");

    try expectError(SessionError.SessionNotFound, result);
}

test "session - cleanup expired sessions" {
    const allocator = std.testing.allocator;

    var store = MemoryStore.init(allocator);
    defer store.deinit();

    const store_interface = store.store();

    // Create valid session
    const valid = try store_interface.create(allocator, "user_valid", 3600);
    defer {
        var s = valid;
        s.deinit(allocator);
    }

    // Create expired session
    const expired = try store_interface.create(allocator, "user_expired", -1);
    defer {
        var s = expired;
        s.deinit(allocator);
    }

    try expect(store.count() == 2);

    // Cleanup should remove only expired session
    try store_interface.cleanup();

    try expect(store.count() == 1);

    // Valid session should still exist
    const retrieved = try store_interface.get(allocator, valid.id);
    defer {
        var s = retrieved;
        s.deinit(allocator);
    }
    try expectEqualStrings(valid.id, retrieved.id);

    // Expired session should be gone (cleanup removed it)
    const result = store_interface.get(allocator, expired.id);
    try expectError(SessionError.SessionNotFound, result);
}

test "cookie - build set-cookie header" {
    const allocator = std.testing.allocator;

    const config = Config{
        .cookie_name = "session_id",
        .cookie_path = "/",
        .http_only = true,
        .secure = true,
        .same_site = .lax,
    };

    const cookie = Cookie.fromSession("abc123", config, 3600);
    const header = try cookie.toString(allocator);
    defer allocator.free(header);

    // Check all parts are present
    try expect(std.mem.indexOf(u8, header, "session_id=abc123") != null);
    try expect(std.mem.indexOf(u8, header, "Path=/") != null);
    try expect(std.mem.indexOf(u8, header, "HttpOnly") != null);
    try expect(std.mem.indexOf(u8, header, "Secure") != null);
    try expect(std.mem.indexOf(u8, header, "SameSite=Lax") != null);
    try expect(std.mem.indexOf(u8, header, "Max-Age=3600") != null);
}

test "cookie - parse session id from header" {
    const allocator = std.testing.allocator;

    const cookie_header = "session_id=abc123; other=value";
    const session_id = try zigauth.auth.session.parseSessionId(cookie_header, "session_id", allocator);

    if (session_id) |id| {
        defer allocator.free(id);
        try expectEqualStrings("abc123", id);
    } else {
        try expect(false); // Should have found session_id
    }
}

test "cookie - parse missing session id" {
    const allocator = std.testing.allocator;

    const cookie_header = "other=value; foo=bar";
    const session_id = try zigauth.auth.session.parseSessionId(cookie_header, "session_id", allocator);

    try expect(session_id == null);
}

test "cookie - delete session cookie" {
    const allocator = std.testing.allocator;

    const config = Config{
        .cookie_name = "session_id",
        .cookie_path = "/",
        .http_only = true,
        .secure = true,
        .same_site = .lax,
    };

    const cookie = Cookie.deleteSession(config);
    const header = try cookie.toString(allocator);
    defer allocator.free(header);

    // Check delete cookie has empty value and Max-Age=0
    try expect(std.mem.indexOf(u8, header, "session_id=") != null);
    try expect(std.mem.indexOf(u8, header, "Max-Age=0") != null);
}
