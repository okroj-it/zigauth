const std = @import("std");
const mem = std.mem;
const session_mod = @import("../auth/session.zig");
const Session = session_mod.Session;
const SessionError = session_mod.Error;

/// Thread-safe in-memory session storage
pub const MemoryStore = struct {
    allocator: mem.Allocator,
    sessions: std.StringHashMap(SessionEntry),
    mutex: std.Thread.Mutex,

    const SessionEntry = struct {
        session: Session,
        owned: bool, // Whether this store owns the session data
    };

    pub fn init(allocator: mem.Allocator) MemoryStore {
        return .{
            .allocator = allocator,
            .sessions = std.StringHashMap(SessionEntry).init(allocator),
            .mutex = .{},
        };
    }

    pub fn deinit(self: *MemoryStore) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        var iter = self.sessions.iterator();
        while (iter.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            if (entry.value_ptr.owned) {
                var session = entry.value_ptr.session;
                session.deinit(self.allocator);
            }
        }
        self.sessions.deinit();
    }

    /// Get Store interface
    pub fn store(self: *MemoryStore) session_mod.Store {
        return .{
            .ptr = self,
            .vtable = &.{
                .create = create,
                .get = get,
                .update = update,
                .destroy = destroy,
                .cleanup = cleanup,
            },
        };
    }

    // VTable implementations
    fn create(ptr: *anyopaque, allocator: mem.Allocator, user_id: []const u8, ttl: i64) SessionError!Session {
        const self: *MemoryStore = @ptrCast(@alignCast(ptr));
        self.mutex.lock();
        defer self.mutex.unlock();

        // Generate session ID
        const session_id = try session_mod.generateSessionId(allocator);
        errdefer allocator.free(session_id);

        const now = std.time.timestamp();

        // Create session
        const data = std.StringHashMap([]const u8).init(allocator);
        const new_session = Session{
            .id = session_id,
            .user_id = try allocator.dupe(u8, user_id),
            .data = data,
            .created_at = now,
            .expires_at = now + ttl,
            .last_accessed = now,
        };

        // Store session
        const key = try allocator.dupe(u8, session_id);
        try self.sessions.put(key, .{
            .session = new_session,
            .owned = true,
        });

        // Return a copy for the caller
        return Session{
            .id = try allocator.dupe(u8, new_session.id),
            .user_id = try allocator.dupe(u8, new_session.user_id),
            .data = std.StringHashMap([]const u8).init(allocator),
            .created_at = new_session.created_at,
            .expires_at = new_session.expires_at,
            .last_accessed = new_session.last_accessed,
        };
    }

    fn get(ptr: *anyopaque, allocator: mem.Allocator, session_id: []const u8) SessionError!Session {
        const self: *MemoryStore = @ptrCast(@alignCast(ptr));
        self.mutex.lock();
        defer self.mutex.unlock();

        const entry = self.sessions.get(session_id) orelse return SessionError.SessionNotFound;

        // Check expiration
        if (entry.session.isExpired()) {
            return SessionError.SessionExpired;
        }

        // Return a copy
        return Session{
            .id = try allocator.dupe(u8, entry.session.id),
            .user_id = try allocator.dupe(u8, entry.session.user_id),
            .data = std.StringHashMap([]const u8).init(allocator),
            .created_at = entry.session.created_at,
            .expires_at = entry.session.expires_at,
            .last_accessed = entry.session.last_accessed,
        };
    }

    fn update(ptr: *anyopaque, updated_session: Session) SessionError!void {
        const self: *MemoryStore = @ptrCast(@alignCast(ptr));
        self.mutex.lock();
        defer self.mutex.unlock();

        var entry = self.sessions.getPtr(updated_session.id) orelse return SessionError.SessionNotFound;

        // Update mutable fields
        entry.session.expires_at = updated_session.expires_at;
        entry.session.last_accessed = updated_session.last_accessed;
    }

    fn destroy(ptr: *anyopaque, session_id: []const u8) SessionError!void {
        const self: *MemoryStore = @ptrCast(@alignCast(ptr));
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.sessions.fetchRemove(session_id)) |kv| {
            self.allocator.free(kv.key);
            if (kv.value.owned) {
                var session = kv.value.session;
                session.deinit(self.allocator);
            }
        } else {
            return SessionError.SessionNotFound;
        }
    }

    fn cleanup(ptr: *anyopaque) SessionError!void {
        const self: *MemoryStore = @ptrCast(@alignCast(ptr));
        self.mutex.lock();
        defer self.mutex.unlock();

        const now = std.time.timestamp();
        var to_remove: std.ArrayListUnmanaged([]const u8) = .empty;
        defer to_remove.deinit(self.allocator);

        // Find expired sessions
        var iter = self.sessions.iterator();
        while (iter.next()) |entry| {
            if (entry.value_ptr.session.expires_at < now) {
                try to_remove.append(self.allocator, entry.key_ptr.*);
            }
        }

        // Remove expired sessions
        for (to_remove.items) |session_id| {
            if (self.sessions.fetchRemove(session_id)) |kv| {
                self.allocator.free(kv.key);
                if (kv.value.owned) {
                    var session = kv.value.session;
                    session.deinit(self.allocator);
                }
            }
        }
    }

    /// Get count of sessions (for testing)
    pub fn count(self: *MemoryStore) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.sessions.count();
    }
};

// Tests
test "memory store - create session" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var store = MemoryStore.init(allocator);
    defer store.deinit();

    const store_interface = store.store();
    const session = try store_interface.create(allocator, "user_123", 3600);
    defer {
        var s = session;
        s.deinit(allocator);
    }

    try testing.expectEqualStrings("user_123", session.user_id);
    try testing.expect(session.id.len > 0);
    try testing.expect(store.count() == 1);
}

test "memory store - get session" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var store = MemoryStore.init(allocator);
    defer store.deinit();

    const store_interface = store.store();

    // Create session
    const created = try store_interface.create(allocator, "user_456", 3600);
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

    try testing.expectEqualStrings(created.id, retrieved.id);
    try testing.expectEqualStrings(created.user_id, retrieved.user_id);
}

test "memory store - destroy session" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var store = MemoryStore.init(allocator);
    defer store.deinit();

    const store_interface = store.store();

    // Create session
    const session = try store_interface.create(allocator, "user_789", 3600);
    const session_id = try allocator.dupe(u8, session.id);
    defer allocator.free(session_id);
    defer {
        var s = session;
        s.deinit(allocator);
    }

    try testing.expect(store.count() == 1);

    // Destroy session
    try store_interface.destroy(session_id);

    try testing.expect(store.count() == 0);

    // Get should fail
    const result = store_interface.get(allocator, session_id);
    try testing.expectError(SessionError.SessionNotFound, result);
}

test "memory store - cleanup expired sessions" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var store = MemoryStore.init(allocator);
    defer store.deinit();

    const store_interface = store.store();

    // Create session that's already expired
    const session = try store_interface.create(allocator, "user_expired", -1);
    defer {
        var s = session;
        s.deinit(allocator);
    }

    try testing.expect(store.count() == 1);

    // Cleanup should remove expired session
    try store_interface.cleanup();

    try testing.expect(store.count() == 0);
}

test "memory store - update session" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var store = MemoryStore.init(allocator);
    defer store.deinit();

    const store_interface = store.store();

    // Create session
    var session = try store_interface.create(allocator, "user_update", 3600);
    defer session.deinit(allocator);

    const old_accessed = session.last_accessed;

    // Update session
    session.touch();
    try store_interface.update(session);

    // Get updated session
    const retrieved = try store_interface.get(allocator, session.id);
    defer {
        var s = retrieved;
        s.deinit(allocator);
    }

    try testing.expect(retrieved.last_accessed > old_accessed);
}
