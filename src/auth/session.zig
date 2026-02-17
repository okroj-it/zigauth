const std = @import("std");
const crypto = std.crypto;
const mem = std.mem;

/// Session data
pub const Session = struct {
    id: []const u8,
    user_id: []const u8,
    data: std.StringHashMap([]const u8),
    created_at: i64,
    expires_at: i64,
    last_accessed: i64,

    pub fn deinit(self: *Session, allocator: mem.Allocator) void {
        allocator.free(self.id);
        allocator.free(self.user_id);

        var iter = self.data.iterator();
        while (iter.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            allocator.free(entry.value_ptr.*);
        }
        self.data.deinit();
    }

    /// Check if session is expired
    pub fn isExpired(self: Session) bool {
        const now = std.time.timestamp();
        return now >= self.expires_at;
    }

    /// Check if session is valid (not expired)
    pub fn isValid(self: Session) bool {
        return !self.isExpired();
    }

    /// Update last accessed time
    pub fn touch(self: *Session) void {
        self.last_accessed = std.time.timestamp();
    }
};

/// Session configuration
pub const Config = struct {
    /// Default TTL for sessions (in seconds)
    default_ttl: i64 = 3600 * 24, // 24 hours
    /// Cookie name
    cookie_name: []const u8 = "session_id",
    /// Cookie path
    cookie_path: []const u8 = "/",
    /// Cookie HTTP only
    http_only: bool = true,
    /// Cookie secure (HTTPS only)
    secure: bool = true,
    /// Cookie SameSite attribute
    same_site: SameSite = .lax,
};

/// SameSite cookie attribute
pub const SameSite = enum {
    strict,
    lax,
    none,

    pub fn toString(self: SameSite) []const u8 {
        return switch (self) {
            .strict => "Strict",
            .lax => "Lax",
            .none => "None",
        };
    }
};

/// Session errors
pub const Error = error{
    SessionNotFound,
    SessionExpired,
    InvalidSession,
    OutOfMemory,
    InvalidSessionId,
};

/// Session storage interface
pub const Store = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        create: *const fn (ptr: *anyopaque, allocator: mem.Allocator, user_id: []const u8, ttl: i64) Error!Session,
        get: *const fn (ptr: *anyopaque, allocator: mem.Allocator, session_id: []const u8) Error!Session,
        update: *const fn (ptr: *anyopaque, session: Session) Error!void,
        destroy: *const fn (ptr: *anyopaque, session_id: []const u8) Error!void,
        cleanup: *const fn (ptr: *anyopaque) Error!void,
    };

    pub fn create(self: Store, allocator: mem.Allocator, user_id: []const u8, ttl: i64) Error!Session {
        return self.vtable.create(self.ptr, allocator, user_id, ttl);
    }

    pub fn get(self: Store, allocator: mem.Allocator, session_id: []const u8) Error!Session {
        return self.vtable.get(self.ptr, allocator, session_id);
    }

    pub fn update(self: Store, session: Session) Error!void {
        return self.vtable.update(self.ptr, session);
    }

    pub fn destroy(self: Store, session_id: []const u8) Error!void {
        return self.vtable.destroy(self.ptr, session_id);
    }

    pub fn cleanup(self: Store) Error!void {
        return self.vtable.cleanup(self.ptr);
    }
};

/// Generate a cryptographically secure session ID
pub fn generateSessionId(allocator: mem.Allocator) Error![]u8 {
    var random_bytes: [32]u8 = undefined;
    crypto.random.bytes(&random_bytes);

    // Base64url encode (URL-safe, no padding)
    const encoder = std.base64.url_safe_no_pad.Encoder;
    const encoded_len = encoder.calcSize(random_bytes.len);
    const result = try allocator.alloc(u8, encoded_len);
    _ = encoder.encode(result, &random_bytes);
    return result;
}

/// Cookie builder for session management
pub const Cookie = struct {
    name: []const u8,
    value: []const u8,
    path: []const u8,
    http_only: bool,
    secure: bool,
    same_site: SameSite,
    max_age: ?i64,

    /// Build Set-Cookie header value
    pub fn toString(self: Cookie, allocator: mem.Allocator) Error![]u8 {
        var parts: std.ArrayListUnmanaged(u8) = .empty;
        defer parts.deinit(allocator);

        const writer = parts.writer(allocator);

        // name=value
        try writer.print("{s}={s}", .{ self.name, self.value });

        // Path
        try writer.print("; Path={s}", .{self.path});

        // HttpOnly
        if (self.http_only) {
            try writer.writeAll("; HttpOnly");
        }

        // Secure
        if (self.secure) {
            try writer.writeAll("; Secure");
        }

        // SameSite
        try writer.print("; SameSite={s}", .{self.same_site.toString()});

        // Max-Age
        if (self.max_age) |age| {
            try writer.print("; Max-Age={d}", .{age});
        }

        return parts.toOwnedSlice(allocator);
    }

    /// Create session cookie from config
    pub fn fromSession(session_id: []const u8, config: Config, ttl: i64) Cookie {
        return Cookie{
            .name = config.cookie_name,
            .value = session_id,
            .path = config.cookie_path,
            .http_only = config.http_only,
            .secure = config.secure,
            .same_site = config.same_site,
            .max_age = ttl,
        };
    }

    /// Create delete cookie (expires immediately)
    pub fn deleteSession(config: Config) Cookie {
        return Cookie{
            .name = config.cookie_name,
            .value = "",
            .path = config.cookie_path,
            .http_only = config.http_only,
            .secure = config.secure,
            .same_site = config.same_site,
            .max_age = 0,
        };
    }
};

/// Parse session ID from Cookie header
pub fn parseSessionId(cookie_header: []const u8, cookie_name: []const u8, allocator: mem.Allocator) Error!?[]u8 {
    var cookies = mem.splitSequence(u8, cookie_header, "; ");

    while (cookies.next()) |cookie| {
        var parts = mem.splitSequence(u8, cookie, "=");
        const name = parts.next() orelse continue;
        const value = parts.next() orelse continue;

        if (mem.eql(u8, name, cookie_name)) {
            return try allocator.dupe(u8, value);
        }
    }

    return null;
}

// Tests
test "session - generate id" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const id1 = try generateSessionId(allocator);
    defer allocator.free(id1);

    const id2 = try generateSessionId(allocator);
    defer allocator.free(id2);

    // IDs should be different
    try testing.expect(!mem.eql(u8, id1, id2));

    // IDs should be base64url encoded (no padding)
    try testing.expect(mem.indexOf(u8, id1, "=") == null);
    try testing.expect(mem.indexOf(u8, id2, "=") == null);

    // IDs should have reasonable length
    try testing.expect(id1.len > 40);
    try testing.expect(id2.len > 40);
}

test "session - create and validate" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const now = std.time.timestamp();
    var session = Session{
        .id = try allocator.dupe(u8, "session_123"),
        .user_id = try allocator.dupe(u8, "user_456"),
        .data = std.StringHashMap([]const u8).init(allocator),
        .created_at = now,
        .expires_at = now + 3600,
        .last_accessed = now,
    };
    defer session.deinit(allocator);

    // Session should be valid (not expired)
    try testing.expect(session.isValid());
    try testing.expect(!session.isExpired());
}

test "session - expiration" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const now = std.time.timestamp();
    var session = Session{
        .id = try allocator.dupe(u8, "session_123"),
        .user_id = try allocator.dupe(u8, "user_456"),
        .data = std.StringHashMap([]const u8).init(allocator),
        .created_at = now - 7200,
        .expires_at = now - 1, // Expired 1 second ago
        .last_accessed = now - 3600,
    };
    defer session.deinit(allocator);

    // Session should be expired
    try testing.expect(!session.isValid());
    try testing.expect(session.isExpired());
}

test "session - touch updates last accessed" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const now = std.time.timestamp();
    var session = Session{
        .id = try allocator.dupe(u8, "session_123"),
        .user_id = try allocator.dupe(u8, "user_456"),
        .data = std.StringHashMap([]const u8).init(allocator),
        .created_at = now - 3600,
        .expires_at = now + 3600,
        .last_accessed = now - 1000,
    };
    defer session.deinit(allocator);

    const old_accessed = session.last_accessed;
    session.touch();

    // Last accessed should be updated
    try testing.expect(session.last_accessed > old_accessed);
}

test "cookie - build set-cookie header" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const cookie = Cookie{
        .name = "session_id",
        .value = "abc123",
        .path = "/",
        .http_only = true,
        .secure = true,
        .same_site = .lax,
        .max_age = 3600,
    };

    const header = try cookie.toString(allocator);
    defer allocator.free(header);

    // Check all parts are present
    try testing.expect(mem.indexOf(u8, header, "session_id=abc123") != null);
    try testing.expect(mem.indexOf(u8, header, "Path=/") != null);
    try testing.expect(mem.indexOf(u8, header, "HttpOnly") != null);
    try testing.expect(mem.indexOf(u8, header, "Secure") != null);
    try testing.expect(mem.indexOf(u8, header, "SameSite=Lax") != null);
    try testing.expect(mem.indexOf(u8, header, "Max-Age=3600") != null);
}

test "cookie - parse session id" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const cookie_header = "session_id=abc123; other=value";
    const session_id = try parseSessionId(cookie_header, "session_id", allocator);

    if (session_id) |id| {
        defer allocator.free(id);
        try testing.expectEqualStrings("abc123", id);
    } else {
        try testing.expect(false); // Should have found session_id
    }
}

test "cookie - parse missing session id" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const cookie_header = "other=value; foo=bar";
    const session_id = try parseSessionId(cookie_header, "session_id", allocator);

    try testing.expect(session_id == null);
}
