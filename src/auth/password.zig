const std = @import("std");
const crypto = std.crypto;
const mem = std.mem;

/// Password hashing configuration using Argon2id
pub const Config = struct {
    /// Time cost (iterations)
    time_cost: u32 = 3,
    /// Memory cost in KiB
    memory_cost: u32 = 65536, // 64 MiB
    /// Parallelism factor (max 16777215)
    parallelism: u24 = 4,
    /// Hash length in bytes
    hash_len: u32 = 32,
    /// Salt length in bytes
    salt_len: u32 = 16,
};

/// Default configuration (OWASP recommended)
pub const default_config = Config{};

/// Password hashing error types
pub const Error = error{
    InvalidPassword,
    InvalidHash,
    HashTooLong,
    OutOfMemory,
    VerificationFailed,
    SystemResources,
    Unexpected,
    LockedMemoryLimitExceeded,
    AuthenticationFailed,
    OutputTooLong,
    IdentityElement,
    InvalidEncoding,
    SignatureVerificationFailed,
    KeyMismatch,
    NonCanonical,
    NotSquare,
    PasswordVerificationFailed,
    WeakParameters,
    WeakPublicKey,
    UnexpectedSubgroup,
    ThreadQuotaExceeded,
    InvalidCharacter,
    Overflow,
    NoSpaceLeft,
    InvalidLength,
};

/// Hash a password using Argon2id
pub fn hash(
    allocator: mem.Allocator,
    password: []const u8,
    config: Config,
) Error![]const u8 {
    if (password.len == 0) return Error.InvalidPassword;

    // Generate random salt
    var salt: [32]u8 = undefined;
    crypto.random.bytes(&salt);
    const salt_slice = salt[0..config.salt_len];

    // Allocate hash buffer
    const hash_buf = try allocator.alloc(u8, config.hash_len);
    errdefer allocator.free(hash_buf);

    // Hash password with Argon2id
    try crypto.pwhash.argon2.kdf(
        allocator,
        hash_buf,
        password,
        salt_slice,
        .{
            .t = config.time_cost,
            .m = config.memory_cost,
            .p = config.parallelism,
        },
        .argon2id,
    );

    // Encode as PHC string format:
    // $argon2id$v=19$m=65536,t=3,p=4$salt$hash
    const salt_hex = try toHex(allocator, salt_slice);
    defer allocator.free(salt_hex);

    const hash_hex = try toHex(allocator, hash_buf);
    defer allocator.free(hash_hex);

    const encoded = try std.fmt.allocPrint(
        allocator,
        "$argon2id$v=19$m={d},t={d},p={d}${s}${s}",
        .{
            config.memory_cost,
            config.time_cost,
            config.parallelism,
            salt_hex,
            hash_hex,
        },
    );

    allocator.free(hash_buf);
    return encoded;
}

/// Verify a password against a hash
pub fn verify(
    allocator: mem.Allocator,
    password: []const u8,
    encoded_hash: []const u8,
) Error!bool {
    if (password.len == 0) return Error.InvalidPassword;

    // Parse PHC string format
    const parsed = try parsePHC(allocator, encoded_hash);
    defer {
        allocator.free(parsed.salt);
        allocator.free(parsed.hash);
    }

    // Hash password with same parameters
    const hash_buf = try allocator.alloc(u8, parsed.hash.len);
    defer allocator.free(hash_buf);

    try crypto.pwhash.argon2.kdf(
        allocator,
        hash_buf,
        password,
        parsed.salt,
        .{
            .t = parsed.time_cost,
            .m = parsed.memory_cost,
            .p = parsed.parallelism,
        },
        .argon2id,
    );

    // Constant-time comparison to prevent timing attacks
    if (hash_buf.len != parsed.hash.len) return false;

    var diff: u8 = 0;
    for (hash_buf, parsed.hash) |a, b| {
        diff |= a ^ b;
    }
    return diff == 0;
}

/// Parsed PHC hash components
const ParsedHash = struct {
    memory_cost: u32,
    time_cost: u32,
    parallelism: u24,
    salt: []u8,
    hash: []u8,
};

/// Encode bytes to hex string (lowercase)
fn toHex(allocator: mem.Allocator, bytes: []const u8) Error![]u8 {
    const hex_chars = "0123456789abcdef";
    const result = try allocator.alloc(u8, bytes.len * 2);
    for (bytes, 0..) |byte, i| {
        result[i * 2] = hex_chars[byte >> 4];
        result[i * 2 + 1] = hex_chars[byte & 0x0F];
    }
    return result;
}

/// Parse PHC string format
fn parsePHC(allocator: mem.Allocator, encoded: []const u8) Error!ParsedHash {
    // Expected format: $argon2id$v=19$m=65536,t=3,p=4$salt$hash
    var parts = mem.splitSequence(u8, encoded, "$");

    // Skip empty first part
    _ = parts.next() orelse return Error.InvalidHash;

    // Algorithm
    const algo = parts.next() orelse return Error.InvalidHash;
    if (!mem.eql(u8, algo, "argon2id")) return Error.InvalidHash;

    // Version
    const version = parts.next() orelse return Error.InvalidHash;
    if (!mem.eql(u8, version, "v=19")) return Error.InvalidHash;

    // Parameters (m=65536,t=3,p=4)
    const params_str = parts.next() orelse return Error.InvalidHash;
    var params = mem.splitSequence(u8, params_str, ",");

    var memory_cost: u32 = 0;
    var time_cost: u32 = 0;
    var parallelism: u24 = 0;

    while (params.next()) |param| {
        var kv = mem.splitSequence(u8, param, "=");
        const key = kv.next() orelse continue;
        const value = kv.next() orelse continue;

        if (mem.eql(u8, key, "m")) {
            memory_cost = try std.fmt.parseInt(u32, value, 10);
        } else if (mem.eql(u8, key, "t")) {
            time_cost = try std.fmt.parseInt(u32, value, 10);
        } else if (mem.eql(u8, key, "p")) {
            parallelism = try std.fmt.parseInt(u24, value, 10);
        }
    }

    // Salt
    const salt_hex = parts.next() orelse return Error.InvalidHash;
    const salt = try allocator.alloc(u8, salt_hex.len / 2);
    errdefer allocator.free(salt);
    _ = try std.fmt.hexToBytes(salt, salt_hex);

    // Hash
    const hash_hex = parts.next() orelse return Error.InvalidHash;
    const hash_buf = try allocator.alloc(u8, hash_hex.len / 2);
    errdefer allocator.free(hash_buf);
    _ = try std.fmt.hexToBytes(hash_buf, hash_hex);

    return ParsedHash{
        .memory_cost = memory_cost,
        .time_cost = time_cost,
        .parallelism = parallelism,
        .salt = salt,
        .hash = hash_buf,
    };
}

/// Quick hash function for testing (less secure, faster)
pub fn hashFast(
    allocator: mem.Allocator,
    password: []const u8,
) Error![]const u8 {
    return hash(allocator, password, .{
        .time_cost = 1,
        .memory_cost = 8192, // 8 MiB
        .parallelism = 1,
    });
}

test "password hash and verify" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const password = "my_secure_password_123!";
    const hashed = try hashFast(allocator, password);
    defer allocator.free(hashed);

    // Verify correct password
    const valid = try verify(allocator, password, hashed);
    try testing.expect(valid);

    // Verify incorrect password
    const invalid = try verify(allocator, "wrong_password", hashed);
    try testing.expect(!invalid);
}

test "password hash format" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const password = "test123";
    const hashed = try hashFast(allocator, password);
    defer allocator.free(hashed);

    // Check PHC format
    try testing.expect(mem.startsWith(u8, hashed, "$argon2id$v=19$"));
    try testing.expect(mem.indexOf(u8, hashed, "$") != null);
}

test "empty password rejected" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const result = hash(allocator, "", default_config);
    try testing.expectError(Error.InvalidPassword, result);
}

test "timing safe comparison" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const password1 = "password123";
    const password2 = "password123";
    const password3 = "different_password";

    const hash1 = try hashFast(allocator, password1);
    defer allocator.free(hash1);

    // Same password should verify
    try testing.expect(try verify(allocator, password2, hash1));

    // Different password should not verify
    try testing.expect(!try verify(allocator, password3, hash1));
}
