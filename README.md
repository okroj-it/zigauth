# ZigAuth

**Production-ready authentication & authorization framework for Zig**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Zig](https://img.shields.io/badge/Zig-0.15.2-orange.svg)](https://ziglang.org/)

## 🚀 Status

**Current Version**: v0.2.0-dev
**Phase**: Foundation - Password Hashing ✅ | JWT Tokens ✅ | Sessions ✅ | RBAC ✅

## 🎯 What is ZigAuth?

ZigAuth is the first comprehensive authentication and authorization framework for Zig. It fills the #1 gap in the Zig ecosystem by providing:

- 🔐 **Password Hashing**: Argon2id with OWASP-recommended settings ✅
- 🎫 **JWT Tokens**: HMAC-SHA256 signing, verification, refresh tokens ✅
- 📝 **Sessions**: Memory storage with cookie support, thread-safe operations ✅
- 👥 **RBAC**: Role-Based Access Control with permission wildcards ✅
- 🔌 **Framework Adapters**: Zigzap, http.zig, Jetzig, Tokamak (Planned)

## 📦 Installation

Add to your `build.zig.zon`:

```zig
.dependencies = .{
    .zigauth = .{
        .url = "https://github.com/okroj-it/zigauth/archive/v0.1.0.tar.gz",
        .hash = "...",
    },
},
```

## 🔥 Quick Start

### Password Hashing

```zig
const zigauth = @import("zigauth");

// Hash a password
const hashed = try zigauth.auth.password.hash(
    allocator,
    "my_secure_password",
    zigauth.auth.password.default_config,
);
defer allocator.free(hashed);

// Verify password
const valid = try zigauth.auth.password.verify(
    allocator,
    "my_secure_password",
    hashed,
);
```

### JWT Tokens

```zig
const zigauth = @import("zigauth");
const jwt = zigauth.auth.jwt;

// Create claims
const claims = jwt.Claims{
    .sub = "user_12345",
    .exp = std.time.timestamp() + 3600, // 1 hour
    .iat = std.time.timestamp(),
};

// Sign token
const token = try jwt.sign(allocator, claims, secret, .hs256);
defer token.deinit(allocator);

// Verify token
const verified = try jwt.verify(allocator, token.raw, secret);
defer jwt.freeClaims(allocator, verified);

// Generate refresh token
const refresh = try jwt.generateRefreshToken(allocator);
defer allocator.free(refresh);
```

### Sessions

```zig
const zigauth = @import("zigauth");

// Initialize session store
var store = zigauth.storage.memory.MemoryStore.init(allocator);
defer store.deinit();

const store_interface = store.store();

// Create session
const session = try store_interface.create(allocator, "user_12345", 3600 * 24);
defer {
    var s = session;
    s.deinit(allocator);
}

// Build Set-Cookie header
const config = zigauth.auth.session.Config{};
const cookie = zigauth.auth.session.Cookie.fromSession(session.id, config, 3600 * 24);
const header = try cookie.toString(allocator);
defer allocator.free(header);

// Verify session is valid
if (session.isValid()) {
    // Session not expired
}

// Get session by ID
const retrieved = try store_interface.get(allocator, session.id);
defer {
    var s = retrieved;
    s.deinit(allocator);
}

// Update last accessed time
session.touch();
try store_interface.update(session);

// Destroy session
try store_interface.destroy(session.id);
```

### RBAC (Role-Based Access Control)

```zig
const zigauth = @import("zigauth");

// Initialize RBAC manager
var rbac = zigauth.authz.rbac.RBAC.init(allocator);
defer rbac.deinit();

// Define roles with permissions
const editor = zigauth.authz.rbac.Role{
    .name = "editor",
    .permissions = &[_][]const u8{ "posts:*", "comments:delete" }, // Wildcard support
};

const admin = zigauth.authz.rbac.Role{
    .name = "admin",
    .permissions = &[_][]const u8{"*"}, // Full access
};

try rbac.defineRole(editor);
try rbac.defineRole(admin);

// Assign roles to users
try rbac.assignRole("user_123", "editor");

// Check permissions
if (rbac.userHasPermission("user_123", "posts:write")) {
    // User has permission
}

// Check multiple permissions
const required = [_][]const u8{ "posts:read", "posts:write" };
if (rbac.userHasAllPermissions("user_123", &required)) {
    // User has all required permissions
}
```

## ✅ Completed Features

**Password Hashing**:
- [x] Argon2id with OWASP settings
- [x] PHC format encoding/decoding
- [x] Timing-safe verification
- [x] Fast mode for testing

**JWT Tokens**:
- [x] HMAC-SHA256 signing
- [x] Token verification
- [x] Claims validation (exp, iat)
- [x] Refresh token generation
- [x] Base64url encoding

**Sessions**:
- [x] Thread-safe in-memory storage
- [x] Session creation, retrieval, update, destroy
- [x] Cookie building with SameSite support
- [x] Session expiration and validation
- [x] Automatic cleanup of expired sessions
- [x] Cookie parsing from headers

**RBAC (Role-Based Access Control)**:
- [x] Permission wildcards (`*`, `resource:*`)
- [x] Role definitions with permission sets
- [x] User-role assignments (multiple roles per user)
- [x] Permission checking (single, any, all)
- [x] Memory-safe role management
- [x] Permission parsing (`resource:action`)

**Testing**:
- [x] 61 comprehensive tests passing
- [x] No memory leaks
- [x] Zero external dependencies

## 🧪 Testing & Examples

```bash
# Run all tests
zig build test

# Run examples
zig build example-password
zig build example-jwt
zig build example-session
zig build example-rbac
zig build example  # Run all examples
```

## 🗺️ Roadmap

### Phase 1: Foundation
- ✅ Password hashing
- ✅ JWT tokens
- ✅ Sessions
- ✅ RBAC
- 🚧 Zigzap adapter

### Phase 2: Advanced Auth
- OAuth2 & MFA support
- PBAC & ABAC authorization
- CSRF protection & rate limiting

### Phase 3: Framework Integrations
- http.zig, Jetzig, Tokamak adapters
- PostgreSQL & SQLite storage

### Phase 4: Production Ready
- Complete documentation
- Performance benchmarks
- Security audit

## 🤝 Contributing

ZigAuth is MIT licensed and open to contributions.

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

---

**Built with ⚡ by the Zig community**
