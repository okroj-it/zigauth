# ZigAuth

**Production-ready authentication & authorization framework for Zig**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Zig](https://img.shields.io/badge/Zig-0.15.2-orange.svg)](https://ziglang.org/)

## 🚀 Status

**Current Version**: v0.2.0-dev
**Phase**: Foundation - Password Hashing ✅ | JWT Tokens ✅

## 🎯 What is ZigAuth?

ZigAuth is the first comprehensive authentication and authorization framework for Zig. It fills the #1 gap in the Zig ecosystem by providing:

- 🔐 **Password Hashing**: Argon2id with OWASP-recommended settings ✅
- 🎫 **JWT Tokens**: HMAC-SHA256 signing, verification, refresh tokens ✅
- 📝 **Sessions**: Memory and Redis backends (Coming soon)
- 👥 **RBAC**: Role-Based Access Control with comptime validation (Planned)
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

**Testing**:
- [x] 21 comprehensive tests passing
- [x] No memory leaks
- [x] Zero external dependencies

## 🧪 Testing & Examples

```bash
# Run all tests
zig build test

# Run examples
zig build example-password
zig build example-jwt
zig build example  # Run all examples
```

## 🗺️ Roadmap

### Phase 1: Foundation
- ✅ Password hashing
- ✅ JWT tokens
- 🚧 Sessions
- 🚧 RBAC
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
