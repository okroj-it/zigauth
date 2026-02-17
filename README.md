# ZigAuth

**Production-ready authentication & authorization framework for Zig**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Zig](https://img.shields.io/badge/Zig-0.15.2-orange.svg)](https://ziglang.org/)

## 🚀 Status

**Current Version**: v0.1.0-dev
**Phase**: Foundation - Password Hashing ✅

## 🎯 What is ZigAuth?

ZigAuth is the first comprehensive authentication and authorization framework for Zig. It fills the #1 gap in the Zig ecosystem by providing:

- 🔐 **Password Hashing**: Argon2id with OWASP-recommended settings
- 🎫 **JWT Tokens**: Access + refresh with rotation (Coming soon)
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
const std = @import("std");
const zigauth = @import("zigauth");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Hash a password
    const password = "my_secure_password";
    const hashed = try zigauth.auth.password.hash(
        allocator,
        password,
        zigauth.auth.password.default_config,
    );
    defer allocator.free(hashed);

    std.debug.print("Hashed: {s}\n", .{hashed});

    // Verify password
    const valid = try zigauth.auth.password.verify(
        allocator,
        password,
        hashed,
    );

    std.debug.print("Valid: {}\n", .{valid});
}
```

## ✅ Completed Features

- [x] Project structure created
- [x] Password hashing implemented (Argon2id)
- [x] PHC string format encoding/decoding
- [x] Timing-safe password verification
- [x] Comprehensive test suite (11 tests)
- [x] Fast hashing for testing

## 🧪 Testing

```bash
cd zigauth
zig build test
```

## 🗺️ Roadmap

### Phase 1: Foundation
- ✅ Password hashing
- 🚧 JWT + Sessions
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
