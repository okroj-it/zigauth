# ZigAuth

**Production-ready authentication & authorization framework for Zig**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Zig](https://img.shields.io/badge/Zig-0.15.2-orange.svg)](https://ziglang.org/)

## 🚀 Status

**Current Version**: v0.1.0-dev  
**Phase**: Foundation (Week 1) - Password Hashing ✅

## 🎯 What is ZigAuth?

ZigAuth is the first comprehensive authentication and authorization framework for Zig. It fills the #1 gap in the Zig ecosystem by providing:

- 🔐 **Password Hashing**: Argon2id with OWASP-recommended settings
- 🎫 **JWT Tokens**: Access + refresh with rotation (Coming Week 2)
- 📝 **Sessions**: Memory and Redis backends (Coming Week 2)
- 👥 **RBAC**: Role-Based Access Control with comptime validation (Coming Week 3)
- 🔌 **Framework Adapters**: Zigzap, http.zig, Jetzig, Tokamak (Coming Week 4)

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

## ✅ Week 1 Complete

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

### Phase 1: Foundation (4 weeks)
- ✅ **Week 1**: Password hashing
- 🚧 **Week 2**: JWT + Sessions
- 🚧 **Week 3**: RBAC
- 🚧 **Week 4**: Zigzap adapter

### Phase 2-4: Advanced Features
See [ZIGAUTH_PLAN.md](../zigumms/ZIGAUTH_PLAN.md) for full roadmap.

## 🤝 Contributing

ZigAuth is MIT licensed and open to contributions.

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

---

**Built with ⚡ by the Zig community**
