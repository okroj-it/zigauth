# Framework Integration Examples

This directory contains working example applications demonstrating ZigAuth integration with popular Zig web frameworks.

**Note**: These are **standalone examples**, not part of the ZigAuth library build. To run them, you must add the framework dependencies to your own project.

## Available Examples

### ✅ Core Examples (No Framework Required)
These examples demonstrate ZigAuth core features and can be run directly:
- `basic_password.zig` - Password hashing with Argon2id
- `basic_jwt.zig` - JWT token generation and verification
- `basic_session.zig` - Session management with in-memory storage
- `basic_rbac.zig` - Role-based access control

Run with: `zig build example`

### 🌐 Framework Integration Examples

#### Zigzap (`zigzap_app.zig`)
**Full web server with session auth, RBAC, and cookie management**

To run this example:
1. Add Zap to your `build.zig.zon`:
```zig
.dependencies = .{
    .zigauth = .{
        .url = "https://github.com/okroj-it/zigauth/archive/main.tar.gz",
        .hash = "...",
    },
    .zap = .{
        .url = "https://github.com/zigzap/zap/archive/refs/tags/v0.11.0.tar.gz",
        .hash = "12204b8288998d664c313e53b2867938ed8465eea3db84535181077b479ff495b776",
    },
},
```

2. Copy `zigzap_app.zig` to your project
3. Add build target in your `build.zig`:
```zig
const zap_dep = b.dependency("zap", .{ .target = target, .optimize = optimize });
const zap_mod = zap_dep.module("zap");

const exe = b.addExecutable(.{
    .name = "myapp",
    .root_module = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "zigauth", .module = zigauth_mod },
            .{ .name = "zap", .module = zap_mod },
        },
    }),
});
```

4. Run: `zig build run`

**Features demonstrated:**
- Session authentication middleware
- RBAC authorization middleware
- Cookie management
- Login/logout flows
- Protected routes
- Admin panel with role checks

#### http.zig (`httpz_app.zig`)
**Lightweight HTTP server with authentication**

To run this example:
1. Add http.zig to your `build.zig.zon`:
```zig
.dependencies = .{
    .zigauth = .{
        .url = "https://github.com/okroj-it/zigauth/archive/main.tar.gz",
        .hash = "...",
    },
    .httpz = .{
        .url = "git+https://github.com/karlseguin/http.zig?ref=master#ddaf1989f9c5fe1b139fa846ad273efd4368083a",
        .hash = "httpz-0.0.0-PNVzrN40BwD3lGAE8l_pShvVIGSlWglmFOsdhJnMVcXR",
    },
},
```

2. Copy `httpz_app.zig` to your project
3. Add build target (similar to Zigzap above)
4. Run: `zig build run`

**Features demonstrated:**
- Session validation helpers
- User authentication
- RBAC permission checks
- JSON responses
- Logout functionality

### 📝 Documentation-Only Examples

#### Jetzig (`jetzig_usage.md`)
Full-featured MVC framework with file-based routing. See the usage guide for integration patterns.

**Why documentation-only?** Jetzig has 8 dependencies and requires a specific project structure. Users should initialize projects with `jetzig init`.

#### Tokamak (`tokamak_usage.md`)
Modern web framework with dependency injection. See the usage guide for integration patterns.

## Adapter Code

All framework adapters are available in `src/adapters/`:
- `src/adapters/zigzap.zig` - Middleware for Zigzap
- `src/adapters/httpz.zig` - Helpers for http.zig
- `src/adapters/jetzig.zig` - Helpers for Jetzig
- `src/adapters/tokamak.zig` - Middleware for Tokamak

These adapters are part of the ZigAuth library and can be used directly:

```zig
const zigauth = @import("zigauth");

// Use framework-specific adapter
const session_config = zigauth.adapters.zigzap.SessionConfig{
    .store = &session_store,
    .required = true,
};
```

## Why No Framework Dependencies in ZigAuth?

ZigAuth is a **framework-agnostic** authentication library. Users should only install the frameworks they actually use, not all of them.

**Benefits:**
- ✅ Smaller dependency tree
- ✅ Faster builds
- ✅ No unused code
- ✅ Freedom to choose your framework

**The adapters are always available** - you just need to add your chosen framework to your own `build.zig.zon`.
