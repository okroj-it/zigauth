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

    try stdout.writeAll("=== ZigAuth RBAC Example ===\n\n");

    // Initialize RBAC manager
    var rbac = zigauth.authz.rbac.RBAC.init(allocator);
    defer rbac.deinit();

    try stdout.writeAll("1. Defining roles...\n");

    // Define user role
    const user_role = zigauth.authz.rbac.Role{
        .name = "user",
        .permissions = &[_][]const u8{
            "posts:read",
            "profile:edit",
            "comments:create",
        },
        .description = "Basic user role",
    };

    // Define editor role
    const editor_role = zigauth.authz.rbac.Role{
        .name = "editor",
        .permissions = &[_][]const u8{
            "posts:*", // Wildcard: all post actions
            "comments:delete",
        },
        .description = "Content editor role",
    };

    // Define admin role
    const admin_role = zigauth.authz.rbac.Role{
        .name = "admin",
        .permissions = &[_][]const u8{"*"}, // Full wildcard: all permissions
        .description = "Administrator role",
    };

    try rbac.defineRole(user_role);
    try rbac.defineRole(editor_role);
    try rbac.defineRole(admin_role);

    try stdout.writeAll("   ✅ Defined roles: user, editor, admin\n\n");

    try stdout.writeAll("2. Assigning roles to users...\n");

    try rbac.assignRole("alice", "user");
    try rbac.assignRole("bob", "editor");
    try rbac.assignRole("charlie", "admin");

    // Bob has both user and editor roles
    try rbac.assignRole("bob", "user");

    try stdout.writeAll("   ✅ alice: user\n");
    try stdout.writeAll("   ✅ bob: user, editor\n");
    try stdout.writeAll("   ✅ charlie: admin\n\n");

    try stdout.writeAll("3. Checking permissions...\n\n");

    // Alice (user) permissions
    try stdout.writeAll("   Alice (user):\n");
    try stdout.print("   - Can read posts? {}\n", .{rbac.userHasPermission("alice", "posts:read")});
    try stdout.print("   - Can write posts? {}\n", .{rbac.userHasPermission("alice", "posts:write")});
    try stdout.print("   - Can edit profile? {}\n", .{rbac.userHasPermission("alice", "profile:edit")});
    try stdout.print("   - Can delete users? {}\n\n", .{rbac.userHasPermission("alice", "users:delete")});

    // Bob (user + editor) permissions
    try stdout.writeAll("   Bob (user + editor):\n");
    try stdout.print("   - Can read posts? {}\n", .{rbac.userHasPermission("bob", "posts:read")});
    try stdout.print("   - Can write posts? {}\n", .{rbac.userHasPermission("bob", "posts:write")});
    try stdout.print("   - Can delete posts? {}\n", .{rbac.userHasPermission("bob", "posts:delete")});
    try stdout.print("   - Can delete comments? {}\n\n", .{rbac.userHasPermission("bob", "comments:delete")});

    // Charlie (admin) permissions
    try stdout.writeAll("   Charlie (admin):\n");
    try stdout.print("   - Can read posts? {}\n", .{rbac.userHasPermission("charlie", "posts:read")});
    try stdout.print("   - Can delete users? {}\n", .{rbac.userHasPermission("charlie", "users:delete")});
    try stdout.print("   - Can do anything? {}\n\n", .{rbac.userHasPermission("charlie", "anything:anything")});

    try stdout.writeAll("4. Checking multiple permissions...\n\n");

    const read_write = [_][]const u8{ "posts:read", "posts:write" };

    try stdout.print("   Alice has ANY of (posts:read, posts:write)? {}\n", .{
        rbac.userHasAnyPermission("alice", &read_write),
    });
    try stdout.print("   Alice has ALL of (posts:read, posts:write)? {}\n", .{
        rbac.userHasAllPermissions("alice", &read_write),
    });

    try stdout.print("   Bob has ANY of (posts:read, posts:write)? {}\n", .{
        rbac.userHasAnyPermission("bob", &read_write),
    });
    try stdout.print("   Bob has ALL of (posts:read, posts:write)? {}\n\n", .{
        rbac.userHasAllPermissions("bob", &read_write),
    });

    try stdout.writeAll("5. Permission wildcards demonstration...\n\n");

    try stdout.writeAll("   Editor role has 'posts:*' wildcard:\n");
    const editor = rbac.getRole("editor").?;
    try stdout.print("   - posts:read? {}\n", .{editor.hasPermission("posts:read")});
    try stdout.print("   - posts:write? {}\n", .{editor.hasPermission("posts:write")});
    try stdout.print("   - posts:delete? {}\n", .{editor.hasPermission("posts:delete")});
    try stdout.print("   - users:read? {}\n\n", .{editor.hasPermission("users:read")});

    try stdout.writeAll("   Admin role has '*' wildcard:\n");
    const admin = rbac.getRole("admin").?;
    try stdout.print("   - Matches any permission: {}\n\n", .{
        admin.hasPermission("any:thing"),
    });

    try stdout.writeAll("6. Removing roles...\n");

    try rbac.removeRole("bob", "user");
    const bob_roles_after = rbac.getUserRoles("bob").?;
    try stdout.print("   Bob now has {} role(s): {s}\n\n", .{
        bob_roles_after.len,
        bob_roles_after[0],
    });

    try stdout.writeAll("7. Permission parsing...\n");

    const perm = zigauth.authz.permissions.Permission.parse("users:read").?;
    try stdout.print("   Parsed 'users:read':\n", .{});
    try stdout.print("   - Resource: {s}\n", .{perm.resource});
    try stdout.print("   - Action: {s}\n\n", .{perm.action});

    try stdout.writeAll("=== RBAC Demo Complete! ===\n");
}
