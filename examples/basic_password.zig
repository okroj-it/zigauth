const std = @import("std");
const zigauth = @import("zigauth");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer {
        const status = gpa.deinit();
        if (status == .leak) @panic("Memory leak detected!");
    }
    const allocator = gpa.allocator();

    const password = "my_secure_password_123!";
    std.debug.print("Original password: {s}\n", .{password});

    std.debug.print("\nHashing password (this may take a moment)...\n", .{});
    const hashed = try zigauth.auth.password.hash(
        allocator,
        password,
        zigauth.auth.password.default_config,
    );
    defer allocator.free(hashed);

    std.debug.print("Hashed: {s}\n", .{hashed});

    std.debug.print("\nVerifying correct password...\n", .{});
    const valid = try zigauth.auth.password.verify(allocator, password, hashed);
    std.debug.print("Valid: {}\n", .{valid});

    std.debug.print("\nVerifying incorrect password...\n", .{});
    const wrong_password = "wrong_password";
    const invalid = try zigauth.auth.password.verify(allocator, wrong_password, hashed);
    std.debug.print("Valid: {}\n", .{invalid});

    std.debug.print("\n--- Fast hashing (for testing) ---\n", .{});
    const fast_hashed = try zigauth.auth.password.hashFast(allocator, password);
    defer allocator.free(fast_hashed);
    std.debug.print("Fast hashed: {s}\n", .{fast_hashed});

    const fast_valid = try zigauth.auth.password.verify(allocator, password, fast_hashed);
    std.debug.print("Fast verify: {}\n", .{fast_valid});

    std.debug.print("\n✅ Password hashing MVP complete!\n", .{});
}
