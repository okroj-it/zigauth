const std = @import("std");

// TODO: JWT implementation (Week 2)
// This module will handle JWT signing and verification

pub const Claims = struct {
    sub: []const u8,
    exp: i64,
    iat: i64,
};

pub const Error = error{
    InvalidToken,
    TokenExpired,
    SignatureMismatch,
};
