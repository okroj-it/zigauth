const std = @import("std");

// TODO: Session management implementation (Week 2)
// This module will handle session creation, validation, and storage

pub const Session = struct {
    id: []const u8,
    user_id: []const u8,
    expires_at: i64,
    created_at: i64,
};

pub const Error = error{
    SessionNotFound,
    SessionExpired,
    InvalidSession,
};
