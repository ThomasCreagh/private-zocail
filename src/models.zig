const std = @import("std");
const crypto = @import("crypto.zig");
const social = @import("mastadon.zig");
const indexOf = std.mem.indexOf;
const Allocator = std.mem.Allocator;

// === Request JSON parsing ===

pub const UserToken = struct {
    access_token: []u8,
};

pub const Message = struct {
    id: usize,
    created_at: []u8,
    content: []u8,
    pub fn getContent(self: *@This()) []const u8 {
        const eom = indexOf(u8, self.content, "</p>") orelse unreachable;
        return self.content[3..eom];
    }
};

pub const User = struct {
    id: usize,
    username: []u8,
    created_at: []u8,
    note: []u8,
    pub fn getPublicKey(self: *@This()) []const u8 {
        const eom = indexOf(u8, self.note, "</p>") orelse unreachable;
        return self.note[3..eom];
    }
};

// === Message Types ===

pub const MessageLabel = enum {
    dm_message,
    dm_invite,
    group_message,
    group_invite,
    group_members,
    group_admins,
};

pub const DmMessage = struct {
    pub const Encrypted = struct {
        nonce: [crypto.Aes128Ocb.nonce_length]u8,
        tag: [crypto.Aes128Ocb.tag_length]u8,
        encrypted: []u8,
    };

    pub const Decrypted = struct {
        nonce: [crypto.Aes128Ocb.nonce_length]u8,
        tag: [crypto.Aes128Ocb.tag_length]u8,
        decrypted: Secret,
    };

    pub const Secret = struct {
        label: MessageLabel = .dm_message,
        message: []const u8,
    };
};

pub const DmInvite = struct {
    pub const Encrypted = struct {
        ephemeral_key: [crypto.X25519.public_length]u8,
        tag: [crypto.Aes128Ocb.tag_length]u8,
        nonce: [crypto.Aes128Ocb.nonce_length]u8,
        id: crypto.UUID = undefined,
        encrypted: []u8,
    };

    pub const Decrypted = struct {
        ephemeral_key: [crypto.X25519.public_length]u8,
        tag: [crypto.Aes128Ocb.tag_length]u8,
        nonce: [crypto.Aes128Ocb.nonce_length]u8,
        id: crypto.UUID = undefined,
        decrypted: Secret,
    };

    pub const Secret = struct {
        label: MessageLabel = .dm_invite,
    };
};

pub const GroupMessage = struct {
    pub const Encrypted = struct {
        label: MessageLabel = .group_message,
        encrypted: []u8,
    };

    pub const Decrypted = struct {
        label: MessageLabel = .group_message,
        decrypted: Secret,
    };

    pub const Secret = struct {
        message: []const u8,
    };
};

pub const GroupInvite = struct {
    pub const Encrypted = struct {
        encrypted: []u8,
    };

    pub const Decrypted = struct {
        decrypted: Secret,
    };

    pub const Secret = struct {
        label: MessageLabel = .group_invite,
        key: crypto.AesKey,
    };
};

pub const GroupMembers = struct {
    pub const Encrypted = struct {
        signature: crypto.Ed25519.Signature,
        encrypted: []u8,
    };

    pub const Decrypted = struct {
        signature: crypto.Ed25519.Signature,
        decrypted: Secret,
    };

    pub const Secret = struct {
        label: MessageLabel = .group_members,
        members: []const social.Username,
    };
};

pub const GroupAdmins = struct {
    pub const Encrypted = struct {
        signature: crypto.Ed25519.Signature,
        encrypted: []u8,
    };

    pub const Decrypted = struct {
        signature: crypto.Ed25519.Signature,
        decrypted: Secret,
    };

    pub const Secret = struct {
        label: MessageLabel = .group_admins,
        admins: []const social.Username,
    };
};
