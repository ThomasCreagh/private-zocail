const std = @import("std");
const crypto = @import("crypto.zig");
const social = @import("mastadon.zig");
const base32 = @import("base32.zig").standard;
const json = std.json;
const indexOf = std.mem.indexOf;
const Allocator = std.mem.Allocator;

// === Request JSON parsing ===

pub const UserToken = struct {
    access_token: []u8,
};

pub const Message = struct {
    id: usize,
    account: User,
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
    pub fn getPublicKey(self: *@This(), decoded_buf: *[crypto.X25519.public_length]u8) !void {
        const eom = indexOf(u8, self.note, "</p>") orelse unreachable;
        try base32.Decoder.decode(decoded_buf, self.note[3..eom]);
    }
};

// === Message Types ===

pub const MessageLabel = enum {
    dm_message,
    dm_invite,
    group_message,
    group_invite,
};

pub const DmMessage = struct {
    base: BaseMethods(DmMessage) = .{},

    pub const Encrypted = struct {
        tag: [crypto.Aes128Ocb.tag_length]u8 = undefined,
        nonce: [crypto.Aes128Ocb.nonce_length]u8 = undefined,
        encrypted: ?[]u8 = null,
    };
    pub const Secret = struct {
        label: MessageLabel = .dm_message,
        message: []const u8,
    };
};

pub const DmInvite = struct {
    base: BaseMethods(DmInvite) = .{},

    pub const Encrypted = struct {
        tag: [crypto.Aes128Ocb.tag_length]u8 = undefined,
        nonce: [crypto.Aes128Ocb.nonce_length]u8 = undefined,
        encrypted: ?[]u8 = null,
        ephemeral_key: [crypto.X25519.public_length]u8,
        id: crypto.UUID = undefined,
    };
    pub const Secret = struct {
        label: MessageLabel = .dm_invite,
    };
};

pub const GroupMessage = struct {
    base: BaseMethods(GroupMessage) = .{},

    pub const Encrypted = struct {
        tag: [crypto.Aes128Ocb.tag_length]u8 = undefined,
        nonce: [crypto.Aes128Ocb.nonce_length]u8 = undefined,
        encrypted: ?[]u8 = null,
    };
    pub const Secret = struct {
        label: MessageLabel = .group_message,
        message: []const u8,
    };
};

pub const GroupInvite = struct {
    base: BaseMethods(GroupInvite) = .{},

    pub const Encrypted = struct {
        tag: [crypto.Aes128Ocb.tag_length]u8 = undefined,
        nonce: [crypto.Aes128Ocb.nonce_length]u8 = undefined,
        encrypted: ?[]u8 = null,
    };
    pub const Secret = struct {
        label: MessageLabel = .group_invite,
        key: crypto.AesKey,
        id: crypto.UUID,
        name: []const u8,
    };
};

pub fn BaseMethods(comptime T: type) type {
    return struct {
        parsed_encrypted: ?json.Parsed(T.Encrypted) = null,
        parsed_secret: ?json.Parsed(T.Secret) = null,
        encrypted: ?T.Encrypted = null,
        secret: ?T.Secret = null,
        json_enc_secret: ?std.io.Writer.Allocating = null,
        json_encrypted: ?std.io.Writer.Allocating = null,
        json_dec_secret: ?[]u8 = null,
        free_encrypt: bool = false,

        pub fn fromEncryptedAndSecret(allocator: Allocator, given_encrypted: T.Encrypted, given_secret: T.Secret) !T {
            var self = T{};
            self.base.secret = given_secret;
            self.base.encrypted = given_encrypted;
            const secret = self.base.secret.?;

            crypto.random.bytes(&self.base.encrypted.?.nonce);

            self.base.json_enc_secret = std.io.Writer.Allocating.init(allocator);

            try self.base.json_enc_secret.?.writer.print("{f}", .{std.json.fmt(secret, .{})});
            return self;
        }
        pub fn fromBase32(allocator: Allocator, str: []const u8) !T {
            const decode_len = try base32.Decoder.calcSize(str);

            const json_buf = try allocator.alloc(u8, decode_len);
            defer allocator.free(json_buf);

            try base32.Decoder.decode(json_buf, str);

            var self = T{};

            self.base.parsed_encrypted = try json.parseFromSlice(T.Encrypted, allocator, json_buf, .{ .ignore_unknown_fields = true });
            self.base.encrypted = self.base.parsed_encrypted.?.value;
            return self;
        }
        pub fn toBase32(m: *@This(), buf: []u8) ![]const u8 {
            const self: *T = @alignCast(@fieldParentPtr("base", m));
            const serialized_str = self.base.json_encrypted.?.written();

            return base32.Encoder.encode(buf, serialized_str);
        }
        pub fn encrypt(m: *@This(), allocator: Allocator, aes_key: crypto.AesKey) !void {
            const self: *T = @alignCast(@fieldParentPtr("base", m));
            const secret_str: []u8 = self.base.json_enc_secret.?.written();
            self.base.encrypted.?.encrypted = try allocator.alloc(u8, secret_str.len);
            self.base.free_encrypt = true;
            const enc = &self.base.encrypted.?;

            crypto.aesEncrypt(
                enc.encrypted.?,
                &enc.tag,
                secret_str,
                &enc.nonce,
                aes_key,
            );

            self.base.json_encrypted = .init(allocator);

            try self.base.json_encrypted.?.writer.print("{f}", .{std.json.fmt(enc, .{})});
        }
        pub fn decrypt(m: *@This(), allocator: Allocator, aes_key: crypto.AesKey) !void {
            const self: *T = @alignCast(@fieldParentPtr("base", m));
            const enc = &self.base.encrypted.?;
            self.base.json_dec_secret = try allocator.alloc(u8, enc.encrypted.?.len);

            crypto.aesDecrypt(
                self.base.json_dec_secret.?,
                enc.encrypted.?,
                enc.tag,
                enc.nonce,
                aes_key,
            ) catch |err| {
                std.debug.print("BaseMethods: couldnt decrypt {}\n", .{err});
                return error.CouldNotDecryptAES;
            };

            self.base.parsed_secret = try json.parseFromSlice(T.Secret, allocator, self.base.json_dec_secret.?, .{});
            self.base.secret = self.base.parsed_secret.?.value;
        }
        pub fn deinit(m: *@This(), allocator: Allocator) void {
            const self: *T = @alignCast(@fieldParentPtr("base", m));
            if (self.base.free_encrypt == true) allocator.free(self.base.encrypted.?.encrypted.?);
            if (self.base.json_dec_secret) |jds| allocator.free(jds);
            if (self.base.json_enc_secret) |*js| js.deinit();
            if (self.base.json_encrypted) |*je| je.deinit();
            if (self.base.parsed_encrypted) |*pe| pe.deinit();
            if (self.base.parsed_secret) |*ps| ps.deinit();
        }
    };
}
