//! This module provides the cryptographic functions in the protocol

const std = @import("std");
const base32 = @import("base32.zig").standard;

const crypto = std.crypto;
pub const random = std.crypto.random;
const Allocator = std.mem.Allocator;
pub const Aes128Ocb = crypto.aead.aes_ocb.Aes128Ocb;
pub const X25519 = crypto.dh.X25519;
pub const HkdfSha256 = crypto.kdf.hkdf.HkdfSha256;

pub const UUID = struct {
    pub const UUID_LENGTH: usize = 16;
    pub const STR_LENGTH: usize = base32.Encoder.calcSize(UUID_LENGTH);
    /// Raw key bytes
    key: [UUID_LENGTH]u8 = undefined,
    /// Base32 reprsentation of the key
    str: [STR_LENGTH]u8 = undefined,

    pub fn init() @This() {
        var uuid: UUID = undefined;
        random.bytes(&uuid.key);

        var buf: [STR_LENGTH]u8 = undefined;
        const encoded = base32.Encoder.encode(&buf, &uuid.key);
        @memcpy(&uuid.str, encoded);

        return uuid;
    }
    /// Create UUID from raw key bytes
    pub fn fromKey(key: [UUID_LENGTH]u8) @This() {
        var uuid: UUID = undefined;
        uuid.key = key;

        var buf: [STR_LENGTH]u8 = undefined;
        const encoded = base32.Encoder.encode(&buf, &uuid.key);
        @memcpy(&uuid.str, encoded);

        return uuid;
    }
    /// Create UUID from key base64 string
    pub fn fromStr(str: [STR_LENGTH]u8) !@This() {
        var uuid: UUID = undefined;
        uuid.str = str;

        var buf: [UUID_LENGTH]u8 = undefined;
        const decoded = try base32.Decoder.decode(&buf, &uuid.str);
        @memcpy(&uuid.key, decoded);

        return uuid;
    }
};

// === AES Encryption ===
pub const AesKey = [Aes128Ocb.key_length]u8;

/// Generate random AES key
pub fn generateRandomAesKey(buf: *AesKey) void {
    random.bytes(buf);
}

/// Encrypting messages with symmetric keys
pub fn aesEncrypt(
    /// Cipher Text
    c: []u8,
    tag: *[Aes128Ocb.tag_length]u8,
    /// Message
    m: []const u8,
    nonce: *[Aes128Ocb.nonce_length]u8,
    key: AesKey,
) void {
    Aes128Ocb.encrypt(c, tag, m, &[_]u8{}, nonce.*, key);
}

/// Decrypting messages with symmetric keys
pub fn aesDecrypt(
    /// Message
    m: []u8,
    /// Cipher Text
    c: []const u8,
    tag: [Aes128Ocb.tag_length]u8,
    nonce: [Aes128Ocb.nonce_length]u8,
    key: AesKey,
) !void {
    try Aes128Ocb.decrypt(m, c, tag, &[_]u8{}, nonce, key);
}

// === Key Exchange ===

/// Generate new ephemeral keypair
pub fn genKeyPair() X25519.KeyPair {
    return X25519.KeyPair.generate();
}

/// Key derivation funciton which uses Sha256 to generate a 32 bytes key
fn keyDerivationFunction(
    out: *AesKey,
    ikm: [X25519.shared_length]u8,
    nonce: [Aes128Ocb.nonce_length]u8,
    ctx: []const u8,
) void {
    const prk = HkdfSha256.extract(&nonce, &ikm);
    HkdfSha256.expand(out, ctx, prk);
}

/// Derives the X25519 secret with given keys
fn deriveKeyExchangeSecret(
    secret_key: [X25519.secret_length]u8,
    public_key: [X25519.public_length]u8,
) error{IdentityElement}![X25519.shared_length]u8 {
    return try X25519.scalarmult(secret_key, public_key);
}

/// Gernerates the AES key with given keys
pub fn deriveAesKey(
    out: *AesKey,
    secret_key: [X25519.secret_length]u8,
    public_key: [X25519.public_length]u8,
    nonce: [Aes128Ocb.nonce_length]u8,
    ctx: []const u8,
) error{IdentityElement}!void {
    const secret = try deriveKeyExchangeSecret(secret_key, public_key);
    keyDerivationFunction(out, secret, nonce, ctx);
}
