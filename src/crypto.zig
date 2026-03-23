//! This module provides the cryptographic functions in the protocol

const std = @import("std");
const crypto = std.crypto;
pub const random = std.crypto.random;
const Allocator = std.mem.Allocator;
pub const Aes128Ocb = crypto.aead.aes_ocb.Aes128Ocb;
pub const X25519 = crypto.dh.X25519;
pub const HkdfSha256 = crypto.kdf.hkdf.HkdfSha256;
pub const Ed25519 = crypto.sign.Ed25519;

pub const base64 = std.base64.url_safe;

pub const UUID = struct {
    pub const UUID_LENGTH: usize = 16;
    pub const STR_LENGTH: usize = base64.Encoder.calcSize(UUID_LENGTH);
    /// Raw key bytes
    key: [UUID_LENGTH]u8 = undefined,
    /// Base64 reprsentation of the key
    str: [STR_LENGTH]u8 = undefined,

    pub fn init() @This() {
        var uuid: UUID = undefined;
        random.bytes(&uuid.key);

        var buf: [STR_LENGTH]u8 = undefined;
        const encoded = base64.Encoder.encode(&buf, &uuid.key);
        @memcpy(&uuid.str, encoded);

        return uuid;
    }
    /// Create UUID from raw key bytes
    pub fn fromKey(key: [UUID_LENGTH]u8) @This() {
        var uuid: UUID = undefined;
        uuid.key = key;

        var buf: [STR_LENGTH]u8 = undefined;
        const encoded = base64.Encoder.encode(&buf, &uuid.key);
        @memcpy(&uuid.str, encoded);

        return uuid;
    }
    /// Create UUID from key base64 string
    pub fn fromStr(str: [STR_LENGTH]u8) !@This() {
        var uuid: UUID = undefined;
        uuid.str = str;

        var buf: [UUID_LENGTH]u8 = undefined;
        const decoded = try base64.Decoder.decode(&buf, &uuid.str);
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
pub fn getEphemeralKeyPair() X25519.KeyPair {
    return X25519.KeyPair.generate();
}

/// Translates Ed25519 public key to be used in X25519 key exchange
pub fn getRecieversPublicKeyFromEd25519(public_key: Ed25519.PublicKey) ![X25519.public_length]u8 {
    return X25519.publicKeyFromEd25519(public_key);
}

/// Deerive X25519 KeyPair from Ed25519 KeyPair
pub fn deriveX25519KeyPair(key_pair: Ed25519.KeyPair) !X25519.KeyPair {
    return try X25519.KeyPair.fromEd25519(key_pair);
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

// === Signatures ===

/// Generate long term keypair for key exchange and signing
pub fn generateSigningKeyPair() Ed25519.KeyPair {
    return Ed25519.KeyPair.generate();
}

pub fn signMessage(key_pair: Ed25519.KeyPair, msg: []const u8) !Ed25519.Signature {
    var noise: [Ed25519.noise_length]u8 = undefined;
    random.bytes(&noise);
    return try key_pair.sign(msg, noise);
}

pub fn verifyMessage(
    sig: Ed25519.Signature,
    msg: []const u8,
    public_key: Ed25519.PublicKey,
) Ed25519.Signature.VerifyError!void {
    try sig.verify(msg, public_key);
}
