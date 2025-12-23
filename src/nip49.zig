//! NIP-49: Private Key Encryption
//!
//! This module implements NIP-49 for encrypting and decrypting Nostr private keys
//! using password-based encryption with scrypt and XChaCha20-Poly1305.
//!
//! IMPORTANT: Per NIP-49 spec, passwords MUST be normalized to NFKC Unicode format
//! before being passed to encrypt/decrypt functions. This normalization is the
//! caller's responsibility since Zig's standard library does not include NFKC
//! normalization. For ASCII-only passwords, no normalization is needed.

const std = @import("std");
const bech32 = @import("bech32.zig");

const scrypt = std.crypto.pwhash.scrypt;
const XChaCha20Poly1305 = std.crypto.aead.chacha_poly.XChaCha20Poly1305;

pub const Error = error{
    InvalidFormat,
    UnsupportedVersion,
    DecryptionFailed,
    EncryptionFailed,
    InvalidLogN,
    WeakParameters,
    OutOfMemory,
};

pub const KeySecurity = enum(u8) {
    known_insecure = 0x00,
    known_secure = 0x01,
    unknown = 0x02,
};

const VERSION: u8 = 0x02;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const KEY_LEN: usize = 32;
const TAG_LEN: usize = 16;
const PAYLOAD_LEN: usize = 1 + 1 + SALT_LEN + NONCE_LEN + 1 + KEY_LEN + TAG_LEN; // 91 bytes

pub fn encrypt(
    allocator: std.mem.Allocator,
    secret_key: *const [32]u8,
    password: []const u8,
    log_n: u8,
    key_security: KeySecurity,
    out: []u8,
) !usize {
    if (log_n < 1 or log_n > 22) return Error.InvalidLogN;
    if (out.len < 256) return bech32.Error.BufferTooSmall;

    var salt: [SALT_LEN]u8 = undefined;
    std.crypto.random.bytes(&salt);

    var nonce: [NONCE_LEN]u8 = undefined;
    std.crypto.random.bytes(&nonce);

    var symmetric_key: [KEY_LEN]u8 = undefined;
    defer @memset(&symmetric_key, 0);

    const params = scrypt.Params{ .ln = @intCast(log_n), .r = 8, .p = 1 };
    scrypt.kdf(allocator, &symmetric_key, password, &salt, params) catch |err| {
        return switch (err) {
            error.OutOfMemory => Error.OutOfMemory,
            else => Error.WeakParameters,
        };
    };

    const ad = [_]u8{@intFromEnum(key_security)};
    var ciphertext: [KEY_LEN]u8 = undefined;
    var tag: [TAG_LEN]u8 = undefined;

    XChaCha20Poly1305.encrypt(&ciphertext, &tag, secret_key, &ad, nonce, symmetric_key);

    var payload: [PAYLOAD_LEN]u8 = undefined;
    payload[0] = VERSION;
    payload[1] = log_n;
    @memcpy(payload[2 .. 2 + SALT_LEN], &salt);
    @memcpy(payload[2 + SALT_LEN .. 2 + SALT_LEN + NONCE_LEN], &nonce);
    payload[2 + SALT_LEN + NONCE_LEN] = @intFromEnum(key_security);
    @memcpy(payload[2 + SALT_LEN + NONCE_LEN + 1 .. 2 + SALT_LEN + NONCE_LEN + 1 + KEY_LEN], &ciphertext);
    @memcpy(payload[2 + SALT_LEN + NONCE_LEN + 1 + KEY_LEN ..], &tag);

    return try bech32.encode("ncryptsec", &payload, out);
}

pub fn decrypt(
    allocator: std.mem.Allocator,
    ncryptsec: []const u8,
    password: []const u8,
    secret_key_out: *[32]u8,
) !DecryptResult {
    var hrp_buf: [16]u8 = undefined;
    var payload: [128]u8 = undefined;

    const result = bech32.decode(ncryptsec, &hrp_buf, &payload) catch return Error.InvalidFormat;

    if (!std.mem.eql(u8, hrp_buf[0..result.hrp_len], "ncryptsec")) return Error.InvalidFormat;
    if (result.data_len != PAYLOAD_LEN) return Error.InvalidFormat;

    const data = payload[0..PAYLOAD_LEN];

    const version = data[0];
    if (version != VERSION) return Error.UnsupportedVersion;

    const log_n = data[1];
    if (log_n < 1 or log_n > 22) return Error.InvalidLogN;

    const salt = data[2 .. 2 + SALT_LEN];
    const nonce = data[2 + SALT_LEN .. 2 + SALT_LEN + NONCE_LEN];
    const key_security_byte = data[2 + SALT_LEN + NONCE_LEN];
    const ciphertext = data[2 + SALT_LEN + NONCE_LEN + 1 .. 2 + SALT_LEN + NONCE_LEN + 1 + KEY_LEN];
    const tag = data[2 + SALT_LEN + NONCE_LEN + 1 + KEY_LEN ..][0..TAG_LEN];

    var symmetric_key: [KEY_LEN]u8 = undefined;
    defer @memset(&symmetric_key, 0);

    const params = scrypt.Params{ .ln = @intCast(log_n), .r = 8, .p = 1 };
    scrypt.kdf(allocator, &symmetric_key, password, salt, params) catch |err| {
        return switch (err) {
            error.OutOfMemory => Error.OutOfMemory,
            else => Error.WeakParameters,
        };
    };

    const ad = [_]u8{key_security_byte};

    XChaCha20Poly1305.decrypt(secret_key_out, ciphertext, tag.*, &ad, nonce[0..NONCE_LEN].*, symmetric_key) catch {
        return Error.DecryptionFailed;
    };

    const key_security: KeySecurity = std.meta.intToEnum(KeySecurity, key_security_byte) catch .unknown;

    return .{
        .log_n = log_n,
        .key_security = key_security,
    };
}

pub const DecryptResult = struct {
    log_n: u8,
    key_security: KeySecurity,
};

test "nip49 encrypt decrypt roundtrip" {
    const allocator = std.testing.allocator;

    var secret_key: [32]u8 = undefined;
    @memset(&secret_key, 0x42);

    var encoded: [256]u8 = undefined;
    const len = try encrypt(allocator, &secret_key, "testpassword", 14, .known_secure, &encoded);

    var decrypted_key: [32]u8 = undefined;
    const result = try decrypt(allocator, encoded[0..len], "testpassword", &decrypted_key);

    try std.testing.expectEqualSlices(u8, &secret_key, &decrypted_key);
    try std.testing.expectEqual(KeySecurity.known_secure, result.key_security);
    try std.testing.expectEqual(@as(u8, 14), result.log_n);
}

test "nip49 decrypt test vector" {
    const allocator = std.testing.allocator;

    const ncryptsec = "ncryptsec1qgg9947rlpvqu76pj5ecreduf9jxhselq2nae2kghhvd5g7dgjtcxfqtd67p9m0w57lspw8gsq6yphnm8623nsl8xn9j4jdzz84zm3frztj3z7s35vpzmqf6ksu8r89qk5z2zxfmu5gv8th8wclt0h4p";

    var decrypted_key: [32]u8 = undefined;
    const result = try decrypt(allocator, ncryptsec, "nostr", &decrypted_key);

    const expected_hex = "3501454135014541350145413501453fefb02227e449e57cf4d3a3ce05378683";
    var expected: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&expected, expected_hex) catch unreachable;

    try std.testing.expectEqualSlices(u8, &expected, &decrypted_key);
    try std.testing.expectEqual(@as(u8, 16), result.log_n);
}

test "nip49 wrong password fails" {
    const allocator = std.testing.allocator;

    const ncryptsec = "ncryptsec1qgg9947rlpvqu76pj5ecreduf9jxhselq2nae2kghhvd5g7dgjtcxfqtd67p9m0w57lspw8gsq6yphnm8623nsl8xn9j4jdzz84zm3frztj3z7s35vpzmqf6ksu8r89qk5z2zxfmu5gv8th8wclt0h4p";

    var decrypted_key: [32]u8 = undefined;
    const result = decrypt(allocator, ncryptsec, "wrongpassword", &decrypted_key);

    try std.testing.expectError(Error.DecryptionFailed, result);
}

test "nip49 invalid format" {
    const allocator = std.testing.allocator;

    var decrypted_key: [32]u8 = undefined;

    try std.testing.expectError(Error.InvalidFormat, decrypt(allocator, "npub1abc", "test", &decrypted_key));
    try std.testing.expectError(Error.InvalidFormat, decrypt(allocator, "invalid", "test", &decrypted_key));
}
