//! NIP-49: Private Key Encryption
//!
//! This module implements NIP-49 for encrypting/decrypting private keys with a password
//! using scrypt key derivation and XChaCha20-Poly1305 authenticated encryption.
//!
//! **Important: Password Normalization**
//! Per NIP-49, passwords should be Unicode NFKC normalized before use.
//! This library does NOT perform normalization - callers must normalize
//! passwords before passing them to encrypt/decrypt functions to ensure
//! interoperability with other NIP-49 implementations.

const std = @import("std");
const bech32 = @import("bech32.zig");

pub const KeySecurity = enum(u8) {
    known_insecure = 0x00,
    known_secure = 0x01,
    unknown = 0x02,
};

pub const Error = error{
    InvalidPayload,
    InvalidVersion,
    InvalidKeySecurity,
    DecryptionFailed,
    WeakParameters,
    OutOfMemory,
    BufferTooSmall,
    InvalidChecksum,
    InvalidPrefix,
    InvalidLength,
    InvalidCharacter,
    InvalidPadding,
    MixedCase,
};

const VERSION: u8 = 0x02;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const KEY_LEN: usize = 32;
const TAG_LEN: usize = 16;
const PAYLOAD_LEN: usize = 1 + 1 + SALT_LEN + NONCE_LEN + 1 + KEY_LEN + TAG_LEN; // 91 bytes

const XChaCha20Poly1305 = std.crypto.aead.chacha_poly.XChaCha20Poly1305;
const scrypt = std.crypto.pwhash.scrypt;

pub fn encrypt(
    allocator: std.mem.Allocator,
    secret_key: *const [32]u8,
    password: []const u8,
    log_n: u6,
    key_security: KeySecurity,
    out: []u8,
) Error![]const u8 {
    if (out.len < 160) return Error.BufferTooSmall;

    var salt: [SALT_LEN]u8 = undefined;
    std.crypto.random.bytes(&salt);

    var nonce: [NONCE_LEN]u8 = undefined;
    std.crypto.random.bytes(&nonce);

    var symmetric_key: [KEY_LEN]u8 = undefined;
    defer @memset(&symmetric_key, 0);

    scrypt.kdf(allocator, &symmetric_key, password, &salt, .{
        .ln = log_n,
        .r = 8,
        .p = 1,
    }) catch |err| return switch (err) {
        error.OutOfMemory => Error.OutOfMemory,
        else => Error.WeakParameters,
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

    return bech32.encode("ncryptsec", &payload, out) catch |err| switch (err) {
        bech32.Error.InvalidLength => Error.InvalidLength,
        bech32.Error.InvalidCharacter => Error.InvalidCharacter,
        bech32.Error.InvalidChecksum => Error.InvalidChecksum,
        bech32.Error.InvalidPrefix => Error.InvalidPrefix,
        bech32.Error.InvalidPadding => Error.InvalidPadding,
        bech32.Error.BufferTooSmall => Error.BufferTooSmall,
        bech32.Error.MixedCase => Error.MixedCase,
    };
}

pub fn decrypt(
    allocator: std.mem.Allocator,
    ncryptsec: []const u8,
    password: []const u8,
    secret_key_out: *[32]u8,
) Error!KeySecurity {
    // Zero output buffer on any error to prevent leaking partial data
    errdefer @memset(secret_key_out, 0);

    var hrp_buf: [16]u8 = undefined;
    var payload: [PAYLOAD_LEN]u8 = undefined;

    const result = bech32.decode(ncryptsec, &hrp_buf, &payload) catch |err| return switch (err) {
        bech32.Error.InvalidLength => Error.InvalidLength,
        bech32.Error.InvalidCharacter => Error.InvalidCharacter,
        bech32.Error.InvalidChecksum => Error.InvalidChecksum,
        bech32.Error.InvalidPrefix => Error.InvalidPrefix,
        bech32.Error.InvalidPadding => Error.InvalidPadding,
        bech32.Error.BufferTooSmall => Error.BufferTooSmall,
        bech32.Error.MixedCase => Error.MixedCase,
    };

    if (!std.mem.eql(u8, hrp_buf[0..result.hrp_len], "ncryptsec")) {
        return Error.InvalidPrefix;
    }
    if (result.data_len != PAYLOAD_LEN) {
        return Error.InvalidPayload;
    }

    const version = payload[0];
    if (version != VERSION) {
        return Error.InvalidVersion;
    }

    const log_n_byte = payload[1];
    if (log_n_byte > std.math.maxInt(u6)) {
        return Error.InvalidPayload;
    }
    const log_n: u6 = @intCast(log_n_byte);
    const salt = payload[2 .. 2 + SALT_LEN];
    const nonce = payload[2 + SALT_LEN .. 2 + SALT_LEN + NONCE_LEN];
    const key_security_byte = payload[2 + SALT_LEN + NONCE_LEN];
    const ciphertext = payload[2 + SALT_LEN + NONCE_LEN + 1 .. 2 + SALT_LEN + NONCE_LEN + 1 + KEY_LEN];
    const tag = payload[2 + SALT_LEN + NONCE_LEN + 1 + KEY_LEN ..][0..TAG_LEN];

    const key_security: KeySecurity = std.meta.intToEnum(KeySecurity, key_security_byte) catch {
        return Error.InvalidKeySecurity;
    };

    var symmetric_key: [KEY_LEN]u8 = undefined;
    defer @memset(&symmetric_key, 0);

    scrypt.kdf(allocator, &symmetric_key, password, salt, .{
        .ln = log_n,
        .r = 8,
        .p = 1,
    }) catch |err| return switch (err) {
        error.OutOfMemory => Error.OutOfMemory,
        else => Error.WeakParameters,
    };

    const ad = [_]u8{key_security_byte};
    XChaCha20Poly1305.decrypt(secret_key_out, ciphertext, tag.*, &ad, nonce[0..NONCE_LEN].*, symmetric_key) catch {
        return Error.DecryptionFailed;
    };

    return key_security;
}

test "nip49 decrypt test vector" {
    const allocator = std.testing.allocator;
    const ncryptsec = "ncryptsec1qgg9947rlpvqu76pj5ecreduf9jxhselq2nae2kghhvd5g7dgjtcxfqtd67p9m0w57lspw8gsq6yphnm8623nsl8xn9j4jdzz84zm3frztj3z7s35vpzmqf6ksu8r89qk5z2zxfmu5gv8th8wclt0h4p";
    const password = "nostr";
    const expected_hex = "3501454135014541350145413501453fefb02227e449e57cf4d3a3ce05378683";

    var secret_key: [32]u8 = undefined;
    const key_security = try decrypt(allocator, ncryptsec, password, &secret_key);

    var hex_buf: [64]u8 = undefined;
    const hex = std.fmt.bytesToHex(secret_key, .lower);
    @memcpy(&hex_buf, &hex);

    try std.testing.expectEqualStrings(expected_hex, &hex_buf);
    try std.testing.expectEqual(KeySecurity.known_insecure, key_security);
}

test "nip49 encrypt decrypt roundtrip" {
    const allocator = std.testing.allocator;

    var secret_key: [32]u8 = undefined;
    @memset(&secret_key, 0);
    secret_key[31] = 1;

    const password = "test_password";
    const log_n: u6 = 4;

    var out: [256]u8 = undefined;
    const ncryptsec = try encrypt(allocator, &secret_key, password, log_n, .known_secure, &out);

    try std.testing.expect(std.mem.startsWith(u8, ncryptsec, "ncryptsec1"));

    var decrypted_key: [32]u8 = undefined;
    const key_security = try decrypt(allocator, ncryptsec, password, &decrypted_key);

    try std.testing.expectEqualSlices(u8, &secret_key, &decrypted_key);
    try std.testing.expectEqual(KeySecurity.known_secure, key_security);
}

test "nip49 wrong password fails" {
    const allocator = std.testing.allocator;
    const ncryptsec = "ncryptsec1qgg9947rlpvqu76pj5ecreduf9jxhselq2nae2kghhvd5g7dgjtcxfqtd67p9m0w57lspw8gsq6yphnm8623nsl8xn9j4jdzz84zm3frztj3z7s35vpzmqf6ksu8r89qk5z2zxfmu5gv8th8wclt0h4p";
    const wrong_password = "wrong";

    var secret_key: [32]u8 = undefined;
    try std.testing.expectError(Error.DecryptionFailed, decrypt(allocator, ncryptsec, wrong_password, &secret_key));
}

test "nip49 invalid prefix fails" {
    const allocator = std.testing.allocator;
    const npub = "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6";

    var secret_key: [32]u8 = undefined;
    try std.testing.expectError(Error.InvalidPrefix, decrypt(allocator, npub, "password", &secret_key));
}

test "nip49 all key security values roundtrip" {
    const allocator = std.testing.allocator;

    var secret_key: [32]u8 = undefined;
    std.crypto.random.bytes(&secret_key);

    const password = "test";
    const log_n: u6 = 4;

    for ([_]KeySecurity{ .known_insecure, .known_secure, .unknown }) |expected_security| {
        var out: [256]u8 = undefined;
        const ncryptsec = try encrypt(allocator, &secret_key, password, log_n, expected_security, &out);

        var decrypted_key: [32]u8 = undefined;
        const actual_security = try decrypt(allocator, ncryptsec, password, &decrypted_key);

        try std.testing.expectEqualSlices(u8, &secret_key, &decrypted_key);
        try std.testing.expectEqual(expected_security, actual_security);
    }
}
