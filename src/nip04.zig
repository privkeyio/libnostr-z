const std = @import("std");
const Aes256 = std.crypto.core.aes.Aes256;

const nc = @cImport({
    @cInclude("noscrypt.h");
});

const NC_SUCCESS: i64 = 0;
const BLOCK_SIZE: usize = 16;

pub const DM_KIND: i32 = 4;

pub const Nip04Error = error{
    InvalidPayload,
    DecryptionFailed,
    EncryptionFailed,
    NotInitialized,
};

fn xorBlocks(dst: *[BLOCK_SIZE]u8, a: *const [BLOCK_SIZE]u8, b: *const [BLOCK_SIZE]u8) void {
    for (0..BLOCK_SIZE) |i| {
        dst[i] = a[i] ^ b[i];
    }
}

fn aesCbcEncrypt(key: *const [32]u8, iv: *const [BLOCK_SIZE]u8, plaintext: []const u8, ciphertext: []u8) void {
    const cipher = Aes256.initEnc(key.*);
    var prev_block: [BLOCK_SIZE]u8 = iv.*;

    var i: usize = 0;
    while (i < plaintext.len) : (i += BLOCK_SIZE) {
        var block: [BLOCK_SIZE]u8 = undefined;
        xorBlocks(&block, plaintext[i..][0..BLOCK_SIZE], &prev_block);
        cipher.encrypt(&prev_block, &block);
        @memcpy(ciphertext[i..][0..BLOCK_SIZE], &prev_block);
    }
}

fn aesCbcDecrypt(key: *const [32]u8, iv: *const [BLOCK_SIZE]u8, ciphertext: []const u8, plaintext: []u8) void {
    const cipher = Aes256.initDec(key.*);
    var prev_block: [BLOCK_SIZE]u8 = iv.*;

    var i: usize = 0;
    while (i < ciphertext.len) : (i += BLOCK_SIZE) {
        var decrypted: [BLOCK_SIZE]u8 = undefined;
        cipher.decrypt(&decrypted, ciphertext[i..][0..BLOCK_SIZE]);
        xorBlocks(plaintext[i..][0..BLOCK_SIZE], &decrypted, &prev_block);
        @memcpy(&prev_block, ciphertext[i..][0..BLOCK_SIZE]);
    }
}

pub fn encrypt(
    secret_key: *const [32]u8,
    pubkey: *const [32]u8,
    plaintext: []const u8,
    allocator: std.mem.Allocator,
) ![]u8 {
    const ctx = nc.NCGetSharedContext();
    if (ctx == null) return Nip04Error.NotInitialized;

    const sk = nc.NCByteCastToSecretKey(secret_key);
    const pk = nc.NCByteCastToPublicKey(pubkey);

    var shared_secret: [32]u8 = undefined;
    if (nc.NCGetSharedSecret(ctx, sk, pk, &shared_secret) != NC_SUCCESS) {
        return Nip04Error.EncryptionFailed;
    }
    defer @memset(&shared_secret, 0);

    const padded_len = ((plaintext.len / BLOCK_SIZE) + 1) * BLOCK_SIZE;
    const padded = try allocator.alloc(u8, padded_len);
    defer allocator.free(padded);

    @memcpy(padded[0..plaintext.len], plaintext);
    const pad_byte: u8 = @intCast(padded_len - plaintext.len);
    @memset(padded[plaintext.len..], pad_byte);

    var ciphertext = try allocator.alloc(u8, padded_len);
    defer allocator.free(ciphertext);

    var iv: [BLOCK_SIZE]u8 = undefined;
    std.crypto.random.bytes(&iv);

    aesCbcEncrypt(&shared_secret, &iv, padded, ciphertext);

    const ct_b64_len = std.base64.standard.Encoder.calcSize(padded_len);
    const iv_b64_len = std.base64.standard.Encoder.calcSize(BLOCK_SIZE);
    const total_len = ct_b64_len + 4 + iv_b64_len;

    const output = try allocator.alloc(u8, total_len);
    errdefer allocator.free(output);

    _ = std.base64.standard.Encoder.encode(output[0..ct_b64_len], ciphertext[0..padded_len]);
    @memcpy(output[ct_b64_len .. ct_b64_len + 4], "?iv=");
    _ = std.base64.standard.Encoder.encode(output[ct_b64_len + 4 ..], &iv);

    return output;
}

pub fn decrypt(
    secret_key: *const [32]u8,
    pubkey: *const [32]u8,
    payload: []const u8,
    allocator: std.mem.Allocator,
) ![]u8 {
    const ctx = nc.NCGetSharedContext();
    if (ctx == null) return Nip04Error.NotInitialized;

    const sk = nc.NCByteCastToSecretKey(secret_key);
    const pk = nc.NCByteCastToPublicKey(pubkey);

    var shared_secret: [32]u8 = undefined;
    if (nc.NCGetSharedSecret(ctx, sk, pk, &shared_secret) != NC_SUCCESS) {
        return Nip04Error.DecryptionFailed;
    }
    defer @memset(&shared_secret, 0);

    const iv_sep = std.mem.indexOf(u8, payload, "?iv=") orelse return Nip04Error.InvalidPayload;
    const ct_b64 = payload[0..iv_sep];
    const iv_b64 = payload[iv_sep + 4 ..];

    if (iv_b64.len == 0 or ct_b64.len == 0) return Nip04Error.InvalidPayload;

    // Validate IV size before decoding to prevent partial writes or buffer overflow
    const expected_iv_size = std.base64.standard.Decoder.calcSizeForSlice(iv_b64) catch return Nip04Error.InvalidPayload;
    if (expected_iv_size != BLOCK_SIZE) return Nip04Error.InvalidPayload;

    var iv: [BLOCK_SIZE]u8 = undefined;
    std.base64.standard.Decoder.decode(&iv, iv_b64) catch return Nip04Error.InvalidPayload;

    const ct_len = std.base64.standard.Decoder.calcSizeForSlice(ct_b64) catch return Nip04Error.InvalidPayload;
    if (ct_len == 0 or ct_len % BLOCK_SIZE != 0) return Nip04Error.InvalidPayload;

    const ciphertext = try allocator.alloc(u8, ct_len);
    defer allocator.free(ciphertext);
    std.base64.standard.Decoder.decode(ciphertext, ct_b64) catch return Nip04Error.InvalidPayload;

    var plaintext = try allocator.alloc(u8, ct_len);
    errdefer allocator.free(plaintext);

    aesCbcDecrypt(&shared_secret, &iv, ciphertext, plaintext);

    const pad_byte = plaintext[ct_len - 1];
    if (pad_byte == 0 or pad_byte > BLOCK_SIZE) return Nip04Error.InvalidPayload;

    const unpadded_len = ct_len - pad_byte;
    for (plaintext[unpadded_len..ct_len]) |b| {
        if (b != pad_byte) return Nip04Error.InvalidPayload;
    }

    const output = try allocator.realloc(plaintext, unpadded_len);
    return output;
}

pub fn isDM(event_kind: i32) bool {
    return event_kind == DM_KIND;
}

pub fn parsePayload(payload: []const u8) ?struct { ciphertext: []const u8, iv: []const u8 } {
    const iv_sep = std.mem.indexOf(u8, payload, "?iv=") orelse return null;
    const ct_b64 = payload[0..iv_sep];
    const iv_b64 = payload[iv_sep + 4 ..];
    if (iv_b64.len == 0 or ct_b64.len == 0) return null;
    return .{ .ciphertext = ct_b64, .iv = iv_b64 };
}

const crypto = @import("crypto.zig");

test "encrypt and decrypt roundtrip" {
    try crypto.init();
    defer crypto.cleanup();

    const allocator = std.testing.allocator;

    var sk1: [32]u8 = undefined;
    var sk2: [32]u8 = undefined;
    @memset(&sk1, 0);
    @memset(&sk2, 0);
    sk1[31] = 1;
    sk2[31] = 2;

    var pk1: [32]u8 = undefined;
    var pk2: [32]u8 = undefined;
    try crypto.getPublicKey(&sk1, &pk1);
    try crypto.getPublicKey(&sk2, &pk2);

    const plaintext = "Hello, NIP-04!";
    const encrypted = try encrypt(&sk1, &pk2, plaintext, allocator);
    defer allocator.free(encrypted);

    try std.testing.expect(std.mem.indexOf(u8, encrypted, "?iv=") != null);

    const decrypted = try decrypt(&sk2, &pk1, encrypted, allocator);
    defer allocator.free(decrypted);

    try std.testing.expectEqualStrings(plaintext, decrypted);
}

test "encrypt and decrypt empty message" {
    try crypto.init();
    defer crypto.cleanup();

    const allocator = std.testing.allocator;

    var sk1: [32]u8 = undefined;
    var sk2: [32]u8 = undefined;
    @memset(&sk1, 0);
    @memset(&sk2, 0);
    sk1[31] = 3;
    sk2[31] = 4;

    var pk1: [32]u8 = undefined;
    var pk2: [32]u8 = undefined;
    try crypto.getPublicKey(&sk1, &pk1);
    try crypto.getPublicKey(&sk2, &pk2);

    const plaintext = "";
    const encrypted = try encrypt(&sk1, &pk2, plaintext, allocator);
    defer allocator.free(encrypted);

    const decrypted = try decrypt(&sk2, &pk1, encrypted, allocator);
    defer allocator.free(decrypted);

    try std.testing.expectEqualStrings(plaintext, decrypted);
}

test "encrypt and decrypt long message" {
    try crypto.init();
    defer crypto.cleanup();

    const allocator = std.testing.allocator;

    var sk1: [32]u8 = undefined;
    var sk2: [32]u8 = undefined;
    @memset(&sk1, 0);
    @memset(&sk2, 0);
    sk1[31] = 5;
    sk2[31] = 6;

    var pk1: [32]u8 = undefined;
    var pk2: [32]u8 = undefined;
    try crypto.getPublicKey(&sk1, &pk1);
    try crypto.getPublicKey(&sk2, &pk2);

    const plaintext = "A" ** 1000;
    const encrypted = try encrypt(&sk1, &pk2, plaintext, allocator);
    defer allocator.free(encrypted);

    const decrypted = try decrypt(&sk2, &pk1, encrypted, allocator);
    defer allocator.free(decrypted);

    try std.testing.expectEqualStrings(plaintext, decrypted);
}

test "decrypt invalid payload" {
    try crypto.init();
    defer crypto.cleanup();

    const allocator = std.testing.allocator;

    var sk: [32]u8 = undefined;
    var pk: [32]u8 = undefined;
    @memset(&sk, 0);
    sk[31] = 7;
    try crypto.getPublicKey(&sk, &pk);

    try std.testing.expectError(Nip04Error.InvalidPayload, decrypt(&sk, &pk, "invalid", allocator));
    try std.testing.expectError(Nip04Error.InvalidPayload, decrypt(&sk, &pk, "?iv=", allocator));
    try std.testing.expectError(Nip04Error.InvalidPayload, decrypt(&sk, &pk, "data?iv=", allocator));
    // Short IV (3 bytes instead of 16)
    try std.testing.expectError(Nip04Error.InvalidPayload, decrypt(&sk, &pk, "AAAAAAAAAAAAAAAAAAAAAA==?iv=AAAA", allocator));
    // Long IV (24 bytes instead of 16)
    try std.testing.expectError(Nip04Error.InvalidPayload, decrypt(&sk, &pk, "AAAAAAAAAAAAAAAAAAAAAA==?iv=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", allocator));
}

test "parsePayload" {
    const result = parsePayload("ciphertext_base64?iv=iv_base64");
    try std.testing.expect(result != null);
    try std.testing.expectEqualStrings("ciphertext_base64", result.?.ciphertext);
    try std.testing.expectEqualStrings("iv_base64", result.?.iv);

    try std.testing.expect(parsePayload("no_iv_separator") == null);
    try std.testing.expect(parsePayload("?iv=") == null);
    try std.testing.expect(parsePayload("?iv=abc") == null);
}

test "isDM" {
    try std.testing.expect(isDM(4));
    try std.testing.expect(!isDM(1));
    try std.testing.expect(!isDM(7));
}

test "DM_KIND constant" {
    try std.testing.expectEqual(@as(i32, 4), DM_KIND);
}
