const std = @import("std");

const nc = @cImport({
    @cInclude("noscrypt.h");
});

const NC_SUCCESS: i64 = 0;

var ctx: ?*nc.NCContext = null;
var initialized = false;

pub const CryptoError = error{
    InitFailed,
    InvalidKey,
    SignatureFailed,
    VerificationFailed,
};

pub fn init() !void {
    if (initialized) return;

    ctx = nc.NCGetSharedContext();
    if (ctx == null) return error.InitFailed;

    var entropy: [32]u8 = undefined;
    std.crypto.random.bytes(&entropy);

    const result = nc.NCInitContext(ctx, &entropy);
    if (result != NC_SUCCESS) {
        return error.InitFailed;
    }

    initialized = true;
}

pub fn cleanup() void {
    if (ctx) |c| {
        _ = nc.NCDestroyContext(c);
        ctx = null;
    }
    initialized = false;
}

pub fn verifySignature(pubkey: *const [32]u8, message: *const [32]u8, sig: *const [64]u8) !void {
    if (!initialized) try init();

    const pk = nc.NCByteCastToPublicKey(pubkey);
    const result = nc.NCVerifyDigest(ctx, pk, message, sig);

    if (result != NC_SUCCESS) {
        return error.VerificationFailed;
    }
}

pub fn sign(secret_key: *const [32]u8, message: *const [32]u8, sig_out: *[64]u8) !void {
    if (!initialized) try init();

    const sk = nc.NCByteCastToSecretKey(secret_key);

    var random: [32]u8 = undefined;
    std.crypto.random.bytes(&random);

    const result = nc.NCSignDigest(ctx, sk, &random, message, sig_out);

    if (result != NC_SUCCESS) {
        return error.SignatureFailed;
    }
}

pub fn getPublicKey(secret_key: *const [32]u8, pubkey_out: *[32]u8) !void {
    if (!initialized) try init();

    const sk = nc.NCByteCastToSecretKey(secret_key);
    const pk = nc.NCByteCastToPublicKey(pubkey_out);

    const result = nc.NCGetPublicKey(ctx, sk, pk);

    if (result != NC_SUCCESS) {
        return error.InvalidKey;
    }
}

pub fn validateSecretKey(secret_key: *const [32]u8) !void {
    if (!initialized) try init();

    const sk = nc.NCByteCastToSecretKey(secret_key);
    const result = nc.NCValidateSecretKey(ctx, sk);

    if (result != NC_SUCCESS) {
        return error.InvalidKey;
    }
}

pub const Nip44Error = error{
    InvalidPayload,
    UnsupportedVersion,
    MacVerificationFailed,
    DecryptionFailed,
    EncryptionFailed,
    InvalidPadding,
    MessageTooLarge,
    MessageTooSmall,
};

const NIP44_VERSION: u8 = 2;
const MIN_PLAINTEXT_SIZE: usize = 1;
const MAX_PLAINTEXT_SIZE: usize = 65535;

fn calcPaddedLen(unpadded_len: usize) usize {
    if (unpadded_len <= 32) return 32;
    const next_power = @as(usize, 1) << (@as(u6, @intCast(std.math.log2(unpadded_len - 1))) + 1);
    const chunk = if (next_power <= 256) 32 else next_power / 8;
    return chunk * ((unpadded_len - 1) / chunk + 1);
}

fn pad(plaintext: []const u8, out: []u8) !usize {
    const len = plaintext.len;
    if (len < MIN_PLAINTEXT_SIZE) return Nip44Error.MessageTooSmall;
    if (len > MAX_PLAINTEXT_SIZE) return Nip44Error.MessageTooLarge;

    const padded_len = calcPaddedLen(len);
    const total_len = 2 + padded_len;
    if (out.len < total_len) return Nip44Error.InvalidPadding;

    out[0] = @intCast((len >> 8) & 0xFF);
    out[1] = @intCast(len & 0xFF);
    @memcpy(out[2 .. 2 + len], plaintext);
    @memset(out[2 + len .. total_len], 0);
    return total_len;
}

fn unpad(padded: []const u8) ![]const u8 {
    if (padded.len < 2) return Nip44Error.InvalidPadding;

    const len: usize = (@as(usize, padded[0]) << 8) | @as(usize, padded[1]);
    if (len == 0 or len > padded.len - 2) return Nip44Error.InvalidPadding;
    if (padded.len != 2 + calcPaddedLen(len)) return Nip44Error.InvalidPadding;

    return padded[2 .. 2 + len];
}

pub fn nip44Encrypt(
    secret_key: *const [32]u8,
    pubkey: *const [32]u8,
    plaintext: []const u8,
    allocator: std.mem.Allocator,
) ![]u8 {
    if (!initialized) try init();

    if (plaintext.len < MIN_PLAINTEXT_SIZE) return Nip44Error.MessageTooSmall;
    if (plaintext.len > MAX_PLAINTEXT_SIZE) return Nip44Error.MessageTooLarge;

    const padded_len = calcPaddedLen(plaintext.len);
    const total_padded = 2 + padded_len;

    const padded_buf = try allocator.alloc(u8, total_padded);
    defer allocator.free(padded_buf);
    _ = try pad(plaintext, padded_buf);

    var ciphertext = try allocator.alloc(u8, total_padded);
    defer allocator.free(ciphertext);

    var nonce: [32]u8 = undefined;
    std.crypto.random.bytes(&nonce);

    var hmac_key: [32]u8 = undefined;

    var args: nc.NCEncryptionArgs = .{
        .ivData = &nonce,
        .keyData = &hmac_key,
        .inputData = padded_buf.ptr,
        .outputData = ciphertext.ptr,
        .dataSize = @intCast(total_padded),
        .version = nc.NC_ENC_VERSION_NIP44,
    };

    const sk = nc.NCByteCastToSecretKey(secret_key);
    const pk = nc.NCByteCastToPublicKey(pubkey);

    const result = nc.NCEncrypt(ctx, sk, pk, &args);
    if (result != NC_SUCCESS) return Nip44Error.EncryptionFailed;

    var mac: [32]u8 = undefined;
    var hmac_ctx = std.crypto.auth.hmac.sha2.HmacSha256.init(&hmac_key);
    hmac_ctx.update(&nonce);
    hmac_ctx.update(ciphertext[0..total_padded]);
    hmac_ctx.final(&mac);

    const raw_len = 1 + 32 + total_padded + 32;
    var raw = try allocator.alloc(u8, raw_len);
    defer allocator.free(raw);

    raw[0] = NIP44_VERSION;
    @memcpy(raw[1..33], &nonce);
    @memcpy(raw[33 .. 33 + total_padded], ciphertext[0..total_padded]);
    @memcpy(raw[33 + total_padded .. raw_len], &mac);

    const encoded_len = std.base64.standard.Encoder.calcSize(raw_len);
    const encoded = try allocator.alloc(u8, encoded_len);
    _ = std.base64.standard.Encoder.encode(encoded, raw);

    return encoded;
}

pub fn nip44Decrypt(
    secret_key: *const [32]u8,
    pubkey: *const [32]u8,
    payload: []const u8,
    allocator: std.mem.Allocator,
) ![]u8 {
    if (!initialized) try init();

    if (payload.len == 0) return Nip44Error.InvalidPayload;
    if (payload[0] == '#') return Nip44Error.UnsupportedVersion;
    if (payload.len < 132 or payload.len > 87472) return Nip44Error.InvalidPayload;

    const decoded_len = std.base64.standard.Decoder.calcSizeForSlice(payload) catch return Nip44Error.InvalidPayload;
    if (decoded_len < 99 or decoded_len > 65603) return Nip44Error.InvalidPayload;

    var decoded = try allocator.alloc(u8, decoded_len);
    defer allocator.free(decoded);
    std.base64.standard.Decoder.decode(decoded, payload) catch return Nip44Error.InvalidPayload;

    const version = decoded[0];
    if (version != NIP44_VERSION) return Nip44Error.UnsupportedVersion;

    const nonce = decoded[1..33];
    const mac = decoded[decoded_len - 32 .. decoded_len];
    const mac_data = decoded[1 .. decoded_len - 32];
    const ciphertext = decoded[33 .. decoded_len - 32];
    const ciphertext_len = ciphertext.len;

    const sk = nc.NCByteCastToSecretKey(secret_key);
    const pk = nc.NCByteCastToPublicKey(pubkey);

    const mac_args: nc.NCMacVerifyArgs = .{
        .mac32 = mac.ptr,
        .nonce32 = nonce.ptr,
        .payload = mac_data.ptr,
        .payloadSize = @intCast(mac_data.len),
    };
    const mac_verify = nc.NCVerifyMac(ctx, sk, pk, &mac_args);
    if (mac_verify != NC_SUCCESS) return Nip44Error.MacVerificationFailed;

    const padded = try allocator.alloc(u8, ciphertext_len);
    defer allocator.free(padded);

    var args: nc.NCEncryptionArgs = .{
        .ivData = nonce.ptr,
        .keyData = null,
        .inputData = ciphertext.ptr,
        .outputData = padded.ptr,
        .dataSize = @intCast(ciphertext_len),
        .version = nc.NC_ENC_VERSION_NIP44,
    };

    const result = nc.NCDecrypt(ctx, sk, pk, &args);
    if (result != NC_SUCCESS) return Nip44Error.DecryptionFailed;

    const unpadded = try unpad(padded);
    const out = try allocator.alloc(u8, unpadded.len);
    @memcpy(out, unpadded);
    return out;
}

pub fn getConversationKey(secret_key: *const [32]u8, pubkey: *const [32]u8, out: *[32]u8) !void {
    if (!initialized) try init();

    const sk = nc.NCByteCastToSecretKey(secret_key);
    const pk = nc.NCByteCastToPublicKey(pubkey);

    const result = nc.NCGetConversationKey(ctx, sk, pk, out);
    if (result != NC_SUCCESS) return Nip44Error.EncryptionFailed;
}

test "calcPaddedLen" {
    try std.testing.expectEqual(@as(usize, 32), calcPaddedLen(1));
    try std.testing.expectEqual(@as(usize, 32), calcPaddedLen(32));
    try std.testing.expectEqual(@as(usize, 64), calcPaddedLen(33));
    try std.testing.expectEqual(@as(usize, 64), calcPaddedLen(64));
    try std.testing.expectEqual(@as(usize, 96), calcPaddedLen(65));
    try std.testing.expectEqual(@as(usize, 256), calcPaddedLen(256));
    try std.testing.expectEqual(@as(usize, 320), calcPaddedLen(257));
}

test "pad and unpad" {
    var buf: [34]u8 = undefined;
    const len = try pad("a", &buf);
    try std.testing.expectEqual(@as(usize, 34), len);
    try std.testing.expectEqual(@as(u8, 0), buf[0]);
    try std.testing.expectEqual(@as(u8, 1), buf[1]);
    try std.testing.expectEqual(@as(u8, 'a'), buf[2]);

    const unpadded = try unpad(buf[0..len]);
    try std.testing.expectEqualStrings("a", unpadded);
}

test "nip44 encrypt/decrypt roundtrip" {
    const allocator = std.testing.allocator;

    var sk1: [32]u8 = undefined;
    var sk2: [32]u8 = undefined;
    @memset(&sk1, 0);
    @memset(&sk2, 0);
    sk1[31] = 1;
    sk2[31] = 2;

    var pk1: [32]u8 = undefined;
    var pk2: [32]u8 = undefined;
    try getPublicKey(&sk1, &pk1);
    try getPublicKey(&sk2, &pk2);

    const plaintext = "Hello, NIP-44!";
    const encrypted = try nip44Encrypt(&sk1, &pk2, plaintext, allocator);
    defer allocator.free(encrypted);

    const decrypted = try nip44Decrypt(&sk2, &pk1, encrypted, allocator);
    defer allocator.free(decrypted);

    try std.testing.expectEqualStrings(plaintext, decrypted);
}

test "nip44 conversation key symmetry" {
    var sk1: [32]u8 = undefined;
    var sk2: [32]u8 = undefined;
    @memset(&sk1, 0);
    @memset(&sk2, 0);
    sk1[31] = 1;
    sk2[31] = 2;

    var pk1: [32]u8 = undefined;
    var pk2: [32]u8 = undefined;
    try getPublicKey(&sk1, &pk1);
    try getPublicKey(&sk2, &pk2);

    var conv1: [32]u8 = undefined;
    var conv2: [32]u8 = undefined;
    try getConversationKey(&sk1, &pk2, &conv1);
    try getConversationKey(&sk2, &pk1, &conv2);

    try std.testing.expectEqualSlices(u8, &conv1, &conv2);
}

test "nip44 decrypt known test vector" {
    const allocator = std.testing.allocator;

    var sk2: [32]u8 = undefined;
    @memset(&sk2, 0);
    sk2[31] = 2;

    var sk1: [32]u8 = undefined;
    @memset(&sk1, 0);
    sk1[31] = 1;

    var pk1: [32]u8 = undefined;
    try getPublicKey(&sk1, &pk1);

    const payload = "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABee0G5VSK0/9YypIObAtDKfYEAjD35uVkHyB0F4DwrcNaCXlCWZKaArsGrY6M9wnuTMxWfp1RTN9Xga8no+kF5Vsb";
    const decrypted = try nip44Decrypt(&sk2, &pk1, payload, allocator);
    defer allocator.free(decrypted);

    try std.testing.expectEqualStrings("a", decrypted);
}

test "nip44 conversation key test vector" {
    var sk1: [32]u8 = undefined;
    @memset(&sk1, 0);
    sk1[31] = 1;

    var sk2: [32]u8 = undefined;
    @memset(&sk2, 0);
    sk2[31] = 2;

    var pk2: [32]u8 = undefined;
    try getPublicKey(&sk2, &pk2);

    var conv_key: [32]u8 = undefined;
    try getConversationKey(&sk1, &pk2, &conv_key);

    const expected = [_]u8{ 0xc4, 0x1c, 0x77, 0x53, 0x56, 0xfd, 0x92, 0xea, 0xdc, 0x63, 0xff, 0x5a, 0x0d, 0xc1, 0xda, 0x21, 0x1b, 0x26, 0x8c, 0xbe, 0xa2, 0x23, 0x16, 0x76, 0x70, 0x95, 0xb2, 0x87, 0x1e, 0xa1, 0x41, 0x2d };
    try std.testing.expectEqualSlices(u8, &expected, &conv_key);
}
