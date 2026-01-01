//! Abstract signer interface for Nostr event signing.
//!
//! Provides a unified interface for different signing backends:
//! - Local keypair (secret key in memory)
//! - NIP-07 browser extensions
//! - NIP-46 remote signing
//! - Hardware wallets
//!
//! Custom implementations can be created by providing getPublicKey and sign functions.

const std = @import("std");
const crypto = @import("crypto.zig");

pub const SignerType = enum {
    local,
    remote,
    browser,
    hardware,
    custom,
};

pub const Error = error{
    SigningFailed,
    KeyGenerationFailed,
    NotSupported,
    Timeout,
    Cancelled,
    ConnectionFailed,
};

pub const Signer = struct {
    ptr: *anyopaque,
    signer_type: SignerType,
    getPublicKeyFn: *const fn (ptr: *anyopaque) [32]u8,
    signFn: *const fn (ptr: *anyopaque, message: *const [32]u8, sig: *[64]u8) Error!void,

    pub fn getPublicKey(self: Signer) [32]u8 {
        return self.getPublicKeyFn(self.ptr);
    }

    pub fn sign(self: Signer, message: *const [32]u8, sig: *[64]u8) Error!void {
        return self.signFn(self.ptr, message, sig);
    }

    pub fn init(
        comptime T: type,
        ptr: *T,
        signer_type: SignerType,
    ) Signer {
        const gen = struct {
            pub fn getPublicKey(p: *anyopaque) [32]u8 {
                const self: *T = @ptrCast(@alignCast(p));
                return self.getPublicKey();
            }
            pub fn signImpl(p: *anyopaque, message: *const [32]u8, sig: *[64]u8) Error!void {
                const self: *T = @ptrCast(@alignCast(p));
                return self.sign(message, sig);
            }
        };
        return .{
            .ptr = ptr,
            .signer_type = signer_type,
            .getPublicKeyFn = gen.getPublicKey,
            .signFn = gen.signImpl,
        };
    }
};

/// A local signer that holds cryptographic keys directly in memory.
///
/// # Security Considerations
///
/// **WARNING**: This signer stores the secret key unencrypted in process memory.
///
/// - **Memory exposure**: The secret key remains in memory until explicitly zeroed
///   by calling `deinit()`. Until then, it is vulnerable to:
///   - Memory dumps (core dumps, crash dumps)
///   - Swap file/partition exposure if memory is paged out
///   - Memory scanning by malicious processes with sufficient privileges
///   - Cold boot attacks on physical hardware
///
/// - **No memory protection**: The key material is stored in regular process memory
///   without any special protections (no mlock, no guard pages).
///
/// - **Recommended usage**:
///   - Call `deinit()` as soon as the signer is no longer needed to zero key material
///   - Consider using `CallbackSigner` with a secure enclave or hardware wallet for
///     high-security applications
///   - Disable core dumps in production environments handling sensitive keys
///   - Use memory-locking mechanisms at the application level if required
///
pub const LocalSigner = struct {
    secret_key: [32]u8,
    public_key: [32]u8,

    /// Creates a LocalSigner from an existing secret key.
    ///
    /// The caller should zero their copy of the secret key after calling this function
    /// if it's no longer needed. Call `deinit()` when done with the signer.
    pub fn fromSecretKey(secret_key: [32]u8) Error!LocalSigner {
        var public_key: [32]u8 = undefined;
        crypto.getPublicKey(&secret_key, &public_key) catch return error.KeyGenerationFailed;
        return .{
            .secret_key = secret_key,
            .public_key = public_key,
        };
    }

    /// Generates a new LocalSigner with a random secret key.
    ///
    /// Returns `error.KeyGenerationFailed` if public key derivation fails (e.g., if the
    /// randomly generated secret key is invalid for the curve, which is extremely rare).
    /// Call `deinit()` when done with the signer.
    pub fn generate() Error!LocalSigner {
        var secret_key: [32]u8 = undefined;
        std.crypto.random.bytes(&secret_key);
        var public_key: [32]u8 = undefined;
        crypto.getPublicKey(&secret_key, &public_key) catch {
            // Zero the secret key before returning on error
            std.crypto.secureZero(u8, &secret_key);
            return error.KeyGenerationFailed;
        };
        return .{
            .secret_key = secret_key,
            .public_key = public_key,
        };
    }

    pub fn getPublicKey(self: *LocalSigner) [32]u8 {
        return self.public_key;
    }

    pub fn sign(self: *LocalSigner, message: *const [32]u8, sig: *[64]u8) Error!void {
        crypto.sign(&self.secret_key, message, sig) catch return error.SigningFailed;
    }

    pub fn signer(self: *LocalSigner) Signer {
        return Signer.init(LocalSigner, self, .local);
    }

    /// Securely zeros the secret key and public key material.
    ///
    /// Call this method when the signer is no longer needed to minimize the time
    /// sensitive key material remains in memory. After calling `deinit()`, the
    /// signer should not be used for signing operations.
    ///
    /// This uses `std.crypto.secureZero` which prevents the compiler from optimizing
    /// away the memory clearing operation.
    pub fn deinit(self: *LocalSigner) void {
        std.crypto.secureZero(u8, &self.secret_key);
        std.crypto.secureZero(u8, &self.public_key);
    }
};

pub const CallbackSigner = struct {
    context: *anyopaque,
    public_key: [32]u8,
    signCallback: *const fn (context: *anyopaque, message: *const [32]u8, sig: *[64]u8) Error!void,

    pub fn getPublicKey(self: *CallbackSigner) [32]u8 {
        return self.public_key;
    }

    pub fn sign(self: *CallbackSigner, message: *const [32]u8, sig: *[64]u8) Error!void {
        return self.signCallback(self.context, message, sig);
    }

    pub fn signer(self: *CallbackSigner, signer_type: SignerType) Signer {
        return Signer.init(CallbackSigner, self, signer_type);
    }
};

test "LocalSigner generate and sign" {
    const event_mod = @import("event.zig");
    try event_mod.init();
    defer event_mod.cleanup();

    var local = try LocalSigner.generate();
    defer local.deinit();
    const pubkey = local.getPublicKey();
    try std.testing.expect(!std.mem.eql(u8, &pubkey, &[_]u8{0} ** 32));

    var message: [32]u8 = undefined;
    std.crypto.random.bytes(&message);
    var sig: [64]u8 = undefined;
    try local.sign(&message, &sig);

    try crypto.verifySignature(&pubkey, &message, &sig);
}

test "LocalSigner from secret key" {
    const event_mod = @import("event.zig");
    try event_mod.init();
    defer event_mod.cleanup();

    var secret_key: [32]u8 = undefined;
    std.crypto.random.bytes(&secret_key);

    var local = try LocalSigner.fromSecretKey(secret_key);
    defer local.deinit();
    try std.testing.expectEqualSlices(u8, &secret_key, &local.secret_key);

    const s = local.signer();
    try std.testing.expectEqual(SignerType.local, s.signer_type);
    try std.testing.expectEqualSlices(u8, &local.public_key, &s.getPublicKey());
}

test "Signer interface with LocalSigner" {
    const event_mod = @import("event.zig");
    try event_mod.init();
    defer event_mod.cleanup();

    var local = try LocalSigner.generate();
    defer local.deinit();
    const s = local.signer();

    try std.testing.expectEqual(SignerType.local, s.signer_type);

    var message: [32]u8 = undefined;
    std.crypto.random.bytes(&message);
    var sig: [64]u8 = undefined;
    try s.sign(&message, &sig);

    const pubkey = s.getPublicKey();
    try crypto.verifySignature(&pubkey, &message, &sig);
}

test "LocalSigner deinit zeroes key material" {
    const event_mod = @import("event.zig");
    try event_mod.init();
    defer event_mod.cleanup();

    var local = try LocalSigner.generate();

    // Verify keys are non-zero before deinit
    try std.testing.expect(!std.mem.eql(u8, &local.secret_key, &[_]u8{0} ** 32));
    try std.testing.expect(!std.mem.eql(u8, &local.public_key, &[_]u8{0} ** 32));

    local.deinit();

    // Verify keys are zeroed after deinit
    try std.testing.expectEqualSlices(u8, &[_]u8{0} ** 32, &local.secret_key);
    try std.testing.expectEqualSlices(u8, &[_]u8{0} ** 32, &local.public_key);
}

test "CallbackSigner with custom implementation" {
    const event_mod = @import("event.zig");
    try event_mod.init();
    defer event_mod.cleanup();

    const TestContext = struct {
        call_count: usize = 0,
        secret_key: [32]u8,

        fn signCallback(ctx: *anyopaque, message: *const [32]u8, sig: *[64]u8) Error!void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.call_count += 1;
            crypto.sign(&self.secret_key, message, sig) catch return error.SigningFailed;
        }
    };

    var secret_key: [32]u8 = undefined;
    std.crypto.random.bytes(&secret_key);
    var public_key: [32]u8 = undefined;
    crypto.getPublicKey(&secret_key, &public_key) catch unreachable;

    var ctx = TestContext{ .secret_key = secret_key };
    var callback_signer = CallbackSigner{
        .context = &ctx,
        .public_key = public_key,
        .signCallback = TestContext.signCallback,
    };

    const s = callback_signer.signer(.browser);
    try std.testing.expectEqual(SignerType.browser, s.signer_type);

    var message: [32]u8 = undefined;
    std.crypto.random.bytes(&message);
    var sig: [64]u8 = undefined;
    try s.sign(&message, &sig);

    try std.testing.expectEqual(@as(usize, 1), ctx.call_count);
    try crypto.verifySignature(&public_key, &message, &sig);
}
