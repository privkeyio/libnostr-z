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

pub const LocalSigner = struct {
    secret_key: [32]u8,
    public_key: [32]u8,

    pub fn fromSecretKey(secret_key: [32]u8) !LocalSigner {
        var public_key: [32]u8 = undefined;
        crypto.getPublicKey(&secret_key, &public_key) catch return error.SigningFailed;
        return .{
            .secret_key = secret_key,
            .public_key = public_key,
        };
    }

    pub fn generate() LocalSigner {
        var secret_key: [32]u8 = undefined;
        std.crypto.random.bytes(&secret_key);
        var public_key: [32]u8 = undefined;
        crypto.getPublicKey(&secret_key, &public_key) catch unreachable;
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

    var local = LocalSigner.generate();
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
    try std.testing.expectEqualSlices(u8, &secret_key, &local.secret_key);

    const s = local.signer();
    try std.testing.expectEqual(SignerType.local, s.signer_type);
    try std.testing.expectEqualSlices(u8, &local.public_key, &s.getPublicKey());
}

test "Signer interface with LocalSigner" {
    const event_mod = @import("event.zig");
    try event_mod.init();
    defer event_mod.cleanup();

    var local = LocalSigner.generate();
    const s = local.signer();

    try std.testing.expectEqual(SignerType.local, s.signer_type);

    var message: [32]u8 = undefined;
    std.crypto.random.bytes(&message);
    var sig: [64]u8 = undefined;
    try s.sign(&message, &sig);

    const pubkey = s.getPublicKey();
    try crypto.verifySignature(&pubkey, &message, &sig);
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
