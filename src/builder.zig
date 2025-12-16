const std = @import("std");
pub const crypto = @import("crypto.zig");
const utils = @import("utils.zig");
const pow = @import("pow.zig");
const hex = @import("hex.zig");

pub const Keypair = struct {
    secret_key: [32]u8,
    public_key: [32]u8,

    pub fn generate() Keypair {
        var secret_key: [32]u8 = undefined;
        std.crypto.random.bytes(&secret_key);

        var public_key: [32]u8 = undefined;
        crypto.getPublicKey(&secret_key, &public_key) catch unreachable;

        return .{
            .secret_key = secret_key,
            .public_key = public_key,
        };
    }
};

pub const EventBuilder = struct {
    id_bytes: [32]u8 = undefined,
    pubkey_bytes: [32]u8 = undefined,
    sig_bytes: [64]u8 = undefined,
    created_at_val: i64 = 0,
    kind_val: i32 = 1,
    content_slice: []const u8 = "",
    tags_data: []const []const []const u8 = &[_][]const []const u8{},
    mined_nonce: ?u64 = null,
    mined_target: ?u8 = null,

    pub fn setKind(self: *EventBuilder, k: i32) *EventBuilder {
        self.kind_val = k;
        return self;
    }

    pub fn setContent(self: *EventBuilder, c: []const u8) *EventBuilder {
        self.content_slice = c;
        return self;
    }

    pub fn setCreatedAt(self: *EventBuilder, t: i64) *EventBuilder {
        self.created_at_val = t;
        return self;
    }

    pub fn setTags(self: *EventBuilder, t: []const []const []const u8) *EventBuilder {
        self.tags_data = t;
        return self;
    }

    pub fn sign(self: *EventBuilder, keypair: *const Keypair) !void {
        @memcpy(&self.pubkey_bytes, &keypair.public_key);

        if (self.created_at_val == 0) {
            self.created_at_val = std.time.timestamp();
        }

        var commitment_buf: [8192]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&commitment_buf);
        const writer = fbs.writer();

        try writer.writeAll("[0,\"");

        var pk_hex: [64]u8 = undefined;
        hex.encode(&keypair.public_key, &pk_hex);
        try writer.writeAll(&pk_hex);

        try writer.writeAll("\",");
        try writer.print("{d}", .{self.created_at_val});
        try writer.writeAll(",");
        try writer.print("{d}", .{self.kind_val});
        try writer.writeAll(",[");

        for (self.tags_data, 0..) |tag, i| {
            if (i > 0) try writer.writeByte(',');
            try writer.writeByte('[');
            for (tag, 0..) |elem, j| {
                if (j > 0) try writer.writeByte(',');
                try writer.writeByte('"');
                try utils.writeJsonEscaped(writer, elem);
                try writer.writeByte('"');
            }
            try writer.writeByte(']');
        }

        try writer.writeAll("],\"");
        try utils.writeJsonEscaped(writer, self.content_slice);
        try writer.writeAll("\"]");

        const commitment = fbs.getWritten();
        std.crypto.hash.sha2.Sha256.hash(commitment, &self.id_bytes, .{});

        crypto.sign(&keypair.secret_key, &self.id_bytes, &self.sig_bytes) catch {
            return error.SignatureFailed;
        };
    }

    pub fn mine(self: *EventBuilder, keypair: *const Keypair, target_difficulty: u8) !u64 {
        @memcpy(&self.pubkey_bytes, &keypair.public_key);

        if (self.created_at_val == 0) {
            self.created_at_val = std.time.timestamp();
        }

        var nonce: u64 = 0;
        var nonce_str_buf: [20]u8 = undefined;
        var target_str_buf: [3]u8 = undefined;
        const target_str = std.fmt.bufPrint(&target_str_buf, "{d}", .{target_difficulty}) catch unreachable;

        var commitment_prefix_buf: [8192]u8 = undefined;
        var prefix_fbs = std.io.fixedBufferStream(&commitment_prefix_buf);
        const prefix_writer = prefix_fbs.writer();

        try prefix_writer.writeAll("[0,\"");
        var mine_pk_hex: [64]u8 = undefined;
        hex.encode(&keypair.public_key, &mine_pk_hex);
        try prefix_writer.writeAll(&mine_pk_hex);
        try prefix_writer.writeAll("\",");
        try prefix_writer.print("{d}", .{self.created_at_val});
        try prefix_writer.writeAll(",");
        try prefix_writer.print("{d}", .{self.kind_val});
        try prefix_writer.writeAll(",[");

        for (self.tags_data, 0..) |tag, i| {
            if (i > 0) try prefix_writer.writeByte(',');
            try prefix_writer.writeByte('[');
            for (tag, 0..) |elem, j| {
                if (j > 0) try prefix_writer.writeByte(',');
                try prefix_writer.writeByte('"');
                try utils.writeJsonEscaped(prefix_writer, elem);
                try prefix_writer.writeByte('"');
            }
            try prefix_writer.writeByte(']');
        }

        const has_existing_tags = self.tags_data.len > 0;
        const prefix = prefix_fbs.getWritten();

        while (true) : (nonce += 1) {
            const nonce_str = std.fmt.bufPrint(&nonce_str_buf, "{d}", .{nonce}) catch unreachable;

            var hasher = std.crypto.hash.sha2.Sha256.init(.{});
            hasher.update(prefix);
            if (has_existing_tags) hasher.update(",");
            hasher.update("[\"nonce\",\"");
            hasher.update(nonce_str);
            hasher.update("\",\"");
            hasher.update(target_str);
            hasher.update("\"]],\"");
            try utils.writeJsonEscapedHash(&hasher, self.content_slice);
            hasher.update("\"]");

            self.id_bytes = hasher.finalResult();

            if (pow.countLeadingZeroBits(&self.id_bytes) >= target_difficulty) {
                self.mined_nonce = nonce;
                self.mined_target = target_difficulty;
                crypto.sign(&keypair.secret_key, &self.id_bytes, &self.sig_bytes) catch {
                    return error.SignatureFailed;
                };
                return nonce;
            }
        }
    }

    pub fn serialize(self: *const EventBuilder, buf: []u8) ![]u8 {
        var fbs = std.io.fixedBufferStream(buf);
        const writer = fbs.writer();

        try writer.writeAll("{\"id\":\"");
        var ser_id_hex: [64]u8 = undefined;
        hex.encode(&self.id_bytes, &ser_id_hex);
        try writer.writeAll(&ser_id_hex);
        try writer.writeAll("\",\"pubkey\":\"");
        var ser_pk_hex: [64]u8 = undefined;
        hex.encode(&self.pubkey_bytes, &ser_pk_hex);
        try writer.writeAll(&ser_pk_hex);
        try writer.writeAll("\",\"created_at\":");
        try writer.print("{d}", .{self.created_at_val});
        try writer.writeAll(",\"kind\":");
        try writer.print("{d}", .{self.kind_val});
        try writer.writeAll(",\"tags\":[");

        for (self.tags_data, 0..) |tag, i| {
            if (i > 0) try writer.writeByte(',');
            try writer.writeByte('[');
            for (tag, 0..) |elem, j| {
                if (j > 0) try writer.writeByte(',');
                try writer.writeByte('"');
                try utils.writeJsonEscaped(writer, elem);
                try writer.writeByte('"');
            }
            try writer.writeByte(']');
        }

        if (self.mined_nonce) |nonce| {
            if (self.tags_data.len > 0) try writer.writeByte(',');
            try writer.writeAll("[\"nonce\",\"");
            try writer.print("{d}", .{nonce});
            try writer.writeAll("\",\"");
            try writer.print("{d}", .{self.mined_target.?});
            try writer.writeAll("\"]");
        }

        try writer.writeAll("],\"content\":\"");
        try utils.writeJsonEscaped(writer, self.content_slice);
        try writer.writeAll("\",\"sig\":\"");
        var ser_sig_hex: [128]u8 = undefined;
        hex.encode(&self.sig_bytes, &ser_sig_hex);
        try writer.writeAll(&ser_sig_hex);
        try writer.writeAll("\"}");

        return fbs.getWritten();
    }
};

test "event builder" {
    const event_mod = @import("event.zig");
    try event_mod.init();
    defer event_mod.cleanup();

    const keypair = Keypair.generate();
    var builder = EventBuilder{};
    _ = builder.setKind(1).setContent("test");
    try builder.sign(&keypair);

    var buf: [4096]u8 = undefined;
    const json = try builder.serialize(&buf);
    try std.testing.expect(json.len > 0);
}

test "event builder - mine with PoW" {
    const event_mod = @import("event.zig");
    try event_mod.init();
    defer event_mod.cleanup();

    const keypair = Keypair.generate();
    var builder = EventBuilder{};
    _ = builder.setKind(1).setContent("It's just me mining my own business");
    const nonce = try builder.mine(&keypair, 8);

    try std.testing.expect(nonce >= 0);
    try std.testing.expect(pow.countLeadingZeroBits(&builder.id_bytes) >= 8);
    try std.testing.expectEqual(@as(?u64, nonce), builder.mined_nonce);
    try std.testing.expectEqual(@as(?u8, 8), builder.mined_target);

    var buf: [4096]u8 = undefined;
    const json = try builder.serialize(&buf);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"nonce\"") != null);

    var event = try event_mod.Event.parse(json);
    defer event.deinit();
    try event.validate();

    const nonce_tag = pow.getNonceTag(json).?;
    try std.testing.expectEqual(nonce, nonce_tag.nonce);
    try std.testing.expectEqual(@as(?u8, 8), nonce_tag.target_difficulty);
}

test "event builder - mine with existing tags" {
    const event_mod = @import("event.zig");
    try event_mod.init();
    defer event_mod.cleanup();

    const keypair = Keypair.generate();
    var builder = EventBuilder{};
    const tags = [_][]const []const u8{
        &[_][]const u8{ "t", "nostr" },
    };
    _ = builder.setKind(1).setContent("test").setTags(&tags);
    _ = try builder.mine(&keypair, 4);

    try std.testing.expect(pow.countLeadingZeroBits(&builder.id_bytes) >= 4);

    var buf: [4096]u8 = undefined;
    const json = try builder.serialize(&buf);
    try std.testing.expect(std.mem.indexOf(u8, json, "[\"t\",\"nostr\"]") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "[\"nonce\",\"") != null);

    var event = try event_mod.Event.parse(json);
    defer event.deinit();
    try event.validate();
}
