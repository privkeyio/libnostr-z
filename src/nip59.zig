const std = @import("std");
const crypto = @import("crypto.zig");
const hex = @import("hex.zig");
const utils = @import("utils.zig");
const builder_mod = @import("builder.zig");

pub const Keypair = builder_mod.Keypair;

pub const Kind = struct {
    pub const seal: i32 = 13;
    pub const gift_wrap: i32 = 1059;
};

pub const Error = error{
    InvalidPayload,
    InvalidEvent,
    DecryptionFailed,
    MissingField,
    InvalidKind,
    BufferTooSmall,
};

const TWO_DAYS_SECS: i64 = 2 * 24 * 60 * 60;

pub const Rumor = struct {
    id: [32]u8,
    pubkey: [32]u8,
    created_at: i64,
    kind: i32,
    content: []const u8,
    tags: []const []const []const u8,

    pub fn serializeJson(self: *const Rumor, buf: []u8) ![]u8 {
        var fbs = std.io.fixedBufferStream(buf);
        const writer = fbs.writer();

        try writer.writeAll("{\"id\":\"");
        var id_hex: [64]u8 = undefined;
        hex.encode(&self.id, &id_hex);
        try writer.writeAll(&id_hex);

        try writer.writeAll("\",\"pubkey\":\"");
        var pk_hex: [64]u8 = undefined;
        hex.encode(&self.pubkey, &pk_hex);
        try writer.writeAll(&pk_hex);

        try writer.writeAll("\",\"created_at\":");
        try writer.print("{d}", .{self.created_at});

        try writer.writeAll(",\"kind\":");
        try writer.print("{d}", .{self.kind});

        try writer.writeAll(",\"tags\":[");
        for (self.tags, 0..) |tag, i| {
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

        try writer.writeAll("],\"content\":\"");
        try utils.writeJsonEscaped(writer, self.content);
        try writer.writeAll("\"}");

        return fbs.getWritten();
    }
};

pub fn createRumor(
    kind: i32,
    content: []const u8,
    tags: []const []const []const u8,
    created_at: i64,
    keypair: *const Keypair,
    allocator: std.mem.Allocator,
) !Rumor {
    var rumor = Rumor{
        .id = undefined,
        .pubkey = keypair.public_key,
        .created_at = created_at,
        .kind = kind,
        .content = content,
        .tags = tags,
    };

    const commitment_buf = try allocator.alloc(u8, 131072);
    defer allocator.free(commitment_buf);

    var fbs = std.io.fixedBufferStream(commitment_buf);
    const writer = fbs.writer();

    try writer.writeAll("[0,\"");
    var pk_hex: [64]u8 = undefined;
    hex.encode(&keypair.public_key, &pk_hex);
    try writer.writeAll(&pk_hex);
    try writer.writeAll("\",");
    try writer.print("{d}", .{created_at});
    try writer.writeAll(",");
    try writer.print("{d}", .{kind});
    try writer.writeAll(",[");

    for (tags, 0..) |tag, i| {
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
    try utils.writeJsonEscaped(writer, content);
    try writer.writeAll("\"]");

    const commitment = fbs.getWritten();
    std.crypto.hash.sha2.Sha256.hash(commitment, &rumor.id, .{});

    return rumor;
}

fn randomPastTimestamp() i64 {
    const now = std.time.timestamp();
    var random_bytes: [8]u8 = undefined;
    std.crypto.random.bytes(&random_bytes);
    const random_offset = @as(i64, @intCast(std.mem.readInt(u64, &random_bytes, .little) % @as(u64, @intCast(TWO_DAYS_SECS))));
    return now - random_offset;
}

fn signAndSerialize(
    kind: i32,
    content: []const u8,
    tags: []const []const []const u8,
    created_at: i64,
    keypair: *const Keypair,
    out_buf: []u8,
    allocator: std.mem.Allocator,
) ![]u8 {
    var id: [32]u8 = undefined;
    var sig: [64]u8 = undefined;

    const commitment_buf = try allocator.alloc(u8, 131072);
    defer allocator.free(commitment_buf);
    var fbs = std.io.fixedBufferStream(commitment_buf);
    const cwriter = fbs.writer();

    try cwriter.writeAll("[0,\"");
    var pk_hex: [64]u8 = undefined;
    hex.encode(&keypair.public_key, &pk_hex);
    try cwriter.writeAll(&pk_hex);
    try cwriter.writeAll("\",");
    try cwriter.print("{d}", .{created_at});
    try cwriter.writeAll(",");
    try cwriter.print("{d}", .{kind});
    try cwriter.writeAll(",[");

    for (tags, 0..) |tag, i| {
        if (i > 0) try cwriter.writeByte(',');
        try cwriter.writeByte('[');
        for (tag, 0..) |elem, j| {
            if (j > 0) try cwriter.writeByte(',');
            try cwriter.writeByte('"');
            try utils.writeJsonEscaped(cwriter, elem);
            try cwriter.writeByte('"');
        }
        try cwriter.writeByte(']');
    }

    try cwriter.writeAll("],\"");
    try utils.writeJsonEscaped(cwriter, content);
    try cwriter.writeAll("\"]");

    const commitment = fbs.getWritten();
    std.crypto.hash.sha2.Sha256.hash(commitment, &id, .{});

    crypto.sign(&keypair.secret_key, &id, &sig) catch {
        return error.SignatureFailed;
    };

    var out_fbs = std.io.fixedBufferStream(out_buf);
    const writer = out_fbs.writer();

    try writer.writeAll("{\"id\":\"");
    var id_hex: [64]u8 = undefined;
    hex.encode(&id, &id_hex);
    try writer.writeAll(&id_hex);

    try writer.writeAll("\",\"pubkey\":\"");
    try writer.writeAll(&pk_hex);

    try writer.writeAll("\",\"created_at\":");
    try writer.print("{d}", .{created_at});

    try writer.writeAll(",\"kind\":");
    try writer.print("{d}", .{kind});

    try writer.writeAll(",\"tags\":[");
    for (tags, 0..) |tag, i| {
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

    try writer.writeAll("],\"content\":\"");
    try utils.writeJsonEscaped(writer, content);

    try writer.writeAll("\",\"sig\":\"");
    var sig_hex: [128]u8 = undefined;
    hex.encode(&sig, &sig_hex);
    try writer.writeAll(&sig_hex);
    try writer.writeAll("\"}");

    return out_fbs.getWritten();
}

pub fn createSeal(
    rumor: *const Rumor,
    sender_keypair: *const Keypair,
    recipient_pubkey: *const [32]u8,
    out_buf: []u8,
    allocator: std.mem.Allocator,
) ![]u8 {
    const rumor_json_buf = try allocator.alloc(u8, 65536);
    defer allocator.free(rumor_json_buf);
    const rumor_json = try rumor.serializeJson(rumor_json_buf);

    const encrypted_content = try crypto.nip44Encrypt(
        &sender_keypair.secret_key,
        recipient_pubkey,
        rumor_json,
        allocator,
    );
    defer allocator.free(encrypted_content);

    const empty_tags: []const []const []const u8 = &[_][]const []const u8{};
    const seal_created_at = randomPastTimestamp();

    return try signAndSerialize(
        Kind.seal,
        encrypted_content,
        empty_tags,
        seal_created_at,
        sender_keypair,
        out_buf,
        allocator,
    );
}

pub const WrapResult = struct {
    json: []u8,
    ephemeral_keypair: Keypair,
};

pub fn createGiftWrap(
    seal_json: []const u8,
    recipient_pubkey: *const [32]u8,
    out_buf: []u8,
    allocator: std.mem.Allocator,
) !WrapResult {
    const ephemeral_keypair = Keypair.generate();

    const encrypted_content = try crypto.nip44Encrypt(
        &ephemeral_keypair.secret_key,
        recipient_pubkey,
        seal_json,
        allocator,
    );
    defer allocator.free(encrypted_content);

    var recipient_hex: [64]u8 = undefined;
    hex.encode(recipient_pubkey, &recipient_hex);

    const p_tag_inner = [_][]const u8{ "p", &recipient_hex };
    const p_tag: []const []const u8 = &p_tag_inner;
    const tags = [_][]const []const u8{p_tag};

    const wrap_created_at = randomPastTimestamp();

    const json = try signAndSerialize(
        Kind.gift_wrap,
        encrypted_content,
        &tags,
        wrap_created_at,
        &ephemeral_keypair,
        out_buf,
        allocator,
    );

    return .{
        .json = json,
        .ephemeral_keypair = ephemeral_keypair,
    };
}

pub fn wrap(
    rumor: *const Rumor,
    sender_keypair: *const Keypair,
    recipient_pubkey: *const [32]u8,
    out_buf: []u8,
    allocator: std.mem.Allocator,
) !WrapResult {
    const seal_buf = try allocator.alloc(u8, 131072);
    defer allocator.free(seal_buf);

    const seal_json = try createSeal(rumor, sender_keypair, recipient_pubkey, seal_buf, allocator);
    return try createGiftWrap(seal_json, recipient_pubkey, out_buf, allocator);
}

pub const UnwrappedGiftWrap = struct {
    seal_json: []const u8,
    seal_pubkey: [32]u8,
    rumor_json: []const u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *UnwrappedGiftWrap) void {
        self.allocator.free(self.seal_json);
        self.allocator.free(self.rumor_json);
    }
};

pub fn unwrap(
    gift_wrap_json: []const u8,
    recipient_keypair: *const Keypair,
    allocator: std.mem.Allocator,
) !UnwrappedGiftWrap {
    const wrap_kind = parseKind(gift_wrap_json) orelse return Error.InvalidEvent;
    if (wrap_kind != Kind.gift_wrap) return Error.InvalidKind;

    const wrap_content = utils.extractJsonString(gift_wrap_json, "content") orelse return Error.MissingField;
    const wrap_pubkey_hex = utils.extractJsonString(gift_wrap_json, "pubkey") orelse return Error.MissingField;

    var wrap_pubkey: [32]u8 = undefined;
    hex.decode(wrap_pubkey_hex, &wrap_pubkey) catch return Error.InvalidPayload;

    const seal_json = crypto.nip44Decrypt(
        &recipient_keypair.secret_key,
        &wrap_pubkey,
        wrap_content,
        allocator,
    ) catch return Error.DecryptionFailed;
    errdefer allocator.free(seal_json);

    const seal_kind = parseKind(seal_json) orelse {
        allocator.free(seal_json);
        return Error.InvalidEvent;
    };
    if (seal_kind != Kind.seal) {
        allocator.free(seal_json);
        return Error.InvalidKind;
    }

    const seal_content = utils.extractJsonString(seal_json, "content") orelse {
        allocator.free(seal_json);
        return Error.MissingField;
    };
    const seal_pubkey_hex = utils.extractJsonString(seal_json, "pubkey") orelse {
        allocator.free(seal_json);
        return Error.MissingField;
    };

    var seal_pubkey: [32]u8 = undefined;
    hex.decode(seal_pubkey_hex, &seal_pubkey) catch {
        allocator.free(seal_json);
        return Error.InvalidPayload;
    };

    const rumor_json = crypto.nip44Decrypt(
        &recipient_keypair.secret_key,
        &seal_pubkey,
        seal_content,
        allocator,
    ) catch {
        allocator.free(seal_json);
        return Error.DecryptionFailed;
    };

    return UnwrappedGiftWrap{
        .seal_json = seal_json,
        .seal_pubkey = seal_pubkey,
        .rumor_json = rumor_json,
        .allocator = allocator,
    };
}

fn parseKind(json: []const u8) ?i32 {
    const start = utils.findJsonFieldStart(json, "kind") orelse return null;
    var end = start;
    if (end < json.len and json[end] == '-') end += 1;
    while (end < json.len and json[end] >= '0' and json[end] <= '9') : (end += 1) {}
    if (end == start) return null;
    const value = std.fmt.parseInt(i32, json[start..end], 10) catch return null;
    if (value < 0 or value > 65535) return null;
    return value;
}

pub fn parseRumorContent(rumor_json: []const u8) ?[]const u8 {
    return utils.extractJsonString(rumor_json, "content");
}

pub fn parseRumorKind(rumor_json: []const u8) ?i32 {
    return parseKind(rumor_json);
}

pub fn parseRumorPubkey(rumor_json: []const u8, out: *[32]u8) bool {
    const pubkey_hex = utils.extractJsonString(rumor_json, "pubkey") orelse return false;
    hex.decode(pubkey_hex, out) catch return false;
    return true;
}

test "createRumor calculates correct id" {
    try crypto.init();
    const allocator = std.testing.allocator;

    const keypair = Keypair.generate();
    const rumor = try createRumor(
        1,
        "test content",
        &[_][]const []const u8{},
        1700000000,
        &keypair,
        allocator,
    );

    try std.testing.expect(!std.mem.eql(u8, &rumor.id, &[_]u8{0} ** 32));
    try std.testing.expectEqual(@as(i32, 1), rumor.kind);
    try std.testing.expectEqualStrings("test content", rumor.content);
    try std.testing.expectEqual(@as(i64, 1700000000), rumor.created_at);
}

test "rumor serialization" {
    try crypto.init();
    const allocator = std.testing.allocator;

    const keypair = Keypair.generate();
    const rumor = try createRumor(
        1,
        "Hello, World!",
        &[_][]const []const u8{},
        1700000000,
        &keypair,
        allocator,
    );

    var buf: [4096]u8 = undefined;
    const json = try rumor.serializeJson(&buf);

    try std.testing.expect(std.mem.indexOf(u8, json, "\"kind\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"content\":\"Hello, World!\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"created_at\":1700000000") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"sig\":") == null);
}

test "createSeal produces kind 13 event" {
    try crypto.init();
    const allocator = std.testing.allocator;

    const sender = Keypair.generate();
    const recipient = Keypair.generate();

    const rumor = try createRumor(
        1,
        "Secret message",
        &[_][]const []const u8{},
        1700000000,
        &sender,
        allocator,
    );

    var seal_buf: [65536]u8 = undefined;
    const seal_json = try createSeal(&rumor, &sender, &recipient.public_key, &seal_buf, allocator);

    const seal_kind = parseKind(seal_json);
    try std.testing.expectEqual(@as(?i32, Kind.seal), seal_kind);

    try std.testing.expect(std.mem.indexOf(u8, seal_json, "\"tags\":[]") != null);
}

test "createGiftWrap produces kind 1059 event" {
    try crypto.init();
    const allocator = std.testing.allocator;

    const sender = Keypair.generate();
    const recipient = Keypair.generate();

    const rumor = try createRumor(
        1,
        "Secret message",
        &[_][]const []const u8{},
        1700000000,
        &sender,
        allocator,
    );

    var seal_buf: [65536]u8 = undefined;
    const seal_json = try createSeal(&rumor, &sender, &recipient.public_key, &seal_buf, allocator);

    var wrap_buf: [65536]u8 = undefined;
    const result = try createGiftWrap(seal_json, &recipient.public_key, &wrap_buf, allocator);

    const wrap_kind = parseKind(result.json);
    try std.testing.expectEqual(@as(?i32, Kind.gift_wrap), wrap_kind);

    try std.testing.expect(std.mem.indexOf(u8, result.json, "[\"p\",\"") != null);
}

test "wrap and unwrap roundtrip" {
    try crypto.init();
    const allocator = std.testing.allocator;

    const sender = Keypair.generate();
    const recipient = Keypair.generate();

    const rumor = try createRumor(
        1,
        "Are you going to the party tonight?",
        &[_][]const []const u8{},
        1700000000,
        &sender,
        allocator,
    );

    var wrap_buf: [131072]u8 = undefined;
    const wrapped = try wrap(&rumor, &sender, &recipient.public_key, &wrap_buf, allocator);

    var unwrapped = try unwrap(wrapped.json, &recipient, allocator);
    defer unwrapped.deinit();

    try std.testing.expectEqualSlices(u8, &sender.public_key, &unwrapped.seal_pubkey);

    const content = parseRumorContent(unwrapped.rumor_json);
    try std.testing.expect(content != null);
    try std.testing.expectEqualStrings("Are you going to the party tonight?", content.?);

    const kind = parseRumorKind(unwrapped.rumor_json);
    try std.testing.expect(kind != null);
    try std.testing.expectEqual(@as(i32, 1), kind.?);
}

test "unwrap fails on wrong kind" {
    try crypto.init();
    const allocator = std.testing.allocator;

    const keypair = Keypair.generate();

    var buf: [4096]u8 = undefined;
    const json = try signAndSerialize(
        1,
        "not a gift wrap",
        &[_][]const []const u8{},
        1700000000,
        &keypair,
        &buf,
        allocator,
    );

    const result = unwrap(json, &keypair, allocator);
    try std.testing.expectError(Error.InvalidKind, result);
}

test "timestamps are randomized in past" {
    try crypto.init();
    const allocator = std.testing.allocator;

    const sender = Keypair.generate();
    const recipient = Keypair.generate();

    const now = std.time.timestamp();
    const rumor = try createRumor(1, "test", &[_][]const []const u8{}, now, &sender, allocator);

    var seal_buf: [65536]u8 = undefined;
    const seal_json = try createSeal(&rumor, &sender, &recipient.public_key, &seal_buf, allocator);

    const seal_created_at = utils.extractIntField(seal_json, "created_at", i64);
    try std.testing.expect(seal_created_at != null);
    try std.testing.expect(seal_created_at.? <= now);
    try std.testing.expect(seal_created_at.? > now - TWO_DAYS_SECS);

    var wrap_buf: [65536]u8 = undefined;
    const result = try createGiftWrap(seal_json, &recipient.public_key, &wrap_buf, allocator);

    const wrap_created_at = utils.extractIntField(result.json, "created_at", i64);
    try std.testing.expect(wrap_created_at != null);
    try std.testing.expect(wrap_created_at.? <= now);
    try std.testing.expect(wrap_created_at.? > now - TWO_DAYS_SECS);
}

test "gift wrap with tags on rumor" {
    try crypto.init();
    const allocator = std.testing.allocator;

    const sender = Keypair.generate();
    const recipient = Keypair.generate();

    const p_tag = [_][]const u8{ "p", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" };
    const tags = [_][]const []const u8{&p_tag};

    const rumor = try createRumor(
        1,
        "tagged message",
        &tags,
        1700000000,
        &sender,
        allocator,
    );

    var wrap_buf: [131072]u8 = undefined;
    const wrapped = try wrap(&rumor, &sender, &recipient.public_key, &wrap_buf, allocator);

    var unwrapped = try unwrap(wrapped.json, &recipient, allocator);
    defer unwrapped.deinit();

    try std.testing.expect(std.mem.indexOf(u8, unwrapped.rumor_json, "\"p\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, unwrapped.rumor_json, "aaaa") != null);
}

test "parseKind rejects out of range values" {
    try std.testing.expectEqual(@as(?i32, 0), parseKind("{\"kind\":0}"));
    try std.testing.expectEqual(@as(?i32, 1), parseKind("{\"kind\":1}"));
    try std.testing.expectEqual(@as(?i32, 65535), parseKind("{\"kind\":65535}"));

    try std.testing.expectEqual(@as(?i32, null), parseKind("{\"kind\":-1}"));
    try std.testing.expectEqual(@as(?i32, null), parseKind("{\"kind\":-100}"));

    try std.testing.expectEqual(@as(?i32, null), parseKind("{\"kind\":65536}"));
    try std.testing.expectEqual(@as(?i32, null), parseKind("{\"kind\":100000}"));
}
