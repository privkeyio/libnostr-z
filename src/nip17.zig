const std = @import("std");
const utils = @import("utils.zig");
const hex = @import("hex.zig");

pub const Kind = struct {
    pub const reaction: i32 = 7;
    pub const seal: i32 = 13;
    pub const chat_message: i32 = 14;
    pub const file_message: i32 = 15;
    pub const gift_wrap: i32 = 1059;
    pub const dm_relay_list: i32 = 10050;
};

pub const Receiver = struct {
    pubkey: []const u8,
    relay: ?[]const u8 = null,
};

pub const FileMetadata = struct {
    file_type: ?[]const u8 = null,
    encryption_algorithm: ?[]const u8 = null,
    decryption_key: ?[]const u8 = null,
    decryption_nonce: ?[]const u8 = null,
    file_hash: ?[]const u8 = null,
    original_hash: ?[]const u8 = null,
    size: ?[]const u8 = null,
    dimensions: ?[]const u8 = null,
    blurhash: ?[]const u8 = null,
    thumb: ?[]const u8 = null,
    fallback: ?[]const u8 = null,
};

pub const ReceiverIterator = struct {
    json: []const u8,
    pos: usize,

    pub fn init(event_json: []const u8) ReceiverIterator {
        return .{ .json = event_json, .pos = 0 };
    }

    pub fn next(self: *ReceiverIterator) ?Receiver {
        while (self.pos < self.json.len) {
            const tag_start = std.mem.indexOf(u8, self.json[self.pos..], "[\"p\",\"");
            if (tag_start == null) return null;

            const abs_start = self.pos + tag_start.? + 6;
            self.pos = abs_start;

            if (abs_start + 64 > self.json.len) return null;

            const pubkey = self.json[abs_start..][0..64];
            var valid = true;
            for (pubkey) |c| {
                if (!std.ascii.isHex(c)) {
                    valid = false;
                    break;
                }
            }
            if (!valid) {
                self.pos = abs_start + 1;
                continue;
            }

            self.pos = abs_start + 64;
            if (self.pos >= self.json.len or self.json[self.pos] != '"') {
                self.pos = abs_start + 1;
                continue;
            }
            self.pos += 1;

            const tag_end = std.mem.indexOf(u8, self.json[self.pos..], "]") orelse return null;
            const rest = self.json[self.pos..][0..tag_end];
            self.pos += tag_end + 1;

            var relay: ?[]const u8 = null;
            var i: usize = 0;
            while (i < rest.len) {
                if (rest[i] == '"') {
                    const str_start = i + 1;
                    const str_end = std.mem.indexOf(u8, rest[str_start..], "\"") orelse break;
                    const value = rest[str_start..][0..str_end];
                    if (value.len > 0) relay = value;
                    break;
                }
                i += 1;
            }

            return .{ .pubkey = pubkey, .relay = relay };
        }
        return null;
    }
};

pub fn parseReceivers(event_json: []const u8, out: [][32]u8) usize {
    var iter = ReceiverIterator.init(event_json);
    var count: usize = 0;
    while (count < out.len) {
        const receiver = iter.next() orelse break;
        hex.decode(receiver.pubkey, &out[count]) catch continue;
        count += 1;
    }
    return count;
}

pub fn parseSubject(event_json: []const u8) ?[]const u8 {
    const start = std.mem.indexOf(u8, event_json, "[\"subject\",\"") orelse return null;
    const value_start = start + 12;
    if (value_start >= event_json.len) return null;
    const value_end = utils.findStringEnd(event_json, value_start) orelse return null;
    if (value_end == value_start) return null;
    return event_json[value_start..value_end];
}

pub fn parseReplyTo(event_json: []const u8) ?[32]u8 {
    const start = std.mem.indexOf(u8, event_json, "[\"e\",\"") orelse return null;
    const hex_start = start + 6;
    if (hex_start + 64 > event_json.len) return null;
    var out: [32]u8 = undefined;
    hex.decode(event_json[hex_start..][0..64], &out) catch return null;
    return out;
}

pub fn parseGiftWrapRecipient(event_json: []const u8) ?[32]u8 {
    const start = std.mem.indexOf(u8, event_json, "[\"p\",\"") orelse return null;
    const hex_start = start + 6;
    if (hex_start + 64 > event_json.len) return null;
    var out: [32]u8 = undefined;
    hex.decode(event_json[hex_start..][0..64], &out) catch return null;
    return out;
}

pub fn parseFileMetadata(event_json: []const u8) FileMetadata {
    return .{
        .file_type = parseTagValue(event_json, "file-type"),
        .encryption_algorithm = parseTagValue(event_json, "encryption-algorithm"),
        .decryption_key = parseTagValue(event_json, "decryption-key"),
        .decryption_nonce = parseTagValue(event_json, "decryption-nonce"),
        .file_hash = parseTagValue(event_json, "x"),
        .original_hash = parseTagValue(event_json, "ox"),
        .size = parseTagValue(event_json, "size"),
        .dimensions = parseTagValue(event_json, "dim"),
        .blurhash = parseTagValue(event_json, "blurhash"),
        .thumb = parseTagValue(event_json, "thumb"),
        .fallback = parseTagValue(event_json, "fallback"),
    };
}

pub const RelayIterator = struct {
    json: []const u8,
    pos: usize,

    pub fn init(event_json: []const u8) RelayIterator {
        return .{ .json = event_json, .pos = 0 };
    }

    pub fn next(self: *RelayIterator) ?[]const u8 {
        const tag_start = std.mem.indexOf(u8, self.json[self.pos..], "[\"relay\",\"") orelse return null;
        const abs_start = self.pos + tag_start + 10;
        self.pos = abs_start;

        if (abs_start >= self.json.len) return null;
        const value_end = std.mem.indexOf(u8, self.json[abs_start..], "\"") orelse return null;
        if (value_end == 0) return null;

        self.pos = abs_start + value_end + 1;
        return self.json[abs_start..][0..value_end];
    }
};

pub fn parseDmRelays(event_json: []const u8, out: [][]const u8) usize {
    var iter = RelayIterator.init(event_json);
    var count: usize = 0;
    while (count < out.len) {
        const relay = iter.next() orelse break;
        out[count] = relay;
        count += 1;
    }
    return count;
}

pub fn parseContent(event_json: []const u8) ?[]const u8 {
    const start = utils.findJsonFieldStart(event_json, "content") orelse return null;
    if (start >= event_json.len or event_json[start] != '"') return null;
    const str_start = start + 1;
    const str_end = utils.findStringEnd(event_json, str_start) orelse return null;
    return event_json[str_start..str_end];
}

pub fn parsePubkey(event_json: []const u8) ?[32]u8 {
    return utils.extractHexField(event_json, "pubkey", 32);
}

pub fn parseKind(event_json: []const u8) ?i32 {
    return utils.extractIntField(event_json, "kind", i32);
}

fn parseTagValue(json: []const u8, tag_name: []const u8) ?[]const u8 {
    var buf: [64]u8 = undefined;
    const needle = std.fmt.bufPrint(&buf, "[\"{s}\",\"", .{tag_name}) catch return null;
    const start = std.mem.indexOf(u8, json, needle) orelse return null;
    const value_start = start + needle.len;
    if (value_start >= json.len) return null;
    const value_end = std.mem.indexOf(u8, json[value_start..], "\"") orelse return null;
    if (value_end == 0) return null;
    return json[value_start..][0..value_end];
}

test "Kind constants" {
    try std.testing.expectEqual(@as(i32, 7), Kind.reaction);
    try std.testing.expectEqual(@as(i32, 13), Kind.seal);
    try std.testing.expectEqual(@as(i32, 14), Kind.chat_message);
    try std.testing.expectEqual(@as(i32, 15), Kind.file_message);
    try std.testing.expectEqual(@as(i32, 1059), Kind.gift_wrap);
    try std.testing.expectEqual(@as(i32, 10050), Kind.dm_relay_list);
}

test "ReceiverIterator" {
    const json =
        \\{"kind":14,"tags":[["p","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","wss://relay1.com"],["p","bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]]}
    ;
    var iter = ReceiverIterator.init(json);

    const first = iter.next().?;
    try std.testing.expectEqualStrings("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", first.pubkey);
    try std.testing.expectEqualStrings("wss://relay1.com", first.relay.?);

    const second = iter.next().?;
    try std.testing.expectEqualStrings("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", second.pubkey);
    try std.testing.expect(second.relay == null);

    try std.testing.expect(iter.next() == null);
}

test "parseReceivers" {
    const json =
        \\{"kind":14,"tags":[["p","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],["p","bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]]}
    ;
    var receivers: [10][32]u8 = undefined;
    const count = parseReceivers(json, &receivers);
    try std.testing.expectEqual(@as(usize, 2), count);
}

test "parseSubject" {
    const json =
        \\{"kind":14,"tags":[["subject","Hello World"]]}
    ;
    const subject = parseSubject(json).?;
    try std.testing.expectEqualStrings("Hello World", subject);
}

test "parseSubject missing" {
    const json = "{\"kind\":14,\"tags\":[]}";
    try std.testing.expect(parseSubject(json) == null);
}

test "parseSubject with escaped quotes" {
    const json =
        \\{"kind":14,"tags":[["subject","Hello \"World\""]]}
    ;
    const subject = parseSubject(json).?;
    try std.testing.expectEqualStrings("Hello \\\"World\\\"", subject);
}

test "parseReplyTo" {
    const json =
        \\{"kind":14,"tags":[["e","cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","wss://relay.com"]]}
    ;
    const reply = parseReplyTo(json).?;
    var expected: [32]u8 = undefined;
    @memset(&expected, 0xcc);
    try std.testing.expectEqualSlices(u8, &expected, &reply);
}

test "parseGiftWrapRecipient" {
    const json =
        \\{"kind":1059,"tags":[["p","dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"]]}
    ;
    const recipient = parseGiftWrapRecipient(json).?;
    var expected: [32]u8 = undefined;
    @memset(&expected, 0xdd);
    try std.testing.expectEqualSlices(u8, &expected, &recipient);
}

test "parseFileMetadata" {
    const json =
        \\{"kind":15,"tags":[["file-type","image/jpeg"],["encryption-algorithm","aes-gcm"],["decryption-key","abc123"],["decryption-nonce","nonce456"],["x","eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"]]}
    ;
    const meta = parseFileMetadata(json);
    try std.testing.expectEqualStrings("image/jpeg", meta.file_type.?);
    try std.testing.expectEqualStrings("aes-gcm", meta.encryption_algorithm.?);
    try std.testing.expectEqualStrings("abc123", meta.decryption_key.?);
    try std.testing.expectEqualStrings("nonce456", meta.decryption_nonce.?);
    try std.testing.expectEqualStrings("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", meta.file_hash.?);
}

test "RelayIterator" {
    const json =
        \\{"kind":10050,"tags":[["relay","wss://inbox.nostr.wine"],["relay","wss://myrelay.nostr1.com"]]}
    ;
    var iter = RelayIterator.init(json);

    try std.testing.expectEqualStrings("wss://inbox.nostr.wine", iter.next().?);
    try std.testing.expectEqualStrings("wss://myrelay.nostr1.com", iter.next().?);
    try std.testing.expect(iter.next() == null);
}

test "parseDmRelays" {
    const json =
        \\{"kind":10050,"tags":[["relay","wss://relay1.com"],["relay","wss://relay2.com"],["relay","wss://relay3.com"]]}
    ;
    var relays: [10][]const u8 = undefined;
    const count = parseDmRelays(json, &relays);
    try std.testing.expectEqual(@as(usize, 3), count);
    try std.testing.expectEqualStrings("wss://relay1.com", relays[0]);
    try std.testing.expectEqualStrings("wss://relay2.com", relays[1]);
    try std.testing.expectEqualStrings("wss://relay3.com", relays[2]);
}

test "parseContent" {
    const json = "{\"kind\":14,\"content\":\"Hello, how are you?\"}";
    const content = parseContent(json).?;
    try std.testing.expectEqualStrings("Hello, how are you?", content);
}

test "parsePubkey" {
    const json =
        \\{"pubkey":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","kind":14}
    ;
    const pubkey = parsePubkey(json).?;
    var expected: [32]u8 = undefined;
    @memset(&expected, 0xaa);
    try std.testing.expectEqualSlices(u8, &expected, &pubkey);
}

test "parseKind" {
    try std.testing.expectEqual(@as(?i32, 14), parseKind("{\"kind\":14}"));
    try std.testing.expectEqual(@as(?i32, 1059), parseKind("{\"kind\":1059}"));
    try std.testing.expectEqual(@as(?i32, 10050), parseKind("{\"kind\":10050}"));
}

test "parseGiftWrapRecipient invalid hex" {
    const json = "{\"tags\":[[\"p\",\"invalidhex\"]]}";
    try std.testing.expect(parseGiftWrapRecipient(json) == null);
}

test "parseReplyTo missing" {
    const json = "{\"kind\":14,\"tags\":[[\"p\",\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"]]}";
    try std.testing.expect(parseReplyTo(json) == null);
}

test "RelayIterator empty" {
    const json = "{\"kind\":10050,\"tags\":[]}";
    var iter = RelayIterator.init(json);
    try std.testing.expect(iter.next() == null);
}
