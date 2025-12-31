const std = @import("std");
const utils = @import("utils.zig");
const hex = @import("hex.zig");

pub const Kind = struct {
    pub const channel_create: i32 = 40;
    pub const channel_metadata: i32 = 41;
    pub const channel_message: i32 = 42;
    pub const hide_message: i32 = 43;
    pub const mute_user: i32 = 44;
};

pub const ChannelMetadata = struct {
    name: ?[]const u8 = null,
    about: ?[]const u8 = null,
    picture: ?[]const u8 = null,
    relays_json: ?[]const u8 = null,
};

pub const ETagRef = struct {
    event_id: []const u8,
    relay: ?[]const u8 = null,
    marker: ?[]const u8 = null,
};

pub fn parseChannelMetadata(content: []const u8) ChannelMetadata {
    return .{
        .name = extractStringField(content, "name"),
        .about = extractStringField(content, "about"),
        .picture = extractStringField(content, "picture"),
        .relays_json = extractArrayField(content, "relays"),
    };
}

pub fn parseReason(content: []const u8) ?[]const u8 {
    return extractStringField(content, "reason");
}

pub fn parseChannelRef(event_json: []const u8) ?[32]u8 {
    var iter = ETagIterator.init(event_json);
    while (iter.next()) |tag| {
        if (tag.marker) |m| {
            if (std.mem.eql(u8, m, "root")) {
                var out: [32]u8 = undefined;
                hex.decode(tag.event_id, &out) catch continue;
                return out;
            }
        }
    }
    return null;
}

pub fn parseReplyRef(event_json: []const u8) ?[32]u8 {
    var iter = ETagIterator.init(event_json);
    while (iter.next()) |tag| {
        if (tag.marker) |m| {
            if (std.mem.eql(u8, m, "reply")) {
                var out: [32]u8 = undefined;
                hex.decode(tag.event_id, &out) catch continue;
                return out;
            }
        }
    }
    return null;
}

pub fn parseChannelMetadataRef(event_json: []const u8) ?[32]u8 {
    var iter = ETagIterator.init(event_json);
    if (iter.next()) |tag| {
        var out: [32]u8 = undefined;
        hex.decode(tag.event_id, &out) catch return null;
        return out;
    }
    return null;
}

pub fn parseHiddenEventId(event_json: []const u8) ?[32]u8 {
    return parseChannelMetadataRef(event_json);
}

pub fn parseMutedPubkey(event_json: []const u8) ?[32]u8 {
    const p_start = std.mem.indexOf(u8, event_json, "[\"p\",\"") orelse return null;
    const hex_start = p_start + 6;
    if (hex_start + 64 > event_json.len) return null;
    var out: [32]u8 = undefined;
    hex.decode(event_json[hex_start..][0..64], &out) catch return null;
    return out;
}

pub const ETagIterator = struct {
    json: []const u8,
    pos: usize,

    pub fn init(event_json: []const u8) ETagIterator {
        return .{ .json = event_json, .pos = 0 };
    }

    pub fn next(self: *ETagIterator) ?ETagRef {
        while (self.pos < self.json.len) {
            const tag_start = std.mem.indexOf(u8, self.json[self.pos..], "[\"e\",\"");
            if (tag_start == null) return null;

            const abs_start = self.pos + tag_start.? + 6;
            self.pos = abs_start;

            if (abs_start + 64 > self.json.len) return null;

            const event_id = self.json[abs_start..][0..64];
            var valid = true;
            for (event_id) |c| {
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
            if (self.pos >= self.json.len or self.json[self.pos] != '"') return null;
            self.pos += 1;

            const tag_end = std.mem.indexOf(u8, self.json[self.pos..], "]") orelse return null;
            const rest = self.json[self.pos..][0..tag_end];
            self.pos += tag_end + 1;

            var relay: ?[]const u8 = null;
            var marker: ?[]const u8 = null;

            var field_idx: usize = 0;
            var i: usize = 0;
            while (i < rest.len) {
                if (rest[i] == '"') {
                    const str_start = i + 1;
                    const str_end = std.mem.indexOf(u8, rest[str_start..], "\"") orelse break;
                    const value = rest[str_start..][0..str_end];
                    if (field_idx == 0) {
                        if (value.len > 0) relay = value;
                    } else if (field_idx == 1) {
                        if (value.len > 0) marker = value;
                    }
                    field_idx += 1;
                    i = str_start + str_end + 1;
                } else {
                    i += 1;
                }
            }

            return .{ .event_id = event_id, .relay = relay, .marker = marker };
        }
        return null;
    }
};

fn extractStringField(json: []const u8, key: []const u8) ?[]const u8 {
    const start = utils.findJsonFieldStart(json, key) orelse return null;
    if (start >= json.len or json[start] != '"') return null;
    const str_start = start + 1;
    const str_end = utils.findStringEnd(json, str_start) orelse return null;
    if (str_end <= str_start) return null;
    return json[str_start..str_end];
}

fn extractArrayField(json: []const u8, key: []const u8) ?[]const u8 {
    const start = utils.findJsonFieldStart(json, key) orelse return null;
    if (start >= json.len or json[start] != '[') return null;
    var depth: i32 = 0;
    var end = start;
    var in_string = false;
    var escape = false;
    for (json[start..], 0..) |c, i| {
        if (escape) {
            escape = false;
            continue;
        }
        if (c == '\\' and in_string) {
            escape = true;
            continue;
        }
        if (c == '"' and !escape) {
            in_string = !in_string;
            continue;
        }
        if (!in_string) {
            if (c == '[') depth += 1;
            if (c == ']') {
                depth -= 1;
                if (depth == 0) {
                    end = start + i + 1;
                    break;
                }
            }
        }
    }
    if (depth != 0) return null;
    return json[start..end];
}

test "Kind constants" {
    try std.testing.expectEqual(@as(i32, 40), Kind.channel_create);
    try std.testing.expectEqual(@as(i32, 41), Kind.channel_metadata);
    try std.testing.expectEqual(@as(i32, 42), Kind.channel_message);
    try std.testing.expectEqual(@as(i32, 43), Kind.hide_message);
    try std.testing.expectEqual(@as(i32, 44), Kind.mute_user);
}

test "parseChannelMetadata" {
    const content =
        \\{"name": "Demo Channel", "about": "A test channel.", "picture": "https://example.com/pic.png", "relays": ["wss://nos.lol", "wss://nostr.mom"]}
    ;
    const meta = parseChannelMetadata(content);
    try std.testing.expectEqualStrings("Demo Channel", meta.name.?);
    try std.testing.expectEqualStrings("A test channel.", meta.about.?);
    try std.testing.expectEqualStrings("https://example.com/pic.png", meta.picture.?);
    try std.testing.expectEqualStrings("[\"wss://nos.lol\", \"wss://nostr.mom\"]", meta.relays_json.?);
}

test "parseChannelMetadata partial" {
    const content = "{\"name\": \"Just Name\"}";
    const meta = parseChannelMetadata(content);
    try std.testing.expectEqualStrings("Just Name", meta.name.?);
    try std.testing.expect(meta.about == null);
    try std.testing.expect(meta.picture == null);
    try std.testing.expect(meta.relays_json == null);
}

test "parseReason" {
    const content = "{\"reason\": \"Spam content\"}";
    const reason = parseReason(content).?;
    try std.testing.expectEqualStrings("Spam content", reason);
}

test "parseReason missing" {
    const content = "{\"other\": \"field\"}";
    try std.testing.expect(parseReason(content) == null);
}

test "parseChannelRef" {
    const json =
        \\{"kind":42,"tags":[["e","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","wss://relay.example.com","root"]]}
    ;
    const ref = parseChannelRef(json).?;
    var expected: [32]u8 = undefined;
    @memset(&expected, 0xaa);
    try std.testing.expectEqualSlices(u8, &expected, &ref);
}

test "parseReplyRef" {
    const json =
        \\{"kind":42,"tags":[["e","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","wss://relay.example.com","root"],["e","bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","wss://relay.example.com","reply"]]}
    ;
    const ref = parseReplyRef(json).?;
    var expected: [32]u8 = undefined;
    @memset(&expected, 0xbb);
    try std.testing.expectEqualSlices(u8, &expected, &ref);
}

test "parseChannelMetadataRef" {
    const json =
        \\{"kind":41,"tags":[["e","eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","wss://relay.example.com"]]}
    ;
    const ref = parseChannelMetadataRef(json).?;
    var expected: [32]u8 = undefined;
    @memset(&expected, 0xee);
    try std.testing.expectEqualSlices(u8, &expected, &ref);
}

test "parseHiddenEventId" {
    const json =
        \\{"kind":43,"tags":[["e","cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"]]}
    ;
    const ref = parseHiddenEventId(json).?;
    var expected: [32]u8 = undefined;
    @memset(&expected, 0xcc);
    try std.testing.expectEqualSlices(u8, &expected, &ref);
}

test "parseMutedPubkey" {
    const json =
        \\{"kind":44,"tags":[["p","dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"]]}
    ;
    const ref = parseMutedPubkey(json).?;
    var expected: [32]u8 = undefined;
    @memset(&expected, 0xdd);
    try std.testing.expectEqualSlices(u8, &expected, &ref);
}

test "ETagIterator multiple tags" {
    const json =
        \\{"tags":[["e","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","wss://r1.com","root"],["e","bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","wss://r2.com","reply"]]}
    ;
    var iter = ETagIterator.init(json);

    const first = iter.next().?;
    try std.testing.expectEqualStrings("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", first.event_id);
    try std.testing.expectEqualStrings("wss://r1.com", first.relay.?);
    try std.testing.expectEqualStrings("root", first.marker.?);

    const second = iter.next().?;
    try std.testing.expectEqualStrings("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", second.event_id);
    try std.testing.expectEqualStrings("wss://r2.com", second.relay.?);
    try std.testing.expectEqualStrings("reply", second.marker.?);

    try std.testing.expect(iter.next() == null);
}

test "ETagIterator no marker" {
    const json =
        \\{"tags":[["e","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]]}
    ;
    var iter = ETagIterator.init(json);
    const tag = iter.next().?;
    try std.testing.expectEqualStrings("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", tag.event_id);
    try std.testing.expect(tag.relay == null);
    try std.testing.expect(tag.marker == null);
}

test "parseMutedPubkey invalid hex" {
    const json = "{\"tags\":[[\"p\",\"invalidhex\"]]}";
    try std.testing.expect(parseMutedPubkey(json) == null);
}

test "parseMutedPubkey missing tag" {
    const json = "{\"tags\":[[\"e\",\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"]]}";
    try std.testing.expect(parseMutedPubkey(json) == null);
}
