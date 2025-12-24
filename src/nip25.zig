//! NIP-25: Reactions
//!
//! A reaction is a `kind 7` event used to indicate user reactions to other events.
//! Supports like (+), dislike (-), emoji, and custom emoji reactions.
//! External content reactions use `kind 17` with NIP-73 `k` + `i` tags.
//!
//! See: https://github.com/nostr-protocol/nips/blob/master/25.md

const std = @import("std");
const event_mod = @import("event.zig");
const utils = @import("utils.zig");

pub const Event = event_mod.Event;

pub const REACTION_KIND: i32 = 7;
pub const EXTERNAL_REACTION_KIND: i32 = 17;

pub const ReactionType = enum {
    like,
    dislike,
    emoji,
    custom_emoji,

    pub fn isPositive(self: ReactionType) bool {
        return self == .like;
    }

    pub fn isNegative(self: ReactionType) bool {
        return self == .dislike;
    }
};

pub const ReactionInfo = struct {
    event_id: ?[32]u8,
    relay_url: ?[]const u8,
    author_pubkey: ?[32]u8,
    reacted_kind: ?i32,
    event_coordinate: ?[]const u8,
    reaction_type: ReactionType,
    content: []const u8,
    custom_emoji_url: ?[]const u8,

    pub fn fromEvent(event: *const Event) !ReactionInfo {
        if (event.kind() != REACTION_KIND) {
            return error.InvalidKind;
        }

        const content = event.content();
        const reaction_type = getReactionType(content);

        var info = ReactionInfo{
            .event_id = null,
            .relay_url = null,
            .author_pubkey = null,
            .reacted_kind = null,
            .event_coordinate = null,
            .reaction_type = reaction_type,
            .content = content,
            .custom_emoji_url = null,
        };

        const tags_json = utils.findJsonValue(event.raw_json, "tags") orelse return error.MissingEventTag;
        var iter = ReactionTagIterator.init(tags_json);

        var found_e_tag = false;
        while (iter.next()) |tag| {
            if (std.mem.eql(u8, tag.name, "e")) {
                if (tag.value.len == 64) {
                    var bytes: [32]u8 = undefined;
                    if (std.fmt.hexToBytes(&bytes, tag.value)) |_| {
                        info.event_id = bytes;
                        found_e_tag = true;
                        if (tag.third) |relay| {
                            if (relay.len > 0) {
                                info.relay_url = relay;
                            }
                        }
                        if (tag.fourth) |pk| {
                            if (pk.len == 64) {
                                var pk_bytes: [32]u8 = undefined;
                                if (std.fmt.hexToBytes(&pk_bytes, pk)) |_| {
                                    info.author_pubkey = pk_bytes;
                                } else |_| {}
                            }
                        }
                    } else |_| {}
                }
            } else if (std.mem.eql(u8, tag.name, "p")) {
                // Per NIP-25: "the target event pubkey should be last of the p tags"
                // So we keep updating to get the last valid p tag
                if (tag.value.len == 64) {
                    var bytes: [32]u8 = undefined;
                    if (std.fmt.hexToBytes(&bytes, tag.value)) |_| {
                        info.author_pubkey = bytes;
                    } else |_| {}
                }
            } else if (std.mem.eql(u8, tag.name, "k")) {
                info.reacted_kind = std.fmt.parseInt(i32, tag.value, 10) catch null;
            } else if (std.mem.eql(u8, tag.name, "a")) {
                info.event_coordinate = tag.value;
            } else if (std.mem.eql(u8, tag.name, "emoji")) {
                if (tag.third) |url| {
                    info.custom_emoji_url = url;
                }
            }
        }

        if (!found_e_tag) {
            return error.MissingEventTag;
        }

        return info;
    }
};

pub const ExternalReactionInfo = struct {
    external_type: ?[]const u8,
    external_id: ?[]const u8,
    external_url: ?[]const u8,
    reaction_type: ReactionType,
    content: []const u8,

    pub fn fromEvent(event: *const Event) !ExternalReactionInfo {
        if (event.kind() != EXTERNAL_REACTION_KIND) {
            return error.InvalidKind;
        }

        const content = event.content();
        const reaction_type = getReactionType(content);

        var info = ExternalReactionInfo{
            .external_type = null,
            .external_id = null,
            .external_url = null,
            .reaction_type = reaction_type,
            .content = content,
        };

        const tags_json = utils.findJsonValue(event.raw_json, "tags") orelse return error.MissingTags;
        var iter = ReactionTagIterator.init(tags_json);

        var found_k_tag = false;
        var found_i_tag = false;

        while (iter.next()) |tag| {
            if (std.mem.eql(u8, tag.name, "k")) {
                info.external_type = tag.value;
                found_k_tag = true;
            } else if (std.mem.eql(u8, tag.name, "i")) {
                info.external_id = tag.value;
                found_i_tag = true;
                if (tag.third) |url| {
                    info.external_url = url;
                }
            }
        }

        if (!found_k_tag or !found_i_tag) {
            return error.MissingTags;
        }

        return info;
    }
};

pub fn isReaction(event: *const Event) bool {
    return event.kind() == REACTION_KIND;
}

pub fn isExternalReaction(event: *const Event) bool {
    return event.kind() == EXTERNAL_REACTION_KIND;
}

pub fn isAnyReaction(event: *const Event) bool {
    const k = event.kind();
    return k == REACTION_KIND or k == EXTERNAL_REACTION_KIND;
}

pub fn getReactionType(content: []const u8) ReactionType {
    if (content.len == 0 or std.mem.eql(u8, content, "+")) {
        return .like;
    }
    if (std.mem.eql(u8, content, "-")) {
        return .dislike;
    }
    if (content.len >= 3 and content[0] == ':' and content[content.len - 1] == ':') {
        return .custom_emoji;
    }
    return .emoji;
}

pub fn isLike(event: *const Event) bool {
    if (!isReaction(event) and !isExternalReaction(event)) return false;
    return getReactionType(event.content()).isPositive();
}

pub fn isDislike(event: *const Event) bool {
    if (!isReaction(event) and !isExternalReaction(event)) return false;
    return getReactionType(event.content()).isNegative();
}

pub fn buildReactionTags(
    event_id_hex: []const u8,
    author_pubkey_hex: ?[]const u8,
    relay_hint: ?[]const u8,
    reacted_kind: ?i32,
    buf: [][]const []const u8,
    string_buf: [][]const u8,
    kind_buf: *[11]u8,
) usize {
    var tag_idx: usize = 0;
    var str_idx: usize = 0;

    if (str_idx + 4 > string_buf.len or tag_idx >= buf.len) return 0;
    string_buf[str_idx] = "e";
    string_buf[str_idx + 1] = event_id_hex;

    var e_tag_size: usize = 2;
    if (relay_hint) |hint| {
        string_buf[str_idx + 2] = hint;
        e_tag_size = 3;
        if (author_pubkey_hex) |pk| {
            string_buf[str_idx + 3] = pk;
            e_tag_size = 4;
        }
    }
    buf[tag_idx] = string_buf[str_idx .. str_idx + e_tag_size];
    str_idx += e_tag_size;
    tag_idx += 1;

    if (author_pubkey_hex) |pk| {
        if (str_idx + 3 > string_buf.len or tag_idx >= buf.len) return tag_idx;
        string_buf[str_idx] = "p";
        string_buf[str_idx + 1] = pk;
        var p_tag_size: usize = 2;
        if (relay_hint) |hint| {
            string_buf[str_idx + 2] = hint;
            p_tag_size = 3;
        }
        buf[tag_idx] = string_buf[str_idx .. str_idx + p_tag_size];
        str_idx += p_tag_size;
        tag_idx += 1;
    }

    if (reacted_kind) |k| {
        if (str_idx + 2 > string_buf.len or tag_idx >= buf.len) return tag_idx;
        const kind_str = std.fmt.bufPrint(kind_buf, "{d}", .{k}) catch return tag_idx;
        string_buf[str_idx] = "k";
        string_buf[str_idx + 1] = kind_str;
        buf[tag_idx] = string_buf[str_idx .. str_idx + 2];
        tag_idx += 1;
    }

    return tag_idx;
}

pub fn buildAddressableReactionTags(
    event_id_hex: []const u8,
    author_pubkey_hex: ?[]const u8,
    relay_hint: ?[]const u8,
    reacted_kind: i32,
    coordinate: []const u8,
    buf: [][]const []const u8,
    string_buf: [][]const u8,
    kind_buf: *[11]u8,
) usize {
    var count = buildReactionTags(
        event_id_hex,
        author_pubkey_hex,
        relay_hint,
        reacted_kind,
        buf,
        string_buf,
        kind_buf,
    );

    var str_idx: usize = 0;
    for (buf[0..count]) |tag| {
        str_idx += tag.len;
    }

    var a_tag_size: usize = 2;
    if (relay_hint != null) a_tag_size = 3;
    if (str_idx + a_tag_size > string_buf.len or count >= buf.len) return count;

    string_buf[str_idx] = "a";
    string_buf[str_idx + 1] = coordinate;
    if (relay_hint) |hint| {
        string_buf[str_idx + 2] = hint;
    }
    buf[count] = string_buf[str_idx .. str_idx + a_tag_size];
    count += 1;

    return count;
}

pub fn buildExternalReactionTags(
    external_type: []const u8,
    external_id: []const u8,
    external_url: ?[]const u8,
    buf: [][]const []const u8,
    string_buf: [][]const u8,
) usize {
    var tag_idx: usize = 0;
    var str_idx: usize = 0;

    if (str_idx + 2 > string_buf.len or tag_idx >= buf.len) return 0;
    string_buf[str_idx] = "k";
    string_buf[str_idx + 1] = external_type;
    buf[tag_idx] = string_buf[str_idx .. str_idx + 2];
    str_idx += 2;
    tag_idx += 1;

    if (str_idx + 3 > string_buf.len or tag_idx >= buf.len) return tag_idx;
    string_buf[str_idx] = "i";
    string_buf[str_idx + 1] = external_id;
    var i_tag_size: usize = 2;
    if (external_url) |url| {
        string_buf[str_idx + 2] = url;
        i_tag_size = 3;
    }
    buf[tag_idx] = string_buf[str_idx .. str_idx + i_tag_size];
    tag_idx += 1;

    return tag_idx;
}

pub fn buildCustomEmojiTag(
    shortcode: []const u8,
    image_url: []const u8,
    buf: [][]const []const u8,
    string_buf: [][]const u8,
) usize {
    if (string_buf.len < 3 or buf.len < 1) return 0;
    string_buf[0] = "emoji";
    string_buf[1] = shortcode;
    string_buf[2] = image_url;
    buf[0] = string_buf[0..3];
    return 1;
}

const ReactionTagIterator = struct {
    json: []const u8,
    pos: usize,

    const Tag = struct {
        name: []const u8,
        value: []const u8,
        third: ?[]const u8,
        fourth: ?[]const u8,
    };

    fn init(json: []const u8) ReactionTagIterator {
        return .{ .json = json, .pos = 0 };
    }

    fn next(self: *ReactionTagIterator) ?Tag {
        while (self.pos < self.json.len) {
            const tag_start = self.findBracket('[') orelse return null;
            self.pos = tag_start + 1;
            const tag_end = self.findBracket(']') orelse return null;
            self.pos = tag_end + 1;

            const tag_content = self.json[tag_start + 1 .. tag_end];
            if (self.parseTag(tag_content)) |tag| {
                return tag;
            }
        }
        return null;
    }

    fn findBracket(self: *ReactionTagIterator, bracket: u8) ?usize {
        var in_string = false;
        var escape = false;

        while (self.pos < self.json.len) {
            const c = self.json[self.pos];

            if (escape) {
                escape = false;
                self.pos += 1;
                continue;
            }

            if (c == '\\' and in_string) {
                escape = true;
                self.pos += 1;
                continue;
            }

            if (c == '"') {
                in_string = !in_string;
                self.pos += 1;
                continue;
            }

            if (!in_string and c == bracket) {
                return self.pos;
            }

            self.pos += 1;
        }
        return null;
    }

    fn parseTag(self: *const ReactionTagIterator, content: []const u8) ?Tag {
        _ = self;
        var strings: [4][]const u8 = undefined;
        var count: usize = 0;

        var i: usize = 0;
        while (i < content.len and count < 4) {
            const quote_start = std.mem.indexOfPos(u8, content, i, "\"") orelse break;
            const str_start = quote_start + 1;
            const quote_end = findStringEnd(content, str_start) orelse break;
            strings[count] = content[str_start..quote_end];
            count += 1;
            i = quote_end + 1;
        }

        if (count < 2) return null;

        return .{
            .name = strings[0],
            .value = strings[1],
            .third = if (count >= 3) strings[2] else null,
            .fourth = if (count >= 4) strings[3] else null,
        };
    }

    fn findStringEnd(content: []const u8, start: usize) ?usize {
        var i = start;
        while (i < content.len) {
            if (content[i] == '\\' and i + 1 < content.len) {
                i += 2;
                continue;
            }
            if (content[i] == '"') return i;
            i += 1;
        }
        return null;
    }
};

test "isReaction detects kind 7" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":7,"created_at":1700000000,"content":"+","tags":[["e","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    try std.testing.expect(isReaction(&event));
    try std.testing.expect(!isExternalReaction(&event));
    try std.testing.expect(isAnyReaction(&event));
}

test "isExternalReaction detects kind 17" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":17,"created_at":1700000000,"content":"+","tags":[["k","web"],["i","https://example.com"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    try std.testing.expect(!isReaction(&event));
    try std.testing.expect(isExternalReaction(&event));
    try std.testing.expect(isAnyReaction(&event));
}

test "getReactionType identifies like reactions" {
    try std.testing.expectEqual(ReactionType.like, getReactionType("+"));
    try std.testing.expectEqual(ReactionType.like, getReactionType(""));
    try std.testing.expect(getReactionType("+").isPositive());
    try std.testing.expect(!getReactionType("+").isNegative());
}

test "getReactionType identifies dislike reactions" {
    try std.testing.expectEqual(ReactionType.dislike, getReactionType("-"));
    try std.testing.expect(getReactionType("-").isNegative());
    try std.testing.expect(!getReactionType("-").isPositive());
}

test "getReactionType identifies emoji reactions" {
    try std.testing.expectEqual(ReactionType.emoji, getReactionType("👍"));
    try std.testing.expectEqual(ReactionType.emoji, getReactionType("❤️"));
    try std.testing.expectEqual(ReactionType.emoji, getReactionType("🔥"));
}

test "getReactionType identifies custom emoji reactions" {
    try std.testing.expectEqual(ReactionType.custom_emoji, getReactionType(":soapbox:"));
    try std.testing.expectEqual(ReactionType.custom_emoji, getReactionType(":nostr:"));
    try std.testing.expectEqual(ReactionType.custom_emoji, getReactionType(":abc:"));
}

test "ReactionInfo.fromEvent parses like reaction" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":7,"created_at":1700000000,"content":"+","tags":[["e","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","wss://relay.example.com","bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"],["p","bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","wss://relay.example.com"],["k","1"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    const info = try ReactionInfo.fromEvent(&event);

    try std.testing.expect(info.event_id != null);
    for (info.event_id.?) |byte| {
        try std.testing.expectEqual(@as(u8, 0xaa), byte);
    }

    try std.testing.expectEqualStrings("wss://relay.example.com", info.relay_url.?);

    try std.testing.expect(info.author_pubkey != null);
    for (info.author_pubkey.?) |byte| {
        try std.testing.expectEqual(@as(u8, 0xbb), byte);
    }

    try std.testing.expectEqual(@as(i32, 1), info.reacted_kind.?);
    try std.testing.expectEqual(ReactionType.like, info.reaction_type);
    try std.testing.expectEqualStrings("+", info.content);
}

test "ReactionInfo.fromEvent parses emoji reaction" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":7,"created_at":1700000000,"content":"🔥","tags":[["e","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    const info = try ReactionInfo.fromEvent(&event);

    try std.testing.expectEqual(ReactionType.emoji, info.reaction_type);
    try std.testing.expect(info.event_id != null);
}

test "ReactionInfo.fromEvent parses custom emoji reaction" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":7,"created_at":1700000000,"content":":soapbox:","tags":[["e","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],["emoji","soapbox","https://gleasonator.com/emoji/Gleasonator/soapbox.png"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    const info = try ReactionInfo.fromEvent(&event);

    try std.testing.expectEqual(ReactionType.custom_emoji, info.reaction_type);
    try std.testing.expectEqualStrings(":soapbox:", info.content);
    try std.testing.expectEqualStrings("https://gleasonator.com/emoji/Gleasonator/soapbox.png", info.custom_emoji_url.?);
}

test "ReactionInfo.fromEvent fails without e tag" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":7,"created_at":1700000000,"content":"+","tags":[["p","bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    const result = ReactionInfo.fromEvent(&event);
    try std.testing.expectError(error.MissingEventTag, result);
}

test "ReactionInfo.fromEvent fails for wrong kind" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":1,"created_at":1700000000,"content":"+","tags":[["e","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    const result = ReactionInfo.fromEvent(&event);
    try std.testing.expectError(error.InvalidKind, result);
}

test "ReactionInfo.fromEvent uses last p tag per NIP-25 spec" {
    try event_mod.init();
    defer event_mod.cleanup();

    // Per NIP-25: "the target event pubkey should be last of the p tags"
    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":7,"created_at":1700000000,"content":"+","tags":[["p","1111111111111111111111111111111111111111111111111111111111111111"],["e","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],["p","bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    const info = try ReactionInfo.fromEvent(&event);

    // Should use the LAST p tag (0xbb...), not the first (0x11...)
    try std.testing.expect(info.author_pubkey != null);
    for (info.author_pubkey.?) |byte| {
        try std.testing.expectEqual(@as(u8, 0xbb), byte);
    }
}

test "ExternalReactionInfo.fromEvent parses web reaction" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":17,"created_at":1700000000,"content":"⭐","tags":[["k","web"],["i","https://example.com"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    const info = try ExternalReactionInfo.fromEvent(&event);

    try std.testing.expectEqualStrings("web", info.external_type.?);
    try std.testing.expectEqualStrings("https://example.com", info.external_id.?);
    try std.testing.expectEqual(ReactionType.emoji, info.reaction_type);
}

test "ExternalReactionInfo.fromEvent parses podcast reaction with url" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":17,"created_at":1700000000,"content":"+","tags":[["k","podcast:guid"],["i","podcast:guid:917393e3-1b1e-5cef-ace4-edaa54e1f810","https://fountain.fm/show/QRT0l2EfrKXNGDlRrmjL"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    const info = try ExternalReactionInfo.fromEvent(&event);

    try std.testing.expectEqualStrings("podcast:guid", info.external_type.?);
    try std.testing.expectEqualStrings("podcast:guid:917393e3-1b1e-5cef-ace4-edaa54e1f810", info.external_id.?);
    try std.testing.expectEqualStrings("https://fountain.fm/show/QRT0l2EfrKXNGDlRrmjL", info.external_url.?);
    try std.testing.expectEqual(ReactionType.like, info.reaction_type);
}

test "ExternalReactionInfo.fromEvent fails without k tag" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":17,"created_at":1700000000,"content":"+","tags":[["i","https://example.com"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    const result = ExternalReactionInfo.fromEvent(&event);
    try std.testing.expectError(error.MissingTags, result);
}

test "ExternalReactionInfo.fromEvent fails without i tag" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":17,"created_at":1700000000,"content":"+","tags":[["k","web"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    const result = ExternalReactionInfo.fromEvent(&event);
    try std.testing.expectError(error.MissingTags, result);
}

test "isLike and isDislike helper functions" {
    try event_mod.init();
    defer event_mod.cleanup();

    const like_json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":7,"created_at":1700000000,"content":"+","tags":[["e","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]]}
    ;

    var like_event = try Event.parse(like_json);
    defer like_event.deinit();

    try std.testing.expect(isLike(&like_event));
    try std.testing.expect(!isDislike(&like_event));

    const dislike_json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":7,"created_at":1700000000,"content":"-","tags":[["e","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]]}
    ;

    var dislike_event = try Event.parse(dislike_json);
    defer dislike_event.deinit();

    try std.testing.expect(!isLike(&dislike_event));
    try std.testing.expect(isDislike(&dislike_event));
}

test "buildReactionTags creates correct structure" {
    var tag_buf: [10][]const []const u8 = undefined;
    var string_buf: [30][]const u8 = undefined;
    var kind_buf: [11]u8 = undefined;

    const event_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const author_pk = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const relay = "wss://relay.example.com";

    const count = buildReactionTags(
        event_id,
        author_pk,
        relay,
        1,
        &tag_buf,
        &string_buf,
        &kind_buf,
    );

    try std.testing.expectEqual(@as(usize, 3), count);

    try std.testing.expectEqual(@as(usize, 4), tag_buf[0].len);
    try std.testing.expectEqualStrings("e", tag_buf[0][0]);
    try std.testing.expectEqualStrings(event_id, tag_buf[0][1]);
    try std.testing.expectEqualStrings(relay, tag_buf[0][2]);
    try std.testing.expectEqualStrings(author_pk, tag_buf[0][3]);

    try std.testing.expectEqual(@as(usize, 3), tag_buf[1].len);
    try std.testing.expectEqualStrings("p", tag_buf[1][0]);
    try std.testing.expectEqualStrings(author_pk, tag_buf[1][1]);
    try std.testing.expectEqualStrings(relay, tag_buf[1][2]);

    try std.testing.expectEqual(@as(usize, 2), tag_buf[2].len);
    try std.testing.expectEqualStrings("k", tag_buf[2][0]);
    try std.testing.expectEqualStrings("1", tag_buf[2][1]);
}

test "buildReactionTags without relay hint" {
    var tag_buf: [10][]const []const u8 = undefined;
    var string_buf: [30][]const u8 = undefined;
    var kind_buf: [11]u8 = undefined;

    const event_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const author_pk = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    const count = buildReactionTags(
        event_id,
        author_pk,
        null,
        null,
        &tag_buf,
        &string_buf,
        &kind_buf,
    );

    try std.testing.expectEqual(@as(usize, 2), count);

    try std.testing.expectEqual(@as(usize, 2), tag_buf[0].len);
    try std.testing.expectEqualStrings("e", tag_buf[0][0]);
    try std.testing.expectEqualStrings(event_id, tag_buf[0][1]);

    try std.testing.expectEqual(@as(usize, 2), tag_buf[1].len);
    try std.testing.expectEqualStrings("p", tag_buf[1][0]);
    try std.testing.expectEqualStrings(author_pk, tag_buf[1][1]);
}

test "buildAddressableReactionTags includes a tag" {
    var tag_buf: [10][]const []const u8 = undefined;
    var string_buf: [30][]const u8 = undefined;
    var kind_buf: [11]u8 = undefined;

    const event_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const author_pk = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const coordinate = "30023:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb:my-article";

    const count = buildAddressableReactionTags(
        event_id,
        author_pk,
        null,
        30023,
        coordinate,
        &tag_buf,
        &string_buf,
        &kind_buf,
    );

    try std.testing.expectEqual(@as(usize, 4), count);

    try std.testing.expectEqualStrings("e", tag_buf[0][0]);
    try std.testing.expectEqualStrings("p", tag_buf[1][0]);
    try std.testing.expectEqualStrings("k", tag_buf[2][0]);
    try std.testing.expectEqualStrings("30023", tag_buf[2][1]);
    try std.testing.expectEqualStrings("a", tag_buf[3][0]);
    try std.testing.expectEqualStrings(coordinate, tag_buf[3][1]);
    try std.testing.expectEqual(@as(usize, 2), tag_buf[3].len);
}

test "buildAddressableReactionTags includes relay hint in a tag" {
    var tag_buf: [10][]const []const u8 = undefined;
    var string_buf: [30][]const u8 = undefined;
    var kind_buf: [11]u8 = undefined;

    const event_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const author_pk = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const relay = "wss://relay.example.com";
    const coordinate = "30023:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb:my-article";

    const count = buildAddressableReactionTags(
        event_id,
        author_pk,
        relay,
        30023,
        coordinate,
        &tag_buf,
        &string_buf,
        &kind_buf,
    );

    try std.testing.expectEqual(@as(usize, 4), count);

    try std.testing.expectEqualStrings("a", tag_buf[3][0]);
    try std.testing.expectEqualStrings(coordinate, tag_buf[3][1]);
    try std.testing.expectEqual(@as(usize, 3), tag_buf[3].len);
    try std.testing.expectEqualStrings(relay, tag_buf[3][2]);
}

test "buildExternalReactionTags creates correct structure" {
    var tag_buf: [10][]const []const u8 = undefined;
    var string_buf: [30][]const u8 = undefined;

    const count = buildExternalReactionTags(
        "web",
        "https://example.com",
        null,
        &tag_buf,
        &string_buf,
    );

    try std.testing.expectEqual(@as(usize, 2), count);

    try std.testing.expectEqual(@as(usize, 2), tag_buf[0].len);
    try std.testing.expectEqualStrings("k", tag_buf[0][0]);
    try std.testing.expectEqualStrings("web", tag_buf[0][1]);

    try std.testing.expectEqual(@as(usize, 2), tag_buf[1].len);
    try std.testing.expectEqualStrings("i", tag_buf[1][0]);
    try std.testing.expectEqualStrings("https://example.com", tag_buf[1][1]);
}

test "buildExternalReactionTags with url hint" {
    var tag_buf: [10][]const []const u8 = undefined;
    var string_buf: [30][]const u8 = undefined;

    const count = buildExternalReactionTags(
        "podcast:guid",
        "podcast:guid:917393e3-1b1e-5cef-ace4-edaa54e1f810",
        "https://fountain.fm/show/QRT0l2EfrKXNGDlRrmjL",
        &tag_buf,
        &string_buf,
    );

    try std.testing.expectEqual(@as(usize, 2), count);

    try std.testing.expectEqual(@as(usize, 3), tag_buf[1].len);
    try std.testing.expectEqualStrings("i", tag_buf[1][0]);
    try std.testing.expectEqualStrings("podcast:guid:917393e3-1b1e-5cef-ace4-edaa54e1f810", tag_buf[1][1]);
    try std.testing.expectEqualStrings("https://fountain.fm/show/QRT0l2EfrKXNGDlRrmjL", tag_buf[1][2]);
}

test "buildCustomEmojiTag creates correct structure" {
    var tag_buf: [10][]const []const u8 = undefined;
    var string_buf: [30][]const u8 = undefined;

    const count = buildCustomEmojiTag(
        "soapbox",
        "https://gleasonator.com/emoji/Gleasonator/soapbox.png",
        &tag_buf,
        &string_buf,
    );

    try std.testing.expectEqual(@as(usize, 1), count);
    try std.testing.expectEqual(@as(usize, 3), tag_buf[0].len);
    try std.testing.expectEqualStrings("emoji", tag_buf[0][0]);
    try std.testing.expectEqualStrings("soapbox", tag_buf[0][1]);
    try std.testing.expectEqualStrings("https://gleasonator.com/emoji/Gleasonator/soapbox.png", tag_buf[0][2]);
}

test "ReactionInfo parses addressable event coordinate" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":7,"created_at":1700000000,"content":"+","tags":[["e","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],["a","30023:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb:my-article"],["k","30023"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    const info = try ReactionInfo.fromEvent(&event);

    try std.testing.expectEqualStrings("30023:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb:my-article", info.event_coordinate.?);
    try std.testing.expectEqual(@as(i32, 30023), info.reacted_kind.?);
}

test "isAnyReaction returns false for non-reaction events" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":1,"created_at":1700000000,"content":"hello","tags":[]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    try std.testing.expect(!isReaction(&event));
    try std.testing.expect(!isExternalReaction(&event));
    try std.testing.expect(!isAnyReaction(&event));
}
