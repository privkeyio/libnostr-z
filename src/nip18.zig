const std = @import("std");
const event_mod = @import("event.zig");
const utils = @import("utils.zig");
const hex = @import("hex.zig");

pub const Event = event_mod.Event;

pub const REPOST_KIND: i32 = 6;
pub const GENERIC_REPOST_KIND: i32 = 16;

pub fn isRepost(event: *const Event) bool {
    return event.kind() == REPOST_KIND;
}

pub fn isGenericRepost(event: *const Event) bool {
    return event.kind() == GENERIC_REPOST_KIND;
}

pub fn isAnyRepost(event: *const Event) bool {
    const k = event.kind();
    return k == REPOST_KIND or k == GENERIC_REPOST_KIND;
}

pub const RepostInfo = struct {
    event_id: [32]u8,
    relay_url: ?[]const u8,
    author_pubkey: ?[32]u8,
    reposted_kind: ?i32,
    event_coordinate: ?[]const u8,

    pub fn fromEvent(event: *const Event) !RepostInfo {
        const k = event.kind();
        if (k != REPOST_KIND and k != GENERIC_REPOST_KIND) {
            return error.InvalidKind;
        }

        const tags_json = utils.findJsonValue(event.raw_json, "tags") orelse return error.MissingTags;
        var iter = RepostTagIterator.init(tags_json);

        var info = RepostInfo{
            .event_id = undefined,
            .relay_url = null,
            .author_pubkey = null,
            .reposted_kind = null,
            .event_coordinate = null,
        };

        var found_e_tag = false;

        while (iter.next()) |tag| {
            if (std.mem.eql(u8, tag.name, "e") and !found_e_tag) {
                if (tag.value.len == 64) {
                    hex.decode(tag.value, &info.event_id) catch continue;
                    found_e_tag = true;
                    info.relay_url = tag.third;
                }
            } else if (std.mem.eql(u8, tag.name, "p") and info.author_pubkey == null) {
                if (tag.value.len == 64) {
                    var pubkey: [32]u8 = undefined;
                    hex.decode(tag.value, &pubkey) catch continue;
                    info.author_pubkey = pubkey;
                }
            } else if (std.mem.eql(u8, tag.name, "k") and info.reposted_kind == null) {
                info.reposted_kind = std.fmt.parseInt(i32, tag.value, 10) catch null;
            } else if (std.mem.eql(u8, tag.name, "a") and info.event_coordinate == null) {
                info.event_coordinate = tag.value;
            }
        }

        if (!found_e_tag) {
            return error.MissingEventTag;
        }

        return info;
    }
};

pub const QuoteTag = struct {
    event_id_or_address: []const u8,
    relay_url: ?[]const u8,
    pubkey: ?[]const u8,

    pub fn isEventId(self: *const QuoteTag) bool {
        if (self.event_id_or_address.len != 64) return false;
        var bytes: [32]u8 = undefined;
        hex.decode(self.event_id_or_address, &bytes) catch return false;
        return true;
    }

    pub fn getEventIdBytes(self: *const QuoteTag) ?[32]u8 {
        if (self.event_id_or_address.len != 64) return null;
        var bytes: [32]u8 = undefined;
        hex.decode(self.event_id_or_address, &bytes) catch return null;
        return bytes;
    }
};

pub fn getQuoteTags(event: *const Event, buf: []QuoteTag) []QuoteTag {
    const tags_json = utils.findJsonValue(event.raw_json, "tags") orelse return buf[0..0];
    var iter = RepostTagIterator.init(tags_json);
    var count: usize = 0;

    while (iter.next()) |tag| {
        if (count >= buf.len) break;
        if (std.mem.eql(u8, tag.name, "q")) {
            buf[count] = .{
                .event_id_or_address = tag.value,
                .relay_url = tag.third,
                .pubkey = tag.fourth,
            };
            count += 1;
        }
    }

    return buf[0..count];
}

pub fn getRepostedEventJson(event: *const Event) ?[]const u8 {
    const content = event.content();
    if (content.len == 0) return null;
    if (content[0] != '{') return null;
    return content;
}

const RepostTagIterator = struct {
    json: []const u8,
    pos: usize,

    const Entry = struct {
        name: []const u8,
        value: []const u8,
        third: ?[]const u8,
        fourth: ?[]const u8,
    };

    fn init(json: []const u8) RepostTagIterator {
        return .{ .json = json, .pos = 0 };
    }

    fn next(self: *RepostTagIterator) ?Entry {
        while (self.pos < self.json.len) {
            const tag_start = self.findBracket('[') orelse return null;
            const saved_pos = self.pos;
            self.pos = tag_start + 1;
            const tag_end = self.findBracket(']') orelse {
                self.pos = saved_pos;
                return null;
            };
            self.pos = tag_end + 1;

            const tag_content = self.json[tag_start + 1 .. tag_end];
            if (self.parseTag(tag_content)) |entry| {
                return entry;
            }
        }
        return null;
    }

    fn findBracket(self: *RepostTagIterator, bracket: u8) ?usize {
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
                const found = self.pos;
                self.pos += 1;
                return found;
            }

            self.pos += 1;
        }
        return null;
    }

    fn parseTag(self: *const RepostTagIterator, content: []const u8) ?Entry {
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
        var idx = start;
        while (idx < content.len) {
            if (content[idx] == '\\' and idx + 1 < content.len) {
                idx += 2;
                continue;
            }
            if (content[idx] == '"') return idx;
            idx += 1;
        }
        return null;
    }
};

pub fn buildRepostTags(
    event_id_hex: []const u8,
    relay_url: ?[]const u8,
    author_pubkey_hex: ?[]const u8,
    buf: [][]const []const u8,
    string_buf: [][]const u8,
) usize {
    var tag_idx: usize = 0;
    var str_idx: usize = 0;

    if (tag_idx >= buf.len) return 0;

    const e_tag_size: usize = if (relay_url != null) 3 else 2;
    if (str_idx + e_tag_size > string_buf.len) return 0;

    string_buf[str_idx] = "e";
    string_buf[str_idx + 1] = event_id_hex;
    if (relay_url) |url| {
        string_buf[str_idx + 2] = url;
    }
    buf[tag_idx] = string_buf[str_idx .. str_idx + e_tag_size];
    str_idx += e_tag_size;
    tag_idx += 1;

    if (author_pubkey_hex) |pubkey| {
        if (tag_idx < buf.len and str_idx + 2 <= string_buf.len) {
            string_buf[str_idx] = "p";
            string_buf[str_idx + 1] = pubkey;
            buf[tag_idx] = string_buf[str_idx .. str_idx + 2];
            str_idx += 2;
            tag_idx += 1;
        }
    }

    return tag_idx;
}

pub fn buildGenericRepostTags(
    event_id_hex: []const u8,
    relay_url: ?[]const u8,
    author_pubkey_hex: ?[]const u8,
    reposted_kind: i32,
    event_coordinate: ?[]const u8,
    buf: [][]const []const u8,
    string_buf: [][]const u8,
    kind_str_buf: *[11]u8,
) usize {
    var tag_idx: usize = 0;
    var str_idx: usize = 0;

    if (tag_idx >= buf.len) return 0;

    const e_tag_size: usize = if (relay_url != null) 3 else 2;
    if (str_idx + e_tag_size > string_buf.len) return 0;

    string_buf[str_idx] = "e";
    string_buf[str_idx + 1] = event_id_hex;
    if (relay_url) |url| {
        string_buf[str_idx + 2] = url;
    }
    buf[tag_idx] = string_buf[str_idx .. str_idx + e_tag_size];
    str_idx += e_tag_size;
    tag_idx += 1;

    if (author_pubkey_hex) |pubkey| {
        if (tag_idx < buf.len and str_idx + 2 <= string_buf.len) {
            string_buf[str_idx] = "p";
            string_buf[str_idx + 1] = pubkey;
            buf[tag_idx] = string_buf[str_idx .. str_idx + 2];
            str_idx += 2;
            tag_idx += 1;
        }
    }

    if (tag_idx < buf.len and str_idx + 2 <= string_buf.len) {
        const kind_str = std.fmt.bufPrint(kind_str_buf, "{d}", .{reposted_kind}) catch return tag_idx;
        string_buf[str_idx] = "k";
        string_buf[str_idx + 1] = kind_str;
        buf[tag_idx] = string_buf[str_idx .. str_idx + 2];
        str_idx += 2;
        tag_idx += 1;
    }

    if (event_coordinate) |coord| {
        if (tag_idx < buf.len and str_idx + 2 <= string_buf.len) {
            string_buf[str_idx] = "a";
            string_buf[str_idx + 1] = coord;
            buf[tag_idx] = string_buf[str_idx .. str_idx + 2];
            tag_idx += 1;
        }
    }

    return tag_idx;
}

pub fn buildQuoteTag(
    event_id_or_address: []const u8,
    relay_url: ?[]const u8,
    pubkey_hex: ?[]const u8,
    string_buf: [][]const u8,
) ?[]const []const u8 {
    var size: usize = 2;
    if (relay_url != null) size = 3;
    if (pubkey_hex != null) size = 4;

    if (string_buf.len < size) return null;

    string_buf[0] = "q";
    string_buf[1] = event_id_or_address;
    if (size >= 3) string_buf[2] = relay_url orelse "";
    if (size >= 4) string_buf[3] = pubkey_hex orelse "";

    return string_buf[0..size];
}

test "isRepost returns true for kind 6" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":6,"created_at":1700000000,"content":"","tags":[["e","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","wss://relay.example.com"],["p","bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    try std.testing.expect(isRepost(&event));
    try std.testing.expect(!isGenericRepost(&event));
    try std.testing.expect(isAnyRepost(&event));
}

test "isGenericRepost returns true for kind 16" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":16,"created_at":1700000000,"content":"","tags":[["e","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","wss://relay.example.com"],["p","bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"],["k","30023"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    try std.testing.expect(!isRepost(&event));
    try std.testing.expect(isGenericRepost(&event));
    try std.testing.expect(isAnyRepost(&event));
}

test "RepostInfo.fromEvent parses kind 6 repost" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":6,"created_at":1700000000,"content":"","tags":[["e","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","wss://relay.example.com"],["p","bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    const info = try RepostInfo.fromEvent(&event);

    for (info.event_id) |b| {
        try std.testing.expectEqual(@as(u8, 0xaa), b);
    }
    try std.testing.expectEqualStrings("wss://relay.example.com", info.relay_url.?);
    try std.testing.expect(info.author_pubkey != null);
    for (info.author_pubkey.?) |b| {
        try std.testing.expectEqual(@as(u8, 0xbb), b);
    }
}

test "RepostInfo.fromEvent parses kind 16 generic repost with k tag" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":16,"created_at":1700000000,"content":"","tags":[["e","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","wss://relay.example.com"],["k","30023"],["a","30023:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc:my-article"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    const info = try RepostInfo.fromEvent(&event);

    try std.testing.expectEqual(@as(i32, 30023), info.reposted_kind.?);
    try std.testing.expectEqualStrings("30023:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc:my-article", info.event_coordinate.?);
}

test "RepostInfo.fromEvent rejects non-repost events" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":1,"created_at":1700000000,"content":"test","tags":[]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    const result = RepostInfo.fromEvent(&event);
    try std.testing.expectError(error.InvalidKind, result);
}

test "RepostInfo.fromEvent requires e tag" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":6,"created_at":1700000000,"content":"","tags":[["p","bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    const result = RepostInfo.fromEvent(&event);
    try std.testing.expectError(error.MissingEventTag, result);
}

test "getQuoteTags extracts q tags" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":1,"created_at":1700000000,"content":"check this out nostr:nevent1...","tags":[["q","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","wss://relay.example.com","bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    var buf: [10]QuoteTag = undefined;
    const quotes = getQuoteTags(&event, &buf);

    try std.testing.expectEqual(@as(usize, 1), quotes.len);
    try std.testing.expectEqualStrings("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", quotes[0].event_id_or_address);
    try std.testing.expectEqualStrings("wss://relay.example.com", quotes[0].relay_url.?);
    try std.testing.expectEqualStrings("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", quotes[0].pubkey.?);
    try std.testing.expect(quotes[0].isEventId());

    const id_bytes = quotes[0].getEventIdBytes().?;
    for (id_bytes) |b| {
        try std.testing.expectEqual(@as(u8, 0xaa), b);
    }
}

test "getRepostedEventJson extracts embedded event" {
    try event_mod.init();
    defer event_mod.cleanup();

    const embedded_event =
        \\{"id":"cccc","pubkey":"dddd","kind":1,"content":"original"}
    ;
    const json = std.fmt.comptimePrint(
        \\{{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":6,"created_at":1700000000,"content":"{s}","tags":[["e","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]]}}
    , .{embedded_event});

    var event = try Event.parse(json);
    defer event.deinit();

    const content = getRepostedEventJson(&event);
    try std.testing.expect(content != null);
}

test "getRepostedEventJson returns null for empty content" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":6,"created_at":1700000000,"content":"","tags":[["e","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    const content = getRepostedEventJson(&event);
    try std.testing.expect(content == null);
}

test "buildRepostTags creates correct tag structure" {
    const event_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const relay_url = "wss://relay.example.com";
    const author_pubkey = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    var tag_buf: [10][]const []const u8 = undefined;
    var string_buf: [30][]const u8 = undefined;

    const count = buildRepostTags(event_id, relay_url, author_pubkey, &tag_buf, &string_buf);

    try std.testing.expectEqual(@as(usize, 2), count);

    try std.testing.expectEqual(@as(usize, 3), tag_buf[0].len);
    try std.testing.expectEqualStrings("e", tag_buf[0][0]);
    try std.testing.expectEqualStrings(event_id, tag_buf[0][1]);
    try std.testing.expectEqualStrings(relay_url, tag_buf[0][2]);

    try std.testing.expectEqual(@as(usize, 2), tag_buf[1].len);
    try std.testing.expectEqualStrings("p", tag_buf[1][0]);
    try std.testing.expectEqualStrings(author_pubkey, tag_buf[1][1]);
}

test "buildGenericRepostTags creates correct tag structure with k and a tags" {
    const event_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const relay_url = "wss://relay.example.com";
    const author_pubkey = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const reposted_kind: i32 = 30023;
    const event_coord = "30023:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc:my-article";

    var tag_buf: [10][]const []const u8 = undefined;
    var string_buf: [30][]const u8 = undefined;
    var kind_str_buf: [11]u8 = undefined;

    const count = buildGenericRepostTags(
        event_id,
        relay_url,
        author_pubkey,
        reposted_kind,
        event_coord,
        &tag_buf,
        &string_buf,
        &kind_str_buf,
    );

    try std.testing.expectEqual(@as(usize, 4), count);

    try std.testing.expectEqualStrings("e", tag_buf[0][0]);
    try std.testing.expectEqualStrings(event_id, tag_buf[0][1]);
    try std.testing.expectEqualStrings(relay_url, tag_buf[0][2]);

    try std.testing.expectEqualStrings("p", tag_buf[1][0]);
    try std.testing.expectEqualStrings(author_pubkey, tag_buf[1][1]);

    try std.testing.expectEqualStrings("k", tag_buf[2][0]);
    try std.testing.expectEqualStrings("30023", tag_buf[2][1]);

    try std.testing.expectEqualStrings("a", tag_buf[3][0]);
    try std.testing.expectEqualStrings(event_coord, tag_buf[3][1]);
}

test "buildQuoteTag creates correct q tag structure" {
    const event_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const relay_url = "wss://relay.example.com";
    const pubkey = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    var string_buf: [4][]const u8 = undefined;

    const tag = buildQuoteTag(event_id, relay_url, pubkey, &string_buf).?;

    try std.testing.expectEqual(@as(usize, 4), tag.len);
    try std.testing.expectEqualStrings("q", tag[0]);
    try std.testing.expectEqualStrings(event_id, tag[1]);
    try std.testing.expectEqualStrings(relay_url, tag[2]);
    try std.testing.expectEqualStrings(pubkey, tag[3]);
}

test "buildRepostTags without relay url" {
    const event_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    var tag_buf: [10][]const []const u8 = undefined;
    var string_buf: [30][]const u8 = undefined;

    const count = buildRepostTags(event_id, null, null, &tag_buf, &string_buf);

    try std.testing.expectEqual(@as(usize, 1), count);
    try std.testing.expectEqual(@as(usize, 2), tag_buf[0].len);
    try std.testing.expectEqualStrings("e", tag_buf[0][0]);
    try std.testing.expectEqualStrings(event_id, tag_buf[0][1]);
}

test "QuoteTag with event address instead of id" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":1,"created_at":1700000000,"content":"quote repost of article","tags":[["q","30023:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:my-article","wss://relay.example.com"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    var buf: [10]QuoteTag = undefined;
    const quotes = getQuoteTags(&event, &buf);

    try std.testing.expectEqual(@as(usize, 1), quotes.len);
    try std.testing.expectEqualStrings("30023:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:my-article", quotes[0].event_id_or_address);
    try std.testing.expect(!quotes[0].isEventId());
    try std.testing.expect(quotes[0].getEventIdBytes() == null);
}
