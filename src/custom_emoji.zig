const std = @import("std");
const utils = @import("utils.zig");
const event_mod = @import("event.zig");

pub const Event = event_mod.Event;

pub const CustomEmoji = struct {
    shortcode: []const u8,
    url: []const u8,
};

pub const EmojiList = struct {
    emojis: std.ArrayListUnmanaged(CustomEmoji),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) EmojiList {
        return .{
            .emojis = .{},
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *EmojiList) void {
        for (self.emojis.items) |emoji| {
            self.allocator.free(emoji.shortcode);
            self.allocator.free(emoji.url);
        }
        self.emojis.deinit(self.allocator);
    }

    pub fn fromEvent(event: *const Event, allocator: std.mem.Allocator) !EmojiList {
        var list = EmojiList.init(allocator);
        errdefer list.deinit();

        const tags_json = utils.findJsonValue(event.raw_json, "tags") orelse return list;
        var iter = EmojiTagIterator.init(tags_json);

        while (iter.next()) |entry| {
            if (!isValidShortcode(entry.shortcode)) continue;

            const shortcode_copy = try allocator.dupe(u8, entry.shortcode);
            errdefer allocator.free(shortcode_copy);
            const url_copy = try allocator.dupe(u8, entry.url);
            errdefer allocator.free(url_copy);

            try list.emojis.append(allocator, .{
                .shortcode = shortcode_copy,
                .url = url_copy,
            });
        }

        return list;
    }

    pub fn count(self: *const EmojiList) usize {
        return self.emojis.items.len;
    }

    pub fn get(self: *const EmojiList, shortcode: []const u8) ?[]const u8 {
        for (self.emojis.items) |emoji| {
            if (std.mem.eql(u8, emoji.shortcode, shortcode)) {
                return emoji.url;
            }
        }
        return null;
    }

    pub fn iterator(self: *const EmojiList) EmojiIterator {
        return .{ .list = self, .index = 0 };
    }
};

pub const EmojiIterator = struct {
    list: *const EmojiList,
    index: usize,

    pub fn next(self: *EmojiIterator) ?CustomEmoji {
        if (self.index >= self.list.emojis.items.len) return null;
        const emoji = self.list.emojis.items[self.index];
        self.index += 1;
        return emoji;
    }
};

pub fn isValidShortcode(shortcode: []const u8) bool {
    if (shortcode.len == 0) return false;
    for (shortcode) |c| {
        const valid = (c >= 'a' and c <= 'z') or
            (c >= 'A' and c <= 'Z') or
            (c >= '0' and c <= '9') or
            c == '_';
        if (!valid) return false;
    }
    return true;
}

pub const ShortcodeMatch = struct {
    shortcode: []const u8,
    start: usize,
    end: usize,
};

pub const ShortcodeFinder = struct {
    text: []const u8,
    pos: usize,

    pub fn init(text: []const u8) ShortcodeFinder {
        return .{ .text = text, .pos = 0 };
    }

    pub fn next(self: *ShortcodeFinder) ?ShortcodeMatch {
        while (self.pos < self.text.len) {
            const colon_start = std.mem.indexOfScalarPos(u8, self.text, self.pos, ':') orelse return null;
            const shortcode_start = colon_start + 1;
            if (shortcode_start >= self.text.len) return null;

            const colon_end = std.mem.indexOfScalarPos(u8, self.text, shortcode_start, ':') orelse {
                self.pos = shortcode_start;
                continue;
            };

            const shortcode = self.text[shortcode_start..colon_end];
            if (isValidShortcode(shortcode)) {
                self.pos = colon_end + 1;
                return .{
                    .shortcode = shortcode,
                    .start = colon_start,
                    .end = colon_end + 1,
                };
            }

            self.pos = shortcode_start;
        }
        return null;
    }
};

const EmojiTagIterator = struct {
    json: []const u8,
    pos: usize,

    const Entry = struct {
        shortcode: []const u8,
        url: []const u8,
    };

    fn init(json: []const u8) EmojiTagIterator {
        return .{ .json = json, .pos = 0 };
    }

    fn next(self: *EmojiTagIterator) ?Entry {
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
            if (self.parseEmojiTag(tag_content)) |entry| {
                return entry;
            }
        }
        return null;
    }

    fn findBracket(self: *EmojiTagIterator, bracket: u8) ?usize {
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

    fn parseEmojiTag(self: *const EmojiTagIterator, content: []const u8) ?Entry {
        _ = self;
        var strings: [3][]const u8 = undefined;
        var str_count: usize = 0;

        var i: usize = 0;
        while (i < content.len and str_count < 3) {
            const quote_start = std.mem.indexOfPos(u8, content, i, "\"") orelse break;
            const str_start = quote_start + 1;
            const quote_end = findStringEnd(content, str_start) orelse break;
            strings[str_count] = content[str_start..quote_end];
            str_count += 1;
            i = quote_end + 1;
        }

        if (str_count < 3) return null;
        if (!std.mem.eql(u8, strings[0], "emoji")) return null;

        const shortcode = strings[1];
        const url = strings[2];
        if (shortcode.len == 0 or url.len == 0) return null;

        return .{ .shortcode = shortcode, .url = url };
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

test "isValidShortcode accepts valid shortcodes" {
    try std.testing.expect(isValidShortcode("soapbox"));
    try std.testing.expect(isValidShortcode("gleasonator"));
    try std.testing.expect(isValidShortcode("ablobcatrainbow"));
    try std.testing.expect(isValidShortcode("disputed"));
    try std.testing.expect(isValidShortcode("dezh"));
    try std.testing.expect(isValidShortcode("custom_emoji"));
    try std.testing.expect(isValidShortcode("emoji123"));
    try std.testing.expect(isValidShortcode("UPPERCASE"));
    try std.testing.expect(isValidShortcode("MixedCase_123"));
}

test "isValidShortcode rejects invalid shortcodes" {
    try std.testing.expect(!isValidShortcode(""));
    try std.testing.expect(!isValidShortcode("has space"));
    try std.testing.expect(!isValidShortcode("has-dash"));
    try std.testing.expect(!isValidShortcode("has.dot"));
    try std.testing.expect(!isValidShortcode("has:colon"));
    try std.testing.expect(!isValidShortcode("emoji!"));
    try std.testing.expect(!isValidShortcode("emoji@test"));
}

test "ShortcodeFinder finds shortcodes in text" {
    var finder = ShortcodeFinder.init("Hello :gleasonator: world :soapbox:!");

    const first = finder.next().?;
    try std.testing.expectEqualStrings("gleasonator", first.shortcode);
    try std.testing.expectEqual(@as(usize, 6), first.start);
    try std.testing.expectEqual(@as(usize, 19), first.end);

    const second = finder.next().?;
    try std.testing.expectEqualStrings("soapbox", second.shortcode);
    try std.testing.expectEqual(@as(usize, 26), second.start);
    try std.testing.expectEqual(@as(usize, 35), second.end);

    try std.testing.expect(finder.next() == null);
}

test "ShortcodeFinder handles edge cases" {
    var finder1 = ShortcodeFinder.init("no emoji here");
    try std.testing.expect(finder1.next() == null);

    var finder2 = ShortcodeFinder.init(":valid:");
    const match = finder2.next().?;
    try std.testing.expectEqualStrings("valid", match.shortcode);

    var finder3 = ShortcodeFinder.init("::");
    try std.testing.expect(finder3.next() == null);

    var finder4 = ShortcodeFinder.init(":has-dash:");
    try std.testing.expect(finder4.next() == null);
}

test "ShortcodeFinder handles consecutive patterns" {
    var finder = ShortcodeFinder.init(":a::b:");

    const first = finder.next().?;
    try std.testing.expectEqualStrings("a", first.shortcode);

    const second = finder.next().?;
    try std.testing.expectEqualStrings("b", second.shortcode);

    try std.testing.expect(finder.next() == null);
}

test "EmojiList.fromEvent parses emoji tags" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":1,"created_at":1682630000,"content":"Hello :gleasonator: 😂 :ablobcatrainbow: :disputed: yolo","tags":[["emoji","ablobcatrainbow","https://gleasonator.com/emoji/blobcat/ablobcatrainbow.png"],["emoji","disputed","https://gleasonator.com/emoji/Fun/disputed.png"],["emoji","gleasonator","https://gleasonator.com/emoji/Gleasonator/gleasonator.png"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    var list = try EmojiList.fromEvent(&event, std.testing.allocator);
    defer list.deinit();

    try std.testing.expectEqual(@as(usize, 3), list.count());

    try std.testing.expectEqualStrings("https://gleasonator.com/emoji/blobcat/ablobcatrainbow.png", list.get("ablobcatrainbow").?);
    try std.testing.expectEqualStrings("https://gleasonator.com/emoji/Fun/disputed.png", list.get("disputed").?);
    try std.testing.expectEqualStrings("https://gleasonator.com/emoji/Gleasonator/gleasonator.png", list.get("gleasonator").?);

    try std.testing.expect(list.get("nonexistent") == null);
}

test "EmojiList.fromEvent handles kind:0 profile events" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"79c2cae114ea28a981e7559b4fe7854a473521a8d22a66bbab9fa248eb820ff6","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":0,"created_at":1682790000,"content":"{\"name\":\"Alex Gleason :soapbox:\"}","tags":[["emoji","soapbox","https://gleasonator.com/emoji/Gleasonator/soapbox.png"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    var list = try EmojiList.fromEvent(&event, std.testing.allocator);
    defer list.deinit();

    try std.testing.expectEqual(@as(usize, 1), list.count());
    try std.testing.expectEqualStrings("https://gleasonator.com/emoji/Gleasonator/soapbox.png", list.get("soapbox").?);
}

test "EmojiList.fromEvent handles kind:7 reaction events" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"79c2cae114ea28a981e7559b4fe7854a473521a8d22a66bbab9fa248eb820ff6","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":7,"created_at":1682630000,"content":":dezh:","tags":[["emoji","dezh","https://raw.githubusercontent.com/dezh-tech/brand-assets/main/dezh/logo/black-normal.svg"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    var list = try EmojiList.fromEvent(&event, std.testing.allocator);
    defer list.deinit();

    try std.testing.expectEqual(@as(usize, 1), list.count());
    try std.testing.expectEqualStrings("https://raw.githubusercontent.com/dezh-tech/brand-assets/main/dezh/logo/black-normal.svg", list.get("dezh").?);
}

test "EmojiList.iterator iterates all emojis" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":1,"created_at":1700000000,"content":"test","tags":[["emoji","a","https://a.png"],["emoji","b","https://b.png"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    var list = try EmojiList.fromEvent(&event, std.testing.allocator);
    defer list.deinit();

    var iter = list.iterator();
    var emoji_count: usize = 0;
    while (iter.next()) |_| {
        emoji_count += 1;
    }

    try std.testing.expectEqual(@as(usize, 2), emoji_count);
}

test "EmojiList.fromEvent ignores invalid shortcodes" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":1,"created_at":1700000000,"content":"test","tags":[["emoji","valid","https://valid.png"],["emoji","in-valid","https://invalid.png"],["emoji","also_valid","https://alsovalid.png"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    var list = try EmojiList.fromEvent(&event, std.testing.allocator);
    defer list.deinit();

    try std.testing.expectEqual(@as(usize, 2), list.count());
    try std.testing.expect(list.get("valid") != null);
    try std.testing.expect(list.get("in-valid") == null);
    try std.testing.expect(list.get("also_valid") != null);
}

test "EmojiList.fromEvent handles empty tags" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":1,"created_at":1700000000,"content":"test","tags":[]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    var list = try EmojiList.fromEvent(&event, std.testing.allocator);
    defer list.deinit();

    try std.testing.expectEqual(@as(usize, 0), list.count());
}

test "EmojiList.fromEvent ignores non-emoji tags" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":1,"created_at":1700000000,"content":"test","tags":[["e","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],["emoji","valid","https://valid.png"],["p","bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    var list = try EmojiList.fromEvent(&event, std.testing.allocator);
    defer list.deinit();

    try std.testing.expectEqual(@as(usize, 1), list.count());
    try std.testing.expectEqualStrings("https://valid.png", list.get("valid").?);
}

test "ShortcodeFinder handles multiple consecutive colons" {
    var finder = ShortcodeFinder.init("::::");
    try std.testing.expect(finder.next() == null);

    var finder2 = ShortcodeFinder.init("::a::");
    const match = finder2.next().?;
    try std.testing.expectEqualStrings("a", match.shortcode);
    try std.testing.expect(finder2.next() == null);
}

test "EmojiList.fromEvent handles URLs with query parameters" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":1,"created_at":1700000000,"content":":test:","tags":[["emoji","test","https://example.com/emoji.png?size=64&format=webp"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    var list = try EmojiList.fromEvent(&event, std.testing.allocator);
    defer list.deinit();

    try std.testing.expectEqual(@as(usize, 1), list.count());
    try std.testing.expectEqualStrings("https://example.com/emoji.png?size=64&format=webp", list.get("test").?);
}

test "EmojiList.fromEvent with duplicate shortcodes returns first" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":1,"created_at":1700000000,"content":":dupe:","tags":[["emoji","dupe","https://first.png"],["emoji","dupe","https://second.png"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    var list = try EmojiList.fromEvent(&event, std.testing.allocator);
    defer list.deinit();

    try std.testing.expectEqual(@as(usize, 2), list.count());
    try std.testing.expectEqualStrings("https://first.png", list.get("dupe").?);
}
