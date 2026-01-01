const std = @import("std");
const utils = @import("utils.zig");
const hex = @import("hex.zig");

/// NIP-10 marker for "e" tags in thread replies.
/// Per spec, valid markers are "root" and "reply" only.
/// The "mention" variant is included for backwards compatibility with older events
/// that used this non-standard marker before it was removed from the spec.
pub const Marker = enum {
    root,
    reply,
    mention,
};

pub const ETagInfo = struct {
    event_id: [32]u8,
    relay_url: ?[]const u8 = null,
    marker: ?Marker = null,
    pubkey: ?[32]u8 = null,
};

pub const QTagInfo = struct {
    event_id: [32]u8,
    relay_url: ?[]const u8 = null,
    pubkey: ?[32]u8 = null,
};

pub const ThreadInfo = struct {
    root: ?ETagInfo = null,
    reply: ?ETagInfo = null,
    mentions: []ETagInfo = &[_]ETagInfo{},
    quotes: []QTagInfo = &[_]QTagInfo{},
    allocator: ?std.mem.Allocator = null,

    pub fn deinit(self: *ThreadInfo) void {
        if (self.allocator) |alloc| {
            if (self.mentions.len > 0) alloc.free(self.mentions);
            if (self.quotes.len > 0) alloc.free(self.quotes);
        }
    }
};

pub const Nip10 = struct {
    pub fn extractThreadInfo(json: []const u8, allocator: std.mem.Allocator) !ThreadInfo {
        var result = ThreadInfo{ .allocator = allocator };
        errdefer result.deinit();
        var e_tags: std.ArrayListUnmanaged(ETagInfo) = .{};
        defer e_tags.deinit(allocator);
        var q_tags: std.ArrayListUnmanaged(QTagInfo) = .{};
        defer q_tags.deinit(allocator);

        var iter = FullTagIterator.init(json, "tags") orelse return result;

        while (iter.next()) |tag_json| {
            const tag_name = extractTagElement(tag_json, 0) orelse continue;

            if (std.mem.eql(u8, tag_name, "e")) {
                const e_tag = parseETag(tag_json) orelse continue;
                if (e_tag.marker) |m| {
                    switch (m) {
                        .root => result.root = e_tag,
                        .reply => result.reply = e_tag,
                        .mention => try e_tags.append(allocator, e_tag),
                    }
                } else {
                    try e_tags.append(allocator, e_tag);
                }
            } else if (std.mem.eql(u8, tag_name, "q")) {
                if (parseQTag(tag_json)) |q_tag| {
                    try q_tags.append(allocator, q_tag);
                }
            }
        }

        if (result.root == null and result.reply == null and e_tags.items.len > 0) {
            result = try resolvePositionalETags(e_tags.items, allocator);
            if (q_tags.items.len > 0) {
                result.quotes = try allocator.dupe(QTagInfo, q_tags.items);
            }
            return result;
        }

        if (e_tags.items.len > 0) {
            result.mentions = try allocator.dupe(ETagInfo, e_tags.items);
        }
        if (q_tags.items.len > 0) {
            result.quotes = try allocator.dupe(QTagInfo, q_tags.items);
        }

        return result;
    }

    fn resolvePositionalETags(tags: []ETagInfo, allocator: std.mem.Allocator) !ThreadInfo {
        var result = ThreadInfo{ .allocator = allocator };

        if (tags.len == 0) return result;

        if (tags.len == 1) {
            // Per NIP-10: "One 'e' tag: The id of the event to which this event is a reply."
            // A single e-tag is both the root and the reply target (direct reply to root).
            result.root = tags[0];
            result.reply = tags[0];
            return result;
        }

        result.root = tags[0];
        result.reply = tags[tags.len - 1];

        if (tags.len > 2) {
            result.mentions = try allocator.dupe(ETagInfo, tags[1 .. tags.len - 1]);
        }

        return result;
    }

    pub fn parseETag(tag_json: []const u8) ?ETagInfo {
        const event_id_hex = extractTagElement(tag_json, 1) orelse return null;
        if (event_id_hex.len != 64) return null;

        var event_id: [32]u8 = undefined;
        hex.decode(event_id_hex, &event_id) catch return null;

        var info = ETagInfo{ .event_id = event_id };

        if (extractTagElement(tag_json, 2)) |relay| {
            if (relay.len > 0) info.relay_url = relay;
        }

        if (extractTagElement(tag_json, 3)) |marker_str| {
            if (std.mem.eql(u8, marker_str, "root")) {
                info.marker = .root;
            } else if (std.mem.eql(u8, marker_str, "reply")) {
                info.marker = .reply;
            } else if (std.mem.eql(u8, marker_str, "mention")) {
                info.marker = .mention;
            }
        }

        if (extractTagElement(tag_json, 4)) |pubkey_hex| {
            if (pubkey_hex.len == 64) {
                var pk: [32]u8 = undefined;
                if (hex.decode(pubkey_hex, &pk)) |_| {
                    info.pubkey = pk;
                } else |_| {}
            }
        }

        return info;
    }

    pub fn parseQTag(tag_json: []const u8) ?QTagInfo {
        const event_id_hex = extractTagElement(tag_json, 1) orelse return null;
        if (event_id_hex.len != 64) return null;

        var event_id: [32]u8 = undefined;
        hex.decode(event_id_hex, &event_id) catch return null;

        var info = QTagInfo{ .event_id = event_id };

        if (extractTagElement(tag_json, 2)) |relay| {
            if (relay.len > 0) info.relay_url = relay;
        }

        if (extractTagElement(tag_json, 3)) |pubkey_hex| {
            if (pubkey_hex.len == 64) {
                var pk: [32]u8 = undefined;
                if (hex.decode(pubkey_hex, &pk)) |_| {
                    info.pubkey = pk;
                } else |_| {}
            }
        }

        return info;
    }

    pub fn getRoot(json: []const u8) ?[32]u8 {
        var iter = FullTagIterator.init(json, "tags") orelse return null;
        var first_e_tag: ?[32]u8 = null;
        var e_tag_count: usize = 0;

        while (iter.next()) |tag_json| {
            const tag_name = extractTagElement(tag_json, 0) orelse continue;
            if (!std.mem.eql(u8, tag_name, "e")) continue;

            const event_id_hex = extractTagElement(tag_json, 1) orelse continue;
            if (event_id_hex.len != 64) continue;

            var event_id: [32]u8 = undefined;
            hex.decode(event_id_hex, &event_id) catch continue;

            if (e_tag_count == 0) first_e_tag = event_id;
            e_tag_count += 1;

            if (extractTagElement(tag_json, 3)) |marker| {
                if (std.mem.eql(u8, marker, "root")) return event_id;
            }
        }

        return first_e_tag;
    }

    pub fn getReply(json: []const u8) ?[32]u8 {
        var iter = FullTagIterator.init(json, "tags") orelse return null;
        var last_e_tag: ?[32]u8 = null;
        var e_tag_count: usize = 0;

        while (iter.next()) |tag_json| {
            const tag_name = extractTagElement(tag_json, 0) orelse continue;
            if (!std.mem.eql(u8, tag_name, "e")) continue;

            const event_id_hex = extractTagElement(tag_json, 1) orelse continue;
            if (event_id_hex.len != 64) continue;

            var event_id: [32]u8 = undefined;
            hex.decode(event_id_hex, &event_id) catch continue;

            e_tag_count += 1;
            last_e_tag = event_id;

            if (extractTagElement(tag_json, 3)) |marker| {
                if (std.mem.eql(u8, marker, "reply")) return event_id;
            }
        }

        if (e_tag_count >= 1) return last_e_tag;
        return null;
    }

    pub fn isReply(json: []const u8) bool {
        var iter = FullTagIterator.init(json, "tags") orelse return false;

        while (iter.next()) |tag_json| {
            const tag_name = extractTagElement(tag_json, 0) orelse continue;
            if (std.mem.eql(u8, tag_name, "e")) return true;
        }
        return false;
    }

    pub fn isDirectReplyToRoot(json: []const u8) bool {
        var iter = FullTagIterator.init(json, "tags") orelse return false;
        var has_root = false;
        var has_reply = false;
        var e_tag_count: usize = 0;

        while (iter.next()) |tag_json| {
            const tag_name = extractTagElement(tag_json, 0) orelse continue;
            if (!std.mem.eql(u8, tag_name, "e")) continue;

            e_tag_count += 1;

            if (extractTagElement(tag_json, 3)) |marker| {
                if (std.mem.eql(u8, marker, "root")) has_root = true;
                if (std.mem.eql(u8, marker, "reply")) has_reply = true;
            }
        }

        if (has_root and !has_reply) return true;
        if (e_tag_count == 1) return true;
        return false;
    }
};

pub const FullTagIterator = struct {
    json: []const u8,
    pos: usize,

    pub fn init(json: []const u8, key: []const u8) ?FullTagIterator {
        const start = utils.findJsonFieldStart(json, key) orelse return null;
        if (start >= json.len or json[start] != '[') return null;
        return .{ .json = json, .pos = start + 1 };
    }

    pub fn next(self: *FullTagIterator) ?[]const u8 {
        while (self.pos < self.json.len and (self.json[self.pos] == ' ' or self.json[self.pos] == ',' or
            self.json[self.pos] == '\n' or self.json[self.pos] == '\r' or self.json[self.pos] == '\t')) : (self.pos += 1)
        {}

        if (self.pos >= self.json.len or self.json[self.pos] == ']') return null;
        if (self.json[self.pos] != '[') return null;

        const tag_start = self.pos;
        var depth: i32 = 0;
        var in_string = false;
        var escaped = false;

        while (self.pos < self.json.len) {
            const c = self.json[self.pos];
            if (escaped) {
                escaped = false;
                self.pos += 1;
                continue;
            }
            if (c == '\\' and in_string) {
                escaped = true;
                self.pos += 1;
                continue;
            }
            if (c == '"') {
                in_string = !in_string;
                self.pos += 1;
                continue;
            }
            if (!in_string) {
                if (c == '[') depth += 1;
                if (c == ']') {
                    depth -= 1;
                    if (depth == 0) {
                        self.pos += 1;
                        return self.json[tag_start..self.pos];
                    }
                }
            }
            self.pos += 1;
        }
        return null;
    }
};

fn extractTagElement(tag_json: []const u8, index: usize) ?[]const u8 {
    var pos: usize = 0;
    while (pos < tag_json.len and tag_json[pos] != '[') : (pos += 1) {}
    if (pos >= tag_json.len) return null;
    pos += 1;

    var current_index: usize = 0;
    while (pos < tag_json.len) {
        while (pos < tag_json.len and (tag_json[pos] == ' ' or tag_json[pos] == ',' or
            tag_json[pos] == '\n' or tag_json[pos] == '\r' or tag_json[pos] == '\t')) : (pos += 1)
        {}

        if (pos >= tag_json.len or tag_json[pos] == ']') return null;

        if (tag_json[pos] == '"') {
            pos += 1;
            const str_start = pos;
            const str_end = utils.findStringEnd(tag_json, pos) orelse return null;

            if (current_index == index) {
                return tag_json[str_start..str_end];
            }
            pos = str_end + 1;
            current_index += 1;
        } else {
            while (pos < tag_json.len and tag_json[pos] != ',' and tag_json[pos] != ']' and
                tag_json[pos] != ' ' and tag_json[pos] != '\n' and tag_json[pos] != '\r' and tag_json[pos] != '\t') : (pos += 1)
            {}
            current_index += 1;
        }
    }
    return null;
}

test "parseETag with marker" {
    const tag = "[\"e\",\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"wss://relay.example.com\",\"root\"]";
    const info = Nip10.parseETag(tag).?;

    for (info.event_id) |b| {
        try std.testing.expectEqual(@as(u8, 0xaa), b);
    }
    try std.testing.expectEqualStrings("wss://relay.example.com", info.relay_url.?);
    try std.testing.expectEqual(Marker.root, info.marker.?);
}

test "parseETag with reply marker" {
    const tag = "[\"e\",\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"\",\"reply\"]";
    const info = Nip10.parseETag(tag).?;

    try std.testing.expectEqual(@as(u8, 0xbb), info.event_id[0]);
    try std.testing.expect(info.relay_url == null);
    try std.testing.expectEqual(Marker.reply, info.marker.?);
}

test "parseETag with pubkey" {
    const tag = "[\"e\",\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"wss://relay.example.com\",\"root\",\"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\"]";
    const info = Nip10.parseETag(tag).?;

    try std.testing.expectEqual(Marker.root, info.marker.?);
    try std.testing.expectEqual(@as(u8, 0xcc), info.pubkey.?[0]);
}

test "parseETag without marker (positional)" {
    const tag = "[\"e\",\"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\",\"wss://relay.example.com\"]";
    const info = Nip10.parseETag(tag).?;

    try std.testing.expectEqual(@as(u8, 0xdd), info.event_id[0]);
    try std.testing.expectEqualStrings("wss://relay.example.com", info.relay_url.?);
    try std.testing.expect(info.marker == null);
}

test "parseQTag" {
    const tag = "[\"q\",\"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\",\"wss://relay.example.com\",\"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\"]";
    const info = Nip10.parseQTag(tag).?;

    try std.testing.expectEqual(@as(u8, 0xee), info.event_id[0]);
    try std.testing.expectEqualStrings("wss://relay.example.com", info.relay_url.?);
    try std.testing.expectEqual(@as(u8, 0xff), info.pubkey.?[0]);
}

test "getRoot with marked tags" {
    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":1,"created_at":1700000000,"content":"test","tags":[["e","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","","root"],["e","bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","","reply"]]}
    ;

    const root = Nip10.getRoot(json).?;
    try std.testing.expectEqual(@as(u8, 0xaa), root[0]);
}

test "getRoot with positional tags (deprecated)" {
    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":1,"created_at":1700000000,"content":"test","tags":[["e","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],["e","bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]]}
    ;

    const root = Nip10.getRoot(json).?;
    try std.testing.expectEqual(@as(u8, 0xaa), root[0]);
}

test "getReply with marked tags" {
    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":1,"created_at":1700000000,"content":"test","tags":[["e","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","","root"],["e","bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","","reply"]]}
    ;

    const reply = Nip10.getReply(json).?;
    try std.testing.expectEqual(@as(u8, 0xbb), reply[0]);
}

test "getReply with positional tags (deprecated)" {
    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":1,"created_at":1700000000,"content":"test","tags":[["e","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],["e","bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]]}
    ;

    const reply = Nip10.getReply(json).?;
    try std.testing.expectEqual(@as(u8, 0xbb), reply[0]);
}

test "getReply returns same event for single positional e-tag" {
    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":1,"created_at":1700000000,"content":"test","tags":[["e","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]]}
    ;

    const reply = Nip10.getReply(json).?;
    try std.testing.expectEqual(@as(u8, 0xaa), reply[0]);
}

test "isReply" {
    const reply_json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":1,"created_at":1700000000,"content":"test","tags":[["e","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]]}
    ;

    const non_reply_json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":1,"created_at":1700000000,"content":"test","tags":[["t","nostr"]]}
    ;

    try std.testing.expect(Nip10.isReply(reply_json));
    try std.testing.expect(!Nip10.isReply(non_reply_json));
}

test "isDirectReplyToRoot" {
    const direct_reply =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":1,"created_at":1700000000,"content":"test","tags":[["e","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","","root"]]}
    ;

    const nested_reply =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":1,"created_at":1700000000,"content":"test","tags":[["e","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","","root"],["e","bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","","reply"]]}
    ;

    try std.testing.expect(Nip10.isDirectReplyToRoot(direct_reply));
    try std.testing.expect(!Nip10.isDirectReplyToRoot(nested_reply));
}

test "extractThreadInfo with marked tags" {
    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":1,"created_at":1700000000,"content":"test","tags":[["e","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","wss://relay1.example.com","root"],["e","bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","wss://relay2.example.com","reply"],["e","cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","","mention"]]}
    ;

    var info = try Nip10.extractThreadInfo(json, std.testing.allocator);
    defer info.deinit();

    try std.testing.expectEqual(@as(u8, 0xaa), info.root.?.event_id[0]);
    try std.testing.expectEqualStrings("wss://relay1.example.com", info.root.?.relay_url.?);
    try std.testing.expectEqual(@as(u8, 0xbb), info.reply.?.event_id[0]);
    try std.testing.expectEqual(@as(usize, 1), info.mentions.len);
    try std.testing.expectEqual(@as(u8, 0xcc), info.mentions[0].event_id[0]);
}

test "extractThreadInfo with positional tags (deprecated)" {
    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":1,"created_at":1700000000,"content":"test","tags":[["e","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],["e","bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"],["e","cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"]]}
    ;

    var info = try Nip10.extractThreadInfo(json, std.testing.allocator);
    defer info.deinit();

    try std.testing.expectEqual(@as(u8, 0xaa), info.root.?.event_id[0]);
    try std.testing.expectEqual(@as(u8, 0xcc), info.reply.?.event_id[0]);
    try std.testing.expectEqual(@as(usize, 1), info.mentions.len);
    try std.testing.expectEqual(@as(u8, 0xbb), info.mentions[0].event_id[0]);
}

test "extractThreadInfo with single positional e-tag" {
    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":1,"created_at":1700000000,"content":"test","tags":[["e","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]]}
    ;

    var info = try Nip10.extractThreadInfo(json, std.testing.allocator);
    defer info.deinit();

    try std.testing.expectEqual(@as(u8, 0xaa), info.root.?.event_id[0]);
    try std.testing.expectEqual(@as(u8, 0xaa), info.reply.?.event_id[0]);
    try std.testing.expectEqual(@as(usize, 0), info.mentions.len);
}

test "extractThreadInfo with quotes" {
    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":1,"created_at":1700000000,"content":"test","tags":[["q","dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","wss://relay.example.com","eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"]]}
    ;

    var info = try Nip10.extractThreadInfo(json, std.testing.allocator);
    defer info.deinit();

    try std.testing.expectEqual(@as(usize, 1), info.quotes.len);
    try std.testing.expectEqual(@as(u8, 0xdd), info.quotes[0].event_id[0]);
    try std.testing.expectEqualStrings("wss://relay.example.com", info.quotes[0].relay_url.?);
    try std.testing.expectEqual(@as(u8, 0xee), info.quotes[0].pubkey.?[0]);
}

test "FullTagIterator" {
    const json =
        \\{"tags":[["e","aaaa"],["p","bbbb"],["t","test"]]}
    ;

    var iter = FullTagIterator.init(json, "tags").?;
    var count: usize = 0;
    while (iter.next()) |_| {
        count += 1;
    }
    try std.testing.expectEqual(@as(usize, 3), count);
}

test "extractTagElement" {
    const tag = "[\"e\",\"abc123\",\"wss://relay.com\",\"root\"]";

    try std.testing.expectEqualStrings("e", extractTagElement(tag, 0).?);
    try std.testing.expectEqualStrings("abc123", extractTagElement(tag, 1).?);
    try std.testing.expectEqualStrings("wss://relay.com", extractTagElement(tag, 2).?);
    try std.testing.expectEqualStrings("root", extractTagElement(tag, 3).?);
    try std.testing.expect(extractTagElement(tag, 4) == null);
}
