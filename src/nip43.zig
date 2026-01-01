//! NIP-43 Relay Access Metadata and Requests.
//!
//! Defines event kinds and parsing utilities for relay membership management:
//! - Membership lists (kind 13534)
//! - Add/remove user notifications (kinds 8000, 8001)
//! - Join/invite/leave requests (kinds 28934, 28935, 28936)
//!
//! Zero-allocation parsing returns slices into the original JSON.

const std = @import("std");
const utils = @import("utils.zig");
const hex = @import("hex.zig");

pub const Kind = struct {
    pub const membership_list: i32 = 13534;
    pub const add_user: i32 = 8000;
    pub const remove_user: i32 = 8001;
    pub const join_request: i32 = 28934;
    pub const invite_request: i32 = 28935;
    pub const leave_request: i32 = 28936;
};

fn findTagsArray(json: []const u8) ?[]const u8 {
    var pos: usize = 0;
    while (std.mem.indexOf(u8, json[pos..], "\"tags\"")) |rel| {
        const tags_key = pos + rel;
        if (tags_key > 0 and json[tags_key - 1] != '{' and json[tags_key - 1] != ',' and json[tags_key - 1] != ' ' and json[tags_key - 1] != '\n' and json[tags_key - 1] != '\t') {
            pos = tags_key + 6;
            continue;
        }
        const after_key = json[tags_key + 6 ..];
        const colon = std.mem.indexOf(u8, after_key, ":") orelse return null;
        const after_colon = after_key[colon + 1 ..];
        const bracket = std.mem.indexOf(u8, after_colon, "[") orelse return null;
        const start = tags_key + 6 + colon + 1 + bracket;
        var depth: usize = 1;
        var i: usize = start + 1;
        while (i < json.len and depth > 0) : (i += 1) {
            switch (json[i]) {
                '[' => depth += 1,
                ']' => depth -= 1,
                '"' => {
                    i += 1;
                    while (i < json.len) : (i += 1) {
                        if (json[i] == '\\') {
                            i += 1;
                        } else if (json[i] == '"') {
                            break;
                        }
                    }
                },
                else => {},
            }
        }
        if (depth != 0) return null;
        return json[start..i];
    }
    return null;
}

pub const MemberIterator = struct {
    tags: []const u8,
    pos: usize,

    pub fn init(event_json: []const u8) MemberIterator {
        const tags = findTagsArray(event_json) orelse return .{ .tags = "", .pos = 0 };
        return .{ .tags = tags, .pos = 0 };
    }

    pub fn next(self: *MemberIterator) ?[]const u8 {
        while (self.pos < self.tags.len) {
            const member_start = std.mem.indexOf(u8, self.tags[self.pos..], "[\"member\",\"") orelse return null;
            const abs_start = self.pos + member_start + 11;
            self.pos = abs_start;
            if (abs_start + 64 > self.tags.len) return null;
            const quote_pos = std.mem.indexOf(u8, self.tags[abs_start..], "\"") orelse {
                self.pos = self.tags.len;
                return null;
            };
            if (quote_pos != 64) {
                self.pos = abs_start + quote_pos + 1;
                continue;
            }
            const pubkey_hex = self.tags[abs_start..][0..64];
            self.pos = abs_start + 65;
            var valid = true;
            for (pubkey_hex) |c| {
                if (!std.ascii.isHex(c)) {
                    valid = false;
                    break;
                }
            }
            if (valid) return pubkey_hex;
        }
        return null;
    }
};

pub fn parseMembers(event_json: []const u8, out: [][32]u8) usize {
    var iter = MemberIterator.init(event_json);
    var count: usize = 0;
    while (count < out.len) {
        const pubkey_hex = iter.next() orelse break;
        hex.decode(pubkey_hex, &out[count]) catch continue;
        count += 1;
    }
    return count;
}

pub fn parsePTag(event_json: []const u8, out: *[32]u8) bool {
    const tags = findTagsArray(event_json) orelse return false;
    const p_start = std.mem.indexOf(u8, tags, "[\"p\",\"") orelse return false;
    const hex_start = p_start + 6;
    if (hex_start + 64 > tags.len) return false;
    hex.decode(tags[hex_start..][0..64], out) catch return false;
    return true;
}

pub fn parseClaim(event_json: []const u8) ?[]const u8 {
    const tags = findTagsArray(event_json) orelse return null;
    const claim_start = std.mem.indexOf(u8, tags, "[\"claim\",\"") orelse return null;
    const value_start = claim_start + 10;
    if (value_start >= tags.len) return null;
    const value_end = std.mem.indexOf(u8, tags[value_start..], "\"") orelse return null;
    if (value_end == 0) return null;
    return tags[value_start..][0..value_end];
}

pub fn hasProtectedTag(event_json: []const u8) bool {
    const tags = findTagsArray(event_json) orelse return false;
    return std.mem.indexOf(u8, tags, "[\"-\"]") != null;
}

pub fn parseKind(event_json: []const u8) ?i32 {
    return utils.extractIntField(event_json, "kind", i32);
}

test "Kind constants" {
    try std.testing.expectEqual(@as(i32, 13534), Kind.membership_list);
    try std.testing.expectEqual(@as(i32, 8000), Kind.add_user);
    try std.testing.expectEqual(@as(i32, 8001), Kind.remove_user);
    try std.testing.expectEqual(@as(i32, 28934), Kind.join_request);
    try std.testing.expectEqual(@as(i32, 28935), Kind.invite_request);
    try std.testing.expectEqual(@as(i32, 28936), Kind.leave_request);
}

test "MemberIterator" {
    const json =
        \\{"kind":13534,"tags":[["member","c308e1f882c1f1dff2a43d4294239ddeec04e575f2d1aad1fa21ea7684e61fb5"],["member","ee1d336e13779e4d4c527b988429d96de16088f958cbf6c074676ac9cfd9c958"]]}
    ;

    var iter = MemberIterator.init(json);

    const first = iter.next().?;
    try std.testing.expectEqualStrings("c308e1f882c1f1dff2a43d4294239ddeec04e575f2d1aad1fa21ea7684e61fb5", first);

    const second = iter.next().?;
    try std.testing.expectEqualStrings("ee1d336e13779e4d4c527b988429d96de16088f958cbf6c074676ac9cfd9c958", second);

    try std.testing.expect(iter.next() == null);
}

test "parseMembers" {
    const json =
        \\{"kind":13534,"tags":[["-"],["member","c308e1f882c1f1dff2a43d4294239ddeec04e575f2d1aad1fa21ea7684e61fb5"],["member","ee1d336e13779e4d4c527b988429d96de16088f958cbf6c074676ac9cfd9c958"]]}
    ;

    var members: [10][32]u8 = undefined;
    const count = parseMembers(json, &members);
    try std.testing.expectEqual(@as(usize, 2), count);
}

test "parsePTag" {
    const json =
        \\{"kind":8000,"tags":[["-"],["p","c308e1f882c1f1dff2a43d4294239ddeec04e575f2d1aad1fa21ea7684e61fb5"]]}
    ;

    var pubkey: [32]u8 = undefined;
    try std.testing.expect(parsePTag(json, &pubkey));

    var expected: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, "c308e1f882c1f1dff2a43d4294239ddeec04e575f2d1aad1fa21ea7684e61fb5");
    try std.testing.expectEqualSlices(u8, &expected, &pubkey);
}

test "parseClaim" {
    const json =
        \\{"kind":28934,"tags":[["-"],["claim","invite-code-123"]]}
    ;

    const claim = parseClaim(json).?;
    try std.testing.expectEqualStrings("invite-code-123", claim);
}

test "parseClaim from invite response" {
    const json =
        \\{"kind":28935,"tags":[["-"],["claim","abc123xyz"]]}
    ;

    const claim = parseClaim(json).?;
    try std.testing.expectEqualStrings("abc123xyz", claim);
}

test "hasProtectedTag" {
    try std.testing.expect(hasProtectedTag("{\"tags\":[[\"-\"]]}"));
    try std.testing.expect(hasProtectedTag("{\"tags\":[[\"p\",\"abc\"],[\"-\"]]}"));
    try std.testing.expect(!hasProtectedTag("{\"tags\":[[\"p\",\"abc\"]]}"));
    try std.testing.expect(!hasProtectedTag("{\"tags\":[]}"));
    try std.testing.expect(!hasProtectedTag("{\"tags\":[[\"-\",\"x\"]]}"));
}

test "parseKind" {
    try std.testing.expectEqual(@as(?i32, 13534), parseKind("{\"kind\":13534}"));
    try std.testing.expectEqual(@as(?i32, 8000), parseKind("{\"kind\":8000}"));
    try std.testing.expectEqual(@as(?i32, 28934), parseKind("{\"kind\":28934}"));
    try std.testing.expect(parseKind("{\"content\":\"test\"}") == null);
}

test "MemberIterator skips invalid hex" {
    const json =
        \\{"tags":[["member","invalid"],["member","c308e1f882c1f1dff2a43d4294239ddeec04e575f2d1aad1fa21ea7684e61fb5"]]}
    ;

    var iter = MemberIterator.init(json);
    const first = iter.next().?;
    try std.testing.expectEqualStrings("c308e1f882c1f1dff2a43d4294239ddeec04e575f2d1aad1fa21ea7684e61fb5", first);
    try std.testing.expect(iter.next() == null);
}

test "parsePTag returns false for missing tag" {
    const json = "{\"kind\":8000,\"tags\":[[\"-\"]]}";
    var pubkey: [32]u8 = undefined;
    try std.testing.expect(!parsePTag(json, &pubkey));
}

test "parseClaim returns null for missing claim" {
    const json = "{\"kind\":28934,\"tags\":[[\"-\"]]}";
    try std.testing.expect(parseClaim(json) == null);
}

test "ignores tags in content" {
    const json =
        \\{"content":"[\"p\",\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"]","tags":[["p","c308e1f882c1f1dff2a43d4294239ddeec04e575f2d1aad1fa21ea7684e61fb5"]]}
    ;
    var pubkey: [32]u8 = undefined;
    try std.testing.expect(parsePTag(json, &pubkey));
    var expected: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, "c308e1f882c1f1dff2a43d4294239ddeec04e575f2d1aad1fa21ea7684e61fb5");
    try std.testing.expectEqualSlices(u8, &expected, &pubkey);
}

test "ignores member tags in content" {
    const json =
        \\{"content":"[\"member\",\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"]","tags":[["member","c308e1f882c1f1dff2a43d4294239ddeec04e575f2d1aad1fa21ea7684e61fb5"]]}
    ;
    var iter = MemberIterator.init(json);
    const first = iter.next().?;
    try std.testing.expectEqualStrings("c308e1f882c1f1dff2a43d4294239ddeec04e575f2d1aad1fa21ea7684e61fb5", first);
    try std.testing.expect(iter.next() == null);
}

test "ignores hashtags field" {
    const json =
        \\{"hashtags":["test"],"tags":[["p","c308e1f882c1f1dff2a43d4294239ddeec04e575f2d1aad1fa21ea7684e61fb5"]]}
    ;
    var pubkey: [32]u8 = undefined;
    try std.testing.expect(parsePTag(json, &pubkey));
}

test "handles escaped quotes in strings" {
    const json =
        \\{"content":"test\"tags\":[\"p\",\"bad\"]","tags":[["p","c308e1f882c1f1dff2a43d4294239ddeec04e575f2d1aad1fa21ea7684e61fb5"]]}
    ;
    var pubkey: [32]u8 = undefined;
    try std.testing.expect(parsePTag(json, &pubkey));
}
