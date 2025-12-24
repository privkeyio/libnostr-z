const std = @import("std");
const event_mod = @import("event.zig");
const utils = @import("utils.zig");
const bech32 = @import("bech32.zig");

pub const Event = event_mod.Event;

pub const METADATA_KIND: i32 = 0;

pub const Platform = enum {
    github,
    twitter,
    mastodon,
    telegram,
    unknown,

    pub fn fromString(s: []const u8) Platform {
        if (std.mem.eql(u8, s, "github")) return .github;
        if (std.mem.eql(u8, s, "twitter")) return .twitter;
        if (std.mem.eql(u8, s, "mastodon")) return .mastodon;
        if (std.mem.eql(u8, s, "telegram")) return .telegram;
        return .unknown;
    }

    pub fn toString(self: Platform) []const u8 {
        return switch (self) {
            .github => "github",
            .twitter => "twitter",
            .mastodon => "mastodon",
            .telegram => "telegram",
            .unknown => "unknown",
        };
    }
};

pub const ExternalIdentity = struct {
    platform: Platform,
    platform_name: []const u8,
    identity: []const u8,
    proof: []const u8,
};

pub const IdentityList = struct {
    identities: std.ArrayListUnmanaged(ExternalIdentity),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) IdentityList {
        return .{
            .identities = .{},
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *IdentityList) void {
        for (self.identities.items) |identity| {
            self.allocator.free(identity.platform_name);
            self.allocator.free(identity.identity);
            self.allocator.free(identity.proof);
        }
        self.identities.deinit(self.allocator);
    }

    pub fn fromEvent(event: *const Event, allocator: std.mem.Allocator) !IdentityList {
        if (event.kind() != METADATA_KIND) {
            return error.InvalidKind;
        }

        var list = IdentityList.init(allocator);
        errdefer list.deinit();

        const tags_json = utils.findJsonValue(event.raw_json, "tags") orelse return list;
        var iter = IdentityTagIterator.init(tags_json);

        while (iter.next()) |entry| {
            const platform_name_copy = try allocator.dupe(u8, entry.platform_name);
            errdefer allocator.free(platform_name_copy);
            const identity_copy = try allocator.dupe(u8, entry.identity);
            errdefer allocator.free(identity_copy);
            const proof_copy = try allocator.dupe(u8, entry.proof);
            errdefer allocator.free(proof_copy);
            try list.identities.append(allocator, .{
                .platform = entry.platform,
                .platform_name = platform_name_copy,
                .identity = identity_copy,
                .proof = proof_copy,
            });
        }

        return list;
    }

    pub fn count(self: *const IdentityList) usize {
        return self.identities.items.len;
    }

    pub fn iterator(self: *const IdentityList) IdentityIterator {
        return .{ .list = self, .index = 0 };
    }
};

pub const IdentityIterator = struct {
    list: *const IdentityList,
    index: usize,

    pub fn next(self: *IdentityIterator) ?ExternalIdentity {
        if (self.index >= self.list.identities.items.len) return null;
        const identity = self.list.identities.items[self.index];
        self.index += 1;
        return identity;
    }
};

const IdentityTagIterator = struct {
    json: []const u8,
    pos: usize,

    const Entry = struct {
        platform: Platform,
        platform_name: []const u8,
        identity: []const u8,
        proof: []const u8,
    };

    fn init(json: []const u8) IdentityTagIterator {
        return .{ .json = json, .pos = 0 };
    }

    fn next(self: *IdentityTagIterator) ?Entry {
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
            if (self.parseITag(tag_content)) |entry| {
                return entry;
            }
        }
        return null;
    }

    fn findBracket(self: *IdentityTagIterator, bracket: u8) ?usize {
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

    fn parseITag(self: *const IdentityTagIterator, content: []const u8) ?Entry {
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
        if (!std.mem.eql(u8, strings[0], "i")) return null;

        const platform_identity = strings[1];
        const colon_pos = std.mem.indexOfScalar(u8, platform_identity, ':') orelse return null;
        if (colon_pos == 0 or colon_pos >= platform_identity.len - 1) return null;

        const platform_name = platform_identity[0..colon_pos];
        const identity = platform_identity[colon_pos + 1 ..];
        const proof = strings[2];

        return .{
            .platform = Platform.fromString(platform_name),
            .platform_name = platform_name,
            .identity = identity,
            .proof = proof,
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

pub fn getProofUrl(identity: ExternalIdentity, buf: []u8) ?[]u8 {
    var stream = std.io.fixedBufferStream(buf);
    const writer = stream.writer();

    switch (identity.platform) {
        .github => {
            writer.print("https://gist.github.com/{s}/{s}", .{ identity.identity, identity.proof }) catch return null;
        },
        .twitter => {
            writer.print("https://twitter.com/{s}/status/{s}", .{ identity.identity, identity.proof }) catch return null;
        },
        .mastodon => {
            writer.print("https://{s}/{s}", .{ identity.identity, identity.proof }) catch return null;
        },
        .telegram => {
            writer.print("https://t.me/{s}", .{identity.proof}) catch return null;
        },
        .unknown => return null,
    }

    return buf[0..stream.pos];
}

pub fn getExpectedProofText(platform: Platform, pubkey: *const [32]u8, buf: []u8) ?[]u8 {
    var npub_buf: [63]u8 = undefined;
    bech32.encodeNpub(pubkey, &npub_buf);

    var stream = std.io.fixedBufferStream(buf);
    const writer = stream.writer();

    switch (platform) {
        .github => {
            writer.print("Verifying that I control the following Nostr public key: {s}", .{npub_buf}) catch return null;
        },
        .twitter => {
            writer.print("Verifying my account on nostr My Public Key: \"{s}\"", .{npub_buf}) catch return null;
        },
        .mastodon, .telegram => {
            writer.print("Verifying that I control the following Nostr public key: \"{s}\"", .{npub_buf}) catch return null;
        },
        .unknown => return null,
    }

    return buf[0..stream.pos];
}

pub fn buildIdentityTags(
    identities: []const ExternalIdentity,
    buf: [][]const []const u8,
    string_buf: [][]const u8,
    platform_identity_buf: []u8,
) usize {
    var tag_idx: usize = 0;
    var str_idx: usize = 0;
    var pi_offset: usize = 0;

    const i_str = "i";

    for (identities) |identity| {
        if (tag_idx >= buf.len) break;
        if (str_idx + 3 > string_buf.len) break;

        const pi_len = identity.platform_name.len + 1 + identity.identity.len;
        if (pi_offset + pi_len > platform_identity_buf.len) break;

        @memcpy(platform_identity_buf[pi_offset .. pi_offset + identity.platform_name.len], identity.platform_name);
        platform_identity_buf[pi_offset + identity.platform_name.len] = ':';
        @memcpy(platform_identity_buf[pi_offset + identity.platform_name.len + 1 .. pi_offset + pi_len], identity.identity);

        string_buf[str_idx] = i_str;
        string_buf[str_idx + 1] = platform_identity_buf[pi_offset .. pi_offset + pi_len];
        string_buf[str_idx + 2] = identity.proof;

        buf[tag_idx] = string_buf[str_idx .. str_idx + 3];
        str_idx += 3;
        tag_idx += 1;
        pi_offset += pi_len;
    }

    return tag_idx;
}

pub fn isValidPlatformName(name: []const u8) bool {
    if (name.len == 0) return false;
    for (name) |c| {
        const valid = (c >= 'a' and c <= 'z') or
            (c >= '0' and c <= '9') or
            c == '.' or c == '_' or c == '-' or c == '/';
        if (!valid) return false;
    }
    return true;
}

test "Platform.fromString parses known platforms" {
    try std.testing.expectEqual(Platform.github, Platform.fromString("github"));
    try std.testing.expectEqual(Platform.twitter, Platform.fromString("twitter"));
    try std.testing.expectEqual(Platform.mastodon, Platform.fromString("mastodon"));
    try std.testing.expectEqual(Platform.telegram, Platform.fromString("telegram"));
    try std.testing.expectEqual(Platform.unknown, Platform.fromString("facebook"));
}

test "IdentityList.fromEvent parses kind:0 i tags" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":0,"created_at":1700000000,"content":"{}","tags":[["i","github:semisol","9721ce4ee4fceb91c9711ca2a6c9a5ab"],["i","twitter:semisol_public","1619358434134196225"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    var list = try IdentityList.fromEvent(&event, std.testing.allocator);
    defer list.deinit();

    try std.testing.expectEqual(@as(usize, 2), list.count());

    const identities = list.identities.items;
    try std.testing.expectEqual(Platform.github, identities[0].platform);
    try std.testing.expectEqualStrings("semisol", identities[0].identity);
    try std.testing.expectEqualStrings("9721ce4ee4fceb91c9711ca2a6c9a5ab", identities[0].proof);

    try std.testing.expectEqual(Platform.twitter, identities[1].platform);
    try std.testing.expectEqualStrings("semisol_public", identities[1].identity);
    try std.testing.expectEqualStrings("1619358434134196225", identities[1].proof);
}

test "IdentityList.fromEvent parses mastodon identity" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":0,"created_at":1700000000,"content":"{}","tags":[["i","mastodon:bitcoinhackers.org/@semisol","109775066355589974"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    var list = try IdentityList.fromEvent(&event, std.testing.allocator);
    defer list.deinit();

    try std.testing.expectEqual(@as(usize, 1), list.count());
    try std.testing.expectEqual(Platform.mastodon, list.identities.items[0].platform);
    try std.testing.expectEqualStrings("bitcoinhackers.org/@semisol", list.identities.items[0].identity);
}

test "IdentityList.fromEvent parses telegram identity" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":0,"created_at":1700000000,"content":"{}","tags":[["i","telegram:1087295469","nostrdirectory/770"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    var list = try IdentityList.fromEvent(&event, std.testing.allocator);
    defer list.deinit();

    try std.testing.expectEqual(@as(usize, 1), list.count());
    try std.testing.expectEqual(Platform.telegram, list.identities.items[0].platform);
    try std.testing.expectEqualStrings("1087295469", list.identities.items[0].identity);
    try std.testing.expectEqualStrings("nostrdirectory/770", list.identities.items[0].proof);
}

test "IdentityList rejects wrong kind" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":1,"created_at":1700000000,"content":"test","tags":[["i","github:test","proof"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    const result = IdentityList.fromEvent(&event, std.testing.allocator);
    try std.testing.expectError(error.InvalidKind, result);
}

test "IdentityList.iterator iterates all identities" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":0,"created_at":1700000000,"content":"{}","tags":[["i","github:user1","proof1"],["i","twitter:user2","proof2"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    var list = try IdentityList.fromEvent(&event, std.testing.allocator);
    defer list.deinit();

    var iter = list.iterator();
    var count: usize = 0;
    while (iter.next()) |_| {
        count += 1;
    }

    try std.testing.expectEqual(@as(usize, 2), count);
}

test "getProofUrl generates correct URLs" {
    var buf: [256]u8 = undefined;

    const github = ExternalIdentity{ .platform = .github, .platform_name = "github", .identity = "semisol", .proof = "abc123" };
    const github_url = getProofUrl(github, &buf).?;
    try std.testing.expectEqualStrings("https://gist.github.com/semisol/abc123", github_url);

    const twitter = ExternalIdentity{ .platform = .twitter, .platform_name = "twitter", .identity = "user", .proof = "12345" };
    const twitter_url = getProofUrl(twitter, &buf).?;
    try std.testing.expectEqualStrings("https://twitter.com/user/status/12345", twitter_url);

    const mastodon = ExternalIdentity{ .platform = .mastodon, .platform_name = "mastodon", .identity = "instance.social/@user", .proof = "67890" };
    const mastodon_url = getProofUrl(mastodon, &buf).?;
    try std.testing.expectEqualStrings("https://instance.social/@user/67890", mastodon_url);

    const telegram = ExternalIdentity{ .platform = .telegram, .platform_name = "telegram", .identity = "123456", .proof = "channel/999" };
    const telegram_url = getProofUrl(telegram, &buf).?;
    try std.testing.expectEqualStrings("https://t.me/channel/999", telegram_url);

    const unknown = ExternalIdentity{ .platform = .unknown, .platform_name = "facebook", .identity = "test", .proof = "proof" };
    try std.testing.expect(getProofUrl(unknown, &buf) == null);
}

test "getExpectedProofText generates correct text" {
    var pubkey: [32]u8 = undefined;
    @memset(&pubkey, 0);
    var buf: [256]u8 = undefined;

    const github_text = getExpectedProofText(.github, &pubkey, &buf).?;
    try std.testing.expect(std.mem.startsWith(u8, github_text, "Verifying that I control the following Nostr public key: npub1"));

    const twitter_text = getExpectedProofText(.twitter, &pubkey, &buf).?;
    try std.testing.expect(std.mem.startsWith(u8, twitter_text, "Verifying my account on nostr My Public Key: \"npub1"));

    const mastodon_text = getExpectedProofText(.mastodon, &pubkey, &buf).?;
    try std.testing.expect(std.mem.startsWith(u8, mastodon_text, "Verifying that I control the following Nostr public key: \"npub1"));

    try std.testing.expect(getExpectedProofText(.unknown, &pubkey, &buf) == null);
}

test "buildIdentityTags creates correct tag structure" {
    const identities = [_]ExternalIdentity{
        .{ .platform = .github, .platform_name = "github", .identity = "user1", .proof = "gist123" },
        .{ .platform = .twitter, .platform_name = "twitter", .identity = "user2", .proof = "tweet456" },
    };

    var tag_buf: [10][]const []const u8 = undefined;
    var string_buf: [30][]const u8 = undefined;
    var pi_buf: [256]u8 = undefined;

    const count = buildIdentityTags(&identities, &tag_buf, &string_buf, &pi_buf);

    try std.testing.expectEqual(@as(usize, 2), count);

    try std.testing.expectEqual(@as(usize, 3), tag_buf[0].len);
    try std.testing.expectEqualStrings("i", tag_buf[0][0]);
    try std.testing.expectEqualStrings("github:user1", tag_buf[0][1]);
    try std.testing.expectEqualStrings("gist123", tag_buf[0][2]);

    try std.testing.expectEqual(@as(usize, 3), tag_buf[1].len);
    try std.testing.expectEqualStrings("i", tag_buf[1][0]);
    try std.testing.expectEqualStrings("twitter:user2", tag_buf[1][1]);
    try std.testing.expectEqualStrings("tweet456", tag_buf[1][2]);
}

test "buildIdentityTags preserves unknown platform names" {
    const identities = [_]ExternalIdentity{
        .{ .platform = .unknown, .platform_name = "facebook", .identity = "user1", .proof = "post123" },
    };

    var tag_buf: [10][]const []const u8 = undefined;
    var string_buf: [30][]const u8 = undefined;
    var pi_buf: [256]u8 = undefined;

    const count = buildIdentityTags(&identities, &tag_buf, &string_buf, &pi_buf);

    try std.testing.expectEqual(@as(usize, 1), count);
    try std.testing.expectEqualStrings("facebook:user1", tag_buf[0][1]);
}

test "IdentityList handles empty tags" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":0,"created_at":1700000000,"content":"{}","tags":[]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    var list = try IdentityList.fromEvent(&event, std.testing.allocator);
    defer list.deinit();

    try std.testing.expectEqual(@as(usize, 0), list.count());
}

test "IdentityList ignores non-i tags" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":0,"created_at":1700000000,"content":"{}","tags":[["p","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],["i","github:test","proof"],["e","bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    var list = try IdentityList.fromEvent(&event, std.testing.allocator);
    defer list.deinit();

    try std.testing.expectEqual(@as(usize, 1), list.count());
    try std.testing.expectEqual(Platform.github, list.identities.items[0].platform);
}

test "IdentityList handles unknown platform" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":0,"created_at":1700000000,"content":"{}","tags":[["i","facebook:user123","proofabc"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    var list = try IdentityList.fromEvent(&event, std.testing.allocator);
    defer list.deinit();

    try std.testing.expectEqual(@as(usize, 1), list.count());
    try std.testing.expectEqual(Platform.unknown, list.identities.items[0].platform);
    try std.testing.expectEqualStrings("facebook", list.identities.items[0].platform_name);
    try std.testing.expectEqualStrings("user123", list.identities.items[0].identity);
}

test "isValidPlatformName validates correctly" {
    try std.testing.expect(isValidPlatformName("github"));
    try std.testing.expect(isValidPlatformName("my_platform"));
    try std.testing.expect(isValidPlatformName("my-platform"));
    try std.testing.expect(isValidPlatformName("my.platform"));
    try std.testing.expect(isValidPlatformName("platform/sub"));
    try std.testing.expect(isValidPlatformName("platform123"));

    try std.testing.expect(!isValidPlatformName(""));
    try std.testing.expect(!isValidPlatformName("Platform"));
    try std.testing.expect(!isValidPlatformName("plat:form"));
    try std.testing.expect(!isValidPlatformName("plat form"));
}
