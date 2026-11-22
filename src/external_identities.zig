const std = @import("std");
const event_mod = @import("event.zig");
const utils = @import("utils.zig");
const bech32 = @import("bech32.zig");

pub const Event = event_mod.Event;

pub const METADATA_KIND: i32 = 0;
pub const IDENTITY_KIND: i32 = 10011;

pub const Platform = enum {
    github,
    twitter,
    mastodon,
    telegram,
    bluesky,
    discord,
    unknown,

    pub fn fromString(s: []const u8) Platform {
        if (std.mem.eql(u8, s, "github")) return .github;
        if (std.mem.eql(u8, s, "twitter")) return .twitter;
        if (std.mem.eql(u8, s, "mastodon")) return .mastodon;
        if (std.mem.eql(u8, s, "telegram")) return .telegram;
        if (std.mem.eql(u8, s, "bluesky")) return .bluesky;
        if (std.mem.eql(u8, s, "discord")) return .discord;
        return .unknown;
    }

    pub fn toString(self: Platform) []const u8 {
        return switch (self) {
            .github => "github",
            .twitter => "twitter",
            .mastodon => "mastodon",
            .telegram => "telegram",
            .bluesky => "bluesky",
            .discord => "discord",
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
            .identities = .empty,
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
        if (event.kind() != IDENTITY_KIND and event.kind() != METADATA_KIND) {
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
            const tag_start = utils.findBracketInJson(self.json, self.pos, '[') orelse return null;
            const tag_end = utils.findBracketInJson(self.json, tag_start + 1, ']') orelse return null;
            self.pos = tag_end + 1;

            const tag_content = self.json[tag_start + 1 .. tag_end];
            const strings = utils.parseTagStrings(tag_content, 3) orelse continue;
            if (!std.mem.eql(u8, strings[0], "i")) continue;
            if (strings[2].len == 0) continue;

            const platform_identity = strings[1];
            const colon_pos = std.mem.indexOfScalar(u8, platform_identity, ':') orelse continue;
            if (colon_pos == 0 or colon_pos >= platform_identity.len - 1) continue;

            return .{
                .platform = Platform.fromString(platform_identity[0..colon_pos]),
                .platform_name = platform_identity[0..colon_pos],
                .identity = platform_identity[colon_pos + 1 ..],
                .proof = strings[2],
            };
        }
        return null;
    }
};

fn isAlnum(c: u8) bool {
    return std.ascii.isAlphanumeric(c);
}

fn isDigit(c: u8) bool {
    return std.ascii.isDigit(c);
}

fn isHandleChar(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '.' or c == '-';
}

fn isGithubChar(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '-';
}

fn isWordChar(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '_';
}

fn isUserChar(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '_' or c == '.' or c == '-';
}

fn allOf(s: []const u8, comptime pred: fn (u8) bool) bool {
    if (s.len == 0) return false;
    for (s) |c| if (!pred(c)) return false;
    return true;
}

fn isHandle(s: []const u8) bool {
    return allOf(s, isHandleChar) and s[0] != '.' and std.mem.indexOf(u8, s, "..") == null;
}

fn isPublicHost(s: []const u8) bool {
    if (!isHandle(s)) return false;
    const dot = std.mem.lastIndexOfScalar(u8, s, '.') orelse return false;
    const tld = s[dot + 1 ..];
    return tld.len > 0 and !allOf(tld, isDigit);
}

fn splitDigits(s: []const u8, comptime parts: usize) bool {
    var it = std.mem.splitScalar(u8, s, '/');
    var n: usize = 0;
    while (it.next()) |part| : (n += 1) {
        if (n >= parts or !allOf(part, isDigit)) return false;
    }
    return n == parts;
}

fn isValidClaim(identity: ExternalIdentity) bool {
    const id = identity.identity;
    const proof = identity.proof;
    return switch (identity.platform) {
        .github => allOf(id, isGithubChar) and allOf(proof, isAlnum),
        .twitter => allOf(id, isWordChar) and allOf(proof, isDigit),
        .mastodon => blk: {
            const sep = std.mem.indexOf(u8, id, "/@") orelse break :blk false;
            break :blk isPublicHost(id[0..sep]) and allOf(id[sep + 2 ..], isUserChar) and allOf(proof, isAlnum);
        },
        .telegram => blk: {
            const slash = std.mem.indexOfScalar(u8, proof, '/') orelse break :blk false;
            break :blk allOf(proof[0..slash], isWordChar) and allOf(proof[slash + 1 ..], isDigit);
        },
        .bluesky => isHandle(id) and allOf(proof, isAlnum),
        .discord => splitDigits(proof, 3),
        .unknown => false,
    };
}

// Returns null when the identity or proof holds characters outside what the
// platform uses, so a crafted value cannot redirect the URL to another account.
pub fn getProofUrl(identity: ExternalIdentity, buf: []u8) ?[]u8 {
    if (!isValidClaim(identity)) return null;

    var stream = std.Io.Writer.fixed(buf);
    const writer = &stream;

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
        .bluesky => {
            writer.print("https://bsky.app/profile/{s}/post/{s}", .{ identity.identity, identity.proof }) catch return null;
        },
        .discord => {
            writer.print("https://discord.com/channels/{s}", .{identity.proof}) catch return null;
        },
        .unknown => return null,
    }

    return stream.buffered();
}

pub fn getExpectedProofText(platform: Platform, pubkey: *const [32]u8, buf: []u8) ?[]u8 {
    if (platform == .unknown) return null;

    var npub_buf: [63]u8 = undefined;
    bech32.encodeNpub(pubkey, &npub_buf);

    var stream = std.Io.Writer.fixed(buf);
    stream.print("Verifying that I control the following Nostr public key: {s}", .{npub_buf}) catch return null;
    return stream.buffered();
}

// NIP-39 asks verifiers to accept any proof that contains the npub, so a post
// that only mentions the npub (for example to disown it) also passes. The caller
// must still check that the proof was published by the claimed identity.
pub fn proofMentionsPubkey(proof_text: []const u8, pubkey: *const [32]u8) bool {
    var npub_buf: [63]u8 = undefined;
    bech32.encodeNpub(pubkey, &npub_buf);
    var pos: usize = 0;
    while (pos + npub_buf.len <= proof_text.len) {
        const at = std.ascii.findIgnoreCasePos(proof_text, pos, &npub_buf) orelse return false;
        const end = at + npub_buf.len;
        const before_ok = at == 0 or !std.ascii.isAlphanumeric(proof_text[at - 1]);
        const after_ok = end == proof_text.len or !std.ascii.isAlphanumeric(proof_text[end]);
        if (before_ok and after_ok) return true;
        pos = at + 1;
    }
    return false;
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
    try std.testing.expectEqual(Platform.bluesky, Platform.fromString("bluesky"));
    try std.testing.expectEqual(Platform.discord, Platform.fromString("discord"));
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

    const bluesky = ExternalIdentity{ .platform = .bluesky, .platform_name = "bluesky", .identity = "alice.bsky.social", .proof = "3kabc" };
    const bluesky_url = getProofUrl(bluesky, &buf).?;
    try std.testing.expectEqualStrings("https://bsky.app/profile/alice.bsky.social/post/3kabc", bluesky_url);

    const discord = ExternalIdentity{ .platform = .discord, .platform_name = "discord", .identity = "alice", .proof = "111/222/333" };
    const discord_url = getProofUrl(discord, &buf).?;
    try std.testing.expectEqualStrings("https://discord.com/channels/111/222/333", discord_url);

    const unknown = ExternalIdentity{ .platform = .unknown, .platform_name = "facebook", .identity = "test", .proof = "proof" };
    try std.testing.expect(getProofUrl(unknown, &buf) == null);
}

test "getExpectedProofText generates correct text" {
    var pubkey: [32]u8 = undefined;
    @memset(&pubkey, 0);
    var buf: [256]u8 = undefined;

    var npub: [63]u8 = undefined;
    bech32.encodeNpub(&pubkey, &npub);
    var want_buf: [128]u8 = undefined;
    const want = try std.fmt.bufPrint(&want_buf, "Verifying that I control the following Nostr public key: {s}", .{npub});

    for ([_]Platform{ .github, .twitter, .mastodon, .telegram, .bluesky, .discord }) |platform| {
        try std.testing.expectEqualStrings(want, getExpectedProofText(platform, &pubkey, &buf).?);
    }

    try std.testing.expect(getExpectedProofText(.unknown, &pubkey, &buf) == null);
    try std.testing.expect(getExpectedProofText(.github, &pubkey, buf[0..10]) == null);
}

test "proofMentionsPubkey accepts current and earlier proof texts" {
    var pubkey: [32]u8 = undefined;
    @memset(&pubkey, 0);
    var other: [32]u8 = undefined;
    @memset(&other, 1);

    var npub: [63]u8 = undefined;
    bech32.encodeNpub(&pubkey, &npub);
    var buf: [256]u8 = undefined;

    const current = getExpectedProofText(.github, &pubkey, &buf).?;
    try std.testing.expect(proofMentionsPubkey(current, &pubkey));
    try std.testing.expect(!proofMentionsPubkey(current, &other));

    const old_twitter = try std.fmt.bufPrint(&buf, "Verifying my account on nostr My Public Key: \"{s}\"", .{npub});
    try std.testing.expect(proofMentionsPubkey(old_twitter, &pubkey));

    const old_quoted = try std.fmt.bufPrint(&buf, "Verifying that I control the following Nostr public key: \"{s}\"", .{npub});
    try std.testing.expect(proofMentionsPubkey(old_quoted, &pubkey));

    try std.testing.expect(!proofMentionsPubkey("Verifying that I control the following Nostr public key: ", &pubkey));
    try std.testing.expect(!proofMentionsPubkey(npub[0..62], &pubkey));

    var upper: [63]u8 = undefined;
    _ = std.ascii.upperString(&upper, &npub);
    try std.testing.expect(proofMentionsPubkey(&upper, &pubkey));

    const embedded = try std.fmt.bufPrint(&buf, "x{s}", .{npub});
    try std.testing.expect(!proofMentionsPubkey(embedded, &pubkey));
    const trailing = try std.fmt.bufPrint(&buf, "{s}q", .{npub});
    try std.testing.expect(!proofMentionsPubkey(trailing, &pubkey));
    const later = try std.fmt.bufPrint(&buf, "x{s} and {s}.", .{ npub, npub });
    try std.testing.expect(proofMentionsPubkey(later, &pubkey));
}

test "getProofUrl rejects values that could point at another account" {
    var buf: [256]u8 = undefined;
    const Case = struct { platform: Platform, identity: []const u8, proof: []const u8 };
    const bad = [_]Case{
        .{ .platform = .bluesky, .identity = "famous.bsky.social", .proof = "../../mallory.bsky.social/post/3kxyz" },
        .{ .platform = .bluesky, .identity = "famous.bsky.social", .proof = "..\\/..\\/x" },
        .{ .platform = .bluesky, .identity = "..", .proof = "3kxyz" },
        .{ .platform = .bluesky, .identity = ".bsky.social", .proof = "3kxyz" },
        .{ .platform = .bluesky, .identity = "a..b", .proof = "3kxyz" },
        .{ .platform = .bluesky, .identity = "famous.bsky.social", .proof = "3kxyz?x" },
        .{ .platform = .bluesky, .identity = "famous.bsky.social", .proof = "" },
        .{ .platform = .github, .identity = "famous", .proof = "../mallory/abc" },
        .{ .platform = .github, .identity = "famous/../mallory", .proof = "abc" },
        .{ .platform = .twitter, .identity = "famous", .proof = "1/../../mallory/status/2" },
        .{ .platform = .twitter, .identity = "famous#", .proof = "1" },
        .{ .platform = .mastodon, .identity = "evil.com@mastodon.social/@a", .proof = "1" },
        .{ .platform = .mastodon, .identity = "127.0.0.1:8080/@a", .proof = "1" },
        .{ .platform = .mastodon, .identity = "169.254.169.254/@a", .proof = "1" },
        .{ .platform = .mastodon, .identity = "localhost/@a", .proof = "1" },
        .{ .platform = .mastodon, .identity = "mastodon.social./@a", .proof = "1" },
        .{ .platform = .mastodon, .identity = "mastodon.social", .proof = "1" },
        .{ .platform = .mastodon, .identity = "mastodon.social/@a/../b", .proof = "1" },
        .{ .platform = .mastodon, .identity = "mastodon.social/@a", .proof = "../1" },
        .{ .platform = .telegram, .identity = "1", .proof = "channel" },
        .{ .platform = .telegram, .identity = "1", .proof = "../evil/1" },
        .{ .platform = .telegram, .identity = "1", .proof = "channel/1/2" },
        .{ .platform = .discord, .identity = "alice", .proof = "1/2" },
        .{ .platform = .discord, .identity = "alice", .proof = "1/2/3/4" },
        .{ .platform = .discord, .identity = "alice", .proof = "1/2/../3" },
        .{ .platform = .discord, .identity = "alice", .proof = "1//3" },
        .{ .platform = .discord, .identity = "alice", .proof = "1/2/3 " },
    };
    for (bad) |c| {
        const id = ExternalIdentity{ .platform = c.platform, .platform_name = c.platform.toString(), .identity = c.identity, .proof = c.proof };
        try std.testing.expect(getProofUrl(id, &buf) == null);
    }

    const dashed = ExternalIdentity{ .platform = .github, .platform_name = "github", .identity = "some-user", .proof = "9721ce4ee4fceb91c9711ca2a6c9a5ab" };
    try std.testing.expectEqualStrings("https://gist.github.com/some-user/9721ce4ee4fceb91c9711ca2a6c9a5ab", getProofUrl(dashed, &buf).?);
    const masto = ExternalIdentity{ .platform = .mastodon, .platform_name = "mastodon", .identity = "bitcoinhackers.org/@semisol", .proof = "109775066355589974" };
    try std.testing.expectEqualStrings("https://bitcoinhackers.org/@semisol/109775066355589974", getProofUrl(masto, &buf).?);
    const tg = ExternalIdentity{ .platform = .telegram, .platform_name = "telegram", .identity = "1087295469", .proof = "nostrdirectory/770" };
    try std.testing.expectEqualStrings("https://t.me/nostrdirectory/770", getProofUrl(tg, &buf).?);
}

test "IdentityList.fromEvent reads kind 10011" {
    const allocator = std.testing.allocator;
    var event = try Event.parseWithAllocator(
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":10011,"created_at":1700000000,"content":"","tags":[["i","bluesky:alice.bsky.social","3kabc"],["i","discord:alice","1/2/3"]]}
    , allocator);
    defer event.deinit();

    var list = try IdentityList.fromEvent(&event, allocator);
    defer list.deinit();
    try std.testing.expectEqual(@as(usize, 2), list.count());
    try std.testing.expectEqual(Platform.bluesky, list.identities.items[0].platform);
    try std.testing.expectEqual(Platform.discord, list.identities.items[1].platform);
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
