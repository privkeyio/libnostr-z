const std = @import("std");
const event_mod = @import("event.zig");
const utils = @import("utils.zig");

pub const Event = event_mod.Event;

pub const BADGE_DEFINITION_KIND: i32 = 30009;
pub const BADGE_AWARD_KIND: i32 = 8;
pub const PROFILE_BADGES_KIND: i32 = 30008;

pub const ImageDimensions = struct {
    width: u32,
    height: u32,

    pub fn parse(dim_str: []const u8) ?ImageDimensions {
        const x_pos = std.mem.indexOfScalar(u8, dim_str, 'x') orelse return null;
        if (x_pos == 0 or x_pos >= dim_str.len - 1) return null;
        const width = std.fmt.parseInt(u32, dim_str[0..x_pos], 10) catch return null;
        const height = std.fmt.parseInt(u32, dim_str[x_pos + 1 ..], 10) catch return null;
        return .{ .width = width, .height = height };
    }
};

pub const Thumbnail = struct {
    url: []const u8,
    dimensions: ?ImageDimensions,
};

pub const BadgeDefinition = struct {
    unique_name: []const u8,
    name: ?[]const u8,
    description: ?[]const u8,
    image_url: ?[]const u8,
    image_dimensions: ?ImageDimensions,
    thumbnails: std.ArrayListUnmanaged(Thumbnail),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) BadgeDefinition {
        return .{
            .unique_name = "",
            .name = null,
            .description = null,
            .image_url = null,
            .image_dimensions = null,
            .thumbnails = .{},
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *BadgeDefinition) void {
        if (self.unique_name.len > 0) self.allocator.free(self.unique_name);
        if (self.name) |n| self.allocator.free(n);
        if (self.description) |d| self.allocator.free(d);
        if (self.image_url) |u| self.allocator.free(u);
        for (self.thumbnails.items) |thumb| {
            self.allocator.free(thumb.url);
        }
        self.thumbnails.deinit(self.allocator);
    }

    pub fn fromEvent(event: *const Event, allocator: std.mem.Allocator) !BadgeDefinition {
        if (event.kind() != BADGE_DEFINITION_KIND) {
            return error.InvalidKind;
        }

        var def = BadgeDefinition.init(allocator);
        errdefer def.deinit();

        const tags_json = utils.findJsonValue(event.raw_json, "tags") orelse return def;
        var iter = BadgeTagIterator.init(tags_json);

        while (iter.next()) |tag| {
            if (std.mem.eql(u8, tag.name, "d")) {
                if (def.unique_name.len > 0) allocator.free(def.unique_name);
                def.unique_name = try allocator.dupe(u8, tag.value);
            } else if (std.mem.eql(u8, tag.name, "name")) {
                if (def.name) |n| allocator.free(n);
                def.name = try allocator.dupe(u8, tag.value);
            } else if (std.mem.eql(u8, tag.name, "description")) {
                if (def.description) |d| allocator.free(d);
                def.description = try allocator.dupe(u8, tag.value);
            } else if (std.mem.eql(u8, tag.name, "image")) {
                if (def.image_url) |u| allocator.free(u);
                def.image_url = try allocator.dupe(u8, tag.value);
                if (tag.extra) |dim_str| {
                    def.image_dimensions = ImageDimensions.parse(dim_str);
                }
            } else if (std.mem.eql(u8, tag.name, "thumb")) {
                const url_copy = try allocator.dupe(u8, tag.value);
                errdefer allocator.free(url_copy);
                const dimensions = if (tag.extra) |dim_str| ImageDimensions.parse(dim_str) else null;
                try def.thumbnails.append(allocator, .{
                    .url = url_copy,
                    .dimensions = dimensions,
                });
            }
        }

        return def;
    }
};

pub const AwardedPubkey = struct {
    pubkey: []const u8,
    relay_url: ?[]const u8,
};

pub const BadgeAward = struct {
    badge_address: []const u8,
    awarded_pubkeys: std.ArrayListUnmanaged(AwardedPubkey),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) BadgeAward {
        return .{
            .badge_address = "",
            .awarded_pubkeys = .{},
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *BadgeAward) void {
        if (self.badge_address.len > 0) self.allocator.free(self.badge_address);
        for (self.awarded_pubkeys.items) |ap| {
            self.allocator.free(ap.pubkey);
            if (ap.relay_url) |r| self.allocator.free(r);
        }
        self.awarded_pubkeys.deinit(self.allocator);
    }

    pub fn fromEvent(event: *const Event, allocator: std.mem.Allocator) !BadgeAward {
        if (event.kind() != BADGE_AWARD_KIND) {
            return error.InvalidKind;
        }

        var award = BadgeAward.init(allocator);
        errdefer award.deinit();

        const tags_json = utils.findJsonValue(event.raw_json, "tags") orelse return award;
        var iter = BadgeTagIterator.init(tags_json);

        while (iter.next()) |tag| {
            if (std.mem.eql(u8, tag.name, "a")) {
                if (std.mem.startsWith(u8, tag.value, "30009:")) {
                    if (award.badge_address.len > 0) allocator.free(award.badge_address);
                    award.badge_address = try allocator.dupe(u8, tag.value);
                }
            } else if (std.mem.eql(u8, tag.name, "p")) {
                if (tag.value.len == 64) {
                    const pk_copy = try allocator.dupe(u8, tag.value);
                    errdefer allocator.free(pk_copy);
                    const relay_copy = if (tag.extra) |r| try allocator.dupe(u8, r) else null;
                    try award.awarded_pubkeys.append(allocator, .{
                        .pubkey = pk_copy,
                        .relay_url = relay_copy,
                    });
                }
            }
        }

        return award;
    }

    pub fn isValid(self: *const BadgeAward) bool {
        return self.badge_address.len > 0 and self.awarded_pubkeys.items.len > 0;
    }
};

pub const ProfileBadge = struct {
    badge_definition_address: []const u8,
    badge_award_id: []const u8,
    relay_url: ?[]const u8,
};

pub const ProfileBadges = struct {
    badges: std.ArrayListUnmanaged(ProfileBadge),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) ProfileBadges {
        return .{
            .badges = .{},
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *ProfileBadges) void {
        for (self.badges.items) |badge| {
            self.allocator.free(badge.badge_definition_address);
            self.allocator.free(badge.badge_award_id);
            if (badge.relay_url) |r| self.allocator.free(r);
        }
        self.badges.deinit(self.allocator);
    }

    pub fn fromEvent(event: *const Event, allocator: std.mem.Allocator) !ProfileBadges {
        if (event.kind() != PROFILE_BADGES_KIND) {
            return error.InvalidKind;
        }

        const d_tag = event.dTag() orelse return error.InvalidTags;
        if (!std.mem.eql(u8, d_tag, "profile_badges")) {
            return error.InvalidTags;
        }

        var profile = ProfileBadges.init(allocator);
        errdefer profile.deinit();

        const tags_json = utils.findJsonValue(event.raw_json, "tags") orelse return profile;
        var iter = ProfileBadgeTagIterator.init(tags_json);

        while (iter.next()) |pair| {
            const addr_copy = try allocator.dupe(u8, pair.a_tag);
            errdefer allocator.free(addr_copy);
            const id_copy = try allocator.dupe(u8, pair.e_tag);
            errdefer allocator.free(id_copy);
            const relay_copy = if (pair.relay_url) |r| try allocator.dupe(u8, r) else null;

            try profile.badges.append(allocator, .{
                .badge_definition_address = addr_copy,
                .badge_award_id = id_copy,
                .relay_url = relay_copy,
            });
        }

        return profile;
    }

    pub fn count(self: *const ProfileBadges) usize {
        return self.badges.items.len;
    }

    pub fn iterator(self: *const ProfileBadges) ProfileBadgesIterator {
        return .{ .profile = self, .index = 0 };
    }
};

pub const ProfileBadgesIterator = struct {
    profile: *const ProfileBadges,
    index: usize,

    pub fn next(self: *ProfileBadgesIterator) ?ProfileBadge {
        if (self.index >= self.profile.badges.items.len) return null;
        const badge = self.profile.badges.items[self.index];
        self.index += 1;
        return badge;
    }
};

/// Shared tag parsing entry
const TagEntry = struct {
    name: []const u8,
    value: []const u8,
    extra: ?[]const u8,
};

/// Find the end of a JSON string, handling escapes
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

/// Parse a single tag array into name/value/extra components
fn parseTagContent(content: []const u8) ?TagEntry {
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

    if (str_count < 2) return null;

    return .{
        .name = strings[0],
        .value = strings[1],
        .extra = if (str_count >= 3) strings[2] else null,
    };
}

/// Find a bracket character in JSON, respecting string boundaries
fn findBracketInJson(json: []const u8, start: usize, bracket: u8) ?usize {
    var pos = start;
    var in_string = false;
    var escape = false;

    while (pos < json.len) {
        const c = json[pos];

        if (escape) {
            escape = false;
            pos += 1;
            continue;
        }

        if (c == '\\' and in_string) {
            escape = true;
            pos += 1;
            continue;
        }

        if (c == '"') {
            in_string = !in_string;
            pos += 1;
            continue;
        }

        if (!in_string and c == bracket) {
            return pos;
        }

        pos += 1;
    }
    return null;
}

const BadgeTagIterator = struct {
    json: []const u8,
    pos: usize,

    fn init(json: []const u8) BadgeTagIterator {
        return .{ .json = json, .pos = 0 };
    }

    fn next(self: *BadgeTagIterator) ?TagEntry {
        while (self.pos < self.json.len) {
            const tag_start = findBracketInJson(self.json, self.pos, '[') orelse return null;
            self.pos = tag_start + 1;
            const tag_end = findBracketInJson(self.json, self.pos, ']') orelse return null;
            self.pos = tag_end + 1;

            const tag_content = self.json[tag_start + 1 .. tag_end];
            if (parseTagContent(tag_content)) |entry| {
                return entry;
            }
        }
        return null;
    }
};

const ProfileBadgeTagIterator = struct {
    json: []const u8,
    pos: usize,

    const Pair = struct {
        a_tag: []const u8,
        e_tag: []const u8,
        relay_url: ?[]const u8,
    };

    fn init(json: []const u8) ProfileBadgeTagIterator {
        return .{ .json = json, .pos = 0 };
    }

    fn next(self: *ProfileBadgeTagIterator) ?Pair {
        var pending_a: ?[]const u8 = null;

        while (self.pos < self.json.len) {
            const tag_start = findBracketInJson(self.json, self.pos, '[') orelse return null;
            self.pos = tag_start + 1;
            const tag_end = findBracketInJson(self.json, self.pos, ']') orelse return null;
            self.pos = tag_end + 1;

            const tag_content = self.json[tag_start + 1 .. tag_end];
            const parsed = parseTagContent(tag_content) orelse continue;

            if (std.mem.eql(u8, parsed.name, "a") and std.mem.startsWith(u8, parsed.value, "30009:")) {
                pending_a = parsed.value;
            } else if (std.mem.eql(u8, parsed.name, "e") and pending_a != null) {
                if (parsed.value.len == 64) {
                    return .{
                        .a_tag = pending_a.?,
                        .e_tag = parsed.value,
                        .relay_url = parsed.extra,
                    };
                }
                pending_a = null;
            } else if (std.mem.eql(u8, parsed.name, "d")) {
                continue;
            } else {
                pending_a = null;
            }
        }
        return null;
    }
};

pub fn buildBadgeDefinitionTags(
    unique_name: []const u8,
    name: ?[]const u8,
    description: ?[]const u8,
    image_url: ?[]const u8,
    image_dimensions: ?[]const u8,
    buf: [][]const []const u8,
    string_buf: [][]const u8,
) usize {
    var tag_idx: usize = 0;
    var str_idx: usize = 0;

    if (tag_idx >= buf.len or str_idx + 2 > string_buf.len) return tag_idx;
    string_buf[str_idx] = "d";
    string_buf[str_idx + 1] = unique_name;
    buf[tag_idx] = string_buf[str_idx .. str_idx + 2];
    str_idx += 2;
    tag_idx += 1;

    if (name) |n| {
        if (tag_idx >= buf.len or str_idx + 2 > string_buf.len) return tag_idx;
        string_buf[str_idx] = "name";
        string_buf[str_idx + 1] = n;
        buf[tag_idx] = string_buf[str_idx .. str_idx + 2];
        str_idx += 2;
        tag_idx += 1;
    }

    if (description) |d| {
        if (tag_idx >= buf.len or str_idx + 2 > string_buf.len) return tag_idx;
        string_buf[str_idx] = "description";
        string_buf[str_idx + 1] = d;
        buf[tag_idx] = string_buf[str_idx .. str_idx + 2];
        str_idx += 2;
        tag_idx += 1;
    }

    if (image_url) |url| {
        const tag_size: usize = if (image_dimensions != null) 3 else 2;
        if (tag_idx >= buf.len or str_idx + tag_size > string_buf.len) return tag_idx;
        string_buf[str_idx] = "image";
        string_buf[str_idx + 1] = url;
        if (image_dimensions) |dim| {
            string_buf[str_idx + 2] = dim;
        }
        buf[tag_idx] = string_buf[str_idx .. str_idx + tag_size];
        str_idx += tag_size;
        tag_idx += 1;
    }

    return tag_idx;
}

pub fn buildBadgeAwardTags(
    badge_address: []const u8,
    pubkeys: []const []const u8,
    relay_urls: ?[]const ?[]const u8,
    buf: [][]const []const u8,
    string_buf: [][]const u8,
) usize {
    var tag_idx: usize = 0;
    var str_idx: usize = 0;

    if (tag_idx >= buf.len or str_idx + 2 > string_buf.len) return tag_idx;
    string_buf[str_idx] = "a";
    string_buf[str_idx + 1] = badge_address;
    buf[tag_idx] = string_buf[str_idx .. str_idx + 2];
    str_idx += 2;
    tag_idx += 1;

    for (pubkeys, 0..) |pk, i| {
        const relay = if (relay_urls) |r| (if (i < r.len) r[i] else null) else null;
        const tag_size: usize = if (relay != null) 3 else 2;
        if (tag_idx >= buf.len or str_idx + tag_size > string_buf.len) break;

        string_buf[str_idx] = "p";
        string_buf[str_idx + 1] = pk;
        if (relay) |r| {
            string_buf[str_idx + 2] = r;
        }
        buf[tag_idx] = string_buf[str_idx .. str_idx + tag_size];
        str_idx += tag_size;
        tag_idx += 1;
    }

    return tag_idx;
}

pub const BadgePair = struct {
    address: []const u8,
    event_id: []const u8,
    relay_url: ?[]const u8,
};

pub fn buildProfileBadgesTags(
    badge_pairs: []const BadgePair,
    buf: [][]const []const u8,
    string_buf: [][]const u8,
) usize {
    var tag_idx: usize = 0;
    var str_idx: usize = 0;

    if (tag_idx >= buf.len or str_idx + 2 > string_buf.len) return tag_idx;
    string_buf[str_idx] = "d";
    string_buf[str_idx + 1] = "profile_badges";
    buf[tag_idx] = string_buf[str_idx .. str_idx + 2];
    str_idx += 2;
    tag_idx += 1;

    for (badge_pairs) |pair| {
        if (tag_idx >= buf.len or str_idx + 2 > string_buf.len) break;
        string_buf[str_idx] = "a";
        string_buf[str_idx + 1] = pair.address;
        buf[tag_idx] = string_buf[str_idx .. str_idx + 2];
        str_idx += 2;
        tag_idx += 1;

        const e_tag_size: usize = if (pair.relay_url != null) 3 else 2;
        if (tag_idx >= buf.len or str_idx + e_tag_size > string_buf.len) break;
        string_buf[str_idx] = "e";
        string_buf[str_idx + 1] = pair.event_id;
        if (pair.relay_url) |r| {
            string_buf[str_idx + 2] = r;
        }
        buf[tag_idx] = string_buf[str_idx .. str_idx + e_tag_size];
        str_idx += e_tag_size;
        tag_idx += 1;
    }

    return tag_idx;
}

test "ImageDimensions.parse valid dimensions" {
    const dim = ImageDimensions.parse("1024x1024").?;
    try std.testing.expectEqual(@as(u32, 1024), dim.width);
    try std.testing.expectEqual(@as(u32, 1024), dim.height);

    const dim2 = ImageDimensions.parse("256x256").?;
    try std.testing.expectEqual(@as(u32, 256), dim2.width);
    try std.testing.expectEqual(@as(u32, 256), dim2.height);
}

test "ImageDimensions.parse invalid dimensions" {
    try std.testing.expect(ImageDimensions.parse("invalid") == null);
    try std.testing.expect(ImageDimensions.parse("x256") == null);
    try std.testing.expect(ImageDimensions.parse("256x") == null);
    try std.testing.expect(ImageDimensions.parse("") == null);
}

test "BadgeDefinition.fromEvent parses kind:30009" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":30009,"created_at":1700000000,"content":"","tags":[["d","bravery"],["name","Medal of Bravery"],["description","Awarded to users demonstrating bravery"],["image","https://nostr.academy/awards/bravery.png","1024x1024"],["thumb","https://nostr.academy/awards/bravery_256x256.png","256x256"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    var def = try BadgeDefinition.fromEvent(&event, std.testing.allocator);
    defer def.deinit();

    try std.testing.expectEqualStrings("bravery", def.unique_name);
    try std.testing.expectEqualStrings("Medal of Bravery", def.name.?);
    try std.testing.expectEqualStrings("Awarded to users demonstrating bravery", def.description.?);
    try std.testing.expectEqualStrings("https://nostr.academy/awards/bravery.png", def.image_url.?);
    try std.testing.expectEqual(@as(u32, 1024), def.image_dimensions.?.width);
    try std.testing.expectEqual(@as(u32, 1024), def.image_dimensions.?.height);
    try std.testing.expectEqual(@as(usize, 1), def.thumbnails.items.len);
    try std.testing.expectEqualStrings("https://nostr.academy/awards/bravery_256x256.png", def.thumbnails.items[0].url);
    try std.testing.expectEqual(@as(u32, 256), def.thumbnails.items[0].dimensions.?.width);
}

test "BadgeDefinition.fromEvent rejects wrong kind" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":1,"created_at":1700000000,"content":"test","tags":[["d","bravery"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    const result = BadgeDefinition.fromEvent(&event, std.testing.allocator);
    try std.testing.expectError(error.InvalidKind, result);
}

test "BadgeAward.fromEvent parses kind:8" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":8,"created_at":1700000000,"content":"","tags":[["a","30009:0000000000000000000000000000000000000000000000000000000000000002:bravery"],["p","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","wss://relay"],["p","bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","wss://relay"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    var award = try BadgeAward.fromEvent(&event, std.testing.allocator);
    defer award.deinit();

    try std.testing.expectEqualStrings("30009:0000000000000000000000000000000000000000000000000000000000000002:bravery", award.badge_address);
    try std.testing.expectEqual(@as(usize, 2), award.awarded_pubkeys.items.len);
    try std.testing.expectEqualStrings("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", award.awarded_pubkeys.items[0].pubkey);
    try std.testing.expectEqualStrings("wss://relay", award.awarded_pubkeys.items[0].relay_url.?);
    try std.testing.expectEqualStrings("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", award.awarded_pubkeys.items[1].pubkey);
    try std.testing.expect(award.isValid());
}

test "BadgeAward.fromEvent rejects wrong kind" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":1,"created_at":1700000000,"content":"test","tags":[]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    const result = BadgeAward.fromEvent(&event, std.testing.allocator);
    try std.testing.expectError(error.InvalidKind, result);
}

test "ProfileBadges.fromEvent parses kind:30008" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":30008,"created_at":1700000000,"content":"","tags":[["d","profile_badges"],["a","30009:0000000000000000000000000000000000000000000000000000000000000002:bravery"],["e","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","wss://nostr.academy"],["a","30009:0000000000000000000000000000000000000000000000000000000000000002:honor"],["e","bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","wss://nostr.academy"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    var profile = try ProfileBadges.fromEvent(&event, std.testing.allocator);
    defer profile.deinit();

    try std.testing.expectEqual(@as(usize, 2), profile.count());

    const badges = profile.badges.items;
    try std.testing.expectEqualStrings("30009:0000000000000000000000000000000000000000000000000000000000000002:bravery", badges[0].badge_definition_address);
    try std.testing.expectEqualStrings("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", badges[0].badge_award_id);
    try std.testing.expectEqualStrings("wss://nostr.academy", badges[0].relay_url.?);

    try std.testing.expectEqualStrings("30009:0000000000000000000000000000000000000000000000000000000000000002:honor", badges[1].badge_definition_address);
    try std.testing.expectEqualStrings("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", badges[1].badge_award_id);
}

test "ProfileBadges.fromEvent rejects wrong kind" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":1,"created_at":1700000000,"content":"test","tags":[["d","profile_badges"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    const result = ProfileBadges.fromEvent(&event, std.testing.allocator);
    try std.testing.expectError(error.InvalidKind, result);
}

test "ProfileBadges.fromEvent rejects wrong d tag" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":30008,"created_at":1700000000,"content":"","tags":[["d","wrong_identifier"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    const result = ProfileBadges.fromEvent(&event, std.testing.allocator);
    try std.testing.expectError(error.InvalidTags, result);
}

test "ProfileBadges.iterator iterates all badges" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":30008,"created_at":1700000000,"content":"","tags":[["d","profile_badges"],["a","30009:0000000000000000000000000000000000000000000000000000000000000002:badge1"],["e","1111111111111111111111111111111111111111111111111111111111111111"],["a","30009:0000000000000000000000000000000000000000000000000000000000000002:badge2"],["e","2222222222222222222222222222222222222222222222222222222222222222"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    var profile = try ProfileBadges.fromEvent(&event, std.testing.allocator);
    defer profile.deinit();

    var iter = profile.iterator();
    var count: usize = 0;
    while (iter.next()) |_| {
        count += 1;
    }

    try std.testing.expectEqual(@as(usize, 2), count);
}

test "ProfileBadges ignores unpaired tags" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":30008,"created_at":1700000000,"content":"","tags":[["d","profile_badges"],["a","30009:0000000000000000000000000000000000000000000000000000000000000002:valid"],["e","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],["a","30009:0000000000000000000000000000000000000000000000000000000000000002:orphan"],["t","random_tag"],["a","30009:0000000000000000000000000000000000000000000000000000000000000002:another"],["e","bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    var profile = try ProfileBadges.fromEvent(&event, std.testing.allocator);
    defer profile.deinit();

    try std.testing.expectEqual(@as(usize, 2), profile.count());
}

test "buildBadgeDefinitionTags creates correct structure" {
    var tag_buf: [10][]const []const u8 = undefined;
    var string_buf: [30][]const u8 = undefined;

    const count = buildBadgeDefinitionTags(
        "bravery",
        "Medal of Bravery",
        "Awarded for bravery",
        "https://example.com/badge.png",
        "1024x1024",
        &tag_buf,
        &string_buf,
    );

    try std.testing.expectEqual(@as(usize, 4), count);

    try std.testing.expectEqualStrings("d", tag_buf[0][0]);
    try std.testing.expectEqualStrings("bravery", tag_buf[0][1]);

    try std.testing.expectEqualStrings("name", tag_buf[1][0]);
    try std.testing.expectEqualStrings("Medal of Bravery", tag_buf[1][1]);

    try std.testing.expectEqualStrings("description", tag_buf[2][0]);
    try std.testing.expectEqualStrings("Awarded for bravery", tag_buf[2][1]);

    try std.testing.expectEqualStrings("image", tag_buf[3][0]);
    try std.testing.expectEqualStrings("https://example.com/badge.png", tag_buf[3][1]);
    try std.testing.expectEqualStrings("1024x1024", tag_buf[3][2]);
}

test "buildBadgeAwardTags creates correct structure" {
    const pubkeys = [_][]const u8{
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    };
    const relay_urls = [_]?[]const u8{ "wss://relay1", "wss://relay2" };

    var tag_buf: [10][]const []const u8 = undefined;
    var string_buf: [30][]const u8 = undefined;

    const count = buildBadgeAwardTags(
        "30009:pubkey:bravery",
        &pubkeys,
        &relay_urls,
        &tag_buf,
        &string_buf,
    );

    try std.testing.expectEqual(@as(usize, 3), count);

    try std.testing.expectEqualStrings("a", tag_buf[0][0]);
    try std.testing.expectEqualStrings("30009:pubkey:bravery", tag_buf[0][1]);

    try std.testing.expectEqualStrings("p", tag_buf[1][0]);
    try std.testing.expectEqualStrings("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", tag_buf[1][1]);
    try std.testing.expectEqualStrings("wss://relay1", tag_buf[1][2]);

    try std.testing.expectEqualStrings("p", tag_buf[2][0]);
    try std.testing.expectEqualStrings("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", tag_buf[2][1]);
    try std.testing.expectEqualStrings("wss://relay2", tag_buf[2][2]);
}

test "buildProfileBadgesTags creates correct structure" {
    const pairs = [_]BadgePair{
        .{ .address = "30009:pubkey:bravery", .event_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", .relay_url = "wss://relay" },
        .{ .address = "30009:pubkey:honor", .event_id = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", .relay_url = null },
    };

    var tag_buf: [10][]const []const u8 = undefined;
    var string_buf: [30][]const u8 = undefined;

    const count = buildProfileBadgesTags(&pairs, &tag_buf, &string_buf);

    try std.testing.expectEqual(@as(usize, 5), count);

    try std.testing.expectEqualStrings("d", tag_buf[0][0]);
    try std.testing.expectEqualStrings("profile_badges", tag_buf[0][1]);

    try std.testing.expectEqualStrings("a", tag_buf[1][0]);
    try std.testing.expectEqualStrings("30009:pubkey:bravery", tag_buf[1][1]);

    try std.testing.expectEqualStrings("e", tag_buf[2][0]);
    try std.testing.expectEqualStrings("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", tag_buf[2][1]);
    try std.testing.expectEqual(@as(usize, 3), tag_buf[2].len);
    try std.testing.expectEqualStrings("wss://relay", tag_buf[2][2]);

    try std.testing.expectEqualStrings("a", tag_buf[3][0]);
    try std.testing.expectEqualStrings("30009:pubkey:honor", tag_buf[3][1]);

    try std.testing.expectEqualStrings("e", tag_buf[4][0]);
    try std.testing.expectEqualStrings("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", tag_buf[4][1]);
    try std.testing.expectEqual(@as(usize, 2), tag_buf[4].len);
}

test "BadgeDefinition handles empty tags" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":30009,"created_at":1700000000,"content":"","tags":[["d","minimal"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    var def = try BadgeDefinition.fromEvent(&event, std.testing.allocator);
    defer def.deinit();

    try std.testing.expectEqualStrings("minimal", def.unique_name);
    try std.testing.expect(def.name == null);
    try std.testing.expect(def.description == null);
    try std.testing.expect(def.image_url == null);
    try std.testing.expectEqual(@as(usize, 0), def.thumbnails.items.len);
}

test "BadgeDefinition handles multiple thumbnails" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":30009,"created_at":1700000000,"content":"","tags":[["d","multi"],["thumb","https://example.com/512.png","512x512"],["thumb","https://example.com/256.png","256x256"],["thumb","https://example.com/64.png","64x64"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    var def = try BadgeDefinition.fromEvent(&event, std.testing.allocator);
    defer def.deinit();

    try std.testing.expectEqual(@as(usize, 3), def.thumbnails.items.len);
    try std.testing.expectEqual(@as(u32, 512), def.thumbnails.items[0].dimensions.?.width);
    try std.testing.expectEqual(@as(u32, 256), def.thumbnails.items[1].dimensions.?.width);
    try std.testing.expectEqual(@as(u32, 64), def.thumbnails.items[2].dimensions.?.width);
}

test "BadgeAward.isValid returns false for empty award" {
    var award = BadgeAward.init(std.testing.allocator);
    defer award.deinit();

    try std.testing.expect(!award.isValid());
}

test "BadgeDefinition handles duplicate tags without leaking" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":30009,"created_at":1700000000,"content":"","tags":[["d","first"],["d","second"],["name","First Name"],["name","Second Name"],["description","First Desc"],["description","Second Desc"],["image","https://first.png"],["image","https://second.png","512x512"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    var def = try BadgeDefinition.fromEvent(&event, std.testing.allocator);
    defer def.deinit();

    // Should use last values (nostr convention)
    try std.testing.expectEqualStrings("second", def.unique_name);
    try std.testing.expectEqualStrings("Second Name", def.name.?);
    try std.testing.expectEqualStrings("Second Desc", def.description.?);
    try std.testing.expectEqualStrings("https://second.png", def.image_url.?);
    try std.testing.expectEqual(@as(u32, 512), def.image_dimensions.?.width);
}

test "BadgeAward handles duplicate a tags without leaking" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":8,"created_at":1700000000,"content":"","tags":[["a","30009:0000000000000000000000000000000000000000000000000000000000000002:first"],["a","30009:0000000000000000000000000000000000000000000000000000000000000002:second"],["p","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    var award = try BadgeAward.fromEvent(&event, std.testing.allocator);
    defer award.deinit();

    // Should use last value (nostr convention)
    try std.testing.expectEqualStrings("30009:0000000000000000000000000000000000000000000000000000000000000002:second", award.badge_address);
    try std.testing.expect(award.isValid());
}
