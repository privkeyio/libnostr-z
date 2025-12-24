const std = @import("std");
const event_mod = @import("event.zig");
const utils = @import("utils.zig");

pub const Event = event_mod.Event;

pub const Kind = struct {
    pub const classified_listing: i32 = 30402;
    pub const draft_listing: i32 = 30403;
};

pub const Status = enum {
    active,
    sold,

    pub fn toString(self: Status) []const u8 {
        return switch (self) {
            .active => "active",
            .sold => "sold",
        };
    }

    pub fn fromString(s: []const u8) ?Status {
        if (std.mem.eql(u8, s, "active")) return .active;
        if (std.mem.eql(u8, s, "sold")) return .sold;
        return null;
    }
};

pub const Price = struct {
    amount: []const u8,
    currency: []const u8,
    frequency: ?[]const u8 = null,
};

pub const Image = struct {
    url: []const u8,
    dimensions: ?[]const u8 = null,
};

pub const ClassifiedListing = struct {
    identifier: ?[]const u8 = null,
    title: ?[]const u8 = null,
    summary: ?[]const u8 = null,
    content: []const u8 = "",
    published_at: ?i64 = null,
    location: ?[]const u8 = null,
    price: ?Price = null,
    status: ?Status = null,
    geohash: ?[]const u8 = null,
    hashtags: std.ArrayListUnmanaged([]const u8),
    images: std.ArrayListUnmanaged(Image),
    allocator: std.mem.Allocator,
    is_draft: bool = false,

    pub fn init(allocator: std.mem.Allocator) ClassifiedListing {
        return .{
            .hashtags = .{},
            .images = .{},
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *ClassifiedListing) void {
        for (self.hashtags.items) |tag| {
            self.allocator.free(tag);
        }
        self.hashtags.deinit(self.allocator);
        for (self.images.items) |img| {
            self.allocator.free(img.url);
            if (img.dimensions) |d| self.allocator.free(d);
        }
        self.images.deinit(self.allocator);
        if (self.identifier) |id| self.allocator.free(id);
        if (self.title) |t| self.allocator.free(t);
        if (self.summary) |s| self.allocator.free(s);
        if (self.location) |l| self.allocator.free(l);
        if (self.geohash) |g| self.allocator.free(g);
        if (self.price) |p| {
            self.allocator.free(p.amount);
            self.allocator.free(p.currency);
            if (p.frequency) |f| self.allocator.free(f);
        }
    }

    pub fn fromEvent(event: *const Event, allocator: std.mem.Allocator) !ClassifiedListing {
        const kind_val = event.kind();
        if (kind_val != Kind.classified_listing and kind_val != Kind.draft_listing) {
            return error.InvalidKind;
        }

        var listing = ClassifiedListing.init(allocator);
        errdefer listing.deinit();

        listing.is_draft = (kind_val == Kind.draft_listing);
        listing.content = event.content();

        const tags_json = utils.findJsonValue(event.raw_json, "tags") orelse return listing;
        var iter = ListingTagIterator.init(tags_json);

        while (iter.next()) |tag| {
            if (std.mem.eql(u8, tag.name, "d")) {
                if (listing.identifier == null and tag.value.len > 0) {
                    listing.identifier = try allocator.dupe(u8, tag.value);
                }
            } else if (std.mem.eql(u8, tag.name, "title")) {
                if (listing.title == null and tag.value.len > 0) {
                    listing.title = try allocator.dupe(u8, tag.value);
                }
            } else if (std.mem.eql(u8, tag.name, "summary")) {
                if (listing.summary == null and tag.value.len > 0) {
                    listing.summary = try allocator.dupe(u8, tag.value);
                }
            } else if (std.mem.eql(u8, tag.name, "published_at")) {
                if (listing.published_at == null and tag.value.len > 0) {
                    listing.published_at = std.fmt.parseInt(i64, tag.value, 10) catch null;
                }
            } else if (std.mem.eql(u8, tag.name, "location")) {
                if (listing.location == null and tag.value.len > 0) {
                    listing.location = try allocator.dupe(u8, tag.value);
                }
            } else if (std.mem.eql(u8, tag.name, "status")) {
                if (listing.status == null and tag.value.len > 0) {
                    listing.status = Status.fromString(tag.value);
                }
            } else if (std.mem.eql(u8, tag.name, "g")) {
                if (listing.geohash == null and tag.value.len > 0) {
                    listing.geohash = try allocator.dupe(u8, tag.value);
                }
            } else if (std.mem.eql(u8, tag.name, "t")) {
                if (tag.value.len > 0) {
                    const hashtag = try allocator.dupe(u8, tag.value);
                    errdefer allocator.free(hashtag);
                    try listing.hashtags.append(allocator, hashtag);
                }
            } else if (std.mem.eql(u8, tag.name, "image")) {
                if (tag.value.len > 0) {
                    const url = try allocator.dupe(u8, tag.value);
                    errdefer allocator.free(url);
                    var dimensions: ?[]const u8 = null;
                    if (tag.extra) |extra| {
                        if (extra.len > 0) {
                            dimensions = try allocator.dupe(u8, extra);
                        }
                    }
                    errdefer if (dimensions) |d| allocator.free(d);
                    try listing.images.append(allocator, .{ .url = url, .dimensions = dimensions });
                }
            } else if (std.mem.eql(u8, tag.name, "price")) {
                if (listing.price == null and tag.value.len > 0) {
                    const amount = try allocator.dupe(u8, tag.value);
                    errdefer allocator.free(amount);
                    if (tag.extra) |currency| {
                        if (currency.len > 0) {
                            const curr = try allocator.dupe(u8, currency);
                            errdefer allocator.free(curr);
                            var freq: ?[]const u8 = null;
                            if (tag.extra2) |f| {
                                if (f.len > 0) {
                                    freq = try allocator.dupe(u8, f);
                                }
                            }
                            listing.price = .{ .amount = amount, .currency = curr, .frequency = freq };
                        } else {
                            allocator.free(amount);
                        }
                    } else {
                        allocator.free(amount);
                    }
                }
            }
        }

        return listing;
    }

    pub fn hashtagCount(self: *const ClassifiedListing) usize {
        return self.hashtags.items.len;
    }

    pub fn imageCount(self: *const ClassifiedListing) usize {
        return self.images.items.len;
    }

    pub fn getHashtags(self: *const ClassifiedListing) []const []const u8 {
        return self.hashtags.items;
    }

    pub fn getImages(self: *const ClassifiedListing) []const Image {
        return self.images.items;
    }
};

const ListingTagIterator = struct {
    json: []const u8,
    pos: usize,

    const Entry = struct {
        name: []const u8,
        value: []const u8,
        extra: ?[]const u8 = null,
        extra2: ?[]const u8 = null,
    };

    fn init(json: []const u8) ListingTagIterator {
        return .{ .json = json, .pos = 0 };
    }

    fn next(self: *ListingTagIterator) ?Entry {
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

    fn findBracket(self: *ListingTagIterator, bracket: u8) ?usize {
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

    fn parseTag(self: *const ListingTagIterator, content: []const u8) ?Entry {
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

        if (count < 1) return null;

        var entry = Entry{
            .name = strings[0],
            .value = if (count >= 2) strings[1] else "",
        };

        if (count >= 3) entry.extra = strings[2];
        if (count >= 4) entry.extra2 = strings[3];

        return entry;
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

/// Builds tag arrays for a ClassifiedListing.
/// The `timestamp_buf` parameter must be provided to store the formatted published_at value.
/// This buffer must outlive the returned tags.
pub fn buildListingTags(
    listing: *const ClassifiedListing,
    buf: [][]const []const u8,
    string_buf: [][]const u8,
    timestamp_buf: *[20]u8,
) usize {
    var tag_idx: usize = 0;
    var str_idx: usize = 0;

    if (listing.identifier) |id| {
        if (tag_idx < buf.len and str_idx + 2 <= string_buf.len) {
            string_buf[str_idx] = "d";
            string_buf[str_idx + 1] = id;
            buf[tag_idx] = string_buf[str_idx .. str_idx + 2];
            str_idx += 2;
            tag_idx += 1;
        }
    }

    if (listing.title) |title| {
        if (tag_idx < buf.len and str_idx + 2 <= string_buf.len) {
            string_buf[str_idx] = "title";
            string_buf[str_idx + 1] = title;
            buf[tag_idx] = string_buf[str_idx .. str_idx + 2];
            str_idx += 2;
            tag_idx += 1;
        }
    }

    if (listing.summary) |summary| {
        if (tag_idx < buf.len and str_idx + 2 <= string_buf.len) {
            string_buf[str_idx] = "summary";
            string_buf[str_idx + 1] = summary;
            buf[tag_idx] = string_buf[str_idx .. str_idx + 2];
            str_idx += 2;
            tag_idx += 1;
        }
    }

    if (listing.published_at) |ts| {
        if (tag_idx < buf.len and str_idx + 2 <= string_buf.len) {
            const ts_str = std.fmt.bufPrint(timestamp_buf, "{d}", .{ts}) catch unreachable;
            string_buf[str_idx] = "published_at";
            string_buf[str_idx + 1] = ts_str;
            buf[tag_idx] = string_buf[str_idx .. str_idx + 2];
            str_idx += 2;
            tag_idx += 1;
        }
    }

    if (listing.location) |loc| {
        if (tag_idx < buf.len and str_idx + 2 <= string_buf.len) {
            string_buf[str_idx] = "location";
            string_buf[str_idx + 1] = loc;
            buf[tag_idx] = string_buf[str_idx .. str_idx + 2];
            str_idx += 2;
            tag_idx += 1;
        }
    }

    if (listing.price) |price| {
        const has_freq = price.frequency != null;
        const tag_size: usize = if (has_freq) 4 else 3;
        if (tag_idx < buf.len and str_idx + tag_size <= string_buf.len) {
            string_buf[str_idx] = "price";
            string_buf[str_idx + 1] = price.amount;
            string_buf[str_idx + 2] = price.currency;
            if (has_freq) {
                string_buf[str_idx + 3] = price.frequency.?;
            }
            buf[tag_idx] = string_buf[str_idx .. str_idx + tag_size];
            str_idx += tag_size;
            tag_idx += 1;
        }
    }

    if (listing.status) |status| {
        if (tag_idx < buf.len and str_idx + 2 <= string_buf.len) {
            string_buf[str_idx] = "status";
            string_buf[str_idx + 1] = status.toString();
            buf[tag_idx] = string_buf[str_idx .. str_idx + 2];
            str_idx += 2;
            tag_idx += 1;
        }
    }

    if (listing.geohash) |geo| {
        if (tag_idx < buf.len and str_idx + 2 <= string_buf.len) {
            string_buf[str_idx] = "g";
            string_buf[str_idx + 1] = geo;
            buf[tag_idx] = string_buf[str_idx .. str_idx + 2];
            str_idx += 2;
            tag_idx += 1;
        }
    }

    for (listing.hashtags.items) |hashtag| {
        if (tag_idx >= buf.len or str_idx + 2 > string_buf.len) break;
        string_buf[str_idx] = "t";
        string_buf[str_idx + 1] = hashtag;
        buf[tag_idx] = string_buf[str_idx .. str_idx + 2];
        str_idx += 2;
        tag_idx += 1;
    }

    for (listing.images.items) |image| {
        const has_dims = image.dimensions != null;
        const img_tag_size: usize = if (has_dims) 3 else 2;
        if (tag_idx >= buf.len or str_idx + img_tag_size > string_buf.len) break;
        string_buf[str_idx] = "image";
        string_buf[str_idx + 1] = image.url;
        if (has_dims) {
            string_buf[str_idx + 2] = image.dimensions.?;
        }
        buf[tag_idx] = string_buf[str_idx .. str_idx + img_tag_size];
        str_idx += img_tag_size;
        tag_idx += 1;
    }

    return tag_idx;
}

test "Status.fromString and toString" {
    try std.testing.expectEqual(Status.active, Status.fromString("active").?);
    try std.testing.expectEqual(Status.sold, Status.fromString("sold").?);
    try std.testing.expect(Status.fromString("invalid") == null);
    try std.testing.expectEqualStrings("active", Status.active.toString());
    try std.testing.expectEqualStrings("sold", Status.sold.toString());
}

test "ClassifiedListing.fromEvent parses kind:30402" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":30402,"created_at":1675642635,"content":"Lorem ipsum dolor sit amet","tags":[["d","lorem-ipsum"],["title","Lorem Ipsum"],["published_at","1296962229"],["t","electronics"],["image","https://url.to.img","256x256"],["summary","More lorem ipsum"],["location","NYC"],["price","100","USD"],["status","active"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    var listing = try ClassifiedListing.fromEvent(&event, std.testing.allocator);
    defer listing.deinit();

    try std.testing.expectEqualStrings("lorem-ipsum", listing.identifier.?);
    try std.testing.expectEqualStrings("Lorem Ipsum", listing.title.?);
    try std.testing.expectEqualStrings("More lorem ipsum", listing.summary.?);
    try std.testing.expectEqual(@as(i64, 1296962229), listing.published_at.?);
    try std.testing.expectEqualStrings("NYC", listing.location.?);
    try std.testing.expectEqualStrings("100", listing.price.?.amount);
    try std.testing.expectEqualStrings("USD", listing.price.?.currency);
    try std.testing.expect(listing.price.?.frequency == null);
    try std.testing.expectEqual(Status.active, listing.status.?);
    try std.testing.expect(!listing.is_draft);

    try std.testing.expectEqual(@as(usize, 1), listing.hashtagCount());
    try std.testing.expectEqualStrings("electronics", listing.getHashtags()[0]);

    try std.testing.expectEqual(@as(usize, 1), listing.imageCount());
    try std.testing.expectEqualStrings("https://url.to.img", listing.getImages()[0].url);
    try std.testing.expectEqualStrings("256x256", listing.getImages()[0].dimensions.?);
}

test "ClassifiedListing.fromEvent parses kind:30403 as draft" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":30403,"created_at":1675642635,"content":"Draft listing","tags":[["d","draft-item"],["title","Draft Item"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    var listing = try ClassifiedListing.fromEvent(&event, std.testing.allocator);
    defer listing.deinit();

    try std.testing.expect(listing.is_draft);
    try std.testing.expectEqualStrings("draft-item", listing.identifier.?);
    try std.testing.expectEqualStrings("Draft Item", listing.title.?);
}

test "ClassifiedListing.fromEvent parses price with frequency" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":30402,"created_at":1675642635,"content":"Rental listing","tags":[["d","rental"],["title","Apartment for Rent"],["price","1500","EUR","month"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    var listing = try ClassifiedListing.fromEvent(&event, std.testing.allocator);
    defer listing.deinit();

    try std.testing.expectEqualStrings("1500", listing.price.?.amount);
    try std.testing.expectEqualStrings("EUR", listing.price.?.currency);
    try std.testing.expectEqualStrings("month", listing.price.?.frequency.?);
}

test "ClassifiedListing.fromEvent parses geohash" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":30402,"created_at":1675642635,"content":"Item with location","tags":[["d","geo-item"],["g","u4pruydqqvj"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    var listing = try ClassifiedListing.fromEvent(&event, std.testing.allocator);
    defer listing.deinit();

    try std.testing.expectEqualStrings("u4pruydqqvj", listing.geohash.?);
}

test "ClassifiedListing.fromEvent parses multiple hashtags and images" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":30402,"created_at":1675642635,"content":"Multi-tag item","tags":[["d","multi"],["t","electronics"],["t","vintage"],["t","rare"],["image","https://img1.example.com"],["image","https://img2.example.com","800x600"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    var listing = try ClassifiedListing.fromEvent(&event, std.testing.allocator);
    defer listing.deinit();

    try std.testing.expectEqual(@as(usize, 3), listing.hashtagCount());
    try std.testing.expectEqualStrings("electronics", listing.getHashtags()[0]);
    try std.testing.expectEqualStrings("vintage", listing.getHashtags()[1]);
    try std.testing.expectEqualStrings("rare", listing.getHashtags()[2]);

    try std.testing.expectEqual(@as(usize, 2), listing.imageCount());
    try std.testing.expectEqualStrings("https://img1.example.com", listing.getImages()[0].url);
    try std.testing.expect(listing.getImages()[0].dimensions == null);
    try std.testing.expectEqualStrings("https://img2.example.com", listing.getImages()[1].url);
    try std.testing.expectEqualStrings("800x600", listing.getImages()[1].dimensions.?);
}

test "ClassifiedListing rejects wrong kind" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":1,"created_at":1700000000,"content":"test","tags":[]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    const result = ClassifiedListing.fromEvent(&event, std.testing.allocator);
    try std.testing.expectError(error.InvalidKind, result);
}

test "ClassifiedListing handles empty tags" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":30402,"created_at":1675642635,"content":"Minimal listing","tags":[]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    var listing = try ClassifiedListing.fromEvent(&event, std.testing.allocator);
    defer listing.deinit();

    try std.testing.expect(listing.identifier == null);
    try std.testing.expect(listing.title == null);
    try std.testing.expect(listing.price == null);
    try std.testing.expectEqual(@as(usize, 0), listing.hashtagCount());
    try std.testing.expectEqual(@as(usize, 0), listing.imageCount());
}

test "ClassifiedListing parses status sold" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":30402,"created_at":1675642635,"content":"Sold item","tags":[["d","sold-item"],["status","sold"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    var listing = try ClassifiedListing.fromEvent(&event, std.testing.allocator);
    defer listing.deinit();

    try std.testing.expectEqual(Status.sold, listing.status.?);
}

test "buildListingTags creates correct tag structure" {
    var listing = ClassifiedListing.init(std.testing.allocator);
    defer listing.deinit();

    listing.identifier = try std.testing.allocator.dupe(u8, "test-item");
    listing.title = try std.testing.allocator.dupe(u8, "Test Item");
    listing.summary = try std.testing.allocator.dupe(u8, "A test item");
    listing.location = try std.testing.allocator.dupe(u8, "NYC");
    listing.status = .active;

    const amount = try std.testing.allocator.dupe(u8, "50");
    const currency = try std.testing.allocator.dupe(u8, "USD");
    listing.price = .{ .amount = amount, .currency = currency };

    const hashtag = try std.testing.allocator.dupe(u8, "test");
    try listing.hashtags.append(std.testing.allocator, hashtag);

    var tag_buf: [20][]const []const u8 = undefined;
    var string_buf: [60][]const u8 = undefined;
    var timestamp_buf: [20]u8 = undefined;

    const count = buildListingTags(&listing, &tag_buf, &string_buf, &timestamp_buf);

    try std.testing.expectEqual(@as(usize, 7), count);

    try std.testing.expectEqual(@as(usize, 2), tag_buf[0].len);
    try std.testing.expectEqualStrings("d", tag_buf[0][0]);
    try std.testing.expectEqualStrings("test-item", tag_buf[0][1]);

    try std.testing.expectEqual(@as(usize, 2), tag_buf[1].len);
    try std.testing.expectEqualStrings("title", tag_buf[1][0]);
    try std.testing.expectEqualStrings("Test Item", tag_buf[1][1]);

    try std.testing.expectEqual(@as(usize, 3), tag_buf[4].len);
    try std.testing.expectEqualStrings("price", tag_buf[4][0]);
    try std.testing.expectEqualStrings("50", tag_buf[4][1]);
    try std.testing.expectEqualStrings("USD", tag_buf[4][2]);
}

test "buildListingTags with price frequency" {
    var listing = ClassifiedListing.init(std.testing.allocator);
    defer listing.deinit();

    listing.identifier = try std.testing.allocator.dupe(u8, "rental");

    const amount = try std.testing.allocator.dupe(u8, "1000");
    const currency = try std.testing.allocator.dupe(u8, "EUR");
    const frequency = try std.testing.allocator.dupe(u8, "month");
    listing.price = .{ .amount = amount, .currency = currency, .frequency = frequency };

    var tag_buf: [10][]const []const u8 = undefined;
    var string_buf: [30][]const u8 = undefined;
    var timestamp_buf: [20]u8 = undefined;

    const count = buildListingTags(&listing, &tag_buf, &string_buf, &timestamp_buf);

    try std.testing.expectEqual(@as(usize, 2), count);

    try std.testing.expectEqual(@as(usize, 4), tag_buf[1].len);
    try std.testing.expectEqualStrings("price", tag_buf[1][0]);
    try std.testing.expectEqualStrings("1000", tag_buf[1][1]);
    try std.testing.expectEqualStrings("EUR", tag_buf[1][2]);
    try std.testing.expectEqualStrings("month", tag_buf[1][3]);
}

test "Kind constants are correct" {
    try std.testing.expectEqual(@as(i32, 30402), Kind.classified_listing);
    try std.testing.expectEqual(@as(i32, 30403), Kind.draft_listing);

    try std.testing.expectEqual(event_mod.KindType.addressable, event_mod.kindType(Kind.classified_listing));
    try std.testing.expectEqual(event_mod.KindType.addressable, event_mod.kindType(Kind.draft_listing));
}
