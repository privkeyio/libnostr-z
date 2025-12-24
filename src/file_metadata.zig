const std = @import("std");
const event_mod = @import("event.zig");
const utils = @import("utils.zig");

pub const Event = event_mod.Event;

pub const FILE_METADATA_KIND: i32 = 1063;

pub const ImageRef = struct {
    url: []const u8,
    hash: ?[]const u8 = null,
};

pub const Dimensions = struct {
    width: u32,
    height: u32,
};

pub const FileMetadata = struct {
    url: []const u8,
    mime_type: []const u8,
    file_hash: []const u8,
    original_hash: ?[]const u8 = null,
    size: ?u64 = null,
    dimensions: ?Dimensions = null,
    magnet: ?[]const u8 = null,
    torrent_infohash: ?[]const u8 = null,
    blurhash: ?[]const u8 = null,
    thumb: ?ImageRef = null,
    image: ?ImageRef = null,
    summary: ?[]const u8 = null,
    alt: ?[]const u8 = null,
    fallbacks: std.ArrayListUnmanaged([]const u8),
    service: ?[]const u8 = null,
    caption: []const u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *FileMetadata) void {
        self.allocator.free(self.url);
        self.allocator.free(self.mime_type);
        self.allocator.free(self.file_hash);
        if (self.original_hash) |oh| self.allocator.free(oh);
        if (self.magnet) |m| self.allocator.free(m);
        if (self.torrent_infohash) |t| self.allocator.free(t);
        if (self.blurhash) |b| self.allocator.free(b);
        if (self.thumb) |t| {
            self.allocator.free(t.url);
            if (t.hash) |h| self.allocator.free(h);
        }
        if (self.image) |i| {
            self.allocator.free(i.url);
            if (i.hash) |h| self.allocator.free(h);
        }
        if (self.summary) |s| self.allocator.free(s);
        if (self.alt) |a| self.allocator.free(a);
        for (self.fallbacks.items) |f| self.allocator.free(f);
        self.fallbacks.deinit(self.allocator);
        if (self.service) |s| self.allocator.free(s);
        self.allocator.free(self.caption);
    }

    pub fn fromEvent(event: *const Event, allocator: std.mem.Allocator) !FileMetadata {
        if (event.kind() != FILE_METADATA_KIND) {
            return error.InvalidKind;
        }

        var url: ?[]const u8 = null;
        var mime_type: ?[]const u8 = null;
        var file_hash: ?[]const u8 = null;
        var original_hash: ?[]const u8 = null;
        var size: ?u64 = null;
        var dimensions: ?Dimensions = null;
        var magnet: ?[]const u8 = null;
        var torrent_infohash: ?[]const u8 = null;
        var blurhash: ?[]const u8 = null;
        var thumb: ?ImageRef = null;
        var image: ?ImageRef = null;
        var summary: ?[]const u8 = null;
        var alt: ?[]const u8 = null;
        var fallbacks = std.ArrayListUnmanaged([]const u8){};
        var service: ?[]const u8 = null;

        errdefer {
            if (url) |u| allocator.free(u);
            if (mime_type) |m| allocator.free(m);
            if (file_hash) |h| allocator.free(h);
            if (original_hash) |oh| allocator.free(oh);
            if (magnet) |m| allocator.free(m);
            if (torrent_infohash) |t| allocator.free(t);
            if (blurhash) |b| allocator.free(b);
            if (thumb) |t| {
                allocator.free(t.url);
                if (t.hash) |h| allocator.free(h);
            }
            if (image) |i| {
                allocator.free(i.url);
                if (i.hash) |h| allocator.free(h);
            }
            if (summary) |s| allocator.free(s);
            if (alt) |a| allocator.free(a);
            for (fallbacks.items) |f| allocator.free(f);
            fallbacks.deinit(allocator);
            if (service) |s| allocator.free(s);
        }

        const tags_json = utils.findJsonValue(event.raw_json, "tags") orelse return error.MissingRequiredTag;
        var iter = FileTagIterator.init(tags_json);

        while (iter.next()) |tag| {
            if (std.mem.eql(u8, tag.name, "url")) {
                if (url == null) url = try allocator.dupe(u8, tag.value);
            } else if (std.mem.eql(u8, tag.name, "m")) {
                if (mime_type == null) mime_type = try allocator.dupe(u8, tag.value);
            } else if (std.mem.eql(u8, tag.name, "x")) {
                if (file_hash == null) file_hash = try allocator.dupe(u8, tag.value);
            } else if (std.mem.eql(u8, tag.name, "ox")) {
                if (original_hash == null) original_hash = try allocator.dupe(u8, tag.value);
            } else if (std.mem.eql(u8, tag.name, "size")) {
                if (size == null) size = std.fmt.parseInt(u64, tag.value, 10) catch null;
            } else if (std.mem.eql(u8, tag.name, "dim")) {
                if (dimensions == null) dimensions = parseDimensions(tag.value);
            } else if (std.mem.eql(u8, tag.name, "magnet")) {
                if (magnet == null) magnet = try allocator.dupe(u8, tag.value);
            } else if (std.mem.eql(u8, tag.name, "i")) {
                if (torrent_infohash == null) torrent_infohash = try allocator.dupe(u8, tag.value);
            } else if (std.mem.eql(u8, tag.name, "blurhash")) {
                if (blurhash == null) blurhash = try allocator.dupe(u8, tag.value);
            } else if (std.mem.eql(u8, tag.name, "thumb")) {
                if (thumb == null) {
                    thumb = .{
                        .url = try allocator.dupe(u8, tag.value),
                        .hash = if (tag.extra) |e| try allocator.dupe(u8, e) else null,
                    };
                }
            } else if (std.mem.eql(u8, tag.name, "image")) {
                if (image == null) {
                    image = .{
                        .url = try allocator.dupe(u8, tag.value),
                        .hash = if (tag.extra) |e| try allocator.dupe(u8, e) else null,
                    };
                }
            } else if (std.mem.eql(u8, tag.name, "summary")) {
                if (summary == null) summary = try allocator.dupe(u8, tag.value);
            } else if (std.mem.eql(u8, tag.name, "alt")) {
                if (alt == null) alt = try allocator.dupe(u8, tag.value);
            } else if (std.mem.eql(u8, tag.name, "fallback")) {
                const fb = try allocator.dupe(u8, tag.value);
                try fallbacks.append(allocator, fb);
            } else if (std.mem.eql(u8, tag.name, "service")) {
                if (service == null) service = try allocator.dupe(u8, tag.value);
            }
        }

        if (url == null) return error.MissingRequiredTag;
        if (mime_type == null) return error.MissingRequiredTag;
        if (file_hash == null) return error.MissingRequiredTag;

        const caption = try allocator.dupe(u8, event.content());

        return .{
            .url = url.?,
            .mime_type = mime_type.?,
            .file_hash = file_hash.?,
            .original_hash = original_hash,
            .size = size,
            .dimensions = dimensions,
            .magnet = magnet,
            .torrent_infohash = torrent_infohash,
            .blurhash = blurhash,
            .thumb = thumb,
            .image = image,
            .summary = summary,
            .alt = alt,
            .fallbacks = fallbacks,
            .service = service,
            .caption = caption,
            .allocator = allocator,
        };
    }
};

fn parseDimensions(value: []const u8) ?Dimensions {
    const x_pos = std.mem.indexOfScalar(u8, value, 'x') orelse return null;
    if (x_pos == 0 or x_pos >= value.len - 1) return null;
    const width = std.fmt.parseInt(u32, value[0..x_pos], 10) catch return null;
    const height = std.fmt.parseInt(u32, value[x_pos + 1 ..], 10) catch return null;
    return .{ .width = width, .height = height };
}

const FileTagIterator = struct {
    json: []const u8,
    pos: usize,

    const Tag = struct {
        name: []const u8,
        value: []const u8,
        extra: ?[]const u8 = null,
    };

    fn init(json: []const u8) FileTagIterator {
        return .{ .json = json, .pos = 0 };
    }

    fn next(self: *FileTagIterator) ?Tag {
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
            if (self.parseTag(tag_content)) |tag| {
                return tag;
            }
        }
        return null;
    }

    fn findBracket(self: *FileTagIterator, bracket: u8) ?usize {
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

    fn parseTag(self: *const FileTagIterator, content: []const u8) ?Tag {
        _ = self;
        var strings: [3][]const u8 = undefined;
        var count: usize = 0;

        var i: usize = 0;
        while (i < content.len and count < 3) {
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
            .extra = if (count >= 3) strings[2] else null,
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

pub const FileMetadataBuilder = struct {
    url: []const u8,
    mime_type: []const u8,
    file_hash: []const u8,
    original_hash: ?[]const u8 = null,
    size: ?u64 = null,
    dimensions: ?Dimensions = null,
    magnet: ?[]const u8 = null,
    torrent_infohash: ?[]const u8 = null,
    blurhash: ?[]const u8 = null,
    thumb: ?ImageRef = null,
    image: ?ImageRef = null,
    summary: ?[]const u8 = null,
    alt: ?[]const u8 = null,
    fallbacks: []const []const u8 = &[_][]const u8{},
    service: ?[]const u8 = null,

    pub fn setOriginalHash(self: *FileMetadataBuilder, hash: []const u8) *FileMetadataBuilder {
        self.original_hash = hash;
        return self;
    }

    pub fn setSize(self: *FileMetadataBuilder, s: u64) *FileMetadataBuilder {
        self.size = s;
        return self;
    }

    pub fn setDimensions(self: *FileMetadataBuilder, width: u32, height: u32) *FileMetadataBuilder {
        self.dimensions = .{ .width = width, .height = height };
        return self;
    }

    pub fn setMagnet(self: *FileMetadataBuilder, m: []const u8) *FileMetadataBuilder {
        self.magnet = m;
        return self;
    }

    pub fn setTorrentInfohash(self: *FileMetadataBuilder, t: []const u8) *FileMetadataBuilder {
        self.torrent_infohash = t;
        return self;
    }

    pub fn setBlurhash(self: *FileMetadataBuilder, b: []const u8) *FileMetadataBuilder {
        self.blurhash = b;
        return self;
    }

    pub fn setThumb(self: *FileMetadataBuilder, url: []const u8, hash: ?[]const u8) *FileMetadataBuilder {
        self.thumb = .{ .url = url, .hash = hash };
        return self;
    }

    pub fn setImage(self: *FileMetadataBuilder, url: []const u8, hash: ?[]const u8) *FileMetadataBuilder {
        self.image = .{ .url = url, .hash = hash };
        return self;
    }

    pub fn setSummary(self: *FileMetadataBuilder, s: []const u8) *FileMetadataBuilder {
        self.summary = s;
        return self;
    }

    pub fn setAlt(self: *FileMetadataBuilder, a: []const u8) *FileMetadataBuilder {
        self.alt = a;
        return self;
    }

    pub fn setFallbacks(self: *FileMetadataBuilder, f: []const []const u8) *FileMetadataBuilder {
        self.fallbacks = f;
        return self;
    }

    pub fn setService(self: *FileMetadataBuilder, s: []const u8) *FileMetadataBuilder {
        self.service = s;
        return self;
    }

    pub fn buildTags(
        self: *const FileMetadataBuilder,
        buf: [][]const []const u8,
        string_buf: [][]const u8,
        size_buf: []u8,
        dim_buf: []u8,
    ) struct { count: usize, size_str: ?[]const u8, dim_str: ?[]const u8 } {
        var tag_idx: usize = 0;
        var str_idx: usize = 0;
        var size_str: ?[]const u8 = null;
        var dim_str: ?[]const u8 = null;

        if (tag_idx >= buf.len or str_idx + 2 > string_buf.len) return .{ .count = tag_idx, .size_str = size_str, .dim_str = dim_str };
        string_buf[str_idx] = "url";
        string_buf[str_idx + 1] = self.url;
        buf[tag_idx] = string_buf[str_idx .. str_idx + 2];
        str_idx += 2;
        tag_idx += 1;

        if (tag_idx >= buf.len or str_idx + 2 > string_buf.len) return .{ .count = tag_idx, .size_str = size_str, .dim_str = dim_str };
        string_buf[str_idx] = "m";
        string_buf[str_idx + 1] = self.mime_type;
        buf[tag_idx] = string_buf[str_idx .. str_idx + 2];
        str_idx += 2;
        tag_idx += 1;

        if (tag_idx >= buf.len or str_idx + 2 > string_buf.len) return .{ .count = tag_idx, .size_str = size_str, .dim_str = dim_str };
        string_buf[str_idx] = "x";
        string_buf[str_idx + 1] = self.file_hash;
        buf[tag_idx] = string_buf[str_idx .. str_idx + 2];
        str_idx += 2;
        tag_idx += 1;

        if (self.original_hash) |oh| {
            if (tag_idx >= buf.len or str_idx + 2 > string_buf.len) return .{ .count = tag_idx, .size_str = size_str, .dim_str = dim_str };
            string_buf[str_idx] = "ox";
            string_buf[str_idx + 1] = oh;
            buf[tag_idx] = string_buf[str_idx .. str_idx + 2];
            str_idx += 2;
            tag_idx += 1;
        }

        if (self.size) |s| {
            size_str = std.fmt.bufPrint(size_buf, "{d}", .{s}) catch null;
            if (size_str) |ss| {
                if (tag_idx < buf.len and str_idx + 2 <= string_buf.len) {
                    string_buf[str_idx] = "size";
                    string_buf[str_idx + 1] = ss;
                    buf[tag_idx] = string_buf[str_idx .. str_idx + 2];
                    str_idx += 2;
                    tag_idx += 1;
                }
            }
        }

        if (self.dimensions) |d| {
            dim_str = std.fmt.bufPrint(dim_buf, "{d}x{d}", .{ d.width, d.height }) catch null;
            if (dim_str) |ds| {
                if (tag_idx < buf.len and str_idx + 2 <= string_buf.len) {
                    string_buf[str_idx] = "dim";
                    string_buf[str_idx + 1] = ds;
                    buf[tag_idx] = string_buf[str_idx .. str_idx + 2];
                    str_idx += 2;
                    tag_idx += 1;
                }
            }
        }

        if (self.magnet) |m| {
            if (tag_idx >= buf.len or str_idx + 2 > string_buf.len) return .{ .count = tag_idx, .size_str = size_str, .dim_str = dim_str };
            string_buf[str_idx] = "magnet";
            string_buf[str_idx + 1] = m;
            buf[tag_idx] = string_buf[str_idx .. str_idx + 2];
            str_idx += 2;
            tag_idx += 1;
        }

        if (self.torrent_infohash) |t| {
            if (tag_idx >= buf.len or str_idx + 2 > string_buf.len) return .{ .count = tag_idx, .size_str = size_str, .dim_str = dim_str };
            string_buf[str_idx] = "i";
            string_buf[str_idx + 1] = t;
            buf[tag_idx] = string_buf[str_idx .. str_idx + 2];
            str_idx += 2;
            tag_idx += 1;
        }

        if (self.blurhash) |b| {
            if (tag_idx >= buf.len or str_idx + 2 > string_buf.len) return .{ .count = tag_idx, .size_str = size_str, .dim_str = dim_str };
            string_buf[str_idx] = "blurhash";
            string_buf[str_idx + 1] = b;
            buf[tag_idx] = string_buf[str_idx .. str_idx + 2];
            str_idx += 2;
            tag_idx += 1;
        }

        if (self.thumb) |t| {
            const tag_size: usize = if (t.hash != null) 3 else 2;
            if (tag_idx >= buf.len or str_idx + tag_size > string_buf.len) return .{ .count = tag_idx, .size_str = size_str, .dim_str = dim_str };
            string_buf[str_idx] = "thumb";
            string_buf[str_idx + 1] = t.url;
            if (t.hash) |h| string_buf[str_idx + 2] = h;
            buf[tag_idx] = string_buf[str_idx .. str_idx + tag_size];
            str_idx += tag_size;
            tag_idx += 1;
        }

        if (self.image) |i| {
            const tag_size: usize = if (i.hash != null) 3 else 2;
            if (tag_idx >= buf.len or str_idx + tag_size > string_buf.len) return .{ .count = tag_idx, .size_str = size_str, .dim_str = dim_str };
            string_buf[str_idx] = "image";
            string_buf[str_idx + 1] = i.url;
            if (i.hash) |h| string_buf[str_idx + 2] = h;
            buf[tag_idx] = string_buf[str_idx .. str_idx + tag_size];
            str_idx += tag_size;
            tag_idx += 1;
        }

        if (self.summary) |s| {
            if (tag_idx >= buf.len or str_idx + 2 > string_buf.len) return .{ .count = tag_idx, .size_str = size_str, .dim_str = dim_str };
            string_buf[str_idx] = "summary";
            string_buf[str_idx + 1] = s;
            buf[tag_idx] = string_buf[str_idx .. str_idx + 2];
            str_idx += 2;
            tag_idx += 1;
        }

        if (self.alt) |a| {
            if (tag_idx >= buf.len or str_idx + 2 > string_buf.len) return .{ .count = tag_idx, .size_str = size_str, .dim_str = dim_str };
            string_buf[str_idx] = "alt";
            string_buf[str_idx + 1] = a;
            buf[tag_idx] = string_buf[str_idx .. str_idx + 2];
            str_idx += 2;
            tag_idx += 1;
        }

        for (self.fallbacks) |f| {
            if (tag_idx >= buf.len or str_idx + 2 > string_buf.len) return .{ .count = tag_idx, .size_str = size_str, .dim_str = dim_str };
            string_buf[str_idx] = "fallback";
            string_buf[str_idx + 1] = f;
            buf[tag_idx] = string_buf[str_idx .. str_idx + 2];
            str_idx += 2;
            tag_idx += 1;
        }

        if (self.service) |s| {
            if (tag_idx >= buf.len or str_idx + 2 > string_buf.len) return .{ .count = tag_idx, .size_str = size_str, .dim_str = dim_str };
            string_buf[str_idx] = "service";
            string_buf[str_idx + 1] = s;
            buf[tag_idx] = string_buf[str_idx .. str_idx + 2];
            str_idx += 2;
            tag_idx += 1;
        }

        return .{ .count = tag_idx, .size_str = size_str, .dim_str = dim_str };
    }
};

test "FileMetadata.fromEvent parses kind:1063" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":1063,"created_at":1700000000,"content":"A beautiful sunset","tags":[["url","https://example.com/image.jpg"],["m","image/jpeg"],["x","abc123def456"],["size","1024000"],["dim","1920x1080"],["blurhash","LEHV6nWB2yk8pyo0adR*.7kCMdnj"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    var metadata = try FileMetadata.fromEvent(&event, std.testing.allocator);
    defer metadata.deinit();

    try std.testing.expectEqualStrings("https://example.com/image.jpg", metadata.url);
    try std.testing.expectEqualStrings("image/jpeg", metadata.mime_type);
    try std.testing.expectEqualStrings("abc123def456", metadata.file_hash);
    try std.testing.expectEqual(@as(?u64, 1024000), metadata.size);
    try std.testing.expect(metadata.dimensions != null);
    try std.testing.expectEqual(@as(u32, 1920), metadata.dimensions.?.width);
    try std.testing.expectEqual(@as(u32, 1080), metadata.dimensions.?.height);
    try std.testing.expectEqualStrings("LEHV6nWB2yk8pyo0adR*.7kCMdnj", metadata.blurhash.?);
    try std.testing.expectEqualStrings("A beautiful sunset", metadata.caption);
}

test "FileMetadata.fromEvent parses optional tags" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":1063,"created_at":1700000000,"content":"","tags":[["url","https://example.com/file.mp4"],["m","video/mp4"],["x","hash123"],["ox","originalhash456"],["magnet","magnet:?xt=urn:btih:abc"],["i","torrentinfohash"],["thumb","https://example.com/thumb.jpg","thumbhash123"],["image","https://example.com/preview.jpg"],["summary","A short summary"],["alt","Accessible description"],["fallback","https://backup1.com/file.mp4"],["fallback","https://backup2.com/file.mp4"],["service","nip96"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    var metadata = try FileMetadata.fromEvent(&event, std.testing.allocator);
    defer metadata.deinit();

    try std.testing.expectEqualStrings("https://example.com/file.mp4", metadata.url);
    try std.testing.expectEqualStrings("video/mp4", metadata.mime_type);
    try std.testing.expectEqualStrings("hash123", metadata.file_hash);
    try std.testing.expectEqualStrings("originalhash456", metadata.original_hash.?);
    try std.testing.expectEqualStrings("magnet:?xt=urn:btih:abc", metadata.magnet.?);
    try std.testing.expectEqualStrings("torrentinfohash", metadata.torrent_infohash.?);

    try std.testing.expect(metadata.thumb != null);
    try std.testing.expectEqualStrings("https://example.com/thumb.jpg", metadata.thumb.?.url);
    try std.testing.expectEqualStrings("thumbhash123", metadata.thumb.?.hash.?);

    try std.testing.expect(metadata.image != null);
    try std.testing.expectEqualStrings("https://example.com/preview.jpg", metadata.image.?.url);
    try std.testing.expect(metadata.image.?.hash == null);

    try std.testing.expectEqualStrings("A short summary", metadata.summary.?);
    try std.testing.expectEqualStrings("Accessible description", metadata.alt.?);

    try std.testing.expectEqual(@as(usize, 2), metadata.fallbacks.items.len);
    try std.testing.expectEqualStrings("https://backup1.com/file.mp4", metadata.fallbacks.items[0]);
    try std.testing.expectEqualStrings("https://backup2.com/file.mp4", metadata.fallbacks.items[1]);

    try std.testing.expectEqualStrings("nip96", metadata.service.?);
}

test "FileMetadata.fromEvent rejects wrong kind" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":1,"created_at":1700000000,"content":"test","tags":[["url","https://example.com"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    const result = FileMetadata.fromEvent(&event, std.testing.allocator);
    try std.testing.expectError(error.InvalidKind, result);
}

test "FileMetadata.fromEvent rejects missing required tags" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":1063,"created_at":1700000000,"content":"","tags":[["url","https://example.com"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    const result = FileMetadata.fromEvent(&event, std.testing.allocator);
    try std.testing.expectError(error.MissingRequiredTag, result);
}

test "FileMetadataBuilder.buildTags creates correct structure" {
    var builder = FileMetadataBuilder{
        .url = "https://example.com/image.jpg",
        .mime_type = "image/jpeg",
        .file_hash = "abc123",
    };
    _ = builder.setSize(1024000).setDimensions(1920, 1080).setBlurhash("LEHV6n").setAlt("Test image");

    var tag_buf: [20][]const []const u8 = undefined;
    var string_buf: [60][]const u8 = undefined;
    var size_buf: [20]u8 = undefined;
    var dim_buf: [20]u8 = undefined;

    const result = builder.buildTags(&tag_buf, &string_buf, &size_buf, &dim_buf);

    try std.testing.expectEqual(@as(usize, 7), result.count);

    try std.testing.expectEqualStrings("url", tag_buf[0][0]);
    try std.testing.expectEqualStrings("https://example.com/image.jpg", tag_buf[0][1]);

    try std.testing.expectEqualStrings("m", tag_buf[1][0]);
    try std.testing.expectEqualStrings("image/jpeg", tag_buf[1][1]);

    try std.testing.expectEqualStrings("x", tag_buf[2][0]);
    try std.testing.expectEqualStrings("abc123", tag_buf[2][1]);

    try std.testing.expectEqualStrings("size", tag_buf[3][0]);
    try std.testing.expectEqualStrings("1024000", tag_buf[3][1]);

    try std.testing.expectEqualStrings("dim", tag_buf[4][0]);
    try std.testing.expectEqualStrings("1920x1080", tag_buf[4][1]);

    try std.testing.expectEqualStrings("blurhash", tag_buf[5][0]);
    try std.testing.expectEqualStrings("LEHV6n", tag_buf[5][1]);

    try std.testing.expectEqualStrings("alt", tag_buf[6][0]);
    try std.testing.expectEqualStrings("Test image", tag_buf[6][1]);
}

test "FileMetadataBuilder with thumb and image hashes" {
    var builder = FileMetadataBuilder{
        .url = "https://example.com/video.mp4",
        .mime_type = "video/mp4",
        .file_hash = "videohash",
    };
    _ = builder.setThumb("https://example.com/thumb.jpg", "thumbhash").setImage("https://example.com/preview.jpg", null);

    var tag_buf: [20][]const []const u8 = undefined;
    var string_buf: [60][]const u8 = undefined;
    var size_buf: [20]u8 = undefined;
    var dim_buf: [20]u8 = undefined;

    const result = builder.buildTags(&tag_buf, &string_buf, &size_buf, &dim_buf);

    try std.testing.expectEqual(@as(usize, 5), result.count);

    try std.testing.expectEqualStrings("thumb", tag_buf[3][0]);
    try std.testing.expectEqualStrings("https://example.com/thumb.jpg", tag_buf[3][1]);
    try std.testing.expectEqual(@as(usize, 3), tag_buf[3].len);
    try std.testing.expectEqualStrings("thumbhash", tag_buf[3][2]);

    try std.testing.expectEqualStrings("image", tag_buf[4][0]);
    try std.testing.expectEqualStrings("https://example.com/preview.jpg", tag_buf[4][1]);
    try std.testing.expectEqual(@as(usize, 2), tag_buf[4].len);
}

test "parseDimensions" {
    const dim1 = parseDimensions("1920x1080");
    try std.testing.expect(dim1 != null);
    try std.testing.expectEqual(@as(u32, 1920), dim1.?.width);
    try std.testing.expectEqual(@as(u32, 1080), dim1.?.height);

    const dim2 = parseDimensions("640x480");
    try std.testing.expect(dim2 != null);
    try std.testing.expectEqual(@as(u32, 640), dim2.?.width);
    try std.testing.expectEqual(@as(u32, 480), dim2.?.height);

    try std.testing.expect(parseDimensions("invalid") == null);
    try std.testing.expect(parseDimensions("x100") == null);
    try std.testing.expect(parseDimensions("100x") == null);
    try std.testing.expect(parseDimensions("") == null);
}

test "FileMetadata handles empty content" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":1063,"created_at":1700000000,"content":"","tags":[["url","https://example.com/file.bin"],["m","application/octet-stream"],["x","filehash"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    var metadata = try FileMetadata.fromEvent(&event, std.testing.allocator);
    defer metadata.deinit();

    try std.testing.expectEqualStrings("", metadata.caption);
}
