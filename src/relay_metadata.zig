const std = @import("std");
const event_mod = @import("event.zig");
const utils = @import("utils.zig");

pub const Event = event_mod.Event;

pub const RELAY_LIST_KIND: i32 = 10002;

pub const RelayMarker = enum {
    read,
    write,
    read_write,

    pub fn canRead(self: RelayMarker) bool {
        return self == .read or self == .read_write;
    }

    pub fn canWrite(self: RelayMarker) bool {
        return self == .write or self == .read_write;
    }
};

pub const RelayInfo = struct {
    url: []const u8,
    marker: RelayMarker,
};

pub const RelayList = struct {
    relays: std.ArrayListUnmanaged(RelayInfo),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) RelayList {
        return .{
            .relays = .{},
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *RelayList) void {
        for (self.relays.items) |relay| {
            self.allocator.free(relay.url);
        }
        self.relays.deinit(self.allocator);
    }

    pub fn fromEvent(event: *const Event, allocator: std.mem.Allocator) !RelayList {
        if (event.kind() != RELAY_LIST_KIND) {
            return error.InvalidKind;
        }

        var list = RelayList.init(allocator);
        errdefer list.deinit();

        const tags_json = utils.findJsonValue(event.raw_json, "tags") orelse return list;
        var iter = RelayTagIterator.init(tags_json);

        while (iter.next()) |entry| {
            const url_copy = try allocator.dupe(u8, entry.url);
            errdefer allocator.free(url_copy);
            try list.relays.append(allocator, .{
                .url = url_copy,
                .marker = entry.marker,
            });
        }

        return list;
    }

    pub fn count(self: *const RelayList) usize {
        return self.relays.items.len;
    }

    pub fn getReadRelays(self: *const RelayList, buf: []RelayInfo) []RelayInfo {
        var n: usize = 0;
        for (self.relays.items) |relay| {
            if (relay.marker.canRead()) {
                if (n >= buf.len) break;
                buf[n] = relay;
                n += 1;
            }
        }
        return buf[0..n];
    }

    pub fn getWriteRelays(self: *const RelayList, buf: []RelayInfo) []RelayInfo {
        var n: usize = 0;
        for (self.relays.items) |relay| {
            if (relay.marker.canWrite()) {
                if (n >= buf.len) break;
                buf[n] = relay;
                n += 1;
            }
        }
        return buf[0..n];
    }

    pub fn iterator(self: *const RelayList) RelayIterator {
        return .{ .list = self, .index = 0 };
    }
};

pub const RelayIterator = struct {
    list: *const RelayList,
    index: usize,

    pub fn next(self: *RelayIterator) ?RelayInfo {
        if (self.index >= self.list.relays.items.len) return null;
        const relay = self.list.relays.items[self.index];
        self.index += 1;
        return relay;
    }
};

const RelayTagIterator = struct {
    json: []const u8,
    pos: usize,

    const Entry = struct {
        url: []const u8,
        marker: RelayMarker,
    };

    fn init(json: []const u8) RelayTagIterator {
        return .{ .json = json, .pos = 0 };
    }

    fn next(self: *RelayTagIterator) ?Entry {
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
            if (self.parseRTag(tag_content)) |entry| {
                return entry;
            }
        }
        return null;
    }

    fn findBracket(self: *RelayTagIterator, bracket: u8) ?usize {
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

    fn parseRTag(self: *const RelayTagIterator, content: []const u8) ?Entry {
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
        if (!std.mem.eql(u8, strings[0], "r")) return null;

        const url = strings[1];
        if (url.len == 0) return null;

        var marker: RelayMarker = .read_write;
        if (count >= 3) {
            if (std.mem.eql(u8, strings[2], "read")) {
                marker = .read;
            } else if (std.mem.eql(u8, strings[2], "write")) {
                marker = .write;
            }
        }

        return .{ .url = url, .marker = marker };
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

pub fn buildRelayTags(
    relays: []const RelayInfo,
    buf: [][]const []const u8,
    string_buf: [][]const u8,
) usize {
    var tag_idx: usize = 0;
    var str_idx: usize = 0;

    for (relays) |relay| {
        if (tag_idx >= buf.len) break;

        const r_str = "r";
        const tag_size: usize = switch (relay.marker) {
            .read_write => 2,
            else => 3,
        };

        if (str_idx + tag_size > string_buf.len) break;

        string_buf[str_idx] = r_str;
        string_buf[str_idx + 1] = relay.url;

        if (relay.marker == .read) {
            string_buf[str_idx + 2] = "read";
        } else if (relay.marker == .write) {
            string_buf[str_idx + 2] = "write";
        }

        buf[tag_idx] = string_buf[str_idx .. str_idx + tag_size];
        str_idx += tag_size;
        tag_idx += 1;
    }

    return tag_idx;
}

test "RelayMarker canRead and canWrite" {
    try std.testing.expect(RelayMarker.read.canRead());
    try std.testing.expect(!RelayMarker.read.canWrite());

    try std.testing.expect(!RelayMarker.write.canRead());
    try std.testing.expect(RelayMarker.write.canWrite());

    try std.testing.expect(RelayMarker.read_write.canRead());
    try std.testing.expect(RelayMarker.read_write.canWrite());
}

test "RelayList.fromEvent parses kind:10002" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":10002,"created_at":1700000000,"content":"","tags":[["r","wss://relay1.example.com"],["r","wss://relay2.example.com","write"],["r","wss://relay3.example.com","read"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    var list = try RelayList.fromEvent(&event, std.testing.allocator);
    defer list.deinit();

    try std.testing.expectEqual(@as(usize, 3), list.count());

    const relays = list.relays.items;
    try std.testing.expectEqualStrings("wss://relay1.example.com", relays[0].url);
    try std.testing.expectEqual(RelayMarker.read_write, relays[0].marker);

    try std.testing.expectEqualStrings("wss://relay2.example.com", relays[1].url);
    try std.testing.expectEqual(RelayMarker.write, relays[1].marker);

    try std.testing.expectEqualStrings("wss://relay3.example.com", relays[2].url);
    try std.testing.expectEqual(RelayMarker.read, relays[2].marker);
}

test "RelayList.getReadRelays filters correctly" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":10002,"created_at":1700000000,"content":"","tags":[["r","wss://both.example.com"],["r","wss://write.example.com","write"],["r","wss://read.example.com","read"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    var list = try RelayList.fromEvent(&event, std.testing.allocator);
    defer list.deinit();

    var read_buf: [10]RelayInfo = undefined;
    const read_relays = list.getReadRelays(&read_buf);

    try std.testing.expectEqual(@as(usize, 2), read_relays.len);
    try std.testing.expectEqualStrings("wss://both.example.com", read_relays[0].url);
    try std.testing.expectEqualStrings("wss://read.example.com", read_relays[1].url);
}

test "RelayList.getWriteRelays filters correctly" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":10002,"created_at":1700000000,"content":"","tags":[["r","wss://both.example.com"],["r","wss://write.example.com","write"],["r","wss://read.example.com","read"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    var list = try RelayList.fromEvent(&event, std.testing.allocator);
    defer list.deinit();

    var write_buf: [10]RelayInfo = undefined;
    const write_relays = list.getWriteRelays(&write_buf);

    try std.testing.expectEqual(@as(usize, 2), write_relays.len);
    try std.testing.expectEqualStrings("wss://both.example.com", write_relays[0].url);
    try std.testing.expectEqualStrings("wss://write.example.com", write_relays[1].url);
}

test "RelayList rejects wrong kind" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":1,"created_at":1700000000,"content":"test","tags":[["r","wss://relay.example.com"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    const result = RelayList.fromEvent(&event, std.testing.allocator);
    try std.testing.expectError(error.InvalidKind, result);
}

test "RelayList.iterator iterates all relays" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":10002,"created_at":1700000000,"content":"","tags":[["r","wss://relay1.example.com"],["r","wss://relay2.example.com"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    var list = try RelayList.fromEvent(&event, std.testing.allocator);
    defer list.deinit();

    var iter = list.iterator();
    var count: usize = 0;
    while (iter.next()) |_| {
        count += 1;
    }

    try std.testing.expectEqual(@as(usize, 2), count);
}

test "buildRelayTags creates correct tag structure" {
    const relays = [_]RelayInfo{
        .{ .url = "wss://relay1.example.com", .marker = .read_write },
        .{ .url = "wss://relay2.example.com", .marker = .write },
        .{ .url = "wss://relay3.example.com", .marker = .read },
    };

    var tag_buf: [10][]const []const u8 = undefined;
    var string_buf: [30][]const u8 = undefined;

    const count = buildRelayTags(&relays, &tag_buf, &string_buf);

    try std.testing.expectEqual(@as(usize, 3), count);

    try std.testing.expectEqual(@as(usize, 2), tag_buf[0].len);
    try std.testing.expectEqualStrings("r", tag_buf[0][0]);
    try std.testing.expectEqualStrings("wss://relay1.example.com", tag_buf[0][1]);

    try std.testing.expectEqual(@as(usize, 3), tag_buf[1].len);
    try std.testing.expectEqualStrings("r", tag_buf[1][0]);
    try std.testing.expectEqualStrings("wss://relay2.example.com", tag_buf[1][1]);
    try std.testing.expectEqualStrings("write", tag_buf[1][2]);

    try std.testing.expectEqual(@as(usize, 3), tag_buf[2].len);
    try std.testing.expectEqualStrings("r", tag_buf[2][0]);
    try std.testing.expectEqualStrings("wss://relay3.example.com", tag_buf[2][1]);
    try std.testing.expectEqualStrings("read", tag_buf[2][2]);
}

test "RelayList handles empty tags" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":10002,"created_at":1700000000,"content":"","tags":[]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    var list = try RelayList.fromEvent(&event, std.testing.allocator);
    defer list.deinit();

    try std.testing.expectEqual(@as(usize, 0), list.count());
}

test "RelayList ignores non-r tags" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":10002,"created_at":1700000000,"content":"","tags":[["e","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],["r","wss://relay.example.com"],["p","bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    var list = try RelayList.fromEvent(&event, std.testing.allocator);
    defer list.deinit();

    try std.testing.expectEqual(@as(usize, 1), list.count());
    try std.testing.expectEqualStrings("wss://relay.example.com", list.relays.items[0].url);
}

test "RelayList handles URLs with special characters" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":10002,"created_at":1700000000,"content":"","tags":[["r","wss://relay.example.com/?foo=]&bar=test"],["r","wss://normal.example.com","write"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    var list = try RelayList.fromEvent(&event, std.testing.allocator);
    defer list.deinit();

    try std.testing.expectEqual(@as(usize, 2), list.count());
    try std.testing.expectEqualStrings("wss://relay.example.com/?foo=]&bar=test", list.relays.items[0].url);
    try std.testing.expectEqual(RelayMarker.read_write, list.relays.items[0].marker);
    try std.testing.expectEqualStrings("wss://normal.example.com", list.relays.items[1].url);
    try std.testing.expectEqual(RelayMarker.write, list.relays.items[1].marker);
}
