const std = @import("std");
const tags = @import("tags.zig");
const event_mod = @import("event.zig");
const utils = @import("utils.zig");

pub const TagValue = tags.TagValue;
pub const Event = event_mod.Event;

pub const FilterTagEntry = struct {
    letter: u8,
    values: []const TagValue,
};

pub const Filter = struct {
    kinds_slice: ?[]const i32 = null,
    ids_bytes: ?[][32]u8 = null,
    authors_bytes: ?[][32]u8 = null,
    since_val: i64 = 0,
    until_val: i64 = 0,
    limit_val: i32 = 0,
    tag_filters: ?[]FilterTagEntry = null,
    search_str: ?[]const u8 = null,
    allocator: ?std.mem.Allocator = null,

    pub fn clone(self: *const Filter, allocator: std.mem.Allocator) !Filter {
        var new_filter = self.*;
        new_filter.allocator = allocator;

        if (self.kinds_slice) |k| {
            new_filter.kinds_slice = try allocator.dupe(i32, k);
        }
        if (self.ids_bytes) |id_list| {
            new_filter.ids_bytes = try allocator.dupe([32]u8, id_list);
        }
        if (self.authors_bytes) |author_list| {
            new_filter.authors_bytes = try allocator.dupe([32]u8, author_list);
        }
        if (self.tag_filters) |tag_list| {
            var new_tags = try allocator.alloc(FilterTagEntry, tag_list.len);
            for (tag_list, 0..) |entry, i| {
                var new_values = try allocator.alloc(TagValue, entry.values.len);
                for (entry.values, 0..) |val, j| {
                    new_values[j] = switch (val) {
                        .string => |s| .{ .string = try allocator.dupe(u8, s) },
                        .binary => |b| .{ .binary = b },
                    };
                }
                new_tags[i] = .{
                    .letter = entry.letter,
                    .values = new_values,
                };
            }
            new_filter.tag_filters = new_tags;
        }
        if (self.search_str) |s| {
            new_filter.search_str = try allocator.dupe(u8, s);
        }

        return new_filter;
    }

    pub fn matches(self: *const Filter, event: *const Event) bool {
        if (self.ids_bytes) |id_list| {
            var found = false;
            for (id_list) |id_item| {
                if (std.mem.eql(u8, &id_item, &event.id_bytes)) {
                    found = true;
                    break;
                }
            }
            if (!found) return false;
        }

        if (self.authors_bytes) |author_list| {
            var found = false;
            for (author_list) |author| {
                if (std.mem.eql(u8, &author, &event.pubkey_bytes)) {
                    found = true;
                    break;
                }
            }
            if (!found) return false;
        }

        if (self.kinds_slice) |k_slice| {
            var found = false;
            for (k_slice) |k| {
                if (k == event.kind()) {
                    found = true;
                    break;
                }
            }
            if (!found) return false;
        }

        if (self.since_val > 0 and event.createdAt() < self.since_val) {
            return false;
        }

        if (self.until_val > 0 and event.createdAt() > self.until_val) {
            return false;
        }

        if (self.tag_filters) |tag_entries| {
            for (tag_entries) |filter_entry| {
                const event_tag_values = event.tags.get(filter_entry.letter) orelse return false;
                var tag_found = false;
                outer: for (filter_entry.values) |filter_val| {
                    for (event_tag_values) |event_val| {
                        if (filter_val.eql(event_val)) {
                            tag_found = true;
                            break :outer;
                        }
                    }
                }
                if (!tag_found) return false;
            }
        }

        if (self.search_str) |query| {
            if (query.len > 0) {
                if (!utils.searchMatches(query, event.content())) return false;
            }
        }

        return true;
    }

    pub fn kinds(self: *const Filter) ?[]const i32 {
        return self.kinds_slice;
    }

    pub fn ids(self: *const Filter) ?[][32]u8 {
        return self.ids_bytes;
    }

    pub fn authors(self: *const Filter) ?[][32]u8 {
        return self.authors_bytes;
    }

    pub fn since(self: *const Filter) i64 {
        return self.since_val;
    }

    pub fn until(self: *const Filter) i64 {
        return self.until_val;
    }

    pub fn limit(self: *const Filter) i32 {
        return self.limit_val;
    }

    pub fn search(self: *const Filter) ?[]const u8 {
        return self.search_str;
    }

    pub fn hasTagFilters(self: *const Filter) bool {
        return self.tag_filters != null and self.tag_filters.?.len > 0;
    }

    pub fn serialize(self: *const Filter, buf: []u8) ![]u8 {
        var fbs = std.io.fixedBufferStream(buf);
        const writer = fbs.writer();

        try writer.writeByte('{');
        var first = true;

        if (self.ids_bytes) |id_list| {
            if (!first) try writer.writeByte(',');
            first = false;
            try writer.writeAll("\"ids\":[");
            for (id_list, 0..) |id_item, i| {
                if (i > 0) try writer.writeByte(',');
                try writer.writeByte('"');
                for (id_item) |b| {
                    try writer.print("{x:0>2}", .{b});
                }
                try writer.writeByte('"');
            }
            try writer.writeByte(']');
        }

        if (self.authors_bytes) |authors_list| {
            if (!first) try writer.writeByte(',');
            first = false;
            try writer.writeAll("\"authors\":[");
            for (authors_list, 0..) |author, i| {
                if (i > 0) try writer.writeByte(',');
                try writer.writeByte('"');
                for (author) |b| {
                    try writer.print("{x:0>2}", .{b});
                }
                try writer.writeByte('"');
            }
            try writer.writeByte(']');
        }

        if (self.kinds_slice) |kinds_list| {
            if (!first) try writer.writeByte(',');
            first = false;
            try writer.writeAll("\"kinds\":[");
            for (kinds_list, 0..) |k, i| {
                if (i > 0) try writer.writeByte(',');
                try writer.print("{d}", .{k});
            }
            try writer.writeByte(']');
        }

        if (self.since_val > 0) {
            if (!first) try writer.writeByte(',');
            first = false;
            try writer.print("\"since\":{d}", .{self.since_val});
        }

        if (self.until_val > 0) {
            if (!first) try writer.writeByte(',');
            first = false;
            try writer.print("\"until\":{d}", .{self.until_val});
        }

        if (self.limit_val > 0) {
            if (!first) try writer.writeByte(',');
            first = false;
            try writer.print("\"limit\":{d}", .{self.limit_val});
        }

        if (self.tag_filters) |tag_list| {
            for (tag_list) |entry| {
                if (!first) try writer.writeByte(',');
                first = false;
                try writer.print("\"#{c}\":[", .{entry.letter});
                for (entry.values, 0..) |val, i| {
                    if (i > 0) try writer.writeByte(',');
                    try writer.writeByte('"');
                    switch (val) {
                        .binary => |b| {
                            for (b) |byte| try writer.print("{x:0>2}", .{byte});
                        },
                        .string => |s| try utils.writeJsonEscaped(writer, s),
                    }
                    try writer.writeByte('"');
                }
                try writer.writeByte(']');
            }
        }

        if (self.search_str) |search_query| {
            if (search_query.len > 0) {
                if (!first) try writer.writeByte(',');
                try writer.writeAll("\"search\":\"");
                try utils.writeJsonEscaped(writer, search_query);
                try writer.writeByte('"');
            }
        }

        try writer.writeByte('}');

        return fbs.getWritten();
    }

    pub fn deinit(self: *Filter) void {
        if (self.allocator) |alloc| {
            if (self.kinds_slice) |k| alloc.free(k);
            if (self.ids_bytes) |id_list| alloc.free(id_list);
            if (self.authors_bytes) |author_list| alloc.free(author_list);
            if (self.tag_filters) |tag_list| {
                for (tag_list) |entry| {
                    for (entry.values) |val| {
                        switch (val) {
                            .string => |s| alloc.free(s),
                            .binary => {},
                        }
                    }
                    alloc.free(entry.values);
                }
                alloc.free(tag_list);
            }
            if (self.search_str) |s| alloc.free(s);
        }
        self.* = .{};
    }
};

pub fn filtersMatch(filters: []const Filter, event: *const Event) bool {
    for (filters) |f| {
        if (f.matches(event)) return true;
    }
    return false;
}

test "Filter matches uppercase tags correctly" {
    const event_module = @import("event.zig");
    try event_module.init();
    defer event_module.cleanup();

    const allocator = std.testing.allocator;

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":1,"created_at":1700000000,"content":"test","tags":[["E","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]]}
    ;

    var event = try Event.parseWithAllocator(json, allocator);
    defer event.deinit();

    var E_bytes: [32]u8 = undefined;
    @memset(&E_bytes, 0xaa);

    var E_tag_values = [_]TagValue{.{ .binary = E_bytes }};
    const E_tag_entry = FilterTagEntry{ .letter = 'E', .values = &E_tag_values };
    var tag_filters = [_]FilterTagEntry{E_tag_entry};

    const filter_E = Filter{
        .tag_filters = &tag_filters,
    };

    try std.testing.expect(filter_E.matches(&event));

    const e_tag_entry = FilterTagEntry{ .letter = 'e', .values = &E_tag_values };
    var e_tag_filters = [_]FilterTagEntry{e_tag_entry};

    const filter_e = Filter{
        .tag_filters = &e_tag_filters,
    };

    try std.testing.expect(!filter_e.matches(&event));
}

test "Filter with mixed-case tags matches correctly" {
    const event_module = @import("event.zig");
    try event_module.init();
    defer event_module.cleanup();

    const allocator = std.testing.allocator;

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":1,"created_at":1700000000,"content":"test","tags":[["e","1111111111111111111111111111111111111111111111111111111111111111"],["E","2222222222222222222222222222222222222222222222222222222222222222"],["t","hello"],["T","HELLO"]]}
    ;

    var event = try Event.parseWithAllocator(json, allocator);
    defer event.deinit();

    var e_bytes: [32]u8 = undefined;
    @memset(&e_bytes, 0x11);
    var e_values = [_]TagValue{.{ .binary = e_bytes }};
    const e_entry = FilterTagEntry{ .letter = 'e', .values = &e_values };
    var e_filters = [_]FilterTagEntry{e_entry};
    const filter_e = Filter{ .tag_filters = &e_filters };
    try std.testing.expect(filter_e.matches(&event));

    var E_bytes: [32]u8 = undefined;
    @memset(&E_bytes, 0x22);
    var E_values = [_]TagValue{.{ .binary = E_bytes }};
    const E_entry = FilterTagEntry{ .letter = 'E', .values = &E_values };
    var E_filters = [_]FilterTagEntry{E_entry};
    const filter_E = Filter{ .tag_filters = &E_filters };
    try std.testing.expect(filter_E.matches(&event));

    var wrong_e_values = [_]TagValue{.{ .binary = E_bytes }};
    const wrong_e_entry = FilterTagEntry{ .letter = 'e', .values = &wrong_e_values };
    var wrong_e_filters = [_]FilterTagEntry{wrong_e_entry};
    const filter_wrong_e = Filter{ .tag_filters = &wrong_e_filters };
    try std.testing.expect(!filter_wrong_e.matches(&event));

    var wrong_E_values = [_]TagValue{.{ .binary = e_bytes }};
    const wrong_E_entry = FilterTagEntry{ .letter = 'E', .values = &wrong_E_values };
    var wrong_E_filters = [_]FilterTagEntry{wrong_E_entry};
    const filter_wrong_E = Filter{ .tag_filters = &wrong_E_filters };
    try std.testing.expect(!filter_wrong_E.matches(&event));

    var t_values = [_]TagValue{.{ .string = "hello" }};
    const t_entry = FilterTagEntry{ .letter = 't', .values = &t_values };
    var t_filters = [_]FilterTagEntry{t_entry};
    const filter_t = Filter{ .tag_filters = &t_filters };
    try std.testing.expect(filter_t.matches(&event));

    var T_values = [_]TagValue{.{ .string = "HELLO" }};
    const T_entry = FilterTagEntry{ .letter = 'T', .values = &T_values };
    var T_filters = [_]FilterTagEntry{T_entry};
    const filter_T = Filter{ .tag_filters = &T_filters };
    try std.testing.expect(filter_T.matches(&event));

    var wrong_t_values = [_]TagValue{.{ .string = "HELLO" }};
    const wrong_t_entry = FilterTagEntry{ .letter = 't', .values = &wrong_t_values };
    var wrong_t_filters = [_]FilterTagEntry{wrong_t_entry};
    const filter_wrong_t = Filter{ .tag_filters = &wrong_t_filters };
    try std.testing.expect(!filter_wrong_t.matches(&event));
}

test "Filter.matches by kind" {
    const event_module = @import("event.zig");
    try event_module.init();
    defer event_module.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":1,"created_at":1700000000,"content":"test","tags":[]}
    ;

    var event = try Event.parseWithAllocator(json, std.testing.allocator);
    defer event.deinit();

    var kinds_match = [_]i32{ 1, 7 };
    const filter_match = Filter{ .kinds_slice = &kinds_match };
    try std.testing.expect(filter_match.matches(&event));

    var kinds_no_match = [_]i32{ 0, 7 };
    const filter_no_match = Filter{ .kinds_slice = &kinds_no_match };
    try std.testing.expect(!filter_no_match.matches(&event));
}

test "Filter.matches by since and until" {
    const event_module = @import("event.zig");
    try event_module.init();
    defer event_module.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":1,"created_at":1700000000,"content":"test","tags":[]}
    ;

    var event = try Event.parseWithAllocator(json, std.testing.allocator);
    defer event.deinit();

    const filter_since_ok = Filter{ .since_val = 1699999999 };
    try std.testing.expect(filter_since_ok.matches(&event));

    const filter_since_exact = Filter{ .since_val = 1700000000 };
    try std.testing.expect(filter_since_exact.matches(&event));

    const filter_since_fail = Filter{ .since_val = 1700000001 };
    try std.testing.expect(!filter_since_fail.matches(&event));

    const filter_until_ok = Filter{ .until_val = 1700000001 };
    try std.testing.expect(filter_until_ok.matches(&event));

    const filter_until_exact = Filter{ .until_val = 1700000000 };
    try std.testing.expect(filter_until_exact.matches(&event));

    const filter_until_fail = Filter{ .until_val = 1699999999 };
    try std.testing.expect(!filter_until_fail.matches(&event));
}

test "Filter.matches by id" {
    const event_module = @import("event.zig");
    try event_module.init();
    defer event_module.cleanup();

    const json =
        \\{"id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":1,"created_at":1700000000,"content":"test","tags":[]}
    ;

    var event = try Event.parseWithAllocator(json, std.testing.allocator);
    defer event.deinit();

    var id_match: [32]u8 = undefined;
    @memset(&id_match, 0xaa);
    var ids_match = [_][32]u8{id_match};
    const filter_match = Filter{ .ids_bytes = &ids_match };
    try std.testing.expect(filter_match.matches(&event));

    var id_no_match: [32]u8 = undefined;
    @memset(&id_no_match, 0xbb);
    var ids_no_match = [_][32]u8{id_no_match};
    const filter_no_match = Filter{ .ids_bytes = &ids_no_match };
    try std.testing.expect(!filter_no_match.matches(&event));
}

test "Filter.matches by author" {
    const event_module = @import("event.zig");
    try event_module.init();
    defer event_module.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":1,"created_at":1700000000,"content":"test","tags":[]}
    ;

    var event = try Event.parseWithAllocator(json, std.testing.allocator);
    defer event.deinit();

    var author_match: [32]u8 = undefined;
    @memset(&author_match, 0xcc);
    var authors_match = [_][32]u8{author_match};
    const filter_match = Filter{ .authors_bytes = &authors_match };
    try std.testing.expect(filter_match.matches(&event));

    var author_no_match: [32]u8 = undefined;
    @memset(&author_no_match, 0xdd);
    var authors_no_match = [_][32]u8{author_no_match};
    const filter_no_match = Filter{ .authors_bytes = &authors_no_match };
    try std.testing.expect(!filter_no_match.matches(&event));
}

test "Filter.serialize with kinds and limit" {
    var kinds = [_]i32{ 1, 7, 30023 };
    const filter = Filter{
        .kinds_slice = &kinds,
        .limit_val = 100,
        .since_val = 1700000000,
    };

    var buf: [256]u8 = undefined;
    const result = try filter.serialize(&buf);
    try std.testing.expectEqualStrings("{\"kinds\":[1,7,30023],\"since\":1700000000,\"limit\":100}", result);
}

test "Filter.serialize with ids and authors" {
    var id: [32]u8 = undefined;
    @memset(&id, 0xaa);
    var ids = [_][32]u8{id};

    var author: [32]u8 = undefined;
    @memset(&author, 0xbb);
    var authors = [_][32]u8{author};

    const filter = Filter{
        .ids_bytes = &ids,
        .authors_bytes = &authors,
    };

    var buf: [512]u8 = undefined;
    const result = try filter.serialize(&buf);
    try std.testing.expect(std.mem.indexOf(u8, result, "\"ids\":[\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"]") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "\"authors\":[\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"]") != null);
}

test "Filter.clone creates independent copy" {
    const allocator = std.testing.allocator;

    var kinds = [_]i32{ 1, 7 };
    var id: [32]u8 = undefined;
    @memset(&id, 0xaa);
    var ids = [_][32]u8{id};

    const original = Filter{
        .kinds_slice = &kinds,
        .ids_bytes = &ids,
        .since_val = 1700000000,
        .limit_val = 50,
    };

    var cloned = try original.clone(allocator);
    defer cloned.deinit();

    try std.testing.expectEqual(@as(usize, 2), cloned.kinds_slice.?.len);
    try std.testing.expectEqual(@as(i32, 1), cloned.kinds_slice.?[0]);
    try std.testing.expectEqual(@as(i64, 1700000000), cloned.since_val);
    try std.testing.expectEqual(@as(i32, 50), cloned.limit_val);

    try std.testing.expect(cloned.kinds_slice.?.ptr != original.kinds_slice.?.ptr);
    try std.testing.expect(cloned.ids_bytes.?.ptr != original.ids_bytes.?.ptr);
}

test "filtersMatch with multiple filters OR logic" {
    const event_module = @import("event.zig");
    try event_module.init();
    defer event_module.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":1,"created_at":1700000000,"content":"test","tags":[]}
    ;

    var event = try Event.parseWithAllocator(json, std.testing.allocator);
    defer event.deinit();

    var kinds_no = [_]i32{7};
    var kinds_yes = [_]i32{1};
    const filters = [_]Filter{
        .{ .kinds_slice = &kinds_no },
        .{ .kinds_slice = &kinds_yes },
    };

    try std.testing.expect(filtersMatch(&filters, &event));

    const filters_none = [_]Filter{
        .{ .kinds_slice = &kinds_no },
        .{ .since_val = 1800000000 },
    };
    try std.testing.expect(!filtersMatch(&filters_none, &event));
}
