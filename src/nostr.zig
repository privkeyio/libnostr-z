const std = @import("std");
pub const crypto = @import("crypto.zig");
pub const negentropy = @import("negentropy.zig");

pub const Error = error{
    InvalidJson,
    MissingField,
    InvalidId,
    InvalidPubkey,
    InvalidSig,
    InvalidCreatedAt,
    InvalidKind,
    InvalidTags,
    InvalidContent,
    IdMismatch,
    SigMismatch,
    FutureEvent,
    ExpiredEvent,
    InvalidSubscriptionId,
    TooManyFilters,
    BufferTooSmall,
    AllocFailed,
    SignatureFailed,
    Unknown,
};

pub fn errorMessage(err: Error) []const u8 {
    return switch (err) {
        error.InvalidJson => "invalid: malformed JSON",
        error.MissingField => "invalid: missing required field",
        error.InvalidId => "invalid: bad event ID",
        error.InvalidPubkey => "invalid: bad pubkey",
        error.InvalidSig => "invalid: bad signature",
        error.InvalidCreatedAt => "invalid: bad created_at",
        error.InvalidKind => "invalid: bad kind",
        error.InvalidTags => "invalid: bad tags",
        error.InvalidContent => "invalid: bad content",
        error.IdMismatch => "invalid: ID doesn't match content",
        error.SigMismatch => "invalid: signature verification failed",
        error.FutureEvent => "invalid: created_at too far in future",
        error.ExpiredEvent => "invalid: event expired",
        error.InvalidSubscriptionId => "invalid: bad subscription ID",
        error.TooManyFilters => "invalid: too many filters",
        error.BufferTooSmall => "error: buffer too small",
        error.AllocFailed => "error: allocation failed",
        error.SignatureFailed => "error: signature failed",
        error.Unknown => "error: unknown error",
    };
}

pub const TagValue = union(enum) {
    binary: [32]u8,
    string: []const u8,

    pub fn eql(self: TagValue, other: TagValue) bool {
        return switch (self) {
            .binary => |b| switch (other) {
                .binary => |ob| std.mem.eql(u8, &b, &ob),
                .string => false,
            },
            .string => |s| switch (other) {
                .binary => false,
                .string => |os| std.mem.eql(u8, s, os),
            },
        };
    }
};

pub const TagIndex = struct {
    entries: [52]std.ArrayListUnmanaged(TagValue),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) TagIndex {
        var entries: [52]std.ArrayListUnmanaged(TagValue) = undefined;
        for (&entries) |*e| {
            e.* = .{};
        }
        return .{ .entries = entries, .allocator = allocator };
    }

    pub fn deinit(self: *TagIndex) void {
        for (&self.entries) |*list| {
            for (list.items) |val| {
                switch (val) {
                    .string => |s| self.allocator.free(s),
                    .binary => {},
                }
            }
            list.deinit(self.allocator);
        }
    }

    fn letterIndex(letter: u8) ?usize {
        if (letter >= 'a' and letter <= 'z') return letter - 'a';
        if (letter >= 'A' and letter <= 'Z') return (letter - 'A') + 26;
        return null;
    }

    fn indexToLetter(idx: usize) u8 {
        if (idx < 26) return @intCast(idx + 'a');
        return @intCast((idx - 26) + 'A');
    }

    pub fn append(self: *TagIndex, tag_letter: u8, value: TagValue) !void {
        const idx = letterIndex(tag_letter) orelse return;
        try self.entries[idx].append(self.allocator, value);
    }

    pub fn get(self: *const TagIndex, tag_letter: u8) ?[]const TagValue {
        const idx = letterIndex(tag_letter) orelse return null;
        if (self.entries[idx].items.len == 0) return null;
        return self.entries[idx].items;
    }

    pub fn iterator(self: *const TagIndex) TagIterator {
        return TagIterator.init(self);
    }
};

pub const TagIterator = struct {
    index: *const TagIndex,
    letter_idx: usize = 0,
    value_idx: usize = 0,

    pub fn init(index: *const TagIndex) TagIterator {
        return .{ .index = index };
    }

    pub const Entry = struct {
        letter: u8,
        value: TagValue,
    };

    pub fn next(self: *TagIterator) ?Entry {
        while (self.letter_idx < 52) {
            const list = &self.index.entries[self.letter_idx];
            if (self.value_idx < list.items.len) {
                const entry = Entry{
                    .letter = TagIndex.indexToLetter(self.letter_idx),
                    .value = list.items[self.value_idx],
                };
                self.value_idx += 1;
                return entry;
            }
            self.letter_idx += 1;
            self.value_idx = 0;
        }
        return null;
    }
};

pub const Event = struct {
    id_bytes: [32]u8,
    pubkey_bytes: [32]u8,
    sig_bytes: [64]u8,
    created_at_val: i64,
    kind_val: i32,
    raw_json: []const u8,

    d_tag_val: ?[]const u8 = null,
    expiration_val: ?i64 = null,
    e_tags: std.ArrayListUnmanaged([32]u8),
    tags: TagIndex,
    tag_count: u32 = 0,
    allocator: std.mem.Allocator,

    pub fn parse(json: []const u8) Error!Event {
        return parseWithAllocator(json, std.heap.page_allocator);
    }

    pub fn parseWithAllocator(json: []const u8, allocator: std.mem.Allocator) Error!Event {
        const parsed = std.json.parseFromSlice(std.json.Value, allocator, json, .{}) catch return error.InvalidJson;
        defer parsed.deinit();

        const root = parsed.value.object;

        const id_hex = (root.get("id") orelse return error.MissingField).string;
        const pubkey_hex = (root.get("pubkey") orelse return error.MissingField).string;
        const sig_hex = (root.get("sig") orelse return error.MissingField).string;
        const created_at_val = root.get("created_at") orelse return error.MissingField;
        const kind_val = root.get("kind") orelse return error.MissingField;
        _ = (root.get("content") orelse return error.MissingField).string;

        const created_at: i64 = switch (created_at_val) {
            .integer => |i| i,
            else => return error.InvalidCreatedAt,
        };

        const kind_num: i32 = switch (kind_val) {
            .integer => |i| @intCast(i),
            else => return error.InvalidKind,
        };

        var id_bytes: [32]u8 = undefined;
        var pubkey_bytes: [32]u8 = undefined;
        var sig_bytes: [64]u8 = undefined;

        if (id_hex.len != 64) return error.InvalidId;
        if (pubkey_hex.len != 64) return error.InvalidPubkey;
        if (sig_hex.len != 128) return error.InvalidSig;

        _ = std.fmt.hexToBytes(&id_bytes, id_hex) catch return error.InvalidId;
        _ = std.fmt.hexToBytes(&pubkey_bytes, pubkey_hex) catch return error.InvalidPubkey;
        _ = std.fmt.hexToBytes(&sig_bytes, sig_hex) catch return error.InvalidSig;

        var event = Event{
            .id_bytes = id_bytes,
            .pubkey_bytes = pubkey_bytes,
            .sig_bytes = sig_bytes,
            .created_at_val = created_at,
            .kind_val = kind_num,
            .raw_json = json,
            .allocator = allocator,
            .e_tags = .{},
            .tags = TagIndex.init(allocator),
        };

        if (root.get("tags")) |tags_val| {
            if (tags_val == .array) {
                event.tag_count = @intCast(tags_val.array.items.len);
                for (tags_val.array.items) |tag| {
                    if (tag != .array or tag.array.items.len < 2) continue;

                    const tag_name = if (tag.array.items[0] == .string) tag.array.items[0].string else continue;
                    const tag_value_str = if (tag.array.items[1] == .string) tag.array.items[1].string else continue;

                    if (std.mem.eql(u8, tag_name, "d")) {
                        event.d_tag_val = findStringInJson(json, tag_value_str);
                    } else if (std.mem.eql(u8, tag_name, "expiration")) {
                        event.expiration_val = std.fmt.parseInt(i64, tag_value_str, 10) catch null;
                    }

                    if (tag_name.len == 1) {
                        const letter = tag_name[0];

                        if (letter == 'e' or letter == 'p' or letter == 'E' or letter == 'P') {
                            if (tag_value_str.len == 64) {
                                var bytes: [32]u8 = undefined;
                                if (std.fmt.hexToBytes(&bytes, tag_value_str)) |_| {
                                    event.tags.append(letter, .{ .binary = bytes }) catch {};
                                    if (letter == 'e' or letter == 'E') {
                                        event.e_tags.append(allocator, bytes) catch {};
                                    }
                                } else |_| {}
                            }
                        } else {
                            if (tag_value_str.len > 0 and tag_value_str.len <= 256) {
                                const duped = allocator.dupe(u8, tag_value_str) catch continue;
                                event.tags.append(letter, .{ .string = duped }) catch {
                                    allocator.free(duped);
                                };
                            }
                        }
                    }
                }
            }
        }

        return event;
    }

    pub fn validate(self: *const Event) Error!void {
        const now = std.time.timestamp();
        if (self.created_at_val > now + 900) return error.FutureEvent;

        const computed_id = self.computeId() catch return error.IdMismatch;
        if (!std.mem.eql(u8, &computed_id, &self.id_bytes)) return error.IdMismatch;

        crypto.verifySignature(&self.pubkey_bytes, &computed_id, &self.sig_bytes) catch return error.SigMismatch;
    }

    fn computeId(self: *const Event) ![32]u8 {
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update("[0,\"");

        var pubkey_hex: [64]u8 = undefined;
        for (&self.pubkey_bytes, 0..) |b, i| {
            _ = std.fmt.bufPrint(pubkey_hex[i * 2 ..][0..2], "{x:0>2}", .{b}) catch unreachable;
        }
        hasher.update(&pubkey_hex);

        hasher.update("\",");

        var created_buf: [20]u8 = undefined;
        const created_str = std.fmt.bufPrint(&created_buf, "{d}", .{self.created_at_val}) catch unreachable;
        hasher.update(created_str);

        hasher.update(",");

        var kind_buf: [11]u8 = undefined;
        const kind_str = std.fmt.bufPrint(&kind_buf, "{d}", .{self.kind_val}) catch unreachable;
        hasher.update(kind_str);

        hasher.update(",");

        if (findJsonValue(self.raw_json, "tags")) |tags_slice| {
            hasher.update(tags_slice);
        } else {
            hasher.update("[]");
        }

        hasher.update(",");
        if (findJsonValue(self.raw_json, "content")) |content_slice| {
            hasher.update(content_slice);
        } else {
            hasher.update("\"\"");
        }

        hasher.update("]");

        return hasher.finalResult();
    }

    pub fn serialize(self: *const Event, buf: []u8) ![]u8 {
        if (self.raw_json.len > 0 and self.raw_json.len <= buf.len) {
            @memcpy(buf[0..self.raw_json.len], self.raw_json);
            return buf[0..self.raw_json.len];
        }
        return error.BufferTooSmall;
    }

    pub fn id(self: *const Event) *const [32]u8 {
        return &self.id_bytes;
    }

    pub fn pubkey(self: *const Event) *const [32]u8 {
        return &self.pubkey_bytes;
    }

    pub fn idHex(self: *const Event, buf: *[65]u8) void {
        for (&self.id_bytes, 0..) |b, i| {
            _ = std.fmt.bufPrint(buf[i * 2 ..][0..2], "{x:0>2}", .{b}) catch {};
        }
        buf[64] = 0;
    }

    pub fn pubkeyHex(self: *const Event, buf: *[65]u8) void {
        for (&self.pubkey_bytes, 0..) |b, i| {
            _ = std.fmt.bufPrint(buf[i * 2 ..][0..2], "{x:0>2}", .{b}) catch {};
        }
        buf[64] = 0;
    }

    pub fn kind(self: *const Event) i32 {
        return self.kind_val;
    }

    pub fn createdAt(self: *const Event) i64 {
        return self.created_at_val;
    }

    pub fn content(self: *const Event) []const u8 {
        return extractJsonString(self.raw_json, "content") orelse "";
    }

    pub fn dTag(self: *const Event) ?[]const u8 {
        return self.d_tag_val;
    }

    pub fn tagCount(self: *const Event) u32 {
        return self.tag_count;
    }

    pub fn deinit(self: *Event) void {
        self.e_tags.deinit(self.allocator);
        self.tags.deinit();
    }
};

pub const KindType = enum {
    regular,
    replaceable,
    ephemeral,
    addressable,
};

pub fn kindType(kind_num: i32) KindType {
    if (kind_num == 0 or kind_num == 3) return .replaceable;
    if (kind_num >= 10000 and kind_num < 20000) return .replaceable;
    if (kind_num >= 20000 and kind_num < 30000) return .ephemeral;
    if (kind_num >= 30000 and kind_num < 40000) return .addressable;
    return .regular;
}

pub fn isExpired(event: *const Event) bool {
    if (event.expiration_val) |exp| {
        return std.time.timestamp() > exp;
    }
    return false;
}

pub fn isDeletion(event: *const Event) bool {
    return event.kind() == 5;
}

pub fn getDeletionIds(allocator: std.mem.Allocator, event: *const Event) ![]const [32]u8 {
    if (event.e_tags.items.len > 0) {
        return allocator.dupe([32]u8, event.e_tags.items);
    }
    return &[_][32]u8{};
}

fn containsInsensitive(haystack: []const u8, needle: []const u8) bool {
    if (needle.len == 0) return true;
    if (needle.len > haystack.len) return false;

    var i: usize = 0;
    while (i <= haystack.len - needle.len) : (i += 1) {
        var match = true;
        for (needle, 0..) |nc, j| {
            const hc = haystack[i + j];
            if (std.ascii.toLower(hc) != std.ascii.toLower(nc)) {
                match = false;
                break;
            }
        }
        if (match) return true;
    }
    return false;
}

fn isNip50Extension(token: []const u8) bool {
    if (token.len < 3) return false;
    if (std.mem.indexOf(u8, token, "://") != null) return false;

    const first = token[0];
    if (!((first >= 'A' and first <= 'Z') or (first >= 'a' and first <= 'z'))) return false;

    const colon_pos = std.mem.indexOfScalar(u8, token, ':') orelse return false;
    if (colon_pos == 0 or colon_pos >= token.len - 1) return false;

    for (token[1..colon_pos]) |c| {
        const valid = (c >= 'A' and c <= 'Z') or
            (c >= 'a' and c <= 'z') or
            (c >= '0' and c <= '9') or
            c == '_' or c == '-';
        if (!valid) return false;
    }

    if (token[colon_pos + 1] == '/') return false;
    return true;
}

fn searchMatches(query: []const u8, content: []const u8) bool {
    var words_iter = std.mem.splitScalar(u8, query, ' ');
    while (words_iter.next()) |word| {
        if (word.len == 0) continue;
        if (isNip50Extension(word)) continue;
        if (!containsInsensitive(content, word)) return false;
    }
    return true;
}

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
        if (self.tag_filters) |tags| {
            var new_tags = try allocator.alloc(FilterTagEntry, tags.len);
            for (tags, 0..) |entry, i| {
                new_tags[i] = .{
                    .letter = entry.letter,
                    .values = try allocator.dupe(TagValue, entry.values),
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
                if (!searchMatches(query, event.content())) return false;
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

        if (self.search_str) |search_query| {
            if (search_query.len > 0) {
                if (!first) try writer.writeByte(',');
                try writer.writeAll("\"search\":\"");
                try writeJsonEscaped(writer, search_query);
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
            if (self.tag_filters) |tags| {
                for (tags) |entry| {
                    for (entry.values) |val| {
                        switch (val) {
                            .string => |s| alloc.free(s),
                            .binary => {},
                        }
                    }
                    alloc.free(entry.values);
                }
                alloc.free(tags);
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

pub const ClientMsgType = enum {
    event,
    req,
    close,
    auth,
    count,
    neg_open,
    neg_msg,
    neg_close,
};

pub const ClientMsg = struct {
    msg_type: ClientMsgType,
    raw_json: []const u8,
    subscription_id_slice: []const u8 = "",
    event_obj: ?Event = null,
    allocator: std.mem.Allocator,

    pub fn parse(json: []const u8) Error!ClientMsg {
        return parseWithAllocator(json, std.heap.page_allocator);
    }

    pub fn parseWithAllocator(json: []const u8, allocator: std.mem.Allocator) Error!ClientMsg {
        const parsed = std.json.parseFromSlice(std.json.Value, allocator, json, .{}) catch return error.InvalidJson;
        defer parsed.deinit();

        if (parsed.value != .array or parsed.value.array.items.len < 1) {
            return error.InvalidJson;
        }

        const arr = parsed.value.array.items;
        const type_str = if (arr[0] == .string) arr[0].string else return error.InvalidJson;

        var msg = ClientMsg{
            .msg_type = .event,
            .raw_json = json,
            .allocator = allocator,
        };

        if (std.mem.eql(u8, type_str, "EVENT")) {
            msg.msg_type = .event;
        } else if (std.mem.eql(u8, type_str, "REQ")) {
            msg.msg_type = .req;
            if (arr.len > 1 and arr[1] == .string) {
                msg.subscription_id_slice = findStringInJson(json, arr[1].string) orelse "";
            }
        } else if (std.mem.eql(u8, type_str, "CLOSE")) {
            msg.msg_type = .close;
            if (arr.len > 1 and arr[1] == .string) {
                msg.subscription_id_slice = findStringInJson(json, arr[1].string) orelse "";
            }
        } else if (std.mem.eql(u8, type_str, "AUTH")) {
            msg.msg_type = .auth;
        } else if (std.mem.eql(u8, type_str, "COUNT")) {
            msg.msg_type = .count;
            if (arr.len > 1 and arr[1] == .string) {
                msg.subscription_id_slice = findStringInJson(json, arr[1].string) orelse "";
            }
        } else if (std.mem.eql(u8, type_str, "NEG-OPEN")) {
            msg.msg_type = .neg_open;
            if (arr.len > 1 and arr[1] == .string) {
                msg.subscription_id_slice = findStringInJson(json, arr[1].string) orelse "";
            }
        } else if (std.mem.eql(u8, type_str, "NEG-MSG")) {
            msg.msg_type = .neg_msg;
            if (arr.len > 1 and arr[1] == .string) {
                msg.subscription_id_slice = findStringInJson(json, arr[1].string) orelse "";
            }
        } else if (std.mem.eql(u8, type_str, "NEG-CLOSE")) {
            msg.msg_type = .neg_close;
            if (arr.len > 1 and arr[1] == .string) {
                msg.subscription_id_slice = findStringInJson(json, arr[1].string) orelse "";
            }
        } else {
            return error.InvalidJson;
        }

        return msg;
    }

    pub fn msgType(self: *const ClientMsg) ClientMsgType {
        return self.msg_type;
    }

    pub fn getEvent(self: *ClientMsg) Error!Event {
        if (self.event_obj) |ev| {
            return ev;
        }

        if (findArrayElement(self.raw_json, 1)) |event_json| {
            self.event_obj = try Event.parseWithAllocator(event_json, self.allocator);
            return self.event_obj.?;
        }

        return error.InvalidJson;
    }

    pub fn subscriptionId(self: *const ClientMsg) []const u8 {
        return self.subscription_id_slice;
    }

    pub fn getFilters(self: *const ClientMsg, allocator: std.mem.Allocator) ![]Filter {
        if (self.msg_type != .req and self.msg_type != .count) return &[_]Filter{};

        const parsed = std.json.parseFromSlice(std.json.Value, allocator, self.raw_json, .{}) catch return error.InvalidJson;
        defer parsed.deinit();

        if (parsed.value != .array) return &[_]Filter{};

        const arr = parsed.value.array.items;
        if (arr.len < 3) return &[_]Filter{};

        var filters: std.ArrayListUnmanaged(Filter) = .{};
        errdefer filters.deinit(allocator);

        for (arr[2..]) |filter_val| {
            if (filter_val != .object) continue;

            var filter = Filter{ .allocator = allocator };
            errdefer filter.deinit();
            const filter_obj = filter_val.object;

            if (filter_obj.get("ids")) |ids_val| {
                if (ids_val == .array) {
                    var ids_list: std.ArrayListUnmanaged([32]u8) = .{};
                    for (ids_val.array.items) |id_val| {
                        if (id_val == .string and id_val.string.len == 64) {
                            var id_bytes: [32]u8 = undefined;
                            if (std.fmt.hexToBytes(&id_bytes, id_val.string)) |_| {
                                try ids_list.append(allocator, id_bytes);
                            } else |_| {}
                        }
                    }
                    if (ids_list.items.len > 0) {
                        filter.ids_bytes = try ids_list.toOwnedSlice(allocator);
                    } else {
                        ids_list.deinit(allocator);
                    }
                }
            }

            if (filter_obj.get("authors")) |authors_val| {
                if (authors_val == .array) {
                    var authors_list: std.ArrayListUnmanaged([32]u8) = .{};
                    for (authors_val.array.items) |author_val| {
                        if (author_val == .string and author_val.string.len == 64) {
                            var author_bytes: [32]u8 = undefined;
                            if (std.fmt.hexToBytes(&author_bytes, author_val.string)) |_| {
                                try authors_list.append(allocator, author_bytes);
                            } else |_| {}
                        }
                    }
                    if (authors_list.items.len > 0) {
                        filter.authors_bytes = try authors_list.toOwnedSlice(allocator);
                    } else {
                        authors_list.deinit(allocator);
                    }
                }
            }

            if (filter_obj.get("kinds")) |kinds_val| {
                if (kinds_val == .array) {
                    var kinds_list: std.ArrayListUnmanaged(i32) = .{};
                    for (kinds_val.array.items) |k| {
                        if (k == .integer) {
                            try kinds_list.append(allocator, @intCast(k.integer));
                        }
                    }
                    if (kinds_list.items.len > 0) {
                        filter.kinds_slice = try kinds_list.toOwnedSlice(allocator);
                    } else {
                        kinds_list.deinit(allocator);
                    }
                }
            }

            if (filter_obj.get("limit")) |v| {
                if (v == .integer) {
                    filter.limit_val = @intCast(v.integer);
                }
            }

            if (filter_obj.get("since")) |v| {
                if (v == .integer) {
                    filter.since_val = v.integer;
                }
            }
            if (filter_obj.get("until")) |v| {
                if (v == .integer) {
                    filter.until_val = v.integer;
                }
            }

            if (filter_obj.get("search")) |v| {
                if (v == .string) {
                    filter.search_str = try allocator.dupe(u8, v.string);
                }
            }

            var tag_entries: std.ArrayListUnmanaged(FilterTagEntry) = .{};
            errdefer {
                for (tag_entries.items) |entry| {
                    for (entry.values) |val| {
                        switch (val) {
                            .string => |s| allocator.free(s),
                            .binary => {},
                        }
                    }
                    allocator.free(entry.values);
                }
                tag_entries.deinit(allocator);
            }

            var filter_iter = filter_obj.iterator();
            while (filter_iter.next()) |kv| {
                const key = kv.key_ptr.*;
                if (key.len == 2 and key[0] == '#') {
                    const letter = key[1];
                    if ((letter >= 'a' and letter <= 'z') or (letter >= 'A' and letter <= 'Z')) {
                        const tag_val = kv.value_ptr.*;
                        if (tag_val == .array) {
                            var values_list: std.ArrayListUnmanaged(TagValue) = .{};
                            errdefer values_list.deinit(allocator);

                            for (tag_val.array.items) |item| {
                                if (item == .string) {
                                    const str = item.string;
                                    if ((letter == 'e' or letter == 'p' or letter == 'E' or letter == 'P') and str.len == 64) {
                                        var bytes: [32]u8 = undefined;
                                        if (std.fmt.hexToBytes(&bytes, str)) |_| {
                                            try values_list.append(allocator, .{ .binary = bytes });
                                        } else |_| {
                                            const duped = try allocator.dupe(u8, str);
                                            try values_list.append(allocator, .{ .string = duped });
                                        }
                                    } else {
                                        if (str.len > 0 and str.len <= 256) {
                                            const duped = try allocator.dupe(u8, str);
                                            try values_list.append(allocator, .{ .string = duped });
                                        }
                                    }
                                }
                            }

                            if (values_list.items.len > 0) {
                                try tag_entries.append(allocator, .{
                                    .letter = letter,
                                    .values = try values_list.toOwnedSlice(allocator),
                                });
                            } else {
                                values_list.deinit(allocator);
                            }
                        }
                    }
                }
            }

            if (tag_entries.items.len > 0) {
                filter.tag_filters = try tag_entries.toOwnedSlice(allocator);
            } else {
                tag_entries.deinit(allocator);
            }

            try filters.append(allocator, filter);
        }

        return filters.toOwnedSlice(allocator);
    }

    pub fn getNegFilter(self: *const ClientMsg, allocator: std.mem.Allocator) !?Filter {
        if (self.msg_type != .neg_open) return null;

        const parsed = std.json.parseFromSlice(std.json.Value, allocator, self.raw_json, .{}) catch return error.InvalidJson;
        defer parsed.deinit();

        if (parsed.value != .array) return null;
        const arr = parsed.value.array.items;
        if (arr.len < 3 or arr[2] != .object) return null;

        var filter = Filter{ .allocator = allocator };
        errdefer filter.deinit();
        const filter_obj = arr[2].object;

        if (filter_obj.get("ids")) |ids_val| {
            if (ids_val == .array) {
                var ids_list: std.ArrayListUnmanaged([32]u8) = .{};
                for (ids_val.array.items) |id_val| {
                    if (id_val == .string and id_val.string.len == 64) {
                        var id_bytes: [32]u8 = undefined;
                        if (std.fmt.hexToBytes(&id_bytes, id_val.string)) |_| {
                            try ids_list.append(allocator, id_bytes);
                        } else |_| {}
                    }
                }
                if (ids_list.items.len > 0) {
                    filter.ids_bytes = try ids_list.toOwnedSlice(allocator);
                } else {
                    ids_list.deinit(allocator);
                }
            }
        }

        if (filter_obj.get("authors")) |authors_val| {
            if (authors_val == .array) {
                var authors_list: std.ArrayListUnmanaged([32]u8) = .{};
                for (authors_val.array.items) |author_val| {
                    if (author_val == .string and author_val.string.len == 64) {
                        var author_bytes: [32]u8 = undefined;
                        if (std.fmt.hexToBytes(&author_bytes, author_val.string)) |_| {
                            try authors_list.append(allocator, author_bytes);
                        } else |_| {}
                    }
                }
                if (authors_list.items.len > 0) {
                    filter.authors_bytes = try authors_list.toOwnedSlice(allocator);
                } else {
                    authors_list.deinit(allocator);
                }
            }
        }

        if (filter_obj.get("kinds")) |kinds_val| {
            if (kinds_val == .array) {
                var kinds_list: std.ArrayListUnmanaged(i32) = .{};
                for (kinds_val.array.items) |kind_val| {
                    if (kind_val == .integer) {
                        try kinds_list.append(allocator, @intCast(kind_val.integer));
                    }
                }
                if (kinds_list.items.len > 0) {
                    filter.kinds_slice = try kinds_list.toOwnedSlice(allocator);
                } else {
                    kinds_list.deinit(allocator);
                }
            }
        }

        if (filter_obj.get("since")) |since_val| {
            if (since_val == .integer) filter.since_val = since_val.integer;
        }

        if (filter_obj.get("until")) |until_val| {
            if (until_val == .integer) filter.until_val = until_val.integer;
        }

        if (filter_obj.get("limit")) |limit_val| {
            if (limit_val == .integer) filter.limit_val = @intCast(limit_val.integer);
        }

        return filter;
    }

    pub fn getNegPayload(self: *const ClientMsg, out: []u8) ![]u8 {
        if (self.msg_type != .neg_open and self.msg_type != .neg_msg) return error.InvalidJson;

        const parsed = std.json.parseFromSlice(std.json.Value, self.allocator, self.raw_json, .{}) catch return error.InvalidJson;
        defer parsed.deinit();

        if (parsed.value != .array) return error.InvalidJson;
        const arr = parsed.value.array.items;

        const payload_idx: usize = if (self.msg_type == .neg_open) 3 else 2;
        if (arr.len <= payload_idx or arr[payload_idx] != .string) return error.InvalidJson;

        const hex_str = arr[payload_idx].string;
        if (hex_str.len % 2 != 0 or hex_str.len / 2 > out.len) return error.BufferTooSmall;

        const decoded = std.fmt.hexToBytes(out[0 .. hex_str.len / 2], hex_str) catch return error.InvalidJson;
        return decoded;
    }

    pub fn deinit(self: *ClientMsg) void {
        if (self.event_obj) |*ev| {
            ev.deinit();
        }
    }

    pub fn eventMsg(ev: *const Event, buf: []u8) ![]u8 {
        var fbs = std.io.fixedBufferStream(buf);
        const writer = fbs.writer();

        try writer.writeAll("[\"EVENT\",");
        const event_json = try ev.serialize(buf[fbs.pos..]);
        fbs.pos += event_json.len;
        try writer.writeAll("]");

        return fbs.getWritten();
    }

    pub fn reqMsg(sub_id: []const u8, filters: []const Filter, buf: []u8) ![]u8 {
        var fbs = std.io.fixedBufferStream(buf);
        const writer = fbs.writer();

        try writer.writeAll("[\"REQ\",\"");
        try writer.writeAll(sub_id);
        try writer.writeByte('"');

        for (filters) |filter| {
            try writer.writeByte(',');
            const filter_json = try filter.serialize(buf[fbs.pos..]);
            fbs.pos += filter_json.len;
        }

        try writer.writeAll("]");

        return fbs.getWritten();
    }

    pub fn closeMsg(sub_id: []const u8, buf: []u8) ![]u8 {
        var fbs = std.io.fixedBufferStream(buf);
        const writer = fbs.writer();

        try writer.writeAll("[\"CLOSE\",\"");
        try writer.writeAll(sub_id);
        try writer.writeAll("\"]");

        return fbs.getWritten();
    }
};

pub const RelayMsgType = enum {
    event,
    ok,
    eose,
    closed,
    notice,
    auth,
    count,
    unknown,
};

pub const RelayMsgParsed = struct {
    msg_type: RelayMsgType,
    success: bool = false,
    is_duplicate: bool = false,
    is_rate_limited: bool = false,
    count_val: ?u64 = null,

    pub fn parse(json: []const u8, allocator: std.mem.Allocator) !RelayMsgParsed {
        const parsed = std.json.parseFromSlice(std.json.Value, allocator, json, .{}) catch return error.InvalidJson;
        defer parsed.deinit();

        if (parsed.value != .array or parsed.value.array.items.len < 1) {
            return error.InvalidJson;
        }

        const arr = parsed.value.array.items;
        const type_str = if (arr[0] == .string) arr[0].string else return error.InvalidJson;

        var msg = RelayMsgParsed{
            .msg_type = .unknown,
        };

        if (std.mem.eql(u8, type_str, "EVENT")) {
            msg.msg_type = .event;
        } else if (std.mem.eql(u8, type_str, "OK")) {
            msg.msg_type = .ok;
            if (arr.len > 2 and arr[2] == .bool) {
                msg.success = arr[2].bool;
            }
            if (arr.len > 3 and arr[3] == .string) {
                const reason = arr[3].string;
                if (std.mem.indexOf(u8, reason, "duplicate") != null) {
                    msg.is_duplicate = true;
                }
                if (std.mem.indexOf(u8, reason, "rate-limit") != null) {
                    msg.is_rate_limited = true;
                }
            }
        } else if (std.mem.eql(u8, type_str, "EOSE")) {
            msg.msg_type = .eose;
        } else if (std.mem.eql(u8, type_str, "CLOSED")) {
            msg.msg_type = .closed;
        } else if (std.mem.eql(u8, type_str, "NOTICE")) {
            msg.msg_type = .notice;
        } else if (std.mem.eql(u8, type_str, "AUTH")) {
            msg.msg_type = .auth;
        } else if (std.mem.eql(u8, type_str, "COUNT")) {
            msg.msg_type = .count;
            if (arr.len > 2 and arr[2] == .object) {
                if (arr[2].object.get("count")) |c| {
                    if (c == .integer) {
                        msg.count_val = @intCast(c.integer);
                    }
                }
            }
        }

        return msg;
    }
};

pub const RelayMsg = struct {
    pub fn event(sub_id: []const u8, ev: *const Event, buf: []u8) ![]u8 {
        return eventRaw(sub_id, ev.raw_json, buf);
    }

    pub fn eventRaw(sub_id: []const u8, raw_json: []const u8, buf: []u8) ![]u8 {
        var fbs = std.io.fixedBufferStream(buf);
        const writer = fbs.writer();

        try writer.writeAll("[\"EVENT\",\"");
        try writer.writeAll(sub_id);
        try writer.writeAll("\",");
        try writer.writeAll(raw_json);
        try writer.writeAll("]");

        return fbs.getWritten();
    }

    pub fn ok(event_id: *const [32]u8, success: bool, message: []const u8, buf: []u8) ![]u8 {
        var fbs = std.io.fixedBufferStream(buf);
        const writer = fbs.writer();

        try writer.writeAll("[\"OK\",\"");

        for (event_id) |b| {
            try writer.print("{x:0>2}", .{b});
        }

        try writer.writeAll("\",");
        try writer.writeAll(if (success) "true" else "false");
        try writer.writeAll(",\"");

        for (message) |c| {
            switch (c) {
                '"' => try writer.writeAll("\\\""),
                '\\' => try writer.writeAll("\\\\"),
                '\n' => try writer.writeAll("\\n"),
                else => try writer.writeByte(c),
            }
        }

        try writer.writeAll("\"]");

        return fbs.getWritten();
    }

    pub fn eose(sub_id: []const u8, buf: []u8) ![]u8 {
        var fbs = std.io.fixedBufferStream(buf);
        const writer = fbs.writer();

        try writer.writeAll("[\"EOSE\",\"");
        try writer.writeAll(sub_id);
        try writer.writeAll("\"]");

        return fbs.getWritten();
    }

    pub fn closed(sub_id: []const u8, message: []const u8, buf: []u8) ![]u8 {
        var fbs = std.io.fixedBufferStream(buf);
        const writer = fbs.writer();

        try writer.writeAll("[\"CLOSED\",\"");
        try writer.writeAll(sub_id);
        try writer.writeAll("\",\"");

        for (message) |c| {
            switch (c) {
                '"' => try writer.writeAll("\\\""),
                '\\' => try writer.writeAll("\\\\"),
                '\n' => try writer.writeAll("\\n"),
                else => try writer.writeByte(c),
            }
        }

        try writer.writeAll("\"]");

        return fbs.getWritten();
    }

    pub fn notice(message: []const u8, buf: []u8) ![]u8 {
        var fbs = std.io.fixedBufferStream(buf);
        const writer = fbs.writer();

        try writer.writeAll("[\"NOTICE\",\"");

        for (message) |c| {
            switch (c) {
                '"' => try writer.writeAll("\\\""),
                '\\' => try writer.writeAll("\\\\"),
                '\n' => try writer.writeAll("\\n"),
                else => try writer.writeByte(c),
            }
        }

        try writer.writeAll("\"]");

        return fbs.getWritten();
    }

    pub fn auth(challenge: *const [32]u8, buf: []u8) ![]u8 {
        var fbs = std.io.fixedBufferStream(buf);
        const writer = fbs.writer();

        try writer.writeAll("[\"AUTH\",\"");

        for (challenge) |b| {
            try writer.print("{x:0>2}", .{b});
        }

        try writer.writeAll("\"]");

        return fbs.getWritten();
    }

    pub fn count(sub_id: []const u8, count_val: u64, buf: []u8) ![]u8 {
        var fbs = std.io.fixedBufferStream(buf);
        const writer = fbs.writer();

        try writer.writeAll("[\"COUNT\",\"");
        try writer.writeAll(sub_id);
        try writer.writeAll("\",{\"count\":");
        try writer.print("{d}", .{count_val});
        try writer.writeAll("}]");

        return fbs.getWritten();
    }

    pub fn negMsg(sub_id: []const u8, payload: []const u8, buf: []u8) ![]u8 {
        var fbs = std.io.fixedBufferStream(buf);
        const writer = fbs.writer();

        try writer.writeAll("[\"NEG-MSG\",\"");
        try writer.writeAll(sub_id);
        try writer.writeAll("\",\"");

        for (payload) |b| {
            try writer.print("{x:0>2}", .{b});
        }

        try writer.writeAll("\"]");

        return fbs.getWritten();
    }

    pub fn negErr(sub_id: []const u8, reason: []const u8, buf: []u8) ![]u8 {
        var fbs = std.io.fixedBufferStream(buf);
        const writer = fbs.writer();

        try writer.writeAll("[\"NEG-ERR\",\"");
        try writer.writeAll(sub_id);
        try writer.writeAll("\",\"");

        for (reason) |c| {
            switch (c) {
                '"' => try writer.writeAll("\\\""),
                '\\' => try writer.writeAll("\\\\"),
                '\n' => try writer.writeAll("\\n"),
                else => try writer.writeByte(c),
            }
        }

        try writer.writeAll("\"]");

        return fbs.getWritten();
    }
};

pub const Keypair = struct {
    secret_key: [32]u8,
    public_key: [32]u8,

    pub fn generate() Keypair {
        var secret_key: [32]u8 = undefined;
        std.crypto.random.bytes(&secret_key);

        var public_key: [32]u8 = undefined;
        crypto.getPublicKey(&secret_key, &public_key) catch {
            std.crypto.random.bytes(&public_key);
        };

        return .{
            .secret_key = secret_key,
            .public_key = public_key,
        };
    }
};

pub const EventBuilder = struct {
    id_bytes: [32]u8 = undefined,
    pubkey_bytes: [32]u8 = undefined,
    sig_bytes: [64]u8 = undefined,
    created_at_val: i64 = 0,
    kind_val: i32 = 1,
    content_slice: []const u8 = "",
    tags_data: []const []const []const u8 = &[_][]const []const u8{},

    pub fn setKind(self: *EventBuilder, k: i32) *EventBuilder {
        self.kind_val = k;
        return self;
    }

    pub fn setContent(self: *EventBuilder, c: []const u8) *EventBuilder {
        self.content_slice = c;
        return self;
    }

    pub fn setCreatedAt(self: *EventBuilder, t: i64) *EventBuilder {
        self.created_at_val = t;
        return self;
    }

    pub fn setTags(self: *EventBuilder, t: []const []const []const u8) *EventBuilder {
        self.tags_data = t;
        return self;
    }

    pub fn sign(self: *EventBuilder, keypair: *const Keypair) !void {
        @memcpy(&self.pubkey_bytes, &keypair.public_key);

        if (self.created_at_val == 0) {
            self.created_at_val = std.time.timestamp();
        }

        var commitment_buf: [8192]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&commitment_buf);
        const writer = fbs.writer();

        try writer.writeAll("[0,\"");

        for (&keypair.public_key) |byte| {
            try writer.print("{x:0>2}", .{byte});
        }

        try writer.writeAll("\",");
        try writer.print("{d}", .{self.created_at_val});
        try writer.writeAll(",");
        try writer.print("{d}", .{self.kind_val});
        try writer.writeAll(",[");

        for (self.tags_data, 0..) |tag, i| {
            if (i > 0) try writer.writeByte(',');
            try writer.writeByte('[');
            for (tag, 0..) |elem, j| {
                if (j > 0) try writer.writeByte(',');
                try writer.writeByte('"');
                try writeJsonEscaped(writer, elem);
                try writer.writeByte('"');
            }
            try writer.writeByte(']');
        }

        try writer.writeAll("],\"");
        try writeJsonEscaped(writer, self.content_slice);
        try writer.writeAll("\"]");

        const commitment = fbs.getWritten();
        std.crypto.hash.sha2.Sha256.hash(commitment, &self.id_bytes, .{});

        crypto.sign(&keypair.secret_key, &self.id_bytes, &self.sig_bytes) catch {
            return error.SignatureFailed;
        };
    }

    pub fn serialize(self: *const EventBuilder, buf: []u8) ![]u8 {
        var fbs = std.io.fixedBufferStream(buf);
        const writer = fbs.writer();

        try writer.writeAll("{\"id\":\"");
        for (self.id_bytes) |b| {
            try writer.print("{x:0>2}", .{b});
        }
        try writer.writeAll("\",\"pubkey\":\"");
        for (self.pubkey_bytes) |b| {
            try writer.print("{x:0>2}", .{b});
        }
        try writer.writeAll("\",\"created_at\":");
        try writer.print("{d}", .{self.created_at_val});
        try writer.writeAll(",\"kind\":");
        try writer.print("{d}", .{self.kind_val});
        try writer.writeAll(",\"tags\":[");

        for (self.tags_data, 0..) |tag, i| {
            if (i > 0) try writer.writeByte(',');
            try writer.writeByte('[');
            for (tag, 0..) |elem, j| {
                if (j > 0) try writer.writeByte(',');
                try writer.writeByte('"');
                try writeJsonEscaped(writer, elem);
                try writer.writeByte('"');
            }
            try writer.writeByte(']');
        }

        try writer.writeAll("],\"content\":\"");
        try writeJsonEscaped(writer, self.content_slice);
        try writer.writeAll("\",\"sig\":\"");
        for (self.sig_bytes) |b| {
            try writer.print("{x:0>2}", .{b});
        }
        try writer.writeAll("\"}");

        return fbs.getWritten();
    }
};

fn writeJsonEscaped(writer: anytype, str: []const u8) !void {
    for (str) |c| {
        switch (c) {
            '"' => try writer.writeAll("\\\""),
            '\\' => try writer.writeAll("\\\\"),
            '\n' => try writer.writeAll("\\n"),
            '\r' => try writer.writeAll("\\r"),
            '\t' => try writer.writeAll("\\t"),
            else => {
                if (c < 0x20) {
                    try writer.print("\\u{x:0>4}", .{c});
                } else {
                    try writer.writeByte(c);
                }
            },
        }
    }
}

fn findJsonValue(json: []const u8, key: []const u8) ?[]const u8 {
    var search_buf: [68]u8 = undefined;
    const search = std.fmt.bufPrint(&search_buf, "\"{s}\":", .{key}) catch return null;

    if (std.mem.indexOf(u8, json, search)) |pos| {
        var start = pos + search.len;

        while (start < json.len and (json[start] == ' ' or json[start] == '\t' or json[start] == '\n' or json[start] == '\r')) {
            start += 1;
        }

        if (start >= json.len) return null;

        const first = json[start];

        if (first == '"') {
            var end = start + 1;
            var escape = false;
            while (end < json.len) {
                const c = json[end];
                if (escape) {
                    escape = false;
                } else if (c == '\\') {
                    escape = true;
                } else if (c == '"') {
                    return json[start .. end + 1];
                }
                end += 1;
            }
            return null;
        }

        if (first == '[' or first == '{') {
            const close_char: u8 = if (first == '[') ']' else '}';
            var depth: i32 = 0;
            var end = start;
            var in_string = false;
            var escape = false;

            for (json[start..], 0..) |c, i| {
                if (escape) {
                    escape = false;
                    continue;
                }
                if (c == '\\' and in_string) {
                    escape = true;
                    continue;
                }
                if (c == '"' and !escape) {
                    in_string = !in_string;
                    continue;
                }
                if (!in_string) {
                    if (c == first) depth += 1;
                    if (c == close_char) {
                        depth -= 1;
                        if (depth == 0) {
                            end = start + i + 1;
                            break;
                        }
                    }
                }
            }
            return json[start..end];
        }
    }
    return null;
}

fn findArrayElement(json: []const u8, index: usize) ?[]const u8 {
    var pos: usize = 0;
    while (pos < json.len and json[pos] != '[') : (pos += 1) {}
    if (pos >= json.len) return null;
    pos += 1;

    var current_index: usize = 0;
    var depth: i32 = 0;
    var in_string = false;
    var escape = false;
    var element_start: usize = pos;

    while (pos < json.len and (json[pos] == ' ' or json[pos] == '\t' or json[pos] == '\n' or json[pos] == '\r')) : (pos += 1) {}
    element_start = pos;

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

        if (!in_string) {
            if (c == '[' or c == '{') {
                depth += 1;
            } else if (c == ']' or c == '}') {
                if (depth == 0 and c == ']') {
                    if (current_index == index) {
                        return json[element_start..pos];
                    }
                    return null;
                }
                depth -= 1;
            } else if (c == ',' and depth == 0) {
                if (current_index == index) {
                    return json[element_start..pos];
                }
                current_index += 1;
                pos += 1;
                while (pos < json.len and (json[pos] == ' ' or json[pos] == '\t' or json[pos] == '\n' or json[pos] == '\r')) : (pos += 1) {}
                element_start = pos;
                continue;
            }
        }

        pos += 1;
    }

    return null;
}

fn extractJsonString(json: []const u8, key: []const u8) ?[]const u8 {
    var search_buf: [68]u8 = undefined;
    const search = std.fmt.bufPrint(&search_buf, "\"{s}\":", .{key}) catch return null;

    const key_pos = std.mem.indexOf(u8, json, search) orelse return null;
    var pos = key_pos + search.len;

    while (pos < json.len and (json[pos] == ' ' or json[pos] == '\t' or json[pos] == '\n' or json[pos] == '\r')) : (pos += 1) {}

    if (pos >= json.len or json[pos] != '"') return null;
    pos += 1;

    const start = pos;
    var escape = false;

    while (pos < json.len) {
        const c = json[pos];
        if (escape) {
            escape = false;
        } else if (c == '\\') {
            escape = true;
        } else if (c == '"') {
            return json[start..pos];
        }
        pos += 1;
    }
    return null;
}

fn findStringInJson(json: []const u8, needle: []const u8) ?[]const u8 {
    var search_buf: [256]u8 = undefined;
    if (needle.len > 250) return null;

    const search = std.fmt.bufPrint(&search_buf, "\"{s}\"", .{needle}) catch return null;
    const pos = std.mem.indexOf(u8, json, search) orelse return null;

    return json[pos + 1 .. pos + 1 + needle.len];
}

pub fn init() !void {
    try crypto.init();
}

pub fn cleanup() void {
    crypto.cleanup();
}

pub const Auth = struct {
    pub const Tags = struct {
        relay: ?[]const u8 = null,
        challenge: ?[]const u8 = null,
    };

    pub fn extractTags(json: []const u8) Tags {
        var result = Tags{};

        const tags_start = std.mem.indexOf(u8, json, "\"tags\"") orelse return result;
        var pos = tags_start + 6;

        while (pos < json.len and json[pos] != '[') : (pos += 1) {}
        if (pos >= json.len) return result;
        pos += 1;

        var depth: i32 = 0;
        var in_string = false;
        var escape = false;
        var tag_start: ?usize = null;

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

            if (!in_string) {
                if (c == '[') {
                    if (depth == 0) {
                        tag_start = pos;
                    }
                    depth += 1;
                } else if (c == ']') {
                    depth -= 1;
                    if (depth == 0 and tag_start != null) {
                        const tag_json = json[tag_start.? .. pos + 1];
                        extractAuthTagValues(tag_json, &result);
                        tag_start = null;
                    }
                    if (depth < 0) break;
                }
            }

            pos += 1;
        }

        return result;
    }

    fn extractAuthTagValues(tag_json: []const u8, result: *Tags) void {
        var values: [2]?[]const u8 = .{ null, null };
        var value_idx: usize = 0;
        var pos: usize = 0;
        var in_string = false;
        var string_start: usize = 0;
        var escape = false;

        while (pos < tag_json.len and value_idx < 2) {
            const c = tag_json[pos];

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
                if (in_string) {
                    values[value_idx] = tag_json[string_start..pos];
                    value_idx += 1;
                } else {
                    string_start = pos + 1;
                }
                in_string = !in_string;
            }

            pos += 1;
        }

        if (values[0] != null and values[1] != null) {
            if (std.mem.eql(u8, values[0].?, "relay")) {
                result.relay = values[1].?;
            } else if (std.mem.eql(u8, values[0].?, "challenge")) {
                result.challenge = values[1].?;
            }
        }
    }

    pub fn extractDomain(url: []const u8) ?[]const u8 {
        var start: usize = 0;
        if (std.mem.startsWith(u8, url, "wss://")) {
            start = 6;
        } else if (std.mem.startsWith(u8, url, "ws://")) {
            start = 5;
        } else if (std.mem.startsWith(u8, url, "https://")) {
            start = 8;
        } else if (std.mem.startsWith(u8, url, "http://")) {
            start = 7;
        }

        if (start >= url.len) return null;

        var end = start;
        while (end < url.len) {
            if (url[end] == ':' or url[end] == '/' or url[end] == '?') break;
            end += 1;
        }

        if (end <= start) return null;
        return url[start..end];
    }

    pub fn domainsMatch(url1: []const u8, url2: []const u8) bool {
        const domain1 = extractDomain(url1) orelse return false;
        const domain2 = extractDomain(url2) orelse return false;
        return std.ascii.eqlIgnoreCase(domain1, domain2);
    }
};

pub const Replaceable = struct {
    pub const Decision = enum { accept_new, keep_old };

    pub fn buildKey(event: *const Event, buf: *[128]u8) usize {
        var key_len: usize = 0;

        @memcpy(buf[0..32], event.pubkey());
        key_len = 32;

        const kind_be = @byteSwap(@as(u32, @bitCast(event.kind())));
        @memcpy(buf[key_len..][0..4], std.mem.asBytes(&kind_be));
        key_len += 4;

        const kt = kindType(event.kind());
        if (kt == .addressable) {
            if (event.dTag()) |d| {
                const copy_len = @min(d.len, buf.len - key_len);
                @memcpy(buf[key_len..][0..copy_len], d[0..copy_len]);
                key_len += copy_len;
            }
        }

        return key_len;
    }

    pub fn shouldReplace(existing: *const Event, new: *const Event) Decision {
        if (new.createdAt() > existing.createdAt()) return .accept_new;
        if (new.createdAt() < existing.createdAt()) return .keep_old;
        if (std.mem.order(u8, new.id(), existing.id()) == .lt) return .accept_new;
        return .keep_old;
    }
};

pub const IndexKeys = struct {
    pub fn created(event: *const Event, buf: *[40]u8) void {
        const created_at_be = @byteSwap(@as(u64, @bitCast(event.createdAt())));
        @memcpy(buf[0..8], std.mem.asBytes(&created_at_be));
        @memcpy(buf[8..40], event.id());
    }

    pub fn pubkey(event: *const Event, buf: *[72]u8) void {
        const created_at_be = @byteSwap(@as(u64, @bitCast(event.createdAt())));
        @memcpy(buf[0..32], event.pubkey());
        @memcpy(buf[32..40], std.mem.asBytes(&created_at_be));
        @memcpy(buf[40..72], event.id());
    }

    pub fn kind(event: *const Event, buf: *[44]u8) void {
        const kind_be = @byteSwap(@as(u32, @bitCast(event.kind())));
        const created_at_be = @byteSwap(@as(u64, @bitCast(event.createdAt())));
        @memcpy(buf[0..4], std.mem.asBytes(&kind_be));
        @memcpy(buf[4..12], std.mem.asBytes(&created_at_be));
        @memcpy(buf[12..44], event.id());
    }

    pub fn expiration(event: *const Event, buf: *[40]u8) ?*[40]u8 {
        const exp = event.expiration_val orelse return null;
        if (exp < 0) return null;
        const exp_be = @byteSwap(@as(u64, @intCast(exp)));
        @memcpy(buf[0..8], std.mem.asBytes(&exp_be));
        @memcpy(buf[8..40], event.id());
        return buf;
    }

    pub const BinaryTagKey = struct {
        data: [73]u8,

        pub fn init(letter: u8, value: *const [32]u8, created_at_be: *const [8]u8, event_id: *const [32]u8) BinaryTagKey {
            var key = BinaryTagKey{ .data = undefined };
            key.data[0] = letter;
            @memcpy(key.data[1..33], value);
            @memcpy(key.data[33..41], created_at_be);
            @memcpy(key.data[41..73], event_id);
            return key;
        }

        pub fn slice(self: *const BinaryTagKey) []const u8 {
            return &self.data;
        }
    };

    pub const StringTagKey = struct {
        data: [297]u8,
        len: usize,

        pub fn init(letter: u8, value: []const u8, created_at_be: *const [8]u8, event_id: *const [32]u8) ?StringTagKey {
            if (value.len > 256) return null;
            var key = StringTagKey{ .data = undefined, .len = 0 };
            key.data[0] = letter;
            @memcpy(key.data[1..][0..value.len], value);
            @memcpy(key.data[1 + value.len ..][0..8], created_at_be);
            @memcpy(key.data[1 + value.len + 8 ..][0..32], event_id);
            key.len = 1 + value.len + 8 + 32;
            return key;
        }

        pub fn slice(self: *const StringTagKey) []const u8 {
            return self.data[0..self.len];
        }
    };

    pub fn timestampBe(event: *const Event) [8]u8 {
        return @bitCast(@byteSwap(@as(u64, @bitCast(event.createdAt()))));
    }
};

test "event builder" {
    try init();
    defer cleanup();

    const keypair = Keypair.generate();
    var builder = EventBuilder{};
    _ = builder.setKind(1).setContent("test");
    try builder.sign(&keypair);

    var buf: [4096]u8 = undefined;
    const json = try builder.serialize(&buf);
    try std.testing.expect(json.len > 0);
}

test "Auth.extractDomain" {
    try std.testing.expectEqualStrings("example.com", Auth.extractDomain("wss://example.com").?);
    try std.testing.expectEqualStrings("example.com", Auth.extractDomain("wss://example.com/").?);
    try std.testing.expectEqualStrings("example.com", Auth.extractDomain("wss://example.com:8080").?);
    try std.testing.expectEqualStrings("example.com", Auth.extractDomain("ws://example.com").?);
    try std.testing.expectEqualStrings("example.com", Auth.extractDomain("https://example.com").?);
    try std.testing.expectEqualStrings("example.com", Auth.extractDomain("http://example.com/path").?);
    try std.testing.expect(Auth.extractDomain("wss://") == null);
}

test "Auth.domainsMatch" {
    try std.testing.expect(Auth.domainsMatch("wss://example.com", "wss://example.com/"));
    try std.testing.expect(Auth.domainsMatch("wss://EXAMPLE.COM", "wss://example.com"));
    try std.testing.expect(Auth.domainsMatch("wss://example.com:8080", "ws://example.com/path"));
    try std.testing.expect(!Auth.domainsMatch("wss://example.com", "wss://other.com"));
}

test "Auth.extractTags" {
    const json =
        \\{"id":"abc","pubkey":"def","sig":"ghi","kind":22242,"created_at":1234,"content":"","tags":[["relay","wss://relay.example.com"],["challenge","test-challenge-123"]]}
    ;
    const tags = Auth.extractTags(json);
    try std.testing.expectEqualStrings("wss://relay.example.com", tags.relay.?);
    try std.testing.expectEqualStrings("test-challenge-123", tags.challenge.?);
}

test "IndexKeys.created" {
    try init();
    defer cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":1,"created_at":1700000000,"content":"test","tags":[]}
    ;
    var event = try Event.parse(json);
    defer event.deinit();

    var key: [40]u8 = undefined;
    IndexKeys.created(&event, &key);

    // Verify timestamp is big-endian
    const ts_be: u64 = @bitCast(key[0..8].*);
    const ts = @byteSwap(ts_be);
    try std.testing.expectEqual(@as(u64, 1700000000), ts);

    // Verify event ID is appended
    try std.testing.expectEqual(@as(u8, 0), key[8]);
    try std.testing.expectEqual(@as(u8, 1), key[39]);
}

test "TagIndex.letterIndex maps lowercase and uppercase correctly" {
    try std.testing.expectEqual(@as(?usize, 0), TagIndex.letterIndex('a'));
    try std.testing.expectEqual(@as(?usize, 25), TagIndex.letterIndex('z'));
    try std.testing.expectEqual(@as(?usize, 4), TagIndex.letterIndex('e'));
    try std.testing.expectEqual(@as(?usize, 15), TagIndex.letterIndex('p'));

    try std.testing.expectEqual(@as(?usize, 26), TagIndex.letterIndex('A'));
    try std.testing.expectEqual(@as(?usize, 51), TagIndex.letterIndex('Z'));
    try std.testing.expectEqual(@as(?usize, 30), TagIndex.letterIndex('E'));
    try std.testing.expectEqual(@as(?usize, 41), TagIndex.letterIndex('P'));
    try std.testing.expectEqual(@as(?usize, 49), TagIndex.letterIndex('X'));

    try std.testing.expectEqual(@as(?usize, null), TagIndex.letterIndex('0'));
    try std.testing.expectEqual(@as(?usize, null), TagIndex.letterIndex('#'));
    try std.testing.expectEqual(@as(?usize, null), TagIndex.letterIndex(' '));
}

test "TagIndex.indexToLetter converts indices back to letters" {
    try std.testing.expectEqual(@as(u8, 'a'), TagIndex.indexToLetter(0));
    try std.testing.expectEqual(@as(u8, 'z'), TagIndex.indexToLetter(25));
    try std.testing.expectEqual(@as(u8, 'e'), TagIndex.indexToLetter(4));
    try std.testing.expectEqual(@as(u8, 'p'), TagIndex.indexToLetter(15));

    try std.testing.expectEqual(@as(u8, 'A'), TagIndex.indexToLetter(26));
    try std.testing.expectEqual(@as(u8, 'Z'), TagIndex.indexToLetter(51));
    try std.testing.expectEqual(@as(u8, 'E'), TagIndex.indexToLetter(30));
    try std.testing.expectEqual(@as(u8, 'P'), TagIndex.indexToLetter(41));
    try std.testing.expectEqual(@as(u8, 'X'), TagIndex.indexToLetter(49));
}

test "TagIndex stores and retrieves uppercase tags preserving case" {
    const allocator = std.testing.allocator;
    var index = TagIndex.init(allocator);
    defer index.deinit();

    try index.append('e', .{ .string = try allocator.dupe(u8, "lowercase-e") });
    try index.append('E', .{ .string = try allocator.dupe(u8, "uppercase-E") });
    try index.append('P', .{ .string = try allocator.dupe(u8, "uppercase-P") });
    try index.append('X', .{ .string = try allocator.dupe(u8, "uppercase-X") });

    const e_values = index.get('e').?;
    try std.testing.expectEqual(@as(usize, 1), e_values.len);
    try std.testing.expectEqualStrings("lowercase-e", e_values[0].string);

    const E_values = index.get('E').?;
    try std.testing.expectEqual(@as(usize, 1), E_values.len);
    try std.testing.expectEqualStrings("uppercase-E", E_values[0].string);

    const P_values = index.get('P').?;
    try std.testing.expectEqual(@as(usize, 1), P_values.len);
    try std.testing.expectEqualStrings("uppercase-P", P_values[0].string);

    const X_values = index.get('X').?;
    try std.testing.expectEqual(@as(usize, 1), X_values.len);
    try std.testing.expectEqualStrings("uppercase-X", X_values[0].string);

    try std.testing.expect(index.get('p') == null);
    try std.testing.expect(index.get('x') == null);
}

test "TagIterator yields both lowercase and uppercase entries" {
    const allocator = std.testing.allocator;
    var index = TagIndex.init(allocator);
    defer index.deinit();

    try index.append('a', .{ .string = try allocator.dupe(u8, "val-a") });
    try index.append('e', .{ .string = try allocator.dupe(u8, "val-e") });
    try index.append('A', .{ .string = try allocator.dupe(u8, "val-A") });
    try index.append('E', .{ .string = try allocator.dupe(u8, "val-E") });
    try index.append('Z', .{ .string = try allocator.dupe(u8, "val-Z") });

    var iter = index.iterator();
    var found_lowercase_a = false;
    var found_lowercase_e = false;
    var found_uppercase_A = false;
    var found_uppercase_E = false;
    var found_uppercase_Z = false;
    var count: usize = 0;

    while (iter.next()) |entry| {
        count += 1;
        if (entry.letter == 'a' and std.mem.eql(u8, entry.value.string, "val-a")) found_lowercase_a = true;
        if (entry.letter == 'e' and std.mem.eql(u8, entry.value.string, "val-e")) found_lowercase_e = true;
        if (entry.letter == 'A' and std.mem.eql(u8, entry.value.string, "val-A")) found_uppercase_A = true;
        if (entry.letter == 'E' and std.mem.eql(u8, entry.value.string, "val-E")) found_uppercase_E = true;
        if (entry.letter == 'Z' and std.mem.eql(u8, entry.value.string, "val-Z")) found_uppercase_Z = true;
    }

    try std.testing.expectEqual(@as(usize, 5), count);
    try std.testing.expect(found_lowercase_a);
    try std.testing.expect(found_lowercase_e);
    try std.testing.expect(found_uppercase_A);
    try std.testing.expect(found_uppercase_E);
    try std.testing.expect(found_uppercase_Z);
}

test "Event.parse handles uppercase single-letter tags" {
    try init();
    defer cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":1,"created_at":1700000000,"content":"test","tags":[["E","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],["P","bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"],["X","custom-value"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    const E_values = event.tags.get('E').?;
    try std.testing.expectEqual(@as(usize, 1), E_values.len);
    switch (E_values[0]) {
        .binary => |b| {
            for (b) |byte| {
                try std.testing.expectEqual(@as(u8, 0xaa), byte);
            }
        },
        .string => return error.ExpectedBinary,
    }

    const P_values = event.tags.get('P').?;
    try std.testing.expectEqual(@as(usize, 1), P_values.len);
    switch (P_values[0]) {
        .binary => |b| {
            for (b) |byte| {
                try std.testing.expectEqual(@as(u8, 0xbb), byte);
            }
        },
        .string => return error.ExpectedBinary,
    }

    const X_values = event.tags.get('X').?;
    try std.testing.expectEqual(@as(usize, 1), X_values.len);
    try std.testing.expectEqualStrings("custom-value", X_values[0].string);

    try std.testing.expect(event.tags.get('e') == null);
    try std.testing.expect(event.tags.get('p') == null);
}

test "Event.parse keeps lowercase and uppercase tags separate" {
    try init();
    defer cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":1,"created_at":1700000000,"content":"test","tags":[["e","1111111111111111111111111111111111111111111111111111111111111111"],["E","2222222222222222222222222222222222222222222222222222222222222222"],["t","hashtag"],["T","HASHTAG"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    const e_values = event.tags.get('e').?;
    try std.testing.expectEqual(@as(usize, 1), e_values.len);
    try std.testing.expectEqual(@as(u8, 0x11), e_values[0].binary[0]);

    const E_values = event.tags.get('E').?;
    try std.testing.expectEqual(@as(usize, 1), E_values.len);
    try std.testing.expectEqual(@as(u8, 0x22), E_values[0].binary[0]);

    const t_values = event.tags.get('t').?;
    try std.testing.expectEqual(@as(usize, 1), t_values.len);
    try std.testing.expectEqualStrings("hashtag", t_values[0].string);

    const T_values = event.tags.get('T').?;
    try std.testing.expectEqual(@as(usize, 1), T_values.len);
    try std.testing.expectEqualStrings("HASHTAG", T_values[0].string);
}

test "Filter matches uppercase tags correctly" {
    try init();
    defer cleanup();

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

test "Filter parsing handles uppercase tag filters" {
    try init();
    defer cleanup();

    const allocator = std.testing.allocator;

    const req_json =
        \\["REQ","sub1",{"#E":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],"#P":["bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"],"#X":["custom"]}]
    ;

    var msg = try ClientMsg.parseWithAllocator(req_json, allocator);
    defer msg.deinit();

    const filters = try msg.getFilters(allocator);
    defer {
        for (filters) |*f| f.deinit();
        allocator.free(filters);
    }

    try std.testing.expectEqual(@as(usize, 1), filters.len);
    const filter = filters[0];

    try std.testing.expect(filter.tag_filters != null);
    const tag_filters = filter.tag_filters.?;
    try std.testing.expectEqual(@as(usize, 3), tag_filters.len);

    var found_E = false;
    var found_P = false;
    var found_X = false;

    for (tag_filters) |entry| {
        if (entry.letter == 'E') {
            found_E = true;
            try std.testing.expectEqual(@as(usize, 1), entry.values.len);
            switch (entry.values[0]) {
                .binary => |b| try std.testing.expectEqual(@as(u8, 0xaa), b[0]),
                .string => return error.ExpectedBinary,
            }
        }
        if (entry.letter == 'P') {
            found_P = true;
            try std.testing.expectEqual(@as(usize, 1), entry.values.len);
            switch (entry.values[0]) {
                .binary => |b| try std.testing.expectEqual(@as(u8, 0xbb), b[0]),
                .string => return error.ExpectedBinary,
            }
        }
        if (entry.letter == 'X') {
            found_X = true;
            try std.testing.expectEqual(@as(usize, 1), entry.values.len);
            try std.testing.expectEqualStrings("custom", entry.values[0].string);
        }
    }

    try std.testing.expect(found_E);
    try std.testing.expect(found_P);
    try std.testing.expect(found_X);
}

test "Filter with mixed-case tags matches correctly" {
    try init();
    defer cleanup();

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

test "e_tags list includes uppercase E tags" {
    try init();
    defer cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":1,"created_at":1700000000,"content":"test","tags":[["e","1111111111111111111111111111111111111111111111111111111111111111"],["E","2222222222222222222222222222222222222222222222222222222222222222"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    try std.testing.expectEqual(@as(usize, 2), event.e_tags.items.len);
    try std.testing.expectEqual(@as(u8, 0x11), event.e_tags.items[0][0]);
    try std.testing.expectEqual(@as(u8, 0x22), event.e_tags.items[1][0]);
}

test "NEG-OPEN message parsing" {
    const allocator = std.testing.allocator;

    const json =
        \\["NEG-OPEN","sub1",{"kinds":[1],"authors":["0000000000000000000000000000000000000000000000000000000000000001"]},"6100"]
    ;

    var msg = try ClientMsg.parseWithAllocator(json, allocator);
    defer msg.deinit();

    try std.testing.expectEqual(ClientMsgType.neg_open, msg.msgType());
    try std.testing.expectEqualStrings("sub1", msg.subscriptionId());

    var payload_buf: [256]u8 = undefined;
    const payload = try msg.getNegPayload(&payload_buf);
    try std.testing.expectEqual(@as(usize, 2), payload.len);
    try std.testing.expectEqual(@as(u8, 0x61), payload[0]);
    try std.testing.expectEqual(@as(u8, 0x00), payload[1]);

    var filter = (try msg.getNegFilter(allocator)).?;
    defer filter.deinit();
    try std.testing.expectEqual(@as(usize, 1), filter.kinds_slice.?.len);
    try std.testing.expectEqual(@as(i32, 1), filter.kinds_slice.?[0]);
}

test "NEG-MSG message parsing" {
    const allocator = std.testing.allocator;

    const json =
        \\["NEG-MSG","sub1","61deadbeef"]
    ;

    var msg = try ClientMsg.parseWithAllocator(json, allocator);
    defer msg.deinit();

    try std.testing.expectEqual(ClientMsgType.neg_msg, msg.msgType());
    try std.testing.expectEqualStrings("sub1", msg.subscriptionId());

    var payload_buf: [256]u8 = undefined;
    const payload = try msg.getNegPayload(&payload_buf);
    try std.testing.expectEqual(@as(usize, 5), payload.len);
    try std.testing.expectEqual(@as(u8, 0x61), payload[0]);
    try std.testing.expectEqual(@as(u8, 0xde), payload[1]);
}

test "NEG-CLOSE message parsing" {
    const allocator = std.testing.allocator;

    const json =
        \\["NEG-CLOSE","sub1"]
    ;

    var msg = try ClientMsg.parseWithAllocator(json, allocator);
    defer msg.deinit();

    try std.testing.expectEqual(ClientMsgType.neg_close, msg.msgType());
    try std.testing.expectEqualStrings("sub1", msg.subscriptionId());
}

test "RelayMsg.negMsg formatting" {
    var buf: [256]u8 = undefined;
    const payload = [_]u8{ 0x61, 0xde, 0xad, 0xbe, 0xef };
    const result = try RelayMsg.negMsg("sub1", &payload, &buf);
    try std.testing.expectEqualStrings(
        \\["NEG-MSG","sub1","61deadbeef"]
    , result);
}

test "RelayMsg.negErr formatting" {
    var buf: [256]u8 = undefined;
    const result = try RelayMsg.negErr("sub1", "blocked: query too large", &buf);
    try std.testing.expectEqualStrings(
        \\["NEG-ERR","sub1","blocked: query too large"]
    , result);
}
