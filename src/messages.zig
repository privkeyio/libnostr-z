const std = @import("std");
const event_mod = @import("event.zig");
const filter_mod = @import("filter.zig");
const tags = @import("tags.zig");
const utils = @import("utils.zig");
const hex = @import("hex.zig");

pub const Event = event_mod.Event;
pub const Error = event_mod.Error;
pub const Filter = filter_mod.Filter;
pub const FilterTagEntry = filter_mod.FilterTagEntry;
pub const TagValue = tags.TagValue;

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
                msg.subscription_id_slice = utils.findStringInJson(json, arr[1].string) orelse "";
            }
        } else if (std.mem.eql(u8, type_str, "CLOSE")) {
            msg.msg_type = .close;
            if (arr.len > 1 and arr[1] == .string) {
                msg.subscription_id_slice = utils.findStringInJson(json, arr[1].string) orelse "";
            }
        } else if (std.mem.eql(u8, type_str, "AUTH")) {
            msg.msg_type = .auth;
        } else if (std.mem.eql(u8, type_str, "COUNT")) {
            msg.msg_type = .count;
            if (arr.len > 1 and arr[1] == .string) {
                msg.subscription_id_slice = utils.findStringInJson(json, arr[1].string) orelse "";
            }
        } else if (std.mem.eql(u8, type_str, "NEG-OPEN")) {
            msg.msg_type = .neg_open;
            if (arr.len > 1 and arr[1] == .string) {
                msg.subscription_id_slice = utils.findStringInJson(json, arr[1].string) orelse "";
            }
        } else if (std.mem.eql(u8, type_str, "NEG-MSG")) {
            msg.msg_type = .neg_msg;
            if (arr.len > 1 and arr[1] == .string) {
                msg.subscription_id_slice = utils.findStringInJson(json, arr[1].string) orelse "";
            }
        } else if (std.mem.eql(u8, type_str, "NEG-CLOSE")) {
            msg.msg_type = .neg_close;
            if (arr.len > 1 and arr[1] == .string) {
                msg.subscription_id_slice = utils.findStringInJson(json, arr[1].string) orelse "";
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

        if (utils.findArrayElement(self.raw_json, 1)) |event_json| {
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

        var id_hex: [64]u8 = undefined;
        hex.encode(event_id, &id_hex);
        try writer.writeAll(&id_hex);

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

        var challenge_hex: [64]u8 = undefined;
        hex.encode(challenge, &challenge_hex);
        try writer.writeAll(&challenge_hex);

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

        const hex_len = payload.len * 2;
        if (fbs.pos + hex_len + 2 > buf.len) return error.NoSpaceLeft;
        hex.encode(payload, buf[fbs.pos..][0..hex_len]);
        fbs.pos += hex_len;

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

test "Filter parsing handles uppercase tag filters" {
    const event_module = @import("event.zig");
    try event_module.init();
    defer event_module.cleanup();

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
