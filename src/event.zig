const std = @import("std");
pub const crypto = @import("crypto.zig");
const tags = @import("tags.zig");
const utils = @import("utils.zig");

pub const TagIndex = tags.TagIndex;
pub const TagValue = tags.TagValue;

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
    protected_val: bool = false,
    allocator: std.mem.Allocator,

    pub fn parse(json: []const u8) Error!Event {
        return parseWithAllocator(json, std.heap.page_allocator);
    }

    pub fn parseWithAllocator(json: []const u8, allocator: std.mem.Allocator) Error!Event {
        const parsed = std.json.parseFromSlice(std.json.Value, allocator, json, .{}) catch return error.InvalidJson;
        defer parsed.deinit();

        const root = switch (parsed.value) {
            .object => |obj| obj,
            else => return error.InvalidJson,
        };

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
                    if (tag != .array) continue;
                    if (tag.array.items.len == 1) {
                        if (tag.array.items[0] == .string and std.mem.eql(u8, tag.array.items[0].string, "-")) {
                            event.protected_val = true;
                        }
                        continue;
                    }
                    if (tag.array.items.len < 2) continue;

                    const tag_name = if (tag.array.items[0] == .string) tag.array.items[0].string else continue;
                    const tag_value_str = if (tag.array.items[1] == .string) tag.array.items[1].string else continue;

                    if (std.mem.eql(u8, tag_name, "d")) {
                        event.d_tag_val = utils.findStringInJson(json, tag_value_str);
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

        if (utils.findJsonValue(self.raw_json, "tags")) |tags_slice| {
            hasher.update(tags_slice);
        } else {
            hasher.update("[]");
        }

        hasher.update(",");
        if (utils.findJsonValue(self.raw_json, "content")) |content_slice| {
            hasher.update(content_slice);
        } else {
            hasher.update("\"\"");
        }

        hasher.update("]");

        return hasher.finalResult();
    }

    pub fn serialize(self: *const Event, buf: []u8) ![]u8 {
        if (self.raw_json.len == 0) {
            return buf[0..0];
        }
        if (self.raw_json.len <= buf.len) {
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
        return utils.extractJsonString(self.raw_json, "content") orelse "";
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

pub fn isProtected(event: *const Event) bool {
    return event.protected_val;
}

pub fn getDeletionIds(allocator: std.mem.Allocator, event: *const Event) ![][32]u8 {
    return allocator.dupe([32]u8, event.e_tags.items);
}

pub fn init() !void {
    try crypto.init();
}

pub fn cleanup() void {
    crypto.cleanup();
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

test "isProtected detects protected events with minus tag" {
    try init();
    defer cleanup();

    const protected_json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":1,"created_at":1700000000,"content":"protected content","tags":[["-"]]}
    ;

    var event = try Event.parse(protected_json);
    defer event.deinit();

    try std.testing.expect(isProtected(&event));
    try std.testing.expectEqual(@as(u32, 1), event.tag_count);
}

test "isProtected returns false for non-protected events" {
    try init();
    defer cleanup();

    const normal_json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":1,"created_at":1700000000,"content":"normal content","tags":[["t","test"]]}
    ;

    var event = try Event.parse(normal_json);
    defer event.deinit();

    try std.testing.expect(!isProtected(&event));
}

test "isProtected with mixed tags including protected tag" {
    try init();
    defer cleanup();

    const mixed_json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":1,"created_at":1700000000,"content":"mixed content","tags":[["t","hashtag"],["-"],["p","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]]}
    ;

    var event = try Event.parse(mixed_json);
    defer event.deinit();

    try std.testing.expect(isProtected(&event));
    try std.testing.expectEqual(@as(u32, 3), event.tag_count);
}

test "isProtected returns false for minus tag with extra elements" {
    try init();
    defer cleanup();

    // ["-", "x"] should not be considered protected - must be exactly ["-"]
    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":1,"created_at":1700000000,"content":"test","tags":[["-","x"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    try std.testing.expect(!isProtected(&event));
}

test "NIP-65 kind:10002 is classified as replaceable" {
    try std.testing.expectEqual(KindType.replaceable, kindType(10002));
    try std.testing.expectEqual(KindType.replaceable, kindType(0));
    try std.testing.expectEqual(KindType.replaceable, kindType(3));
    try std.testing.expectEqual(KindType.replaceable, kindType(10000));
    try std.testing.expectEqual(KindType.replaceable, kindType(19999));
    try std.testing.expectEqual(KindType.ephemeral, kindType(20000));
    try std.testing.expectEqual(KindType.addressable, kindType(30000));
    try std.testing.expectEqual(KindType.regular, kindType(1));
}
