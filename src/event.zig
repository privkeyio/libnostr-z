const std = @import("std");
pub const crypto = @import("crypto.zig");
const tags = @import("tags.zig");
const utils = @import("utils.zig");
const sz = @import("stringzilla.zig");
const hex = @import("hex.zig");

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
        const id_bytes = utils.extractHexField(json, "id", 32) orelse return error.InvalidId;
        const pubkey_bytes = utils.extractHexField(json, "pubkey", 32) orelse return error.InvalidPubkey;
        const sig_bytes = utils.extractHexField(json, "sig", 64) orelse return error.InvalidSig;
        const created_at = utils.extractIntField(json, "created_at", i64) orelse return error.InvalidCreatedAt;
        const kind_num = utils.extractIntField(json, "kind", i32) orelse return error.InvalidKind;
        if (utils.findJsonFieldStart(json, "content") == null) return error.MissingField;

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

        var iter = utils.TagIterator.init(json, "tags") orelse {
            return event;
        };
        while (iter.next()) |tag| {
            event.tag_count += 1;

            if (tag.name.len == 1 and tag.name[0] == '-' and tag.value.len == 0) {
                event.protected_val = true;
                continue;
            }

            if (std.mem.eql(u8, tag.name, "d")) {
                event.d_tag_val = utils.findStringInJson(json, tag.value);
            } else if (std.mem.eql(u8, tag.name, "expiration")) {
                event.expiration_val = std.fmt.parseInt(i64, tag.value, 10) catch null;
            }

            if (tag.name.len == 1) {
                const letter = tag.name[0];

                if (letter == 'e' or letter == 'p' or letter == 'E' or letter == 'P') {
                    if (tag.value.len == 64) {
                        var bytes: [32]u8 = undefined;
                        if (std.fmt.hexToBytes(&bytes, tag.value)) |_| {
                            event.tags.append(letter, .{ .binary = bytes }) catch {};
                            if (letter == 'e' or letter == 'E') {
                                event.e_tags.append(allocator, bytes) catch {};
                            }
                        } else |_| {}
                    }
                } else {
                    if (tag.value.len > 0 and tag.value.len <= 256) {
                        const duped = allocator.dupe(u8, tag.value) catch continue;
                        event.tags.append(letter, .{ .string = duped }) catch {
                            allocator.free(duped);
                        };
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
        var hasher = sz.Sha256.init();
        hasher.update("[0,\"");

        var pubkey_hex: [64]u8 = undefined;
        hex.encode(&self.pubkey_bytes, &pubkey_hex);
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
        hex.encode(&self.id_bytes, buf[0..64]);
        buf[64] = 0;
    }

    pub fn pubkeyHex(self: *const Event, buf: *[65]u8) void {
        hex.encode(&self.pubkey_bytes, buf[0..64]);
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

pub const Kind = struct {
    pub const metadata: i32 = 0;
    pub const short_text_note: i32 = 1;
    pub const recommend_relay: i32 = 2;
    pub const contacts: i32 = 3;
    pub const encrypted_direct_message: i32 = 4;
    pub const event_deletion: i32 = 5;
    pub const repost: i32 = 6;
    pub const reaction: i32 = 7;
    pub const badge_award: i32 = 8;
    pub const group_chat_message: i32 = 9;
    pub const group_chat_threaded_reply: i32 = 10;
    pub const group_thread: i32 = 11;
    pub const group_thread_reply: i32 = 12;
    pub const seal: i32 = 13;
    pub const direct_message: i32 = 14;
    pub const generic_repost: i32 = 16;
    pub const reaction_to_website: i32 = 17;
    pub const channel_creation: i32 = 40;
    pub const channel_metadata: i32 = 41;
    pub const channel_message: i32 = 42;
    pub const channel_hide_message: i32 = 43;
    pub const channel_mute_user: i32 = 44;
    pub const chess: i32 = 64;
    pub const merge_request: i32 = 818;
    pub const bid: i32 = 1021;
    pub const bid_confirmation: i32 = 1022;
    pub const open_timestamps: i32 = 1040;
    pub const file_metadata: i32 = 1063;
    pub const comment: i32 = 1111;
    pub const live_chat_message: i32 = 1311;
    pub const patches: i32 = 1617;
    pub const issues: i32 = 1621;
    pub const replies: i32 = 1622;
    pub const problem_tracker: i32 = 1971;
    pub const report: i32 = 1984;
    pub const label: i32 = 1985;
    pub const torrent: i32 = 2003;
    pub const torrent_comment: i32 = 2004;
    pub const coinjoin_pool: i32 = 2022;
    pub const community_post_approval: i32 = 4550;
    pub const job_request_start: i32 = 5000;
    pub const job_request_end: i32 = 5999;
    pub const job_result_start: i32 = 6000;
    pub const job_result_end: i32 = 6999;
    pub const job_feedback: i32 = 7000;
    pub const group_add_user: i32 = 9000;
    pub const group_remove_user: i32 = 9001;
    pub const group_edit_metadata: i32 = 9002;
    pub const group_add_permission: i32 = 9003;
    pub const group_remove_permission: i32 = 9004;
    pub const group_delete_event: i32 = 9005;
    pub const group_edit_status: i32 = 9006;
    pub const group_create_group: i32 = 9007;
    pub const group_delete_group: i32 = 9008;
    pub const group_create_invite: i32 = 9009;
    pub const zap_goal: i32 = 9041;
    pub const zap_request: i32 = 9734;
    pub const zap_receipt: i32 = 9735;
    pub const mute_list: i32 = 10000;
    pub const pin_list: i32 = 10001;
    pub const relay_list_metadata: i32 = 10002;
    pub const bookmark_list: i32 = 10003;
    pub const communities_list: i32 = 10004;
    pub const public_chats_list: i32 = 10005;
    pub const blocked_relays_list: i32 = 10006;
    pub const search_relays_list: i32 = 10007;
    pub const user_groups: i32 = 10009;
    pub const interests_list: i32 = 10015;
    pub const user_emoji_list: i32 = 10030;
    pub const dm_relay_list: i32 = 10050;
    pub const file_storage_servers: i32 = 10096;
    pub const nwc_info: i32 = 13194;
    pub const ephemeral_start: i32 = 20000;
    pub const ephemeral_end: i32 = 29999;
    pub const client_authentication: i32 = 22242;
    pub const wallet_request: i32 = 23194;
    pub const wallet_response: i32 = 23195;
    pub const nostr_connect: i32 = 24133;
    pub const http_auth: i32 = 27235;
    pub const follow_sets: i32 = 30000;
    pub const generic_lists: i32 = 30001;
    pub const relay_sets: i32 = 30002;
    pub const bookmark_sets: i32 = 30003;
    pub const curation_sets: i32 = 30004;
    pub const profile_badges: i32 = 30008;
    pub const badge_definition: i32 = 30009;
    pub const interest_sets: i32 = 30015;
    pub const create_update_stall: i32 = 30017;
    pub const create_update_product: i32 = 30018;
    pub const marketplace_ui_ux: i32 = 30019;
    pub const long_form_content: i32 = 30023;
    pub const draft_long_form_content: i32 = 30024;
    pub const emoji_sets: i32 = 30030;
    pub const application_specific_data: i32 = 30078;
    pub const live_event: i32 = 30311;
    pub const user_status: i32 = 30315;
    pub const classified_listing: i32 = 30402;
    pub const draft_classified_listing: i32 = 30403;
    pub const repository_announcement: i32 = 30617;
    pub const repository_state: i32 = 30618;
    pub const wiki_article: i32 = 30818;
    pub const redirects: i32 = 30819;
    pub const date_calendar_event: i32 = 31922;
    pub const time_calendar_event: i32 = 31923;
    pub const calendar: i32 = 31924;
    pub const calendar_event_rsvp: i32 = 31925;
    pub const handler_recommendation: i32 = 31989;
    pub const handler_information: i32 = 31990;
    pub const community_definition: i32 = 34550;

    pub const Type = enum {
        regular,
        replaceable,
        ephemeral,
        addressable,
    };

    pub fn classify(kind_num: i32) Type {
        if (kind_num == metadata or kind_num == contacts) return .replaceable;
        if (kind_num >= 10000 and kind_num < 20000) return .replaceable;
        if (kind_num >= 20000 and kind_num < 30000) return .ephemeral;
        if (kind_num >= 30000 and kind_num < 40000) return .addressable;
        return .regular;
    }

    pub fn isRegular(kind_num: i32) bool {
        return classify(kind_num) == .regular;
    }

    pub fn isReplaceable(kind_num: i32) bool {
        return classify(kind_num) == .replaceable;
    }

    pub fn isEphemeral(kind_num: i32) bool {
        return classify(kind_num) == .ephemeral;
    }

    pub fn isAddressable(kind_num: i32) bool {
        return classify(kind_num) == .addressable;
    }

    pub fn isJobRequest(kind_num: i32) bool {
        return kind_num >= job_request_start and kind_num <= job_request_end;
    }

    pub fn isJobResult(kind_num: i32) bool {
        return kind_num >= job_result_start and kind_num <= job_result_end;
    }
};

pub const KindType = Kind.Type;

pub fn kindType(kind_num: i32) Kind.Type {
    return Kind.classify(kind_num);
}

pub fn isExpired(event: *const Event) bool {
    if (event.expiration_val) |exp| {
        return std.time.timestamp() > exp;
    }
    return false;
}

pub fn isDeletion(event: *const Event) bool {
    return event.kind() == Kind.event_deletion;
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

test "Kind constants have correct values" {
    try std.testing.expectEqual(@as(i32, 0), Kind.metadata);
    try std.testing.expectEqual(@as(i32, 1), Kind.short_text_note);
    try std.testing.expectEqual(@as(i32, 3), Kind.contacts);
    try std.testing.expectEqual(@as(i32, 5), Kind.event_deletion);
    try std.testing.expectEqual(@as(i32, 6), Kind.repost);
    try std.testing.expectEqual(@as(i32, 7), Kind.reaction);
    try std.testing.expectEqual(@as(i32, 9734), Kind.zap_request);
    try std.testing.expectEqual(@as(i32, 9735), Kind.zap_receipt);
    try std.testing.expectEqual(@as(i32, 10002), Kind.relay_list_metadata);
    try std.testing.expectEqual(@as(i32, 30023), Kind.long_form_content);
}

test "Kind.classify matches kindType for backwards compatibility" {
    try std.testing.expectEqual(kindType(Kind.metadata), Kind.classify(Kind.metadata));
    try std.testing.expectEqual(kindType(Kind.short_text_note), Kind.classify(Kind.short_text_note));
    try std.testing.expectEqual(kindType(Kind.relay_list_metadata), Kind.classify(Kind.relay_list_metadata));
    try std.testing.expectEqual(kindType(Kind.wallet_request), Kind.classify(Kind.wallet_request));
    try std.testing.expectEqual(kindType(Kind.long_form_content), Kind.classify(Kind.long_form_content));
}

test "Kind.isReplaceable identifies replaceable kinds" {
    try std.testing.expect(Kind.isReplaceable(Kind.metadata));
    try std.testing.expect(Kind.isReplaceable(Kind.contacts));
    try std.testing.expect(Kind.isReplaceable(Kind.relay_list_metadata));
    try std.testing.expect(Kind.isReplaceable(Kind.mute_list));
    try std.testing.expect(!Kind.isReplaceable(Kind.short_text_note));
    try std.testing.expect(!Kind.isReplaceable(Kind.event_deletion));
}

test "Kind.isEphemeral identifies ephemeral kinds" {
    try std.testing.expect(Kind.isEphemeral(Kind.wallet_request));
    try std.testing.expect(Kind.isEphemeral(Kind.client_authentication));
    try std.testing.expect(Kind.isEphemeral(Kind.nostr_connect));
    try std.testing.expect(Kind.isEphemeral(20001));
    try std.testing.expect(!Kind.isEphemeral(Kind.short_text_note));
    try std.testing.expect(!Kind.isEphemeral(Kind.long_form_content));
}

test "Kind.isAddressable identifies addressable kinds" {
    try std.testing.expect(Kind.isAddressable(Kind.long_form_content));
    try std.testing.expect(Kind.isAddressable(Kind.follow_sets));
    try std.testing.expect(Kind.isAddressable(Kind.badge_definition));
    try std.testing.expect(Kind.isAddressable(Kind.live_event));
    try std.testing.expect(!Kind.isAddressable(Kind.short_text_note));
    try std.testing.expect(!Kind.isAddressable(Kind.relay_list_metadata));
}

test "Kind.isRegular identifies regular kinds" {
    try std.testing.expect(Kind.isRegular(Kind.short_text_note));
    try std.testing.expect(Kind.isRegular(Kind.event_deletion));
    try std.testing.expect(Kind.isRegular(Kind.repost));
    try std.testing.expect(Kind.isRegular(Kind.reaction));
    try std.testing.expect(!Kind.isRegular(Kind.metadata));
    try std.testing.expect(!Kind.isRegular(Kind.long_form_content));
}

test "Kind.isJobRequest and isJobResult" {
    try std.testing.expect(Kind.isJobRequest(5000));
    try std.testing.expect(Kind.isJobRequest(5500));
    try std.testing.expect(Kind.isJobRequest(5999));
    try std.testing.expect(!Kind.isJobRequest(4999));
    try std.testing.expect(!Kind.isJobRequest(6000));

    try std.testing.expect(Kind.isJobResult(6000));
    try std.testing.expect(Kind.isJobResult(6500));
    try std.testing.expect(Kind.isJobResult(6999));
    try std.testing.expect(!Kind.isJobResult(5999));
    try std.testing.expect(!Kind.isJobResult(7000));
}
