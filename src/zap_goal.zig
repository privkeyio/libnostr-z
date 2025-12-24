const std = @import("std");
const event_mod = @import("event.zig");
const utils = @import("utils.zig");

pub const Event = event_mod.Event;

pub const ZAP_GOAL_KIND: i32 = 9041;

pub const ZapBeneficiary = struct {
    pubkey: []const u8,
    relay: ?[]const u8,
    weight: ?[]const u8,
};

pub const ZapGoal = struct {
    amount: u64,
    relays: std.ArrayListUnmanaged([]const u8),
    closed_at: ?i64,
    image: ?[]const u8,
    summary: ?[]const u8,
    linked_url: ?[]const u8,
    linked_address: ?[]const u8,
    beneficiaries: std.ArrayListUnmanaged(ZapBeneficiary),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) ZapGoal {
        return .{
            .amount = 0,
            .relays = .{},
            .closed_at = null,
            .image = null,
            .summary = null,
            .linked_url = null,
            .linked_address = null,
            .beneficiaries = .{},
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *ZapGoal) void {
        for (self.relays.items) |relay| {
            self.allocator.free(relay);
        }
        self.relays.deinit(self.allocator);

        for (self.beneficiaries.items) |b| {
            self.allocator.free(b.pubkey);
            if (b.relay) |r| self.allocator.free(r);
            if (b.weight) |w| self.allocator.free(w);
        }
        self.beneficiaries.deinit(self.allocator);

        if (self.image) |img| self.allocator.free(img);
        if (self.summary) |s| self.allocator.free(s);
        if (self.linked_url) |u| self.allocator.free(u);
        if (self.linked_address) |a| self.allocator.free(a);
    }

    pub fn fromEvent(event: *const Event, allocator: std.mem.Allocator) !ZapGoal {
        if (event.kind() != ZAP_GOAL_KIND) {
            return error.InvalidKind;
        }

        var goal = ZapGoal.init(allocator);
        errdefer goal.deinit();

        const tags_json = utils.findJsonValue(event.raw_json, "tags") orelse return error.MissingTags;
        var iter = TagIterator.init(tags_json);

        var has_amount = false;
        var has_relays = false;

        while (iter.next()) |tag| {
            if (std.mem.eql(u8, tag.name, "amount")) {
                goal.amount = std.fmt.parseInt(u64, tag.value, 10) catch continue;
                has_amount = true;
            } else if (std.mem.eql(u8, tag.name, "relays")) {
                const relay_copy = try allocator.dupe(u8, tag.value);
                errdefer allocator.free(relay_copy);
                try goal.relays.append(allocator, relay_copy);
                has_relays = true;

                while (iter.nextInTag()) |extra_relay| {
                    const extra_copy = try allocator.dupe(u8, extra_relay);
                    errdefer allocator.free(extra_copy);
                    try goal.relays.append(allocator, extra_copy);
                }
            } else if (std.mem.eql(u8, tag.name, "closed_at")) {
                if (goal.closed_at == null) {
                    goal.closed_at = std.fmt.parseInt(i64, tag.value, 10) catch null;
                }
            } else if (std.mem.eql(u8, tag.name, "image")) {
                if (goal.image == null) {
                    goal.image = try allocator.dupe(u8, tag.value);
                }
            } else if (std.mem.eql(u8, tag.name, "summary")) {
                if (goal.summary == null) {
                    goal.summary = try allocator.dupe(u8, tag.value);
                }
            } else if (std.mem.eql(u8, tag.name, "r")) {
                if (goal.linked_url == null) {
                    goal.linked_url = try allocator.dupe(u8, tag.value);
                }
            } else if (std.mem.eql(u8, tag.name, "a")) {
                if (goal.linked_address == null) {
                    goal.linked_address = try allocator.dupe(u8, tag.value);
                }
            } else if (std.mem.eql(u8, tag.name, "zap")) {
                const pubkey_copy = try allocator.dupe(u8, tag.value);
                errdefer allocator.free(pubkey_copy);

                var relay_copy: ?[]const u8 = null;
                var weight_copy: ?[]const u8 = null;
                errdefer if (relay_copy) |r| allocator.free(r);
                errdefer if (weight_copy) |w| allocator.free(w);

                if (iter.nextInTag()) |relay| {
                    relay_copy = try allocator.dupe(u8, relay);

                    if (iter.nextInTag()) |weight| {
                        weight_copy = try allocator.dupe(u8, weight);
                    }
                }

                try goal.beneficiaries.append(allocator, .{
                    .pubkey = pubkey_copy,
                    .relay = relay_copy,
                    .weight = weight_copy,
                });
            }
        }

        if (!has_amount) return error.MissingAmount;
        if (!has_relays) return error.MissingRelays;

        return goal;
    }

    pub fn isClosed(self: *const ZapGoal) bool {
        if (self.closed_at) |closed| {
            return std.time.timestamp() > closed;
        }
        return false;
    }

    pub fn relayCount(self: *const ZapGoal) usize {
        return self.relays.items.len;
    }

    pub fn beneficiaryCount(self: *const ZapGoal) usize {
        return self.beneficiaries.items.len;
    }
};

pub const GoalTag = struct {
    event_id: []const u8,
    relay_hint: ?[]const u8,
};

pub fn parseGoalTag(json: []const u8) ?GoalTag {
    const tags_json = utils.findJsonValue(json, "tags") orelse return null;
    var iter = TagIterator.init(tags_json);

    while (iter.next()) |tag| {
        if (std.mem.eql(u8, tag.name, "goal")) {
            var relay_hint: ?[]const u8 = null;
            if (iter.nextInTag()) |relay| {
                relay_hint = relay;
            }
            return .{
                .event_id = tag.value,
                .relay_hint = relay_hint,
            };
        }
    }
    return null;
}

const TagEntry = struct {
    name: []const u8,
    value: []const u8,
};

const TagIterator = struct {
    json: []const u8,
    pos: usize,
    tag_start: usize,
    tag_end: usize,

    fn init(json: []const u8) TagIterator {
        var pos: usize = 0;
        while (pos < json.len and (json[pos] == ' ' or json[pos] == '\n' or json[pos] == '\r' or json[pos] == '\t')) : (pos += 1) {}
        if (pos < json.len and json[pos] == '[') {
            pos += 1;
        }
        return .{ .json = json, .pos = pos, .tag_start = 0, .tag_end = 0 };
    }

    fn next(self: *TagIterator) ?TagEntry {
        while (self.pos < self.json.len) {
            const bracket_start = self.findBracket('[') orelse return null;
            self.pos = bracket_start + 1;
            self.tag_start = self.pos;
            const bracket_end = self.findMatchingBracket() orelse return null;
            self.tag_end = bracket_end;
            self.pos = self.tag_start;

            const name = self.parseNextString() orelse {
                self.pos = self.tag_end + 1;
                continue;
            };

            const value = self.parseNextString() orelse "";

            return .{ .name = name, .value = value };
        }
        return null;
    }

    fn nextInTag(self: *TagIterator) ?[]const u8 {
        if (self.pos >= self.tag_end) return null;
        return self.parseNextString();
    }

    fn parseNextString(self: *TagIterator) ?[]const u8 {
        while (self.pos < self.tag_end and self.json[self.pos] != '"') : (self.pos += 1) {}
        if (self.pos >= self.tag_end) return null;
        self.pos += 1;

        const str_start = self.pos;
        const str_end = findStringEnd(self.json, str_start) orelse return null;
        self.pos = str_end + 1;

        return self.json[str_start..str_end];
    }

    fn findBracket(self: *TagIterator, bracket: u8) ?usize {
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
                return self.pos;
            }

            self.pos += 1;
        }
        return null;
    }

    fn findMatchingBracket(self: *TagIterator) ?usize {
        var depth: i32 = 1;
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

            if (!in_string) {
                if (c == '[') depth += 1;
                if (c == ']') {
                    depth -= 1;
                    if (depth == 0) return self.pos;
                }
            }

            self.pos += 1;
        }
        return null;
    }
};

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

test "ZapGoal.fromEvent parses kind:9041" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":9041,"created_at":1700000000,"content":"Nostrasia travel expenses","tags":[["relays","wss://alicerelay.example.com","wss://bobrelay.example.com"],["amount","210000"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    var goal = try ZapGoal.fromEvent(&event, std.testing.allocator);
    defer goal.deinit();

    try std.testing.expectEqual(@as(u64, 210000), goal.amount);
    try std.testing.expectEqual(@as(usize, 2), goal.relayCount());
    try std.testing.expectEqualStrings("wss://alicerelay.example.com", goal.relays.items[0]);
    try std.testing.expectEqualStrings("wss://bobrelay.example.com", goal.relays.items[1]);
    try std.testing.expect(goal.closed_at == null);
    try std.testing.expect(goal.image == null);
    try std.testing.expect(goal.summary == null);
}

test "ZapGoal.fromEvent parses optional tags" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":9041,"created_at":1700000000,"content":"Conference funding","tags":[["relays","wss://relay.example.com"],["amount","500000"],["closed_at","1700100000"],["image","https://example.com/goal.png"],["summary","Help fund the conference"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    var goal = try ZapGoal.fromEvent(&event, std.testing.allocator);
    defer goal.deinit();

    try std.testing.expectEqual(@as(u64, 500000), goal.amount);
    try std.testing.expectEqual(@as(i64, 1700100000), goal.closed_at.?);
    try std.testing.expectEqualStrings("https://example.com/goal.png", goal.image.?);
    try std.testing.expectEqualStrings("Help fund the conference", goal.summary.?);
}

test "ZapGoal.fromEvent parses linked url" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":9041,"created_at":1700000000,"content":"Donate","tags":[["relays","wss://relay.example.com"],["amount","100000"],["r","https://example.com/campaign"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    var goal = try ZapGoal.fromEvent(&event, std.testing.allocator);
    defer goal.deinit();

    try std.testing.expectEqualStrings("https://example.com/campaign", goal.linked_url.?);
    try std.testing.expect(goal.linked_address == null);
}

test "ZapGoal.fromEvent parses linked addressable event" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":9041,"created_at":1700000000,"content":"Support article","tags":[["relays","wss://relay.example.com"],["amount","50000"],["a","30023:pubkey:article-id"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    var goal = try ZapGoal.fromEvent(&event, std.testing.allocator);
    defer goal.deinit();

    try std.testing.expectEqualStrings("30023:pubkey:article-id", goal.linked_address.?);
    try std.testing.expect(goal.linked_url == null);
}

test "ZapGoal.fromEvent parses zap beneficiaries" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":9041,"created_at":1700000000,"content":"Multi-beneficiary goal","tags":[["relays","wss://relay.example.com"],["amount","1000000"],["zap","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","wss://relay1.example.com","1"],["zap","bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","wss://relay2.example.com","2"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    var goal = try ZapGoal.fromEvent(&event, std.testing.allocator);
    defer goal.deinit();

    try std.testing.expectEqual(@as(usize, 2), goal.beneficiaryCount());
    try std.testing.expectEqualStrings("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", goal.beneficiaries.items[0].pubkey);
    try std.testing.expectEqualStrings("wss://relay1.example.com", goal.beneficiaries.items[0].relay.?);
    try std.testing.expectEqualStrings("1", goal.beneficiaries.items[0].weight.?);
    try std.testing.expectEqualStrings("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", goal.beneficiaries.items[1].pubkey);
}

test "ZapGoal.fromEvent rejects wrong kind" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":1,"created_at":1700000000,"content":"test","tags":[["relays","wss://relay.example.com"],["amount","100000"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    const result = ZapGoal.fromEvent(&event, std.testing.allocator);
    try std.testing.expectError(error.InvalidKind, result);
}

test "ZapGoal.fromEvent rejects missing amount" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":9041,"created_at":1700000000,"content":"test","tags":[["relays","wss://relay.example.com"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    const result = ZapGoal.fromEvent(&event, std.testing.allocator);
    try std.testing.expectError(error.MissingAmount, result);
}

test "ZapGoal.fromEvent rejects missing relays" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":9041,"created_at":1700000000,"content":"test","tags":[["amount","100000"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    const result = ZapGoal.fromEvent(&event, std.testing.allocator);
    try std.testing.expectError(error.MissingRelays, result);
}

test "ZapGoal.isClosed returns false when no closed_at" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":9041,"created_at":1700000000,"content":"test","tags":[["relays","wss://relay.example.com"],["amount","100000"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    var goal = try ZapGoal.fromEvent(&event, std.testing.allocator);
    defer goal.deinit();

    try std.testing.expect(!goal.isClosed());
}

test "ZapGoal.isClosed returns true for past timestamp" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":9041,"created_at":1700000000,"content":"test","tags":[["relays","wss://relay.example.com"],["amount","100000"],["closed_at","1000000000"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    var goal = try ZapGoal.fromEvent(&event, std.testing.allocator);
    defer goal.deinit();

    try std.testing.expect(goal.isClosed());
}

test "parseGoalTag extracts goal tag from event" {
    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":30023,"created_at":1700000000,"content":"article content","tags":[["d","my-article"],["goal","cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","wss://relay.example.com"]]}
    ;

    const goal_tag = parseGoalTag(json).?;
    try std.testing.expectEqualStrings("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", goal_tag.event_id);
    try std.testing.expectEqualStrings("wss://relay.example.com", goal_tag.relay_hint.?);
}

test "parseGoalTag handles missing relay hint" {
    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":30023,"created_at":1700000000,"content":"article content","tags":[["d","my-article"],["goal","dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"]]}
    ;

    const goal_tag = parseGoalTag(json).?;
    try std.testing.expectEqualStrings("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", goal_tag.event_id);
    try std.testing.expect(goal_tag.relay_hint == null);
}

test "parseGoalTag returns null when no goal tag" {
    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":30023,"created_at":1700000000,"content":"article content","tags":[["d","my-article"],["t","nostr"]]}
    ;

    try std.testing.expect(parseGoalTag(json) == null);
}

test "ZapGoal.fromEvent handles duplicate optional tags" {
    try event_mod.init();
    defer event_mod.cleanup();

    // Event with duplicate image and summary tags - should take first value
    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":9041,"created_at":1700000000,"content":"test","tags":[["relays","wss://relay.example.com"],["amount","100000"],["image","https://first.example.com/img.png"],["image","https://second.example.com/img.png"],["summary","First summary"],["summary","Second summary"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    var goal = try ZapGoal.fromEvent(&event, std.testing.allocator);
    defer goal.deinit();

    // Should take first value, not leak the second
    try std.testing.expectEqualStrings("https://first.example.com/img.png", goal.image.?);
    try std.testing.expectEqualStrings("First summary", goal.summary.?);
}
