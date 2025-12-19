const std = @import("std");
const utils = @import("utils.zig");

pub const Kind = struct {
    pub const oracle_announcement: i32 = 88;
    pub const oracle_attestation: i32 = 89;
    pub const trusted_oracles: i32 = 10088;
};

pub const OracleAnnouncement = struct {
    announcement_data: []const u8,
    relays: []const []const u8,
    title: ?[]const u8 = null,
    description: ?[]const u8 = null,
    asset_pair: ?AssetPair = null,

    pub fn parse(allocator: std.mem.Allocator, content: []const u8, tags_json: []const u8) !OracleAnnouncement {
        var relays: std.ArrayListUnmanaged([]const u8) = .{};
        errdefer {
            for (relays.items) |relay| allocator.free(relay);
            relays.deinit(allocator);
        }
        var asset_pair: ?AssetPair = null;
        var title: ?[]const u8 = null;
        var description: ?[]const u8 = null;
        var n_tags: std.ArrayListUnmanaged([]const u8) = .{};
        defer {
            for (n_tags.items) |n| allocator.free(n);
            n_tags.deinit(allocator);
        }

        var iter = utils.TagIterator.init(tags_json, "tags") orelse {
            return .{
                .announcement_data = content,
                .relays = try relays.toOwnedSlice(allocator),
                .title = null,
                .description = null,
                .asset_pair = null,
            };
        };

        while (iter.next()) |tag| {
            if (std.mem.eql(u8, tag.name, "relays")) {
                // Extract all relay values from this tag (NIP-88: ["relays", "url1", "url2", ...])
                const all_relays = try extractAllTagValues(allocator, tags_json, iter.pos);
                defer allocator.free(all_relays);
                for (all_relays) |relay| {
                    try relays.append(allocator, relay);
                }
            } else if (std.mem.eql(u8, tag.name, "title")) {
                title = tag.value;
            } else if (std.mem.eql(u8, tag.name, "description")) {
                description = tag.value;
            } else if (std.mem.eql(u8, tag.name, "n")) {
                const n_slice = try allocator.dupe(u8, tag.value);
                try n_tags.append(allocator, n_slice);
            }
        }

        if (n_tags.items.len >= 2) {
            asset_pair = .{
                .base = n_tags.items[0],
                .quote = n_tags.items[1],
            };
            // Free any extra n_tags beyond the first two
            for (n_tags.items[2..]) |extra| {
                allocator.free(extra);
            }
            // Clear items so defer doesn't double-free transferred ownership
            n_tags.clearRetainingCapacity();
        }

        return .{
            .announcement_data = content,
            .relays = try relays.toOwnedSlice(allocator),
            .title = title,
            .description = description,
            .asset_pair = asset_pair,
        };
    }

    pub fn deinit(self: *OracleAnnouncement, allocator: std.mem.Allocator) void {
        for (self.relays) |relay| {
            allocator.free(relay);
        }
        allocator.free(self.relays);
        if (self.asset_pair) |pair| {
            allocator.free(pair.base);
            allocator.free(pair.quote);
        }
    }

    pub fn serialize(self: *const OracleAnnouncement, buf: []u8) ![]u8 {
        var fbs = std.io.fixedBufferStream(buf);
        const writer = fbs.writer();

        try writer.writeAll("{\"kind\":88,\"content\":\"");
        try utils.writeJsonEscaped(writer, self.announcement_data);
        try writer.writeAll("\",\"tags\":[");

        if (self.relays.len > 0) {
            try writer.writeAll("[\"relays\"");
            for (self.relays) |relay| {
                try writer.writeAll(",\"");
                try utils.writeJsonEscaped(writer, relay);
                try writer.writeByte('"');
            }
            try writer.writeByte(']');
        }

        if (self.title) |t| {
            if (self.relays.len > 0) try writer.writeByte(',');
            try writer.writeAll("[\"title\",\"");
            try utils.writeJsonEscaped(writer, t);
            try writer.writeAll("\"]");
        }

        if (self.description) |d| {
            if (self.relays.len > 0 or self.title != null) try writer.writeByte(',');
            try writer.writeAll("[\"description\",\"");
            try utils.writeJsonEscaped(writer, d);
            try writer.writeAll("\"]");
        }

        if (self.asset_pair) |pair| {
            if (self.relays.len > 0 or self.title != null or self.description != null) try writer.writeByte(',');
            try writer.writeAll("[\"n\",\"");
            try utils.writeJsonEscaped(writer, pair.base);
            try writer.writeAll("\"],[\"n\",\"");
            try utils.writeJsonEscaped(writer, pair.quote);
            try writer.writeAll("\"]");
        }

        try writer.writeAll("]}");
        return fbs.getWritten();
    }
};

pub const OracleAttestation = struct {
    attestation_data: []const u8,
    announcement_event_id: []const u8,
    asset_pair: ?AssetPair = null,

    pub fn parse(allocator: std.mem.Allocator, content: []const u8, tags_json: []const u8) !OracleAttestation {
        var announcement_id: ?[]const u8 = null;
        var asset_pair: ?AssetPair = null;
        var n_tags: std.ArrayListUnmanaged([]const u8) = .{};
        defer {
            for (n_tags.items) |n| allocator.free(n);
            n_tags.deinit(allocator);
        }

        var iter = utils.TagIterator.init(tags_json, "tags") orelse {
            return error.MissingAnnouncementReference;
        };

        while (iter.next()) |tag| {
            if (std.mem.eql(u8, tag.name, "e")) {
                announcement_id = tag.value;
            } else if (std.mem.eql(u8, tag.name, "n")) {
                const n_slice = try allocator.dupe(u8, tag.value);
                try n_tags.append(allocator, n_slice);
            }
        }

        if (announcement_id == null) {
            return error.MissingAnnouncementReference;
        }

        if (n_tags.items.len >= 2) {
            asset_pair = .{
                .base = n_tags.items[0],
                .quote = n_tags.items[1],
            };
            // Free any extra n_tags beyond the first two
            for (n_tags.items[2..]) |extra| {
                allocator.free(extra);
            }
            // Clear items so defer doesn't double-free transferred ownership
            n_tags.clearRetainingCapacity();
        }

        return .{
            .attestation_data = content,
            .announcement_event_id = announcement_id.?,
            .asset_pair = asset_pair,
        };
    }

    pub fn deinit(self: *OracleAttestation, allocator: std.mem.Allocator) void {
        if (self.asset_pair) |pair| {
            allocator.free(pair.base);
            allocator.free(pair.quote);
        }
    }

    pub fn serialize(self: *const OracleAttestation, buf: []u8) ![]u8 {
        var fbs = std.io.fixedBufferStream(buf);
        const writer = fbs.writer();

        try writer.writeAll("{\"kind\":89,\"content\":\"");
        try utils.writeJsonEscaped(writer, self.attestation_data);
        try writer.writeAll("\",\"tags\":[[\"e\",\"");
        try utils.writeJsonEscaped(writer, self.announcement_event_id);
        try writer.writeAll("\"]");

        if (self.asset_pair) |pair| {
            try writer.writeAll(",[\"n\",\"");
            try utils.writeJsonEscaped(writer, pair.base);
            try writer.writeAll("\"],[\"n\",\"");
            try utils.writeJsonEscaped(writer, pair.quote);
            try writer.writeAll("\"]");
        }

        try writer.writeAll("]}");
        return fbs.getWritten();
    }
};

pub const AssetPair = struct {
    base: []const u8,
    quote: []const u8,
};

pub const TrustedOracle = struct {
    pubkey: []const u8,
    relay: ?[]const u8 = null,
};

pub const TrustedOraclesList = struct {
    oracles: []TrustedOracle,

    pub fn parse(allocator: std.mem.Allocator, tags_json: []const u8) !TrustedOraclesList {
        var oracles: std.ArrayListUnmanaged(TrustedOracle) = .{};
        errdefer {
            for (oracles.items) |oracle| {
                allocator.free(oracle.pubkey);
                if (oracle.relay) |r| allocator.free(r);
            }
            oracles.deinit(allocator);
        }

        var iter = utils.TagIterator.init(tags_json, "tags") orelse {
            return .{ .oracles = try oracles.toOwnedSlice(allocator) };
        };

        while (iter.next()) |tag| {
            if (std.mem.eql(u8, tag.name, "s")) {
                const pubkey = try allocator.dupe(u8, tag.value);
                var oracle = TrustedOracle{
                    .pubkey = pubkey,
                    .relay = null,
                };
                if (extractSecondTagValue(tags_json, iter.pos)) |relay_val| {
                    oracle.relay = try allocator.dupe(u8, relay_val);
                }
                try oracles.append(allocator, oracle);
            }
        }

        return .{ .oracles = try oracles.toOwnedSlice(allocator) };
    }

    pub fn deinit(self: *TrustedOraclesList, allocator: std.mem.Allocator) void {
        for (self.oracles) |oracle| {
            allocator.free(oracle.pubkey);
            if (oracle.relay) |r| allocator.free(r);
        }
        allocator.free(self.oracles);
    }

    pub fn serialize(self: *const TrustedOraclesList, buf: []u8) ![]u8 {
        var fbs = std.io.fixedBufferStream(buf);
        const writer = fbs.writer();

        try writer.writeAll("{\"kind\":10088,\"tags\":[");

        for (self.oracles, 0..) |oracle, i| {
            if (i > 0) try writer.writeByte(',');
            try writer.writeAll("[\"s\",\"");
            try utils.writeJsonEscaped(writer, oracle.pubkey);
            try writer.writeByte('"');
            if (oracle.relay) |r| {
                try writer.writeAll(",\"");
                try utils.writeJsonEscaped(writer, r);
                try writer.writeByte('"');
            }
            try writer.writeByte(']');
        }

        try writer.writeAll("]}");
        return fbs.getWritten();
    }
};

fn extractAllTagValues(allocator: std.mem.Allocator, json: []const u8, start_pos: usize) ![][]const u8 {
    var values: std.ArrayListUnmanaged([]const u8) = .{};
    errdefer {
        for (values.items) |v| allocator.free(v);
        values.deinit(allocator);
    }

    var pos = start_pos;

    // Find the start of the current tag
    while (pos > 0 and json[pos - 1] != '[') : (pos -= 1) {}
    if (pos == 0) return values.toOwnedSlice(allocator);

    var depth: i32 = 0;
    var in_string = false;
    var escaped = false;
    var comma_count: u32 = 0;

    while (pos < json.len) {
        const c = json[pos];

        if (escaped) {
            escaped = false;
            pos += 1;
            continue;
        }

        if (c == '\\' and in_string) {
            escaped = true;
            pos += 1;
            continue;
        }

        if (c == '"') {
            if (!in_string) {
                in_string = true;
                // Values start after the first comma (index 0 is tag name)
                if (depth == 0 and comma_count >= 1) {
                    pos += 1;
                    const value_start = pos;
                    const value_end = utils.findStringEnd(json, value_start) orelse break;
                    const val = try allocator.dupe(u8, json[value_start..value_end]);
                    try values.append(allocator, val);
                    pos = value_end;
                    in_string = false;
                }
            } else {
                in_string = false;
            }
            pos += 1;
            continue;
        }

        if (!in_string) {
            if (c == '[') {
                depth += 1;
            } else if (c == ']') {
                if (depth == 0) break;
                depth -= 1;
            } else if (c == ',' and depth == 0) {
                comma_count += 1;
            }
        }

        pos += 1;
    }

    return values.toOwnedSlice(allocator);
}

fn extractSecondTagValue(json: []const u8, start_pos: usize) ?[]const u8 {
    var pos = start_pos;

    while (pos > 0 and json[pos - 1] != '[') : (pos -= 1) {}
    if (pos == 0) return null;

    var depth: i32 = 0;
    var in_string = false;
    var escaped = false;
    var comma_count: u32 = 0;

    while (pos < json.len) {
        const c = json[pos];

        if (escaped) {
            escaped = false;
            pos += 1;
            continue;
        }

        if (c == '\\' and in_string) {
            escaped = true;
            pos += 1;
            continue;
        }

        if (c == '"') {
            if (!in_string) {
                in_string = true;
                if (depth == 0 and comma_count == 2) {
                    pos += 1;
                    const value_start = pos;
                    const value_end = utils.findStringEnd(json, value_start) orelse return null;
                    return json[value_start..value_end];
                }
            } else {
                in_string = false;
            }
            pos += 1;
            continue;
        }

        if (!in_string) {
            if (c == '[') {
                depth += 1;
            } else if (c == ']') {
                if (depth == 0) return null;
                depth -= 1;
            } else if (c == ',' and depth == 0) {
                comma_count += 1;
            }
        }

        pos += 1;
    }

    return null;
}

pub fn isOracleAnnouncement(kind_num: i32) bool {
    return kind_num == Kind.oracle_announcement;
}

pub fn isOracleAttestation(kind_num: i32) bool {
    return kind_num == Kind.oracle_attestation;
}

pub fn isTrustedOraclesList(kind_num: i32) bool {
    return kind_num == Kind.trusted_oracles;
}

test "Kind constants" {
    try std.testing.expectEqual(@as(i32, 88), Kind.oracle_announcement);
    try std.testing.expectEqual(@as(i32, 89), Kind.oracle_attestation);
    try std.testing.expectEqual(@as(i32, 10088), Kind.trusted_oracles);
}

test "isOracleAnnouncement" {
    try std.testing.expect(isOracleAnnouncement(88));
    try std.testing.expect(!isOracleAnnouncement(89));
    try std.testing.expect(!isOracleAnnouncement(1));
}

test "isOracleAttestation" {
    try std.testing.expect(isOracleAttestation(89));
    try std.testing.expect(!isOracleAttestation(88));
    try std.testing.expect(!isOracleAttestation(1));
}

test "isTrustedOraclesList" {
    try std.testing.expect(isTrustedOraclesList(10088));
    try std.testing.expect(!isTrustedOraclesList(88));
    try std.testing.expect(!isTrustedOraclesList(89));
}

test "OracleAnnouncement.parse basic" {
    const allocator = std.testing.allocator;
    // NIP-88 format: relays tag contains multiple URLs in a single tag
    const json =
        \\{"tags":[["relays","wss://relay1.example.com","wss://relay2.example.com"],["title","BTC/USD Price"],["description","Daily price attestation"],["n","BTC"],["n","USD"]]}
    ;
    const content = "BA/cNhCpdD25j/MwDaa4F42QIq8NsOGmaW1MxyswZnip";

    var announcement = try OracleAnnouncement.parse(allocator, content, json);
    defer announcement.deinit(allocator);

    try std.testing.expectEqualStrings("BA/cNhCpdD25j/MwDaa4F42QIq8NsOGmaW1MxyswZnip", announcement.announcement_data);
    try std.testing.expectEqual(@as(usize, 2), announcement.relays.len);
    try std.testing.expectEqualStrings("wss://relay1.example.com", announcement.relays[0]);
    try std.testing.expectEqualStrings("wss://relay2.example.com", announcement.relays[1]);
    try std.testing.expectEqualStrings("BTC/USD Price", announcement.title.?);
    try std.testing.expectEqualStrings("Daily price attestation", announcement.description.?);
    try std.testing.expectEqualStrings("BTC", announcement.asset_pair.?.base);
    try std.testing.expectEqualStrings("USD", announcement.asset_pair.?.quote);
}

test "OracleAnnouncement.parse minimal" {
    const allocator = std.testing.allocator;
    const json =
        \\{"tags":[]}
    ;
    const content = "somebase64data";

    var announcement = try OracleAnnouncement.parse(allocator, content, json);
    defer announcement.deinit(allocator);

    try std.testing.expectEqualStrings("somebase64data", announcement.announcement_data);
    try std.testing.expectEqual(@as(usize, 0), announcement.relays.len);
    try std.testing.expect(announcement.title == null);
    try std.testing.expect(announcement.description == null);
    try std.testing.expect(announcement.asset_pair == null);
}

test "OracleAnnouncement.serialize" {
    var buf: [1024]u8 = undefined;

    const announcement = OracleAnnouncement{
        .announcement_data = "testdata123",
        .relays = &[_][]const u8{ "wss://relay1.com", "wss://relay2.com" },
        .title = "Test Event",
        .description = "A test oracle event",
        .asset_pair = .{ .base = "BTC", .quote = "USD" },
    };

    const result = try announcement.serialize(&buf);
    try std.testing.expect(std.mem.indexOf(u8, result, "\"kind\":88") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "\"content\":\"testdata123\"") != null);
    // NIP-88 format: all relays in one tag
    try std.testing.expect(std.mem.indexOf(u8, result, "[\"relays\",\"wss://relay1.com\",\"wss://relay2.com\"]") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "[\"title\",\"Test Event\"]") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "[\"n\",\"BTC\"]") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "[\"n\",\"USD\"]") != null);
}

test "OracleAttestation.parse basic" {
    const allocator = std.testing.allocator;
    const json =
        \\{"tags":[["e","30efed56a035b2549fcaeec0bf2c1595f9a9b3bb4b1a38abaf8ee9041c4b7d93"],["n","BTC"],["n","USD"]]}
    ;
    const content = "w7HSaUaPQn7Fa00PoUwTqkR2";

    var attestation = try OracleAttestation.parse(allocator, content, json);
    defer attestation.deinit(allocator);

    try std.testing.expectEqualStrings("w7HSaUaPQn7Fa00PoUwTqkR2", attestation.attestation_data);
    try std.testing.expectEqualStrings("30efed56a035b2549fcaeec0bf2c1595f9a9b3bb4b1a38abaf8ee9041c4b7d93", attestation.announcement_event_id);
    try std.testing.expectEqualStrings("BTC", attestation.asset_pair.?.base);
    try std.testing.expectEqualStrings("USD", attestation.asset_pair.?.quote);
}

test "OracleAttestation.parse missing e tag" {
    const allocator = std.testing.allocator;
    const json =
        \\{"tags":[["n","BTC"],["n","USD"]]}
    ;
    const content = "somedata";

    const result = OracleAttestation.parse(allocator, content, json);
    try std.testing.expectError(error.MissingAnnouncementReference, result);
}

test "OracleAttestation.serialize" {
    var buf: [512]u8 = undefined;

    const attestation = OracleAttestation{
        .attestation_data = "attestdata456",
        .announcement_event_id = "abc123def456",
        .asset_pair = .{ .base = "ETH", .quote = "BTC" },
    };

    const result = try attestation.serialize(&buf);
    try std.testing.expect(std.mem.indexOf(u8, result, "\"kind\":89") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "\"content\":\"attestdata456\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "[\"e\",\"abc123def456\"]") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "[\"n\",\"ETH\"]") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "[\"n\",\"BTC\"]") != null);
}

test "TrustedOraclesList.parse basic" {
    const allocator = std.testing.allocator;
    const json =
        \\{"tags":[["s","4fd5e210530e4f6b2cb083795834bfe5108324f1ed9f00ab73b9e8fcfe5f12fe","wss://bitagent.prices"]]}
    ;

    var list = try TrustedOraclesList.parse(allocator, json);
    defer list.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 1), list.oracles.len);
    try std.testing.expectEqualStrings("4fd5e210530e4f6b2cb083795834bfe5108324f1ed9f00ab73b9e8fcfe5f12fe", list.oracles[0].pubkey);
}

test "TrustedOraclesList.parse multiple oracles" {
    const allocator = std.testing.allocator;
    const json =
        \\{"tags":[["s","pubkey1"],["s","pubkey2"]]}
    ;

    var list = try TrustedOraclesList.parse(allocator, json);
    defer list.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 2), list.oracles.len);
    try std.testing.expectEqualStrings("pubkey1", list.oracles[0].pubkey);
    try std.testing.expectEqualStrings("pubkey2", list.oracles[1].pubkey);
}

test "TrustedOraclesList.serialize" {
    var buf: [512]u8 = undefined;

    const oracle1 = TrustedOracle{ .pubkey = "pk1", .relay = "wss://relay1.com" };
    const oracle2 = TrustedOracle{ .pubkey = "pk2", .relay = null };
    const oracles = [_]TrustedOracle{ oracle1, oracle2 };

    const list = TrustedOraclesList{ .oracles = @constCast(&oracles) };
    const result = try list.serialize(&buf);

    try std.testing.expect(std.mem.indexOf(u8, result, "\"kind\":10088") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "[\"s\",\"pk1\",\"wss://relay1.com\"]") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "[\"s\",\"pk2\"]") != null);
}

test "TrustedOraclesList.parse empty" {
    const allocator = std.testing.allocator;
    const json =
        \\{"tags":[]}
    ;

    var list = try TrustedOraclesList.parse(allocator, json);
    defer list.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 0), list.oracles.len);
}
