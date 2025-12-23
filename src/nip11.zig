const std = @import("std");
const utils = @import("utils.zig");

pub const RelayInformation = struct {
    json: []const u8,
    allocator: ?std.mem.Allocator,
    owned: bool,

    pub fn parse(json: []const u8, allocator: std.mem.Allocator) !RelayInformation {
        const copy = try allocator.dupe(u8, json);
        return .{ .json = copy, .allocator = allocator, .owned = true };
    }

    pub fn parseFromSlice(json: []const u8) RelayInformation {
        return .{ .json = json, .allocator = null, .owned = false };
    }

    pub fn deinit(self: *RelayInformation) void {
        if (self.owned) {
            if (self.allocator) |a| {
                a.free(self.json);
            }
        }
    }

    pub fn name(self: *const RelayInformation) ?[]const u8 {
        return utils.extractJsonString(self.json, "name");
    }

    pub fn description(self: *const RelayInformation) ?[]const u8 {
        return utils.extractJsonString(self.json, "description");
    }

    pub fn banner(self: *const RelayInformation) ?[]const u8 {
        return utils.extractJsonString(self.json, "banner");
    }

    pub fn icon(self: *const RelayInformation) ?[]const u8 {
        return utils.extractJsonString(self.json, "icon");
    }

    pub fn pubkey(self: *const RelayInformation) ?[]const u8 {
        return utils.extractJsonString(self.json, "pubkey");
    }

    pub fn selfPubkey(self: *const RelayInformation) ?[]const u8 {
        return utils.extractJsonString(self.json, "self");
    }

    pub fn contact(self: *const RelayInformation) ?[]const u8 {
        return utils.extractJsonString(self.json, "contact");
    }

    pub fn software(self: *const RelayInformation) ?[]const u8 {
        return utils.extractJsonString(self.json, "software");
    }

    pub fn version(self: *const RelayInformation) ?[]const u8 {
        return utils.extractJsonString(self.json, "version");
    }

    pub fn privacyPolicy(self: *const RelayInformation) ?[]const u8 {
        return utils.extractJsonString(self.json, "privacy_policy");
    }

    pub fn termsOfService(self: *const RelayInformation) ?[]const u8 {
        return utils.extractJsonString(self.json, "terms_of_service");
    }

    pub fn postingPolicy(self: *const RelayInformation) ?[]const u8 {
        return utils.extractJsonString(self.json, "posting_policy");
    }

    pub fn paymentsUrl(self: *const RelayInformation) ?[]const u8 {
        return utils.extractJsonString(self.json, "payments_url");
    }

    pub fn supportedNips(self: *const RelayInformation) NipIterator {
        return NipIterator.init(self.json);
    }

    pub fn supportsNip(self: *const RelayInformation, nip: i64) bool {
        var iter = self.supportedNips();
        while (iter.next()) |n| {
            if (n == nip) return true;
        }
        return false;
    }

    pub fn limitation(self: *const RelayInformation) ?Limitation {
        const limit_json = utils.findJsonValue(self.json, "limitation") orelse return null;
        if (limit_json.len < 2 or limit_json[0] != '{') return null;
        return Limitation{ .json = limit_json };
    }

    pub fn fees(self: *const RelayInformation) ?Fees {
        const fees_json = utils.findJsonValue(self.json, "fees") orelse return null;
        if (fees_json.len < 2 or fees_json[0] != '{') return null;
        return Fees{ .json = fees_json };
    }

    pub fn relayCountries(self: *const RelayInformation) StringArrayIterator {
        return StringArrayIterator.init(self.json, "relay_countries");
    }

    pub fn languageTags(self: *const RelayInformation) StringArrayIterator {
        return StringArrayIterator.init(self.json, "language_tags");
    }

    pub fn tags(self: *const RelayInformation) StringArrayIterator {
        return StringArrayIterator.init(self.json, "tags");
    }

    pub fn retention(self: *const RelayInformation) RetentionIterator {
        return RetentionIterator.init(self.json);
    }
};

pub const Limitation = struct {
    json: []const u8,

    pub fn maxMessageLength(self: *const Limitation) ?i64 {
        return utils.extractIntField(self.json, "max_message_length", i64);
    }

    pub fn maxSubscriptions(self: *const Limitation) ?i64 {
        return utils.extractIntField(self.json, "max_subscriptions", i64);
    }

    pub fn maxLimit(self: *const Limitation) ?i64 {
        return utils.extractIntField(self.json, "max_limit", i64);
    }

    pub fn maxSubidLength(self: *const Limitation) ?i64 {
        return utils.extractIntField(self.json, "max_subid_length", i64);
    }

    pub fn maxEventTags(self: *const Limitation) ?i64 {
        return utils.extractIntField(self.json, "max_event_tags", i64);
    }

    pub fn maxContentLength(self: *const Limitation) ?i64 {
        return utils.extractIntField(self.json, "max_content_length", i64);
    }

    pub fn minPowDifficulty(self: *const Limitation) ?i64 {
        return utils.extractIntField(self.json, "min_pow_difficulty", i64);
    }

    pub fn createdAtLowerLimit(self: *const Limitation) ?i64 {
        return utils.extractIntField(self.json, "created_at_lower_limit", i64);
    }

    pub fn createdAtUpperLimit(self: *const Limitation) ?i64 {
        return utils.extractIntField(self.json, "created_at_upper_limit", i64);
    }

    pub fn defaultLimit(self: *const Limitation) ?i64 {
        return utils.extractIntField(self.json, "default_limit", i64);
    }

    pub fn authRequired(self: *const Limitation) ?bool {
        return extractBool(self.json, "auth_required");
    }

    pub fn paymentRequired(self: *const Limitation) ?bool {
        return extractBool(self.json, "payment_required");
    }

    pub fn restrictedWrites(self: *const Limitation) ?bool {
        return extractBool(self.json, "restricted_writes");
    }
};

pub const Fee = struct {
    json: []const u8,

    pub fn amount(self: *const Fee) ?i64 {
        return utils.extractIntField(self.json, "amount", i64);
    }

    pub fn unit(self: *const Fee) ?[]const u8 {
        return utils.extractJsonString(self.json, "unit");
    }

    pub fn period(self: *const Fee) ?i64 {
        return utils.extractIntField(self.json, "period", i64);
    }

    /// Returns an iterator over the kinds array for publication fees.
    pub fn kinds(self: *const Fee) KindsIterator {
        return KindsIterator.init(self.json);
    }
};

pub const Fees = struct {
    json: []const u8,

    pub fn admission(self: *const Fees) FeeIterator {
        return FeeIterator.init(self.json, "admission");
    }

    pub fn subscription(self: *const Fees) FeeIterator {
        return FeeIterator.init(self.json, "subscription");
    }

    pub fn publication(self: *const Fees) FeeIterator {
        return FeeIterator.init(self.json, "publication");
    }
};

pub const RetentionEntry = struct {
    json: []const u8,

    pub fn time(self: *const RetentionEntry) ?i64 {
        return utils.extractIntField(self.json, "time", i64);
    }

    pub fn count(self: *const RetentionEntry) ?i64 {
        return utils.extractIntField(self.json, "count", i64);
    }

    /// Returns an iterator over the kinds array in this retention entry.
    /// Kinds can be single integers or ranges (represented as [start, end] arrays).
    pub fn kinds(self: *const RetentionEntry) KindsIterator {
        return KindsIterator.init(self.json);
    }
};

/// Represents a kind value in retention/fee entries.
/// Can be a single kind or a range [start, end] inclusive.
pub const KindEntry = union(enum) {
    single: i64,
    range: struct { start: i64, end: i64 },
};

/// Iterator over kinds array which may contain integers or [start, end] ranges.
pub const KindsIterator = struct {
    json: []const u8,
    pos: usize,

    fn init(json: []const u8) KindsIterator {
        const start = utils.findJsonFieldStart(json, "kinds") orelse return .{ .json = "", .pos = 0 };
        if (start >= json.len or json[start] != '[') return .{ .json = "", .pos = 0 };
        return .{ .json = json, .pos = start + 1 };
    }

    pub fn next(self: *KindsIterator) ?KindEntry {
        while (self.pos < self.json.len) {
            const c = self.json[self.pos];
            if (c == ']') return null;

            // Check for nested array (range)
            if (c == '[') {
                self.pos += 1;
                const start_val = self.parseNumber() orelse continue;
                self.skipWhitespaceAndComma();
                const end_val = self.parseNumber() orelse continue;
                // Skip to closing bracket
                while (self.pos < self.json.len and self.json[self.pos] != ']') : (self.pos += 1) {}
                if (self.pos < self.json.len) self.pos += 1;
                return KindEntry{ .range = .{ .start = start_val, .end = end_val } };
            }

            // Check for single number
            if (c >= '0' and c <= '9') {
                const num = self.parseNumber() orelse continue;
                return KindEntry{ .single = num };
            }

            self.pos += 1;
        }
        return null;
    }

    fn parseNumber(self: *KindsIterator) ?i64 {
        while (self.pos < self.json.len and (self.json[self.pos] == ' ' or self.json[self.pos] == '\t' or self.json[self.pos] == '\n' or self.json[self.pos] == '\r')) : (self.pos += 1) {}
        if (self.pos >= self.json.len) return null;

        const start = self.pos;
        while (self.pos < self.json.len and self.json[self.pos] >= '0' and self.json[self.pos] <= '9') : (self.pos += 1) {}
        if (self.pos == start) return null;

        return std.fmt.parseInt(i64, self.json[start..self.pos], 10) catch null;
    }

    fn skipWhitespaceAndComma(self: *KindsIterator) void {
        while (self.pos < self.json.len) {
            const c = self.json[self.pos];
            if (c == ' ' or c == '\t' or c == '\n' or c == '\r' or c == ',') {
                self.pos += 1;
            } else {
                break;
            }
        }
    }
};

pub const NipIterator = struct {
    json: []const u8,
    pos: usize,

    fn init(json: []const u8) NipIterator {
        const start = utils.findJsonFieldStart(json, "supported_nips") orelse return .{ .json = "", .pos = 0 };
        if (start >= json.len or json[start] != '[') return .{ .json = "", .pos = 0 };
        return .{ .json = json, .pos = start + 1 };
    }

    pub fn next(self: *NipIterator) ?i64 {
        while (self.pos < self.json.len) {
            const c = self.json[self.pos];
            if (c == ']') return null;
            if (c >= '0' and c <= '9') {
                var end = self.pos;
                while (end < self.json.len and self.json[end] >= '0' and self.json[end] <= '9') : (end += 1) {}
                const num = std.fmt.parseInt(i64, self.json[self.pos..end], 10) catch {
                    self.pos = end;
                    continue;
                };
                self.pos = end;
                return num;
            }
            self.pos += 1;
        }
        return null;
    }
};

pub const StringArrayIterator = struct {
    json: []const u8,
    pos: usize,

    fn init(json: []const u8, key: []const u8) StringArrayIterator {
        const start = utils.findJsonFieldStart(json, key) orelse return .{ .json = "", .pos = 0 };
        if (start >= json.len or json[start] != '[') return .{ .json = "", .pos = 0 };
        return .{ .json = json, .pos = start + 1 };
    }

    pub fn next(self: *StringArrayIterator) ?[]const u8 {
        while (self.pos < self.json.len) {
            const c = self.json[self.pos];
            if (c == ']') return null;
            if (c == '"') {
                self.pos += 1;
                const start = self.pos;
                const end = utils.findStringEnd(self.json, start) orelse return null;
                self.pos = end + 1;
                return self.json[start..end];
            }
            self.pos += 1;
        }
        return null;
    }
};

pub const FeeIterator = struct {
    json: []const u8,
    pos: usize,

    fn init(json: []const u8, key: []const u8) FeeIterator {
        const start = utils.findJsonFieldStart(json, key) orelse return .{ .json = "", .pos = 0 };
        if (start >= json.len or json[start] != '[') return .{ .json = "", .pos = 0 };
        return .{ .json = json, .pos = start + 1 };
    }

    pub fn next(self: *FeeIterator) ?Fee {
        while (self.pos < self.json.len) {
            const c = self.json[self.pos];
            if (c == ']') return null;
            if (c == '{') {
                const obj_start = self.pos;
                var depth: i32 = 1;
                self.pos += 1;
                while (self.pos < self.json.len and depth > 0) {
                    if (self.json[self.pos] == '{') depth += 1;
                    if (self.json[self.pos] == '}') depth -= 1;
                    self.pos += 1;
                }
                return Fee{ .json = self.json[obj_start..self.pos] };
            }
            self.pos += 1;
        }
        return null;
    }
};

pub const RetentionIterator = struct {
    json: []const u8,
    pos: usize,

    fn init(json: []const u8) RetentionIterator {
        const start = utils.findJsonFieldStart(json, "retention") orelse return .{ .json = "", .pos = 0 };
        if (start >= json.len or json[start] != '[') return .{ .json = "", .pos = 0 };
        return .{ .json = json, .pos = start + 1 };
    }

    pub fn next(self: *RetentionIterator) ?RetentionEntry {
        while (self.pos < self.json.len) {
            const c = self.json[self.pos];
            if (c == ']') return null;
            if (c == '{') {
                const obj_start = self.pos;
                var depth: i32 = 1;
                self.pos += 1;
                while (self.pos < self.json.len and depth > 0) {
                    if (self.json[self.pos] == '{') depth += 1;
                    if (self.json[self.pos] == '}') depth -= 1;
                    self.pos += 1;
                }
                return RetentionEntry{ .json = self.json[obj_start..self.pos] };
            }
            self.pos += 1;
        }
        return null;
    }
};

fn extractBool(json: []const u8, key: []const u8) ?bool {
    const start = utils.findJsonFieldStart(json, key) orelse return null;
    if (start + 4 <= json.len and std.mem.eql(u8, json[start .. start + 4], "true")) return true;
    if (start + 5 <= json.len and std.mem.eql(u8, json[start .. start + 5], "false")) return false;
    return null;
}

test "parse basic relay info" {
    const json =
        \\{"name":"Test Relay","description":"A test relay","pubkey":"bf2bee5281149c7c350f5d12ae32f514c7864ff10805182f4178538c2c421007","contact":"admin@example.com","supported_nips":[1,9,11,42],"software":"https://github.com/test/relay","version":"1.0.0"}
    ;

    var info = RelayInformation.parseFromSlice(json);
    defer info.deinit();

    try std.testing.expectEqualStrings("Test Relay", info.name().?);
    try std.testing.expectEqualStrings("A test relay", info.description().?);
    try std.testing.expectEqualStrings("bf2bee5281149c7c350f5d12ae32f514c7864ff10805182f4178538c2c421007", info.pubkey().?);
    try std.testing.expectEqualStrings("admin@example.com", info.contact().?);
    try std.testing.expectEqualStrings("https://github.com/test/relay", info.software().?);
    try std.testing.expectEqualStrings("1.0.0", info.version().?);
}

test "parse supported_nips" {
    const json =
        \\{"name":"Test","supported_nips":[1,9,11,13,42,70]}
    ;

    var info = RelayInformation.parseFromSlice(json);
    defer info.deinit();

    try std.testing.expect(info.supportsNip(1));
    try std.testing.expect(info.supportsNip(11));
    try std.testing.expect(info.supportsNip(42));
    try std.testing.expect(!info.supportsNip(99));

    var iter = info.supportedNips();
    try std.testing.expectEqual(@as(i64, 1), iter.next().?);
    try std.testing.expectEqual(@as(i64, 9), iter.next().?);
    try std.testing.expectEqual(@as(i64, 11), iter.next().?);
    try std.testing.expectEqual(@as(i64, 13), iter.next().?);
    try std.testing.expectEqual(@as(i64, 42), iter.next().?);
    try std.testing.expectEqual(@as(i64, 70), iter.next().?);
    try std.testing.expect(iter.next() == null);
}

test "parse limitation" {
    const json =
        \\{"name":"Test","limitation":{"max_message_length":16384,"max_subscriptions":20,"auth_required":true,"payment_required":false,"min_pow_difficulty":10}}
    ;

    var info = RelayInformation.parseFromSlice(json);
    defer info.deinit();

    const limit = info.limitation().?;
    try std.testing.expectEqual(@as(i64, 16384), limit.maxMessageLength().?);
    try std.testing.expectEqual(@as(i64, 20), limit.maxSubscriptions().?);
    try std.testing.expectEqual(@as(i64, 10), limit.minPowDifficulty().?);
    try std.testing.expect(limit.authRequired().?);
    try std.testing.expect(!limit.paymentRequired().?);
}

test "parse fees" {
    const json =
        \\{"name":"Test","fees":{"subscription":[{"amount":5000,"unit":"sats","period":2592000}],"admission":[{"amount":1000,"unit":"msats"}]}}
    ;

    var info = RelayInformation.parseFromSlice(json);
    defer info.deinit();

    const f = info.fees().?;

    var sub_iter = f.subscription();
    const sub = sub_iter.next().?;
    try std.testing.expectEqual(@as(i64, 5000), sub.amount().?);
    try std.testing.expectEqualStrings("sats", sub.unit().?);
    try std.testing.expectEqual(@as(i64, 2592000), sub.period().?);

    var adm_iter = f.admission();
    const adm = adm_iter.next().?;
    try std.testing.expectEqual(@as(i64, 1000), adm.amount().?);
    try std.testing.expectEqualStrings("msats", adm.unit().?);
}

test "parse relay_countries and language_tags" {
    const json =
        \\{"name":"Test","relay_countries":["US","CA","EU"],"language_tags":["en","en-419"]}
    ;

    var info = RelayInformation.parseFromSlice(json);
    defer info.deinit();

    var countries = info.relayCountries();
    try std.testing.expectEqualStrings("US", countries.next().?);
    try std.testing.expectEqualStrings("CA", countries.next().?);
    try std.testing.expectEqualStrings("EU", countries.next().?);
    try std.testing.expect(countries.next() == null);

    var langs = info.languageTags();
    try std.testing.expectEqualStrings("en", langs.next().?);
    try std.testing.expectEqualStrings("en-419", langs.next().?);
    try std.testing.expect(langs.next() == null);
}

test "parse with allocator" {
    const json =
        \\{"name":"Allocated Relay","version":"2.0"}
    ;

    var info = try RelayInformation.parse(json, std.testing.allocator);
    defer info.deinit();

    try std.testing.expectEqualStrings("Allocated Relay", info.name().?);
    try std.testing.expectEqualStrings("2.0", info.version().?);
}

test "parse real world example" {
    const json =
        \\{"name":"JellyFish","description":"Stay Immortal!","banner":"https://image.nostr.build/banner.jpg","pubkey":"bf2bee5281149c7c350f5d12ae32f514c7864ff10805182f4178538c2c421007","contact":"hi@dezh.tech","software":"https://github.com/dezh-tech/immortal","supported_nips":[1,9,11,13,17,40,42,59,62,70],"version":"immortal - 0.0.9","relay_countries":["*"],"language_tags":["*"],"tags":[],"posting_policy":"https://jellyfish.land/tos.txt","payments_url":"https://jellyfish.land/relay","icon":"https://image.nostr.build/icon.jpg","limitation":{"auth_required":false,"max_message_length":70000,"max_subid_length":256,"max_subscriptions":350,"min_pow_difficulty":0,"payment_required":true,"restricted_writes":true,"max_event_tags":2000,"max_content_length":70000,"created_at_lower_limit":0,"created_at_upper_limit":2147483647,"default_limit":500,"max_limit":5000}}
    ;

    var info = RelayInformation.parseFromSlice(json);
    defer info.deinit();

    try std.testing.expectEqualStrings("JellyFish", info.name().?);
    try std.testing.expectEqualStrings("Stay Immortal!", info.description().?);
    try std.testing.expectEqualStrings("https://image.nostr.build/banner.jpg", info.banner().?);
    try std.testing.expectEqualStrings("https://image.nostr.build/icon.jpg", info.icon().?);
    try std.testing.expectEqualStrings("https://jellyfish.land/tos.txt", info.postingPolicy().?);
    try std.testing.expectEqualStrings("https://jellyfish.land/relay", info.paymentsUrl().?);

    try std.testing.expect(info.supportsNip(11));
    try std.testing.expect(info.supportsNip(42));
    try std.testing.expect(!info.supportsNip(99));

    const limit = info.limitation().?;
    try std.testing.expectEqual(@as(i64, 70000), limit.maxMessageLength().?);
    try std.testing.expectEqual(@as(i64, 350), limit.maxSubscriptions().?);
    try std.testing.expectEqual(@as(i64, 5000), limit.maxLimit().?);
    try std.testing.expectEqual(@as(i64, 500), limit.defaultLimit().?);
    try std.testing.expect(!limit.authRequired().?);
    try std.testing.expect(limit.paymentRequired().?);
    try std.testing.expect(limit.restrictedWrites().?);
}

test "missing fields return null" {
    const json =
        \\{"name":"Minimal"}
    ;

    var info = RelayInformation.parseFromSlice(json);
    defer info.deinit();

    try std.testing.expectEqualStrings("Minimal", info.name().?);
    try std.testing.expect(info.description() == null);
    try std.testing.expect(info.pubkey() == null);
    try std.testing.expect(info.banner() == null);
    try std.testing.expect(info.limitation() == null);
    try std.testing.expect(info.fees() == null);
}

test "parse retention" {
    const json =
        \\{"name":"Test","retention":[{"time":3600,"count":10000},{"time":100}]}
    ;

    var info = RelayInformation.parseFromSlice(json);
    defer info.deinit();

    var iter = info.retention();
    const first = iter.next().?;
    try std.testing.expectEqual(@as(i64, 3600), first.time().?);
    try std.testing.expectEqual(@as(i64, 10000), first.count().?);

    const second = iter.next().?;
    try std.testing.expectEqual(@as(i64, 100), second.time().?);
    try std.testing.expect(second.count() == null);

    try std.testing.expect(iter.next() == null);
}

test "parse tags array" {
    const json =
        \\{"name":"Test","tags":["sfw-only","bitcoin-only"]}
    ;

    var info = RelayInformation.parseFromSlice(json);
    defer info.deinit();

    var iter = info.tags();
    try std.testing.expectEqualStrings("sfw-only", iter.next().?);
    try std.testing.expectEqualStrings("bitcoin-only", iter.next().?);
    try std.testing.expect(iter.next() == null);
}

test "parse retention with kinds" {
    const json =
        \\{"name":"Test","retention":[{"kinds":[0,1,[5,7],[40,49]],"time":3600},{"kinds":[[30000,39999]],"count":1000}]}
    ;

    var info = RelayInformation.parseFromSlice(json);
    defer info.deinit();

    var ret_iter = info.retention();

    const first = ret_iter.next().?;
    try std.testing.expectEqual(@as(i64, 3600), first.time().?);
    var kinds1 = first.kinds();
    const k1 = kinds1.next().?;
    try std.testing.expectEqual(KindEntry{ .single = 0 }, k1);
    const k2 = kinds1.next().?;
    try std.testing.expectEqual(KindEntry{ .single = 1 }, k2);
    const k3 = kinds1.next().?;
    try std.testing.expectEqual(@as(i64, 5), k3.range.start);
    try std.testing.expectEqual(@as(i64, 7), k3.range.end);
    const k4 = kinds1.next().?;
    try std.testing.expectEqual(@as(i64, 40), k4.range.start);
    try std.testing.expectEqual(@as(i64, 49), k4.range.end);
    try std.testing.expect(kinds1.next() == null);

    const second = ret_iter.next().?;
    try std.testing.expectEqual(@as(i64, 1000), second.count().?);
    var kinds2 = second.kinds();
    const k5 = kinds2.next().?;
    try std.testing.expectEqual(@as(i64, 30000), k5.range.start);
    try std.testing.expectEqual(@as(i64, 39999), k5.range.end);
    try std.testing.expect(kinds2.next() == null);
}

test "parse publication fees with kinds" {
    const json =
        \\{"name":"Test","fees":{"publication":[{"kinds":[4],"amount":100,"unit":"msats"}]}}
    ;

    var info = RelayInformation.parseFromSlice(json);
    defer info.deinit();

    const f = info.fees().?;
    var pub_iter = f.publication();
    const pub_fee = pub_iter.next().?;
    try std.testing.expectEqual(@as(i64, 100), pub_fee.amount().?);
    try std.testing.expectEqualStrings("msats", pub_fee.unit().?);

    var kinds = pub_fee.kinds();
    const k = kinds.next().?;
    try std.testing.expectEqual(KindEntry{ .single = 4 }, k);
    try std.testing.expect(kinds.next() == null);
}
