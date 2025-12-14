const std = @import("std");

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
