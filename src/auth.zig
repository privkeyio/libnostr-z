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

    pub fn urlsMatch(url1: []const u8, url2: []const u8) bool {
        const parsed1 = parseUrl(url1) orelse return false;
        const parsed2 = parseUrl(url2) orelse return false;

        if (!std.ascii.eqlIgnoreCase(parsed1.host, parsed2.host)) return false;
        if (!portsEquivalent(parsed1.port, parsed2.port, parsed1.default_port, parsed2.default_port)) return false;
        if (!pathsMatch(parsed1.path, parsed2.path)) return false;

        return true;
    }

    const ParsedUrl = struct {
        host: []const u8,
        port: ?[]const u8,
        path: []const u8,
        default_port: u16,
    };

    fn parseUrl(url: []const u8) ?ParsedUrl {
        var start: usize = 0;
        var default_port: u16 = 443;

        if (std.mem.startsWith(u8, url, "wss://")) {
            start = 6;
            default_port = 443;
        } else if (std.mem.startsWith(u8, url, "ws://")) {
            start = 5;
            default_port = 80;
        } else if (std.mem.startsWith(u8, url, "https://")) {
            start = 8;
            default_port = 443;
        } else if (std.mem.startsWith(u8, url, "http://")) {
            start = 7;
            default_port = 80;
        }

        if (start >= url.len) return null;

        var host_end = start;
        var port_start: ?usize = null;
        var path_start: usize = url.len;

        while (host_end < url.len) {
            if (url[host_end] == ':') {
                port_start = host_end + 1;
                var port_end = port_start.?;
                while (port_end < url.len and url[port_end] != '/' and url[port_end] != '?') port_end += 1;
                path_start = port_end;
                break;
            } else if (url[host_end] == '/' or url[host_end] == '?') {
                path_start = host_end;
                break;
            }
            host_end += 1;
        }

        if (host_end <= start) return null;

        const port = if (port_start) |ps| blk: {
            var pe = ps;
            while (pe < url.len and url[pe] != '/' and url[pe] != '?') pe += 1;
            break :blk if (pe > ps) url[ps..pe] else null;
        } else null;

        const path = if (path_start < url.len and url[path_start] == '/') url[path_start..] else "/";

        return ParsedUrl{
            .host = url[start..host_end],
            .port = port,
            .path = path,
            .default_port = default_port,
        };
    }

    fn portsEquivalent(port1: ?[]const u8, port2: ?[]const u8, default1: u16, default2: u16) bool {
        const p1 = if (port1) |p| std.fmt.parseInt(u16, p, 10) catch return false else default1;
        const p2 = if (port2) |p| std.fmt.parseInt(u16, p, 10) catch return false else default2;
        return p1 == p2;
    }

    fn pathsMatch(path1: []const u8, path2: []const u8) bool {
        const normalized1 = normalizePath(path1);
        const normalized2 = normalizePath(path2);
        return std.mem.eql(u8, normalized1, normalized2);
    }

    fn normalizePath(path: []const u8) []const u8 {
        if (std.mem.indexOf(u8, path, "?") != null) return path;
        var end = path.len;
        while (end > 1 and path[end - 1] == '/') end -= 1;
        return path[0..end];
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

test "Auth.urlsMatch" {
    try std.testing.expect(Auth.urlsMatch("wss://example.com", "https://example.com"));
    try std.testing.expect(Auth.urlsMatch("wss://example.com/", "https://example.com"));
    try std.testing.expect(Auth.urlsMatch("wss://EXAMPLE.COM", "https://example.com"));
    try std.testing.expect(Auth.urlsMatch("wss://example.com:443", "https://example.com"));
    try std.testing.expect(Auth.urlsMatch("ws://example.com:80", "http://example.com"));
    try std.testing.expect(Auth.urlsMatch("wss://example.com/path", "https://example.com/path"));
    try std.testing.expect(Auth.urlsMatch("wss://example.com/path/", "https://example.com/path"));
    try std.testing.expect(!Auth.urlsMatch("wss://example.com", "https://other.com"));
    try std.testing.expect(!Auth.urlsMatch("wss://example.com/path1", "https://example.com/path2"));
    try std.testing.expect(!Auth.urlsMatch("wss://example.com:8080", "https://example.com"));
    try std.testing.expect(Auth.urlsMatch("wss://example.com:8080", "https://example.com:8080"));
}

test "Auth.extractTags" {
    const json =
        \\{"id":"abc","pubkey":"def","sig":"ghi","kind":22242,"created_at":1234,"content":"","tags":[["relay","wss://relay.example.com"],["challenge","test-challenge-123"]]}
    ;
    const tags = Auth.extractTags(json);
    try std.testing.expectEqualStrings("wss://relay.example.com", tags.relay.?);
    try std.testing.expectEqualStrings("test-challenge-123", tags.challenge.?);
}
