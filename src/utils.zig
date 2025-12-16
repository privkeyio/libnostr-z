const std = @import("std");

pub fn writeJsonEscaped(writer: anytype, str: []const u8) !void {
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

pub fn writeJsonEscapedHash(hasher: *std.crypto.hash.sha2.Sha256, str: []const u8) !void {
    var escape_buf: [6]u8 = undefined;
    for (str) |c| {
        switch (c) {
            '"' => hasher.update("\\\""),
            '\\' => hasher.update("\\\\"),
            '\n' => hasher.update("\\n"),
            '\r' => hasher.update("\\r"),
            '\t' => hasher.update("\\t"),
            else => {
                if (c < 0x20) {
                    const escaped = std.fmt.bufPrint(&escape_buf, "\\u{x:0>4}", .{c}) catch unreachable;
                    hasher.update(escaped);
                } else {
                    hasher.update(&[_]u8{c});
                }
            },
        }
    }
}

pub fn findJsonValue(json: []const u8, key: []const u8) ?[]const u8 {
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

pub fn findArrayElement(json: []const u8, index: usize) ?[]const u8 {
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

pub fn extractJsonString(json: []const u8, key: []const u8) ?[]const u8 {
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

pub fn findStringInJson(json: []const u8, needle: []const u8) ?[]const u8 {
    var search_buf: [256]u8 = undefined;
    if (needle.len > 250) return null;

    const search = std.fmt.bufPrint(&search_buf, "\"{s}\"", .{needle}) catch return null;
    const pos = std.mem.indexOf(u8, json, search) orelse return null;

    return json[pos + 1 .. pos + 1 + needle.len];
}

pub fn containsInsensitive(haystack: []const u8, needle: []const u8) bool {
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

pub fn isNip50Extension(token: []const u8) bool {
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

pub fn searchMatches(query: []const u8, content: []const u8) bool {
    var words_iter = std.mem.splitScalar(u8, query, ' ');
    while (words_iter.next()) |word| {
        if (word.len == 0) continue;
        if (isNip50Extension(word)) continue;
        if (!containsInsensitive(content, word)) return false;
    }
    return true;
}

test "containsInsensitive basic" {
    try std.testing.expect(containsInsensitive("Hello World", "hello"));
    try std.testing.expect(containsInsensitive("Hello World", "WORLD"));
    try std.testing.expect(containsInsensitive("Hello World", "lo Wo"));
    try std.testing.expect(!containsInsensitive("Hello World", "xyz"));
    try std.testing.expect(containsInsensitive("", ""));
    try std.testing.expect(!containsInsensitive("short", "longer needle"));
}

test "containsInsensitive utf8" {
    try std.testing.expect(containsInsensitive("Café au lait", "café"));
    try std.testing.expect(containsInsensitive("NOSTR IS GREAT", "nostr"));
    try std.testing.expect(containsInsensitive("Bitcoin Nostr Lightning", "NOSTR"));
}

test "searchMatches" {
    try std.testing.expect(searchMatches("hello world", "Hello World Today"));
    try std.testing.expect(!searchMatches("hello xyz", "Hello World Today"));
    try std.testing.expect(searchMatches("bitcoin nostr", "I love Bitcoin and Nostr!"));
}
