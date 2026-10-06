const std = @import("std");
const hex = @import("hex.zig");

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
    const start = findJsonFieldStart(json, key) orelse return null;
    if (json[start] != '"' and json[start] != '[' and json[start] != '{') return null;
    const end = skipJsonValue(json, start) orelse return null;
    return json[start..end];
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
    const start = findJsonFieldStart(json, key) orelse return null;
    if (json[start] != '"') return null;
    const end = skipJsonValue(json, start) orelse return null;
    return json[start + 1 .. end - 1];
}

pub fn findStringInJson(json: []const u8, needle: []const u8) ?[]const u8 {
    var search_buf: [256]u8 = undefined;
    if (needle.len > 250) return null;

    const search = std.fmt.bufPrint(&search_buf, "\"{s}\"", .{needle}) catch return null;
    const pos = std.mem.indexOf(u8, json, search) orelse return null;

    return json[pos + 1 .. pos + 1 + needle.len];
}

fn skipWs(json: []const u8, start: usize) usize {
    var pos = start;
    while (pos < json.len and (json[pos] == ' ' or json[pos] == '\n' or json[pos] == '\r' or json[pos] == '\t')) : (pos += 1) {}
    return pos;
}

/// Returns the index just past the JSON value starting at `start`, or null if
/// it is malformed or truncated. Strings and nesting are tracked so that
/// brackets and quotes inside strings are never mistaken for structure.
pub fn skipJsonValue(json: []const u8, start: usize) ?usize {
    if (start >= json.len) return null;
    switch (json[start]) {
        '"' => {
            var pos = start + 1;
            while (pos < json.len) : (pos += 1) {
                switch (json[pos]) {
                    '\\' => pos += 1,
                    '"' => return pos + 1,
                    else => {},
                }
            }
            return null;
        },
        '[', '{' => {
            var depth: usize = 0;
            var pos = start;
            while (pos < json.len) : (pos += 1) {
                switch (json[pos]) {
                    '"' => pos = (skipJsonValue(json, pos) orelse return null) - 1,
                    '[', '{' => depth += 1,
                    ']', '}' => {
                        depth -= 1;
                        if (depth == 0) return pos + 1;
                    },
                    else => {},
                }
            }
            return null;
        },
        else => {
            var pos = start;
            while (pos < json.len) : (pos += 1) {
                switch (json[pos]) {
                    ',', '}', ']', ' ', '\n', '\r', '\t' => break,
                    '"', '[', '{', ':' => return null,
                    else => {},
                }
            }
            return if (pos == start) null else pos;
        },
    }
}

/// Locates the values of `keys` among the top-level members of the JSON
/// object `json`, writing each value's start index into `out` (null when the
/// key is absent). Nested objects and string contents are never searched, so a
/// key can only be found where a JSON parser would find it. Returns false if
/// the object is malformed or any of `keys` appears more than once, since
/// parsers disagree on which duplicate wins. Keys written with escapes never
/// match.
pub fn findTopLevelFields(json: []const u8, keys: []const []const u8, out: []?usize) bool {
    std.debug.assert(keys.len == out.len);
    @memset(out, null);

    var pos = skipWs(json, 0);
    if (pos >= json.len or json[pos] != '{') return false;
    pos = skipWs(json, pos + 1);
    if (pos < json.len and json[pos] == '}') return true;

    while (true) {
        if (pos >= json.len or json[pos] != '"') return false;
        const key_end = skipJsonValue(json, pos) orelse return false;
        const name = json[pos + 1 .. key_end - 1];

        pos = skipWs(json, key_end);
        if (pos >= json.len or json[pos] != ':') return false;
        const value_start = skipWs(json, pos + 1);
        const value_end = skipJsonValue(json, value_start) orelse return false;

        for (keys, out) |k, *slot| {
            if (std.mem.eql(u8, name, k)) {
                if (slot.* != null) return false;
                slot.* = value_start;
            }
        }

        pos = skipWs(json, value_end);
        if (pos >= json.len) return false;
        if (json[pos] == '}') return true;
        if (json[pos] != ',') return false;
        pos = skipWs(json, pos + 1);
    }
}

pub fn findJsonFieldStart(json: []const u8, key: []const u8) ?usize {
    var out: [1]?usize = undefined;
    if (!findTopLevelFields(json, &.{key}, &out)) return null;
    return out[0];
}

pub fn findStringEnd(json: []const u8, start: usize) ?usize {
    var i = start;
    var escaped = false;
    while (i < json.len) {
        if (escaped) {
            escaped = false;
            i += 1;
            continue;
        }
        if (json[i] == '\\') {
            escaped = true;
            i += 1;
            continue;
        }
        if (json[i] == '"') {
            return i;
        }
        const byte = json[i];
        if (byte < 0x80) {
            i += 1;
        } else if (byte < 0xE0) {
            i += 2;
        } else if (byte < 0xF0) {
            i += 3;
        } else {
            i += 4;
        }
    }
    return null;
}

pub fn extractHexField(json: []const u8, key: []const u8, comptime len: usize) ?[len]u8 {
    return hexFieldAt(json, findJsonFieldStart(json, key) orelse return null, len);
}

pub fn hexFieldAt(json: []const u8, start: usize, comptime len: usize) ?[len]u8 {
    const end = skipJsonValue(json, start) orelse return null;
    if (json[start] != '"' or end - start != len * 2 + 2) return null;
    var result: [len]u8 = undefined;
    hex.decode(json[start + 1 .. end - 1], &result) catch return null;
    return result;
}

pub fn extractIntField(json: []const u8, key: []const u8, comptime T: type) ?T {
    return intFieldAt(json, findJsonFieldStart(json, key) orelse return null, T);
}

pub fn intFieldAt(json: []const u8, start: usize, comptime T: type) ?T {
    const end = skipJsonValue(json, start) orelse return null;
    const digits = json[start..end];
    const unsigned = if (digits.len > 0 and digits[0] == '-') digits[1..] else digits;
    if (unsigned.len == 0) return null;
    for (unsigned) |c| if (c < '0' or c > '9') return null;
    return std.fmt.parseInt(T, digits, 10) catch null;
}

pub const TagIterator = struct {
    json: []const u8,
    pos: usize,
    started: bool = false,
    /// Set when iteration stopped at something other than an array of arrays
    /// of strings. Callers that validate events must reject it.
    malformed: bool = false,

    pub const Tag = struct { name: []const u8, value: []const u8 };

    pub fn init(json: []const u8, key: []const u8) ?TagIterator {
        return initAt(json, findJsonFieldStart(json, key) orelse return null);
    }

    pub fn initAt(json: []const u8, start: usize) ?TagIterator {
        if (start >= json.len or json[start] != '[') return null;
        const end = skipJsonValue(json, start) orelse return null;
        return .{ .json = json[0..end], .pos = start + 1 };
    }

    /// Yields each tag's first two strings. Empty tags are skipped.
    pub fn next(self: *TagIterator) ?Tag {
        while (true) {
            self.pos = skipWs(self.json, self.pos);
            if (self.pos >= self.json.len) return self.fail();
            if (self.json[self.pos] == ']') return null;
            if (self.started) {
                if (self.json[self.pos] != ',') return self.fail();
                self.pos = skipWs(self.json, self.pos + 1);
            }
            self.started = true;
            if (self.pos >= self.json.len or self.json[self.pos] != '[') return self.fail();
            self.pos = skipWs(self.json, self.pos + 1);

            var tag = Tag{ .name = "", .value = "" };
            var count: usize = 0;
            while (true) {
                if (self.pos >= self.json.len) return self.fail();
                if (self.json[self.pos] == ']' and count == 0) break;
                if (self.json[self.pos] != '"') return self.fail();
                const end = skipJsonValue(self.json, self.pos) orelse return self.fail();
                const str = self.json[self.pos + 1 .. end - 1];
                if (count == 0) tag.name = str else if (count == 1) tag.value = str;
                count += 1;
                self.pos = skipWs(self.json, end);
                if (self.pos >= self.json.len) return self.fail();
                if (self.json[self.pos] == ']') break;
                if (self.json[self.pos] != ',') return self.fail();
                self.pos = skipWs(self.json, self.pos + 1);
            }
            self.pos += 1;
            if (count > 0) return tag;
        }
    }

    fn fail(self: *TagIterator) ?Tag {
        self.malformed = true;
        self.pos = self.json.len;
        return null;
    }
};

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

pub fn percentDecode(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    var result: std.ArrayListUnmanaged(u8) = .empty;
    errdefer result.deinit(allocator);

    var i: usize = 0;
    while (i < input.len) {
        if (input[i] == '%' and i + 2 < input.len) {
            const byte = std.fmt.parseInt(u8, input[i + 1 .. i + 3], 16) catch {
                try result.append(allocator, input[i]);
                i += 1;
                continue;
            };
            try result.append(allocator, byte);
            i += 3;
        } else if (input[i] == '+') {
            try result.append(allocator, ' ');
            i += 1;
        } else {
            try result.append(allocator, input[i]);
            i += 1;
        }
    }
    return result.toOwnedSlice(allocator);
}

pub fn percentEncode(writer: anytype, input: []const u8) !void {
    for (input) |c| {
        if (std.ascii.isAlphanumeric(c) or c == '-' or c == '_' or c == '.' or c == '~') {
            try writer.writeByte(c);
        } else {
            try writer.print("%{X:0>2}", .{c});
        }
    }
}

pub fn findBracketInJson(json: []const u8, start: usize, bracket: u8) ?usize {
    var pos = start;
    var in_string = false;
    var escape = false;

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

        if (!in_string and c == bracket) {
            return pos;
        }

        pos += 1;
    }
    return null;
}

pub fn parseTagStrings(content: []const u8, comptime max_strings: usize) ?[max_strings][]const u8 {
    var strings: [max_strings][]const u8 = undefined;
    @memset(&strings, "");
    var str_count: usize = 0;

    var i: usize = 0;
    while (i < content.len and str_count < max_strings) {
        const quote_start = std.mem.indexOfPos(u8, content, i, "\"") orelse break;
        const str_start = quote_start + 1;
        const quote_end = findStringEnd(content, str_start) orelse break;
        strings[str_count] = content[str_start..quote_end];
        str_count += 1;
        i = quote_end + 1;
    }

    if (str_count < 1) return null;
    return strings;
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
