const std = @import("std");
const hex = @import("hex.zig");

pub const Method = enum {
    supportedmethods,
    banpubkey,
    listbannedpubkeys,
    allowpubkey,
    listallowedpubkeys,
    banevent,
    allowevent,
    listbannedevents,
    listeventsneedingmoderation,
    changerelayname,
    changerelaydescription,
    changerelayicon,
    allowkind,
    disallowkind,
    listallowedkinds,
    blockip,
    unblockip,
    listblockedips,

    pub fn fromString(s: []const u8) ?Method {
        return std.meta.stringToEnum(Method, s);
    }
};

pub const Request = struct {
    method: []const u8,
    params: []const u8,

    pub fn parse(body: []const u8) ?Request {
        const method_key = "\"method\"";
        const method_idx = std.mem.indexOf(u8, body, method_key) orelse return null;
        var pos = method_idx + method_key.len;

        while (pos < body.len and (body[pos] == ':' or body[pos] == ' ' or body[pos] == '\t')) pos += 1;
        if (pos >= body.len or body[pos] != '"') return null;
        pos += 1;

        const method_start = pos;
        while (pos < body.len and body[pos] != '"') pos += 1;
        if (pos >= body.len) return null;
        const method = body[method_start..pos];

        const params_key = "\"params\"";
        const params_idx = std.mem.indexOf(u8, body, params_key) orelse return Request{ .method = method, .params = "[]" };
        pos = params_idx + params_key.len;

        while (pos < body.len and (body[pos] == ':' or body[pos] == ' ' or body[pos] == '\t')) pos += 1;
        if (pos >= body.len or body[pos] != '[') return Request{ .method = method, .params = "[]" };

        const params_start = pos;
        var depth: i32 = 0;
        while (pos < body.len) {
            if (body[pos] == '[') depth += 1;
            if (body[pos] == ']') {
                depth -= 1;
                if (depth == 0) {
                    pos += 1;
                    break;
                }
            }
            pos += 1;
        }

        return Request{ .method = method, .params = body[params_start..pos] };
    }

    pub fn getMethod(self: Request) ?Method {
        return Method.fromString(self.method);
    }
};

pub const ParsedParams = struct {
    values: [4]?[]const u8 = .{ null, null, null, null },

    pub fn parseStrings(params: []const u8, comptime max_count: usize) ParsedParams {
        var result = ParsedParams{};
        var count: usize = 0;
        var pos: usize = 0;
        var in_string = false;
        var string_start: usize = 0;
        var escape = false;

        while (pos < params.len and count < max_count) {
            const c = params[pos];

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
                    result.values[count] = params[string_start..pos];
                    count += 1;
                } else {
                    string_start = pos + 1;
                }
                in_string = !in_string;
            }

            pos += 1;
        }

        return result;
    }

    pub fn parseKind(params: []const u8) ?i32 {
        var pos: usize = 0;
        while (pos < params.len and (params[pos] == '[' or params[pos] == ' ' or params[pos] == '\t')) pos += 1;

        var num: i32 = 0;
        var found_digit = false;
        while (pos < params.len) {
            const c = params[pos];
            if (c >= '0' and c <= '9') {
                num = num * 10 + @as(i32, @intCast(c - '0'));
                found_digit = true;
            } else if (found_digit) {
                break;
            }
            pos += 1;
        }

        if (found_digit) return num;
        return null;
    }

    pub fn parsePubkey(self: ParsedParams, out: *[32]u8) bool {
        const hex_str = self.values[0] orelse return false;
        if (hex_str.len != 64) return false;
        hex.decode(hex_str, out) catch return false;
        return true;
    }

    pub fn parseEventId(self: ParsedParams, out: *[32]u8) bool {
        return self.parsePubkey(out);
    }
};

pub const Nip98Tags = struct {
    url: ?[]const u8 = null,
    method: ?[]const u8 = null,
    payload: ?[]const u8 = null,

    pub fn extract(json: []const u8) Nip98Tags {
        var result = Nip98Tags{};

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
                        extractTagValue(tag_json, &result);
                        tag_start = null;
                    }
                    if (depth < 0) break;
                }
            }

            pos += 1;
        }

        return result;
    }

    fn extractTagValue(tag_json: []const u8, result: *Nip98Tags) void {
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
            if (std.mem.eql(u8, values[0].?, "u")) {
                result.url = values[1].?;
            } else if (std.mem.eql(u8, values[0].?, "method")) {
                result.method = values[1].?;
            } else if (std.mem.eql(u8, values[0].?, "payload")) {
                result.payload = values[1].?;
            }
        }
    }
};

pub const Response = struct {
    status: u16,
    body: []const u8,
    owned: bool = false,

    pub fn ok(body: []const u8) Response {
        return .{ .status = 200, .body = body };
    }

    pub fn ownedOk(body: []const u8) Response {
        return .{ .status = 200, .body = body, .owned = true };
    }

    pub fn err(status: u16, body: []const u8) Response {
        return .{ .status = status, .body = body };
    }

    pub fn badRequest(body: []const u8) Response {
        return .{ .status = 400, .body = body };
    }

    pub fn unauthorized(body: []const u8) Response {
        return .{ .status = 401, .body = body };
    }

    pub fn forbidden(body: []const u8) Response {
        return .{ .status = 403, .body = body };
    }

    pub fn internalError() Response {
        return .{ .status = 500, .body = "{\"error\":\"internal error\"}" };
    }
};

pub fn writeJsonString(buf: *std.ArrayListUnmanaged(u8), allocator: std.mem.Allocator, value: []const u8) !void {
    try buf.append(allocator, '"');
    for (value) |c| {
        switch (c) {
            '"' => try buf.appendSlice(allocator, "\\\""),
            '\\' => try buf.appendSlice(allocator, "\\\\"),
            '\n' => try buf.appendSlice(allocator, "\\n"),
            '\r' => try buf.appendSlice(allocator, "\\r"),
            '\t' => try buf.appendSlice(allocator, "\\t"),
            0x00...0x08, 0x0b, 0x0c, 0x0e...0x1f => {
                var escape_buf: [6]u8 = undefined;
                const esc = std.fmt.bufPrint(&escape_buf, "\\u{x:0>4}", .{c}) catch continue;
                try buf.appendSlice(allocator, esc);
            },
            else => try buf.append(allocator, c),
        }
    }
    try buf.append(allocator, '"');
}

test "Request.parse" {
    const body = "{\"method\":\"banpubkey\",\"params\":[\"abc123\",\"spam\"]}";
    const req = Request.parse(body).?;
    try std.testing.expectEqualStrings("banpubkey", req.method);
    try std.testing.expectEqualStrings("[\"abc123\",\"spam\"]", req.params);
}

test "Request.parse no params" {
    const body = "{\"method\":\"supportedmethods\"}";
    const req = Request.parse(body).?;
    try std.testing.expectEqualStrings("supportedmethods", req.method);
    try std.testing.expectEqualStrings("[]", req.params);
}

test "ParsedParams.parseStrings" {
    const params = "[\"abc\",\"def\"]";
    const parsed = ParsedParams.parseStrings(params, 2);
    try std.testing.expectEqualStrings("abc", parsed.values[0].?);
    try std.testing.expectEqualStrings("def", parsed.values[1].?);
}

test "ParsedParams.parseKind" {
    try std.testing.expectEqual(@as(i32, 1), ParsedParams.parseKind("[1]").?);
    try std.testing.expectEqual(@as(i32, 30023), ParsedParams.parseKind("[30023]").?);
}

test "Nip98Tags.extract" {
    const json =
        \\{"kind":27235,"tags":[["u","https://relay.example.com"],["method","POST"],["payload","abc123"]]}
    ;
    const tags = Nip98Tags.extract(json);
    try std.testing.expectEqualStrings("https://relay.example.com", tags.url.?);
    try std.testing.expectEqualStrings("POST", tags.method.?);
    try std.testing.expectEqualStrings("abc123", tags.payload.?);
}
