const std = @import("std");
const hex = @import("hex.zig");
const utils = @import("utils.zig");

pub const Method = enum {
    supportedmethods,
    banpubkey,
    unbanpubkey,
    listbannedpubkeys,
    allowpubkey,
    unallowpubkey,
    listallowedpubkeys,
    banevent,
    unbanevent,
    allowevent,
    unallowevent,
    listbannedevents,
    listallowedevents,
    listeventsneedingmoderation,
    changerelayname,
    changerelaydescription,
    changerelayicon,
    allowkind,
    disallowkind,
    listallowedkinds,
    listdisallowedkinds,
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
        var at: [2]?usize = undefined;
        if (!utils.findTopLevelFields(body, &.{ "method", "params" }, &at)) return null;
        const method_start = at[0] orelse return null;
        if (body[method_start] != '"') return null;
        const method_end = utils.skipJsonValue(body, method_start) orelse return null;
        const method = body[method_start + 1 .. method_end - 1];

        const params_start = at[1] orelse return Request{ .method = method, .params = "[]" };
        if (body[params_start] != '[') return Request{ .method = method, .params = "[]" };
        const params_end = utils.skipJsonValue(body, params_start) orelse return null;
        return Request{ .method = method, .params = body[params_start..params_end] };
    }

    pub fn getMethod(self: Request) ?Method {
        return Method.fromString(self.method);
    }
};

pub const ParsedParams = struct {
    values: [4]?[]const u8 = .{ null, null, null, null },
    allocator: ?std.mem.Allocator = null,
    allocated: [4]bool = .{ false, false, false, false },

    pub fn deinit(self: *ParsedParams) void {
        if (self.allocator) |alloc| {
            for (0..4) |i| {
                if (self.allocated[i]) {
                    if (self.values[i]) |v| {
                        alloc.free(v);
                    }
                }
            }
        }
    }

    pub fn parseStrings(params: []const u8, comptime max_count: usize, allocator: std.mem.Allocator) ParsedParams {
        comptime std.debug.assert(max_count <= 4);
        var result = ParsedParams{ .allocator = allocator };
        var count: usize = 0;
        var pos: usize = 0;
        var in_string = false;
        var string_start: usize = 0;

        while (pos < params.len and count < max_count) {
            const c = params[pos];

            if (c == '\\' and in_string and pos + 1 < params.len) {
                pos += 2;
                continue;
            }

            if (c == '"') {
                if (in_string) {
                    const raw = params[string_start..pos];
                    if (std.mem.indexOf(u8, raw, "\\") != null) {
                        if (unescapeString(raw, allocator)) |unescaped| {
                            result.values[count] = unescaped;
                            result.allocated[count] = true;
                        } else {
                            result.values[count] = raw;
                        }
                    } else {
                        result.values[count] = raw;
                    }
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
                const digit: i32 = @intCast(c - '0');
                const mul_result = @mulWithOverflow(num, 10);
                if (mul_result[1] != 0) return null;
                const add_result = @addWithOverflow(mul_result[0], digit);
                if (add_result[1] != 0) return null;
                num = add_result[0];
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

fn unescapeString(raw: []const u8, allocator: std.mem.Allocator) ?[]const u8 {
    var buf = allocator.alloc(u8, raw.len) catch return null;
    var write_pos: usize = 0;
    var read_pos: usize = 0;

    while (read_pos < raw.len) {
        if (raw[read_pos] == '\\' and read_pos + 1 < raw.len) {
            const next = raw[read_pos + 1];
            switch (next) {
                '"' => {
                    buf[write_pos] = '"';
                    write_pos += 1;
                    read_pos += 2;
                },
                '\\' => {
                    buf[write_pos] = '\\';
                    write_pos += 1;
                    read_pos += 2;
                },
                'n' => {
                    buf[write_pos] = '\n';
                    write_pos += 1;
                    read_pos += 2;
                },
                'r' => {
                    buf[write_pos] = '\r';
                    write_pos += 1;
                    read_pos += 2;
                },
                't' => {
                    buf[write_pos] = '\t';
                    write_pos += 1;
                    read_pos += 2;
                },
                else => {
                    buf[write_pos] = raw[read_pos];
                    write_pos += 1;
                    read_pos += 1;
                },
            }
        } else {
            buf[write_pos] = raw[read_pos];
            write_pos += 1;
            read_pos += 1;
        }
    }

    if (write_pos < buf.len) {
        const shrunk = allocator.realloc(buf, write_pos) catch {
            allocator.free(buf);
            return null;
        };
        return shrunk;
    }
    return buf;
}

pub const Nip98Tags = struct {
    url: ?[]const u8 = null,
    method: ?[]const u8 = null,
    payload: ?[]const u8 = null,

    pub fn extract(json: []const u8) Nip98Tags {
        var result = Nip98Tags{};
        var iter = utils.TagIterator.init(json, "tags") orelse return result;
        while (iter.next()) |tag| {
            if (tag.value.len == 0) continue;
            if (std.mem.eql(u8, tag.name, "u")) {
                result.url = tag.value;
            } else if (std.mem.eql(u8, tag.name, "method")) {
                result.method = tag.value;
            } else if (std.mem.eql(u8, tag.name, "payload")) {
                result.payload = tag.value;
            }
        }
        if (iter.malformed) return .{};
        return result;
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
            0x00...0x08, 0x0b, 0x0c, 0x0e...0x1f, 0x7f => {
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

test "Request.parse reads only top-level members" {
    const req = Request.parse(
        \\{"params":["\"method\":\"banpubkey\""],"x":{"method":"banpubkey"},"method":"listbannedpubkeys"}
    ).?;
    try std.testing.expectEqualStrings("listbannedpubkeys", req.method);
    try std.testing.expectEqual(@as(?Method, .listbannedpubkeys), req.getMethod());
    try std.testing.expectEqual(@as(?Request, null), Request.parse("{\"method\":\"a\",\"method\":\"b\"}"));
    try std.testing.expectEqual(@as(?Request, null), Request.parse("{\"params\":[]}"));
}

test "Method covers the NIP-86 ban and allow lifecycle" {
    for ([_][]const u8{ "unbanpubkey", "unallowpubkey", "unbanevent", "unallowevent", "listallowedevents", "listdisallowedkinds" }) |name| {
        try std.testing.expect(Method.fromString(name) != null);
    }
}

test "Request.parse no params" {
    const body = "{\"method\":\"supportedmethods\"}";
    const req = Request.parse(body).?;
    try std.testing.expectEqualStrings("supportedmethods", req.method);
    try std.testing.expectEqualStrings("[]", req.params);
}

test "ParsedParams.parseStrings" {
    const params = "[\"abc\",\"def\"]";
    var parsed = ParsedParams.parseStrings(params, 2, std.testing.allocator);
    defer parsed.deinit();
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

/// Validates NIP-98 HTTP Auth header and returns the pubkey if valid
pub const AuthResult = struct {
    pubkey: ?[32]u8 = null,
    err: ?[]const u8 = null,

    pub fn success(pubkey: [32]u8) AuthResult {
        return .{ .pubkey = pubkey };
    }

    pub fn fail(err: []const u8) AuthResult {
        return .{ .err = err };
    }
};

const Event = @import("event.zig").Event;
const Auth = @import("auth.zig").Auth;

pub fn validateNip98Auth(auth_header: ?[]const u8, body: []const u8, request_url: []const u8) AuthResult {
    const header = auth_header orelse return AuthResult.fail("{\"error\":\"missing authorization header\"}");

    if (!std.ascii.startsWithIgnoreCase(header, "nostr ")) {
        return AuthResult.fail("{\"error\":\"invalid authorization scheme\"}");
    }

    const b64_event = std.mem.trim(u8, header[6..], " ");
    var decode_buf: [4096]u8 = undefined;
    const decoded_len = std.base64.standard.Decoder.calcSizeForSlice(b64_event) catch {
        return AuthResult.fail("{\"error\":\"invalid base64 in authorization\"}");
    };
    if (decoded_len > decode_buf.len) {
        return AuthResult.fail("{\"error\":\"authorization event too large\"}");
    }
    std.base64.standard.Decoder.decode(&decode_buf, b64_event) catch {
        return AuthResult.fail("{\"error\":\"invalid base64 in authorization\"}");
    };
    const decoded = decode_buf[0..decoded_len];

    var event = Event.parse(decoded) catch {
        return AuthResult.fail("{\"error\":\"invalid event in authorization\"}");
    };
    defer event.deinit();

    if (event.kind() != 27235) {
        return AuthResult.fail("{\"error\":\"authorization event must be kind 27235\"}");
    }

    const now = @import("io.zig").timestamp();
    const created = event.createdAt();
    const time_diff = if (now > created) now - created else created - now;
    if (time_diff > 60) {
        if (created > now) {
            return AuthResult.fail("{\"error\":\"authorization event timestamp in the future\"}");
        } else {
            return AuthResult.fail("{\"error\":\"authorization event timestamp too old\"}");
        }
    }

    event.validate() catch {
        return AuthResult.fail("{\"error\":\"invalid event signature\"}");
    };

    const tags = Nip98Tags.extract(decoded);

    if (tags.url == null) {
        return AuthResult.fail("{\"error\":\"missing u tag in authorization\"}");
    }
    if (!Auth.urlsMatch(request_url, tags.url.?)) {
        return AuthResult.fail("{\"error\":\"url mismatch in authorization\"}");
    }

    if (tags.method == null or !std.ascii.eqlIgnoreCase(tags.method.?, "POST")) {
        return AuthResult.fail("{\"error\":\"method must be POST\"}");
    }

    if (tags.payload) |expected_hash| {
        if (expected_hash.len != 64) {
            return AuthResult.fail("{\"error\":\"payload hash mismatch\"}");
        }
        var actual_hash: [64]u8 = undefined;
        var sha256 = std.crypto.hash.sha2.Sha256.init(.{});
        sha256.update(body);
        const digest = sha256.finalResult();
        hex.encode(&digest, &actual_hash);
        if (!std.ascii.eqlIgnoreCase(expected_hash, &actual_hash)) {
            return AuthResult.fail("{\"error\":\"payload hash mismatch\"}");
        }
    } else {
        return AuthResult.fail("{\"error\":\"missing payload tag in authorization\"}");
    }

    var pubkey: [32]u8 = undefined;
    @memcpy(&pubkey, event.pubkey());
    return AuthResult.success(pubkey);
}

test "validateNip98Auth full flow" {
    const event_mod = @import("event.zig");
    const builder_mod = @import("builder.zig");

    try event_mod.init();
    defer event_mod.cleanup();

    const keypair = builder_mod.Keypair.generate();

    const body = "{\"method\":\"supportedmethods\",\"params\":[]}";
    var body_hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(body, &body_hash, .{});
    var payload_hex: [64]u8 = undefined;
    hex.encode(&body_hash, &payload_hex);

    const tags = [_][]const []const u8{
        &[_][]const u8{ "u", "https://relay.example.com" },
        &[_][]const u8{ "method", "POST" },
        &[_][]const u8{ "payload", &payload_hex },
    };

    var builder = builder_mod.EventBuilder{};
    _ = builder.setKind(27235).setContent("").setTags(&tags);
    try builder.sign(&keypair);

    var json_buf: [4096]u8 = undefined;
    const json = try builder.serialize(&json_buf);

    var b64_buf: [8192]u8 = undefined;
    const b64_len = std.base64.standard.Encoder.calcSize(json.len);
    const b64 = b64_buf[0..b64_len];
    _ = std.base64.standard.Encoder.encode(b64, json);

    var header_buf: [8200]u8 = undefined;
    const header = std.fmt.bufPrint(&header_buf, "Nostr {s}", .{b64}) catch unreachable;

    const result = validateNip98Auth(header, body, "https://relay.example.com");

    try std.testing.expect(result.err == null);
    try std.testing.expect(result.pubkey != null);
    try std.testing.expectEqualSlices(u8, &keypair.public_key, &result.pubkey.?);
}

test "Nip98Tags.extract reads only the signed top-level tags" {
    const signed =
        \\"kind":27235,"id":"6a59a67f38997c87352d58d8628cbc1d9770557fa4cb9cce531587be6106c14e","pubkey":"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","created_at":1700000000,"tags":[["u","https://other.example/upload"],["method","POST"],["payload","0000000000000000000000000000000000000000000000000000000000000000"]],"content":"","sig":"44d9e7adb3814ad1d97dec1f711182f0299692aee26ca7293e4c76755da4ca9fbe930354db458401b7126f28e2595f01ed8defddc6ae2627ce0e061c0828ddb0"}
    ;
    const json = "{\"a\":\"tags\",\"b\":[[\"u\",\"https://relay.example\"]],\"x\":{\"tags\" :[[\"u\",\"https://relay.example\"]]}," ++ signed;

    try @import("event.zig").init();
    defer @import("event.zig").cleanup();
    var event = try Event.parse(json);
    defer event.deinit();
    try event.validate();

    const tags = Nip98Tags.extract(json);
    try std.testing.expectEqualStrings("https://other.example/upload", tags.url.?);

    try std.testing.expectEqual(@as(?[]const u8, null), Nip98Tags.extract("{\"tags\":[[\"u\",\"a\"]],\"tags\":[[\"u\",\"b\"]]}").url);
}
