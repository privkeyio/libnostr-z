const std = @import("std");
const utils = @import("utils.zig");
const Event = @import("event.zig").Event;

pub const HttpAuth = struct {
    pub const Kind: i32 = 27235;
    pub const DefaultTimeWindow: i64 = 60;

    pub const Method = enum {
        GET,
        POST,
        PUT,
        DELETE,
        PATCH,
        HEAD,
        OPTIONS,

        pub fn toString(self: Method) []const u8 {
            return switch (self) {
                .GET => "GET",
                .POST => "POST",
                .PUT => "PUT",
                .DELETE => "DELETE",
                .PATCH => "PATCH",
                .HEAD => "HEAD",
                .OPTIONS => "OPTIONS",
            };
        }

        pub fn fromString(s: []const u8) ?Method {
            if (std.ascii.eqlIgnoreCase(s, "GET")) return .GET;
            if (std.ascii.eqlIgnoreCase(s, "POST")) return .POST;
            if (std.ascii.eqlIgnoreCase(s, "PUT")) return .PUT;
            if (std.ascii.eqlIgnoreCase(s, "DELETE")) return .DELETE;
            if (std.ascii.eqlIgnoreCase(s, "PATCH")) return .PATCH;
            if (std.ascii.eqlIgnoreCase(s, "HEAD")) return .HEAD;
            if (std.ascii.eqlIgnoreCase(s, "OPTIONS")) return .OPTIONS;
            return null;
        }
    };

    pub const Tags = struct {
        url: ?[]const u8 = null,
        method: ?[]const u8 = null,
        payload: ?[]const u8 = null,
    };

    pub const ValidationError = error{
        InvalidKind,
        MissingUrl,
        MissingMethod,
        UrlMismatch,
        MethodMismatch,
        PayloadMismatch,
        EventExpired,
        EventTooNew,
        InvalidEvent,
        SignatureInvalid,
    };

    pub fn extractTags(json: []const u8) Tags {
        var result = Tags{};
        var iter = utils.TagIterator.init(json, "tags") orelse return result;

        while (iter.next()) |tag| {
            if (std.mem.eql(u8, tag.name, "u")) {
                result.url = utils.findStringInJson(json, tag.value);
            } else if (std.mem.eql(u8, tag.name, "method")) {
                result.method = utils.findStringInJson(json, tag.value);
            } else if (std.mem.eql(u8, tag.name, "payload")) {
                result.payload = utils.findStringInJson(json, tag.value);
            }
        }

        return result;
    }

    pub fn validate(
        json: []const u8,
        expected_url: []const u8,
        expected_method: []const u8,
        expected_payload_hash: ?[]const u8,
        time_window: ?i64,
    ) ValidationError!void {
        const kind = utils.extractIntField(json, "kind", i32) orelse return error.InvalidKind;
        if (kind != Kind) return error.InvalidKind;

        const created_at = utils.extractIntField(json, "created_at", i64) orelse return error.EventExpired;
        const now = std.time.timestamp();
        const window = time_window orelse DefaultTimeWindow;

        if (created_at < now - window) return error.EventExpired;
        if (created_at > now + window) return error.EventTooNew;

        const tags = extractTags(json);

        if (tags.url == null) return error.MissingUrl;
        if (!std.mem.eql(u8, tags.url.?, expected_url)) return error.UrlMismatch;

        if (tags.method == null) return error.MissingMethod;
        if (!std.ascii.eqlIgnoreCase(tags.method.?, expected_method)) return error.MethodMismatch;

        if (expected_payload_hash) |expected| {
            if (tags.payload) |payload| {
                if (!std.ascii.eqlIgnoreCase(payload, expected)) return error.PayloadMismatch;
            } else {
                return error.PayloadMismatch;
            }
        }
    }

    /// Validates an HTTP Auth event including signature verification.
    /// Returns the authenticated pubkey (32 bytes) on success.
    /// This is the recommended function for server-side validation.
    pub fn validateAndVerify(
        json: []const u8,
        expected_url: []const u8,
        expected_method: []const u8,
        expected_payload_hash: ?[]const u8,
        time_window: ?i64,
    ) ValidationError![32]u8 {
        // Parse and verify the event signature
        var event = Event.parse(json) catch return error.InvalidEvent;
        defer event.deinit();
        event.validate() catch return error.SignatureInvalid;

        // Now validate NIP-98 specific fields
        if (event.kind() != Kind) return error.InvalidKind;

        const now = std.time.timestamp();
        const window = time_window orelse DefaultTimeWindow;
        const created_at = event.createdAt();

        if (created_at < now - window) return error.EventExpired;
        if (created_at > now + window) return error.EventTooNew;

        const tags = extractTags(json);

        if (tags.url == null) return error.MissingUrl;
        if (!std.mem.eql(u8, tags.url.?, expected_url)) return error.UrlMismatch;

        if (tags.method == null) return error.MissingMethod;
        if (!std.ascii.eqlIgnoreCase(tags.method.?, expected_method)) return error.MethodMismatch;

        if (expected_payload_hash) |expected| {
            if (tags.payload) |payload| {
                if (!std.ascii.eqlIgnoreCase(payload, expected)) return error.PayloadMismatch;
            } else {
                return error.PayloadMismatch;
            }
        }

        return event.pubkey().*;
    }

    /// Extracts the pubkey from a JSON event (without signature verification).
    /// Use validateAndVerify for full validation including signature check.
    pub fn extractPubkey(json: []const u8) ?[32]u8 {
        return utils.extractHexField(json, "pubkey", 32);
    }

    pub fn parseAuthorizationHeader(header: []const u8) ?[]const u8 {
        const prefix = "Nostr ";
        if (header.len <= prefix.len) return null;
        if (!std.ascii.eqlIgnoreCase(header[0..prefix.len], prefix)) return null;

        var start = prefix.len;
        while (start < header.len and (header[start] == ' ' or header[start] == '\t')) {
            start += 1;
        }
        if (start >= header.len) return null;

        var end = header.len;
        while (end > start and (header[end - 1] == ' ' or header[end - 1] == '\t' or header[end - 1] == '\r' or header[end - 1] == '\n')) {
            end -= 1;
        }
        if (end <= start) return null;

        return header[start..end];
    }

    pub fn decodeAuthEvent(base64_event: []const u8, out_buf: []u8) ![]u8 {
        const decoded_len = std.base64.standard.Decoder.calcSizeForSlice(base64_event) catch return error.InvalidBase64;
        if (decoded_len > out_buf.len) return error.BufferTooSmall;
        std.base64.standard.Decoder.decode(out_buf[0..decoded_len], base64_event) catch return error.InvalidBase64;
        return out_buf[0..decoded_len];
    }

    pub fn encodeAuthEvent(json: []const u8, out_buf: []u8) ![]u8 {
        const encoded_len = std.base64.standard.Encoder.calcSize(json.len);
        if (encoded_len > out_buf.len) return error.BufferTooSmall;
        _ = std.base64.standard.Encoder.encode(out_buf[0..encoded_len], json);
        return out_buf[0..encoded_len];
    }

    pub fn formatAuthorizationHeader(base64_event: []const u8, out_buf: []u8) ![]u8 {
        const prefix = "Nostr ";
        const total_len = prefix.len + base64_event.len;
        if (total_len > out_buf.len) return error.BufferTooSmall;
        @memcpy(out_buf[0..prefix.len], prefix);
        @memcpy(out_buf[prefix.len..total_len], base64_event);
        return out_buf[0..total_len];
    }

    pub fn computePayloadHash(body: []const u8, out: *[64]u8) void {
        var hash: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(body, &hash, .{});
        const hex_chars = "0123456789abcdef";
        for (hash, 0..) |byte, i| {
            out[i * 2] = hex_chars[byte >> 4];
            out[i * 2 + 1] = hex_chars[byte & 0x0f];
        }
    }
};

test "HttpAuth.extractTags" {
    const json =
        \\{"id":"abc","pubkey":"def","sig":"ghi","kind":27235,"created_at":1682327852,"content":"","tags":[["u","https://api.example.com/v1/data"],["method","GET"]]}
    ;
    const tags = HttpAuth.extractTags(json);
    try std.testing.expectEqualStrings("https://api.example.com/v1/data", tags.url.?);
    try std.testing.expectEqualStrings("GET", tags.method.?);
    try std.testing.expect(tags.payload == null);
}

test "HttpAuth.extractTags with payload" {
    const json =
        \\{"id":"abc","pubkey":"def","sig":"ghi","kind":27235,"created_at":1682327852,"content":"","tags":[["u","https://api.example.com/v1/data"],["method","POST"],["payload","a1b2c3d4e5f6"]]}
    ;
    const tags = HttpAuth.extractTags(json);
    try std.testing.expectEqualStrings("https://api.example.com/v1/data", tags.url.?);
    try std.testing.expectEqualStrings("POST", tags.method.?);
    try std.testing.expectEqualStrings("a1b2c3d4e5f6", tags.payload.?);
}

test "HttpAuth.parseAuthorizationHeader" {
    try std.testing.expectEqualStrings("eyJhYmMiOjEyM30=", HttpAuth.parseAuthorizationHeader("Nostr eyJhYmMiOjEyM30=").?);
    try std.testing.expectEqualStrings("eyJhYmMiOjEyM30=", HttpAuth.parseAuthorizationHeader("Nostr   eyJhYmMiOjEyM30=").?);
    try std.testing.expectEqualStrings("eyJhYmMiOjEyM30=", HttpAuth.parseAuthorizationHeader("nostr eyJhYmMiOjEyM30=").?);
    try std.testing.expect(HttpAuth.parseAuthorizationHeader("Bearer xyz") == null);
    try std.testing.expect(HttpAuth.parseAuthorizationHeader("Nostr") == null);
    try std.testing.expect(HttpAuth.parseAuthorizationHeader("Nostr ") == null);
}

test "HttpAuth.encodeAuthEvent and decodeAuthEvent" {
    const json = "{\"id\":\"abc\",\"kind\":27235}";
    var encode_buf: [1024]u8 = undefined;
    const encoded = try HttpAuth.encodeAuthEvent(json, &encode_buf);

    var decode_buf: [1024]u8 = undefined;
    const decoded = try HttpAuth.decodeAuthEvent(encoded, &decode_buf);
    try std.testing.expectEqualStrings(json, decoded);
}

test "HttpAuth.formatAuthorizationHeader" {
    var buf: [256]u8 = undefined;
    const header = try HttpAuth.formatAuthorizationHeader("eyJhYmMiOjEyM30=", &buf);
    try std.testing.expectEqualStrings("Nostr eyJhYmMiOjEyM30=", header);
}

test "HttpAuth.computePayloadHash" {
    var hash: [64]u8 = undefined;
    HttpAuth.computePayloadHash("{\"test\":123}", &hash);
    try std.testing.expectEqualStrings("612102eefa7e4fb2998807197ab38e6a131b500b53b024c889ad60bdfee0f9a0", &hash);
}

test "HttpAuth.Method" {
    try std.testing.expectEqualStrings("GET", HttpAuth.Method.GET.toString());
    try std.testing.expectEqualStrings("POST", HttpAuth.Method.POST.toString());
    try std.testing.expectEqual(HttpAuth.Method.GET, HttpAuth.Method.fromString("GET").?);
    try std.testing.expectEqual(HttpAuth.Method.GET, HttpAuth.Method.fromString("get").?);
    try std.testing.expectEqual(HttpAuth.Method.POST, HttpAuth.Method.fromString("Post").?);
    try std.testing.expect(HttpAuth.Method.fromString("INVALID") == null);
}

test "HttpAuth.validate kind check" {
    const wrong_kind =
        \\{"id":"abc","pubkey":"def","sig":"ghi","kind":1,"created_at":1682327852,"content":"","tags":[["u","https://api.example.com"],["method","GET"]]}
    ;
    try std.testing.expectError(error.InvalidKind, HttpAuth.validate(wrong_kind, "https://api.example.com", "GET", null, null));
}

test "HttpAuth.validate url mismatch" {
    const now = std.time.timestamp();
    var json_buf: [512]u8 = undefined;
    const json = std.fmt.bufPrint(&json_buf,
        \\{{"id":"abc","pubkey":"def","sig":"ghi","kind":27235,"created_at":{d},"content":"","tags":[["u","https://api.example.com/v1"],["method","GET"]]}}
    , .{now}) catch unreachable;

    try std.testing.expectError(error.UrlMismatch, HttpAuth.validate(json, "https://api.example.com/v2", "GET", null, null));
}

test "HttpAuth.validate method mismatch" {
    const now = std.time.timestamp();
    var json_buf: [512]u8 = undefined;
    const json = std.fmt.bufPrint(&json_buf,
        \\{{"id":"abc","pubkey":"def","sig":"ghi","kind":27235,"created_at":{d},"content":"","tags":[["u","https://api.example.com"],["method","GET"]]}}
    , .{now}) catch unreachable;

    try std.testing.expectError(error.MethodMismatch, HttpAuth.validate(json, "https://api.example.com", "POST", null, null));
}

test "HttpAuth.validate success" {
    const now = std.time.timestamp();
    var json_buf: [512]u8 = undefined;
    const json = std.fmt.bufPrint(&json_buf,
        \\{{"id":"abc","pubkey":"def","sig":"ghi","kind":27235,"created_at":{d},"content":"","tags":[["u","https://api.example.com"],["method","GET"]]}}
    , .{now}) catch unreachable;

    try HttpAuth.validate(json, "https://api.example.com", "GET", null, null);
}

test "HttpAuth.validate with payload" {
    const now = std.time.timestamp();
    var json_buf: [512]u8 = undefined;
    const json = std.fmt.bufPrint(&json_buf,
        \\{{"id":"abc","pubkey":"def","sig":"ghi","kind":27235,"created_at":{d},"content":"","tags":[["u","https://api.example.com"],["method","POST"],["payload","abc123"]]}}
    , .{now}) catch unreachable;

    try HttpAuth.validate(json, "https://api.example.com", "POST", "abc123", null);
    try std.testing.expectError(error.PayloadMismatch, HttpAuth.validate(json, "https://api.example.com", "POST", "xyz789", null));
}

test "HttpAuth.validate expired event" {
    const old_time: i64 = 1000000;
    var json_buf: [512]u8 = undefined;
    const json = std.fmt.bufPrint(&json_buf,
        \\{{"id":"abc","pubkey":"def","sig":"ghi","kind":27235,"created_at":{d},"content":"","tags":[["u","https://api.example.com"],["method","GET"]]}}
    , .{old_time}) catch unreachable;

    try std.testing.expectError(error.EventExpired, HttpAuth.validate(json, "https://api.example.com", "GET", null, null));
}

test "HttpAuth.validate future event" {
    const future_time = std.time.timestamp() + 3600;
    var json_buf: [512]u8 = undefined;
    const json = std.fmt.bufPrint(&json_buf,
        \\{{"id":"abc","pubkey":"def","sig":"ghi","kind":27235,"created_at":{d},"content":"","tags":[["u","https://api.example.com"],["method","GET"]]}}
    , .{future_time}) catch unreachable;

    try std.testing.expectError(error.EventTooNew, HttpAuth.validate(json, "https://api.example.com", "GET", null, null));
}

test "HttpAuth.validateAndVerify with valid signature" {
    const event_mod = @import("event.zig");
    const builder_mod = @import("builder.zig");
    try event_mod.init();
    defer event_mod.cleanup();

    const keypair = builder_mod.Keypair.generate();
    const url = "https://api.example.com/v1/resource";
    const method = "POST";

    const tags = &[_][]const []const u8{
        &[_][]const u8{ "u", url },
        &[_][]const u8{ "method", method },
    };

    var builder = builder_mod.EventBuilder{};
    _ = builder.setKind(HttpAuth.Kind).setContent("").setTags(tags);
    try builder.sign(&keypair);

    var json_buf: [2048]u8 = undefined;
    const json = try builder.serialize(&json_buf);

    const pubkey = try HttpAuth.validateAndVerify(json, url, method, null, null);
    try std.testing.expectEqualSlices(u8, &keypair.public_key, &pubkey);
}

test "HttpAuth.validateAndVerify rejects invalid signature" {
    const event_mod = @import("event.zig");
    try event_mod.init();
    defer event_mod.cleanup();

    // Manually crafted event with invalid signature
    const now = std.time.timestamp();
    var json_buf: [512]u8 = undefined;
    const json = std.fmt.bufPrint(&json_buf,
        \\{{"id":"0000000000000000000000000000000000000000000000000000000000000000","pubkey":"0000000000000000000000000000000000000000000000000000000000000000","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","kind":27235,"created_at":{d},"content":"","tags":[["u","https://api.example.com"],["method","GET"]]}}
    , .{now}) catch unreachable;

    try std.testing.expectError(error.SignatureInvalid, HttpAuth.validateAndVerify(json, "https://api.example.com", "GET", null, null));
}

test "HttpAuth.validateAndVerify rejects wrong kind" {
    const event_mod = @import("event.zig");
    const builder_mod = @import("builder.zig");
    try event_mod.init();
    defer event_mod.cleanup();

    const keypair = builder_mod.Keypair.generate();
    const url = "https://api.example.com";

    const tags = &[_][]const []const u8{
        &[_][]const u8{ "u", url },
        &[_][]const u8{ "method", "GET" },
    };

    var builder = builder_mod.EventBuilder{};
    _ = builder.setKind(1).setContent("").setTags(tags); // Wrong kind
    try builder.sign(&keypair);

    var json_buf: [2048]u8 = undefined;
    const json = try builder.serialize(&json_buf);

    try std.testing.expectError(error.InvalidKind, HttpAuth.validateAndVerify(json, url, "GET", null, null));
}

test "HttpAuth.validateAndVerify with payload hash" {
    const event_mod = @import("event.zig");
    const builder_mod = @import("builder.zig");
    try event_mod.init();
    defer event_mod.cleanup();

    const keypair = builder_mod.Keypair.generate();
    const url = "https://api.example.com/upload";
    const body = "{\"data\":\"test\"}";

    var payload_hash: [64]u8 = undefined;
    HttpAuth.computePayloadHash(body, &payload_hash);

    const tags = &[_][]const []const u8{
        &[_][]const u8{ "u", url },
        &[_][]const u8{ "method", "POST" },
        &[_][]const u8{ "payload", &payload_hash },
    };

    var builder = builder_mod.EventBuilder{};
    _ = builder.setKind(HttpAuth.Kind).setContent("").setTags(tags);
    try builder.sign(&keypair);

    var json_buf: [2048]u8 = undefined;
    const json = try builder.serialize(&json_buf);

    const pubkey = try HttpAuth.validateAndVerify(json, url, "POST", &payload_hash, null);
    try std.testing.expectEqualSlices(u8, &keypair.public_key, &pubkey);

    // Test with wrong payload hash
    var wrong_hash: [64]u8 = undefined;
    HttpAuth.computePayloadHash("wrong body", &wrong_hash);
    try std.testing.expectError(error.PayloadMismatch, HttpAuth.validateAndVerify(json, url, "POST", &wrong_hash, null));
}

test "HttpAuth.extractPubkey" {
    const json =
        \\{"id":"abc","pubkey":"63fe6318dc58583cfe16810f86dd09e18bfd76aabc24a0081ce2856f330504ed","sig":"ghi","kind":27235}
    ;
    const pubkey = HttpAuth.extractPubkey(json);
    try std.testing.expect(pubkey != null);

    const expected = [_]u8{ 0x63, 0xfe, 0x63, 0x18, 0xdc, 0x58, 0x58, 0x3c, 0xfe, 0x16, 0x81, 0x0f, 0x86, 0xdd, 0x09, 0xe1, 0x8b, 0xfd, 0x76, 0xaa, 0xbc, 0x24, 0xa0, 0x08, 0x1c, 0xe2, 0x85, 0x6f, 0x33, 0x05, 0x04, 0xed };
    try std.testing.expectEqualSlices(u8, &expected, &pubkey.?);
}
