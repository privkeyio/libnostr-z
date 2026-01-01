const std = @import("std");
const hex = @import("hex.zig");
const utils = @import("utils.zig");

pub const Identifier = struct {
    local_part: []const u8,
    domain: []const u8,

    pub fn parse(identifier: []const u8) ?Identifier {
        const at_pos = std.mem.indexOfScalar(u8, identifier, '@') orelse return null;
        if (at_pos == 0) return null;
        if (at_pos >= identifier.len - 1) return null;

        const local_part = identifier[0..at_pos];
        const domain = identifier[at_pos + 1 ..];

        if (!isValidLocalPart(local_part)) return null;
        if (domain.len == 0) return null;

        return .{ .local_part = local_part, .domain = domain };
    }

    pub fn isRoot(self: *const Identifier) bool {
        return self.local_part.len == 1 and self.local_part[0] == '_';
    }

    pub fn formatUrl(self: *const Identifier, buf: []u8) ![]u8 {
        var fbs = std.io.fixedBufferStream(buf);
        const writer = fbs.writer();
        try writer.writeAll("https://");
        try writer.writeAll(self.domain);
        try writer.writeAll("/.well-known/nostr.json?name=");
        try percentEncode(writer, self.local_part);
        return fbs.getWritten();
    }

    pub fn formatDisplay(self: *const Identifier, buf: []u8) ![]u8 {
        var fbs = std.io.fixedBufferStream(buf);
        const writer = fbs.writer();
        if (self.isRoot()) {
            try writer.writeAll(self.domain);
        } else {
            try writer.writeAll(self.local_part);
            try writer.writeByte('@');
            try writer.writeAll(self.domain);
        }
        return fbs.getWritten();
    }
};

pub const Response = struct {
    json: []const u8,

    pub fn init(json: []const u8) Response {
        return .{ .json = json };
    }

    pub fn getPubkeyHex(self: *const Response, name: []const u8) ?[]const u8 {
        const names_json = utils.findJsonValue(self.json, "names") orelse return null;
        // NIP-05 specifies local-part is case-insensitive, so normalize to lowercase for lookup
        var name_lower_buf: [64]u8 = undefined;
        if (name.len > name_lower_buf.len) return null;
        const name_lower = toLowerSlice(name, &name_lower_buf);
        return utils.extractJsonString(names_json, name_lower);
    }

    pub fn getPubkey(self: *const Response, name: []const u8) ?[32]u8 {
        const pubkey_hex = self.getPubkeyHex(name) orelse return null;
        if (pubkey_hex.len != 64) return null;
        var pubkey: [32]u8 = undefined;
        hex.decode(pubkey_hex, &pubkey) catch return null;
        return pubkey;
    }

    pub fn verifyPubkey(self: *const Response, name: []const u8, expected_pubkey: *const [32]u8) bool {
        const pubkey = self.getPubkey(name) orelse return false;
        return std.mem.eql(u8, &pubkey, expected_pubkey);
    }

    pub fn verifyPubkeyHex(self: *const Response, name: []const u8, expected_hex: []const u8) bool {
        const pubkey_hex = self.getPubkeyHex(name) orelse return false;
        return std.ascii.eqlIgnoreCase(pubkey_hex, expected_hex);
    }

    pub fn getRelaysForPubkey(self: *const Response, pubkey_hex: []const u8) ?[]const u8 {
        const relays_json = utils.findJsonValue(self.json, "relays") orelse return null;
        return utils.findJsonValue(relays_json, pubkey_hex);
    }

    pub const RelayIterator = struct {
        json: []const u8,
        pos: usize,

        pub fn next(self: *RelayIterator) ?[]const u8 {
            // Skip to the opening quote of the next string
            while (self.pos < self.json.len and self.json[self.pos] != '"') {
                if (self.json[self.pos] == ']') return null;
                self.pos += 1;
            }
            if (self.pos >= self.json.len) return null;
            self.pos += 1; // Skip opening quote

            const start = self.pos;
            // Scan for closing quote, handling escape sequences
            while (self.pos < self.json.len) {
                if (self.json[self.pos] == '\\') {
                    // Skip escape sequence (backslash + next char)
                    self.pos += 2;
                    continue;
                }
                if (self.json[self.pos] == '"') break;
                self.pos += 1;
            }
            if (self.pos >= self.json.len) return null;

            const result = self.json[start..self.pos];
            self.pos += 1; // Skip closing quote
            return result;
        }
    };

    pub fn iterateRelays(self: *const Response, pubkey_hex: []const u8) ?RelayIterator {
        const relays_json = self.getRelaysForPubkey(pubkey_hex) orelse return null;
        return .{ .json = relays_json, .pos = 0 };
    }

    pub fn collectRelays(self: *const Response, pubkey_hex: []const u8, out: [][]const u8) usize {
        var iter = self.iterateRelays(pubkey_hex) orelse return 0;
        var count: usize = 0;
        while (iter.next()) |relay| {
            if (count >= out.len) break;
            out[count] = relay;
            count += 1;
        }
        return count;
    }
};

pub fn verify(identifier: []const u8, response_json: []const u8, expected_pubkey: *const [32]u8) bool {
    const id = Identifier.parse(identifier) orelse return false;
    const resp = Response.init(response_json);
    return resp.verifyPubkey(id.local_part, expected_pubkey);
}

pub fn verifyHex(identifier: []const u8, response_json: []const u8, expected_hex: []const u8) bool {
    const id = Identifier.parse(identifier) orelse return false;
    const resp = Response.init(response_json);
    return resp.verifyPubkeyHex(id.local_part, expected_hex);
}

fn isValidLocalPart(s: []const u8) bool {
    if (s.len == 0) return false;
    if (std.mem.indexOfScalar(u8, s, '%') != null) return false;
    for (s) |c| {
        const lower = std.ascii.toLower(c);
        const valid = (lower >= 'a' and lower <= 'z') or
            (c >= '0' and c <= '9') or
            c == '-' or c == '_' or c == '.';
        if (!valid) return false;
    }
    return true;
}

fn toLowerSlice(input: []const u8, buf: []u8) []u8 {
    const len = @min(input.len, buf.len);
    for (input[0..len], 0..) |c, i| {
        buf[i] = std.ascii.toLower(c);
    }
    return buf[0..len];
}

/// Percent-encode a string for use in URL query parameters (RFC 3986).
/// Note: Input is expected to be validated by isValidLocalPart(), which only
/// allows alphanumeric characters, '-', '_', and '.'. Since '%' is not allowed
/// in valid local parts, double-encoding cannot occur.
fn percentEncode(writer: anytype, input: []const u8) !void {
    for (input) |c| {
        if (std.ascii.isAlphanumeric(c) or c == '-' or c == '_' or c == '.' or c == '~') {
            try writer.writeByte(c);
        } else {
            try writer.print("%{X:0>2}", .{c});
        }
    }
}

test "Identifier.parse valid" {
    const id = Identifier.parse("bob@example.com").?;
    try std.testing.expectEqualStrings("bob", id.local_part);
    try std.testing.expectEqualStrings("example.com", id.domain);
    try std.testing.expect(!id.isRoot());
}

test "Identifier.parse root identifier" {
    const id = Identifier.parse("_@bob.com").?;
    try std.testing.expectEqualStrings("_", id.local_part);
    try std.testing.expectEqualStrings("bob.com", id.domain);
    try std.testing.expect(id.isRoot());
}

test "Identifier.parse with valid characters" {
    const id1 = Identifier.parse("alice-123@domain.org").?;
    try std.testing.expectEqualStrings("alice-123", id1.local_part);

    const id2 = Identifier.parse("user_name.test@sub.domain.com").?;
    try std.testing.expectEqualStrings("user_name.test", id2.local_part);

    const id3 = Identifier.parse("UPPER@example.com").?;
    try std.testing.expectEqualStrings("UPPER", id3.local_part);
}

test "Identifier.parse invalid" {
    try std.testing.expect(Identifier.parse("no-at-sign") == null);
    try std.testing.expect(Identifier.parse("@domain.com") == null);
    try std.testing.expect(Identifier.parse("user@") == null);
    try std.testing.expect(Identifier.parse("") == null);
    try std.testing.expect(Identifier.parse("invalid!char@domain.com") == null);
    try std.testing.expect(Identifier.parse("has space@domain.com") == null);
    try std.testing.expect(Identifier.parse("has+plus@domain.com") == null);
}

test "Identifier.formatUrl" {
    const id = Identifier.parse("bob@example.com").?;
    var buf: [256]u8 = undefined;
    const url = try id.formatUrl(&buf);
    try std.testing.expectEqualStrings("https://example.com/.well-known/nostr.json?name=bob", url);
}

test "Identifier.formatUrl with special chars" {
    const id = Identifier.parse("user_name.test@example.com").?;
    var buf: [256]u8 = undefined;
    const url = try id.formatUrl(&buf);
    try std.testing.expectEqualStrings("https://example.com/.well-known/nostr.json?name=user_name.test", url);
}

test "Identifier.formatDisplay normal" {
    const id = Identifier.parse("bob@example.com").?;
    var buf: [64]u8 = undefined;
    const display = try id.formatDisplay(&buf);
    try std.testing.expectEqualStrings("bob@example.com", display);
}

test "Identifier.formatDisplay root" {
    const id = Identifier.parse("_@bob.com").?;
    var buf: [64]u8 = undefined;
    const display = try id.formatDisplay(&buf);
    try std.testing.expectEqualStrings("bob.com", display);
}

test "Response.getPubkeyHex" {
    const json =
        \\{"names":{"bob":"b0635d6a9851d3aed0cd6c495b282167acf761729078d975fc341b22650b07b9"}}
    ;
    const resp = Response.init(json);
    const pubkey_hex = resp.getPubkeyHex("bob").?;
    try std.testing.expectEqualStrings("b0635d6a9851d3aed0cd6c495b282167acf761729078d975fc341b22650b07b9", pubkey_hex);
    try std.testing.expect(resp.getPubkeyHex("alice") == null);
}

test "Response.getPubkey" {
    const json =
        \\{"names":{"bob":"b0635d6a9851d3aed0cd6c495b282167acf761729078d975fc341b22650b07b9"}}
    ;
    const resp = Response.init(json);
    const pubkey = resp.getPubkey("bob").?;
    const expected = [_]u8{ 0xb0, 0x63, 0x5d, 0x6a, 0x98, 0x51, 0xd3, 0xae, 0xd0, 0xcd, 0x6c, 0x49, 0x5b, 0x28, 0x21, 0x67, 0xac, 0xf7, 0x61, 0x72, 0x90, 0x78, 0xd9, 0x75, 0xfc, 0x34, 0x1b, 0x22, 0x65, 0x0b, 0x07, 0xb9 };
    try std.testing.expectEqualSlices(u8, &expected, &pubkey);
}

test "Response.verifyPubkey" {
    const json =
        \\{"names":{"bob":"b0635d6a9851d3aed0cd6c495b282167acf761729078d975fc341b22650b07b9"}}
    ;
    const resp = Response.init(json);
    const correct_pubkey = [_]u8{ 0xb0, 0x63, 0x5d, 0x6a, 0x98, 0x51, 0xd3, 0xae, 0xd0, 0xcd, 0x6c, 0x49, 0x5b, 0x28, 0x21, 0x67, 0xac, 0xf7, 0x61, 0x72, 0x90, 0x78, 0xd9, 0x75, 0xfc, 0x34, 0x1b, 0x22, 0x65, 0x0b, 0x07, 0xb9 };
    var wrong_pubkey: [32]u8 = undefined;
    @memset(&wrong_pubkey, 0);

    try std.testing.expect(resp.verifyPubkey("bob", &correct_pubkey));
    try std.testing.expect(!resp.verifyPubkey("bob", &wrong_pubkey));
    try std.testing.expect(!resp.verifyPubkey("alice", &correct_pubkey));
}

test "Response.verifyPubkeyHex" {
    const json =
        \\{"names":{"bob":"b0635d6a9851d3aed0cd6c495b282167acf761729078d975fc341b22650b07b9"}}
    ;
    const resp = Response.init(json);
    try std.testing.expect(resp.verifyPubkeyHex("bob", "b0635d6a9851d3aed0cd6c495b282167acf761729078d975fc341b22650b07b9"));
    try std.testing.expect(resp.verifyPubkeyHex("bob", "B0635D6A9851D3AED0CD6C495B282167ACF761729078D975FC341B22650B07B9"));
    try std.testing.expect(!resp.verifyPubkeyHex("bob", "0000000000000000000000000000000000000000000000000000000000000000"));
}

test "Response with relays" {
    const json =
        \\{"names":{"bob":"b0635d6a9851d3aed0cd6c495b282167acf761729078d975fc341b22650b07b9"},"relays":{"b0635d6a9851d3aed0cd6c495b282167acf761729078d975fc341b22650b07b9":["wss://relay.example.com","wss://relay2.example.com"]}}
    ;
    const resp = Response.init(json);
    const pubkey_hex = "b0635d6a9851d3aed0cd6c495b282167acf761729078d975fc341b22650b07b9";

    var relays: [4][]const u8 = undefined;
    const count = resp.collectRelays(pubkey_hex, &relays);
    try std.testing.expectEqual(@as(usize, 2), count);
    try std.testing.expectEqualStrings("wss://relay.example.com", relays[0]);
    try std.testing.expectEqualStrings("wss://relay2.example.com", relays[1]);
}

test "Response relay iterator" {
    const json =
        \\{"names":{"bob":"b0635d6a9851d3aed0cd6c495b282167acf761729078d975fc341b22650b07b9"},"relays":{"b0635d6a9851d3aed0cd6c495b282167acf761729078d975fc341b22650b07b9":["wss://relay1.com","wss://relay2.com","wss://relay3.com"]}}
    ;
    const resp = Response.init(json);
    var iter = resp.iterateRelays("b0635d6a9851d3aed0cd6c495b282167acf761729078d975fc341b22650b07b9").?;

    try std.testing.expectEqualStrings("wss://relay1.com", iter.next().?);
    try std.testing.expectEqualStrings("wss://relay2.com", iter.next().?);
    try std.testing.expectEqualStrings("wss://relay3.com", iter.next().?);
    try std.testing.expect(iter.next() == null);
}

test "Response relay iterator with escaped characters" {
    // Test that the iterator correctly handles JSON escape sequences.
    // Note: The iterator returns raw JSON string slices (not decoded), so escape
    // sequences like \\ remain as-is. This is acceptable for relay URLs since they
    // should not contain characters that need escaping.
    const json =
        \\{"names":{"bob":"b0635d6a9851d3aed0cd6c495b282167acf761729078d975fc341b22650b07b9"},"relays":{"b0635d6a9851d3aed0cd6c495b282167acf761729078d975fc341b22650b07b9":["wss://relay1.com","wss://relay2.com\\path","wss://relay3.com"]}}
    ;
    const resp = Response.init(json);
    var iter = resp.iterateRelays("b0635d6a9851d3aed0cd6c495b282167acf761729078d975fc341b22650b07b9").?;

    try std.testing.expectEqualStrings("wss://relay1.com", iter.next().?);
    // The escaped backslash (\\) is preserved as raw bytes in the slice
    try std.testing.expectEqualStrings("wss://relay2.com\\\\path", iter.next().?);
    try std.testing.expectEqualStrings("wss://relay3.com", iter.next().?);
    try std.testing.expect(iter.next() == null);
}

test "Response no relays" {
    const json =
        \\{"names":{"bob":"b0635d6a9851d3aed0cd6c495b282167acf761729078d975fc341b22650b07b9"}}
    ;
    const resp = Response.init(json);
    try std.testing.expect(resp.iterateRelays("b0635d6a9851d3aed0cd6c495b282167acf761729078d975fc341b22650b07b9") == null);
}

test "verify convenience function" {
    const json =
        \\{"names":{"bob":"b0635d6a9851d3aed0cd6c495b282167acf761729078d975fc341b22650b07b9"}}
    ;
    const pubkey = [_]u8{ 0xb0, 0x63, 0x5d, 0x6a, 0x98, 0x51, 0xd3, 0xae, 0xd0, 0xcd, 0x6c, 0x49, 0x5b, 0x28, 0x21, 0x67, 0xac, 0xf7, 0x61, 0x72, 0x90, 0x78, 0xd9, 0x75, 0xfc, 0x34, 0x1b, 0x22, 0x65, 0x0b, 0x07, 0xb9 };
    try std.testing.expect(verify("bob@example.com", json, &pubkey));
    try std.testing.expect(!verify("alice@example.com", json, &pubkey));
}

test "verifyHex convenience function" {
    const json =
        \\{"names":{"bob":"b0635d6a9851d3aed0cd6c495b282167acf761729078d975fc341b22650b07b9"}}
    ;
    try std.testing.expect(verifyHex("bob@example.com", json, "b0635d6a9851d3aed0cd6c495b282167acf761729078d975fc341b22650b07b9"));
    try std.testing.expect(!verifyHex("bob@example.com", json, "0000000000000000000000000000000000000000000000000000000000000000"));
}

test "multiple names in response" {
    const json =
        \\{"names":{"alice":"a0635d6a9851d3aed0cd6c495b282167acf761729078d975fc341b22650b07b9","bob":"b0635d6a9851d3aed0cd6c495b282167acf761729078d975fc341b22650b07b9","charlie":"c0635d6a9851d3aed0cd6c495b282167acf761729078d975fc341b22650b07b9"}}
    ;
    const resp = Response.init(json);
    try std.testing.expect(resp.getPubkeyHex("alice") != null);
    try std.testing.expect(resp.getPubkeyHex("bob") != null);
    try std.testing.expect(resp.getPubkeyHex("charlie") != null);
    try std.testing.expect(resp.getPubkeyHex("dave") == null);
}

test "case-insensitive local part lookup" {
    const json =
        \\{"names":{"bob":"b0635d6a9851d3aed0cd6c495b282167acf761729078d975fc341b22650b07b9"}}
    ;
    const resp = Response.init(json);
    // NIP-05 specifies local-part is case-insensitive
    try std.testing.expect(resp.getPubkeyHex("bob") != null);
    try std.testing.expect(resp.getPubkeyHex("BOB") != null);
    try std.testing.expect(resp.getPubkeyHex("Bob") != null);
    try std.testing.expect(resp.getPubkeyHex("bOb") != null);

    const pubkey = [_]u8{ 0xb0, 0x63, 0x5d, 0x6a, 0x98, 0x51, 0xd3, 0xae, 0xd0, 0xcd, 0x6c, 0x49, 0x5b, 0x28, 0x21, 0x67, 0xac, 0xf7, 0x61, 0x72, 0x90, 0x78, 0xd9, 0x75, 0xfc, 0x34, 0x1b, 0x22, 0x65, 0x0b, 0x07, 0xb9 };
    try std.testing.expect(verify("BOB@example.com", json, &pubkey));
    try std.testing.expect(verify("Bob@example.com", json, &pubkey));
}

test "isValidLocalPart" {
    try std.testing.expect(isValidLocalPart("bob"));
    try std.testing.expect(isValidLocalPart("alice123"));
    try std.testing.expect(isValidLocalPart("user-name"));
    try std.testing.expect(isValidLocalPart("user_name"));
    try std.testing.expect(isValidLocalPart("user.name"));
    try std.testing.expect(isValidLocalPart("_"));
    try std.testing.expect(isValidLocalPart("UPPERCASE"));
    try std.testing.expect(isValidLocalPart("MixedCase123"));
    try std.testing.expect(!isValidLocalPart(""));
    try std.testing.expect(!isValidLocalPart("has space"));
    try std.testing.expect(!isValidLocalPart("has+plus"));
    try std.testing.expect(!isValidLocalPart("has@at"));
    try std.testing.expect(!isValidLocalPart("has!bang"));
    try std.testing.expect(!isValidLocalPart("pre%20encoded"));
    try std.testing.expect(!isValidLocalPart("bob%40example"));
}
