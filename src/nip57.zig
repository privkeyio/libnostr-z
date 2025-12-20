const std = @import("std");
const utils = @import("utils.zig");
const hex = @import("hex.zig");

pub const Kind = struct {
    pub const zap_request: i32 = 9734;
    pub const zap_receipt: i32 = 9735;
};

pub const ZapRequest = struct {
    recipient_pubkey: ?[32]u8 = null,
    event_id: ?[32]u8 = null,
    sender_pubkey: ?[32]u8 = null,
    amount: ?u64 = null,
    lnurl: ?[]const u8 = null,
    content: []const u8 = "",
    event_kind: ?i32 = null,
    a_tag: ?[]const u8 = null,
    relays_json: ?[]const u8 = null,
    raw_json: []const u8,

    pub fn fromEvent(json: []const u8) ?ZapRequest {
        const kind = utils.extractIntField(json, "kind", i32) orelse return null;
        if (kind != Kind.zap_request) return null;

        var request = ZapRequest{ .raw_json = json };

        request.content = utils.extractJsonString(json, "content") orelse "";
        request.sender_pubkey = utils.extractHexField(json, "pubkey", 32);

        var iter = utils.TagIterator.init(json, "tags") orelse return request;
        while (iter.next()) |tag| {
            if (std.mem.eql(u8, tag.name, "p") and tag.value.len == 64) {
                if (request.recipient_pubkey == null) {
                    request.recipient_pubkey = parseHex32(tag.value);
                }
            } else if (std.mem.eql(u8, tag.name, "e") and tag.value.len == 64) {
                if (request.event_id == null) {
                    request.event_id = parseHex32(tag.value);
                }
            } else if (std.mem.eql(u8, tag.name, "amount")) {
                request.amount = std.fmt.parseInt(u64, tag.value, 10) catch null;
            } else if (std.mem.eql(u8, tag.name, "lnurl")) {
                request.lnurl = tag.value;
            } else if (std.mem.eql(u8, tag.name, "relays")) {
                request.relays_json = utils.findJsonValue(json, "tags");
            } else if (std.mem.eql(u8, tag.name, "a")) {
                request.a_tag = tag.value;
            } else if (std.mem.eql(u8, tag.name, "k")) {
                request.event_kind = std.fmt.parseInt(i32, tag.value, 10) catch null;
            }
        }

        if (request.relays_json == null) {
            request.relays_json = findRelaysTag(json);
        }

        return request;
    }

    pub fn validate(self: *const ZapRequest) ValidationError!void {
        if (self.recipient_pubkey == null) return error.MissingRecipient;
        if (self.relays_json == null) return error.MissingRelays;
    }

    /// Server-side validation per NIP-57 Appendix D.
    /// Validates: exactly one p tag, 0-1 e tags, valid a tag format if present.
    pub fn validateServer(self: *const ZapRequest) ValidationError!void {
        try self.validate();

        // Count p and e tags
        var p_count: usize = 0;
        var e_count: usize = 0;

        var iter = utils.TagIterator.init(self.raw_json, "tags") orelse return;
        while (iter.next()) |tag| {
            if (std.mem.eql(u8, tag.name, "p") and tag.value.len == 64) {
                p_count += 1;
            } else if (std.mem.eql(u8, tag.name, "e") and tag.value.len == 64) {
                e_count += 1;
            } else if (std.mem.eql(u8, tag.name, "a")) {
                if (!isValidEventCoordinate(tag.value)) {
                    return error.InvalidEventCoordinate;
                }
            }
        }

        if (p_count != 1) return error.MultiplePTags;
        if (e_count > 1) return error.MultipleETags;
    }

    pub fn validateWithAmount(self: *const ZapRequest, query_amount: u64) ValidationError!void {
        try self.validate();
        if (self.amount) |amt| {
            if (amt != query_amount) return error.AmountMismatch;
        }
    }

    pub fn getRelays(self: *const ZapRequest, buf: [][]const u8) usize {
        const tags_json = self.relays_json orelse return 0;
        return extractRelaysFromTags(tags_json, buf);
    }
};

pub const ZapReceipt = struct {
    recipient_pubkey: ?[32]u8 = null,
    sender_pubkey: ?[32]u8 = null,
    event_id: ?[32]u8 = null,
    bolt11: ?[]const u8 = null,
    description: ?[]const u8 = null,
    preimage: ?[]const u8 = null,
    event_kind: ?i32 = null,
    a_tag: ?[]const u8 = null,
    provider_pubkey: ?[32]u8 = null,
    raw_json: []const u8,

    pub fn fromEvent(json: []const u8) ?ZapReceipt {
        const kind = utils.extractIntField(json, "kind", i32) orelse return null;
        if (kind != Kind.zap_receipt) return null;

        var receipt = ZapReceipt{ .raw_json = json };
        receipt.provider_pubkey = utils.extractHexField(json, "pubkey", 32);

        var iter = utils.TagIterator.init(json, "tags") orelse return receipt;
        while (iter.next()) |tag| {
            if (std.mem.eql(u8, tag.name, "p") and tag.value.len == 64) {
                if (receipt.recipient_pubkey == null) {
                    receipt.recipient_pubkey = parseHex32(tag.value);
                }
            } else if (std.mem.eql(u8, tag.name, "P") and tag.value.len == 64) {
                receipt.sender_pubkey = parseHex32(tag.value);
            } else if (std.mem.eql(u8, tag.name, "e") and tag.value.len == 64) {
                if (receipt.event_id == null) {
                    receipt.event_id = parseHex32(tag.value);
                }
            } else if (std.mem.eql(u8, tag.name, "bolt11")) {
                receipt.bolt11 = tag.value;
            } else if (std.mem.eql(u8, tag.name, "description")) {
                receipt.description = findDescriptionValue(json);
            } else if (std.mem.eql(u8, tag.name, "preimage")) {
                receipt.preimage = tag.value;
            } else if (std.mem.eql(u8, tag.name, "a")) {
                receipt.a_tag = tag.value;
            } else if (std.mem.eql(u8, tag.name, "k")) {
                receipt.event_kind = std.fmt.parseInt(i32, tag.value, 10) catch null;
            }
        }

        return receipt;
    }

    pub fn validate(self: *const ZapReceipt) ValidationError!void {
        if (self.recipient_pubkey == null) return error.MissingRecipient;
        if (self.bolt11 == null) return error.MissingBolt11;
        if (self.description == null) return error.MissingDescription;
    }

    pub fn validateProvider(self: *const ZapReceipt, expected_pubkey: *const [32]u8) ValidationError!void {
        try self.validate();
        if (self.provider_pubkey) |pk| {
            if (!std.mem.eql(u8, &pk, expected_pubkey)) return error.InvalidProvider;
        } else {
            return error.InvalidProvider;
        }
    }

    /// Extract the embedded zap request from the description tag.
    /// Note: The description is JSON-escaped. Use getZapRequestBuf for proper parsing.
    /// This method only works if the description contains no escape sequences.
    pub fn getZapRequest(self: *const ZapReceipt) ?ZapRequest {
        const desc = self.description orelse return null;
        return ZapRequest.fromEvent(desc);
    }

    /// Extract the embedded zap request, unescaping the description into the provided buffer.
    /// This is the recommended method as zap request descriptions are JSON-escaped.
    pub fn getZapRequestBuf(self: *const ZapReceipt, buf: []u8) ?ZapRequest {
        const desc = self.description orelse return null;
        const unescaped = unescapeJsonString(desc, buf) orelse return null;
        return ZapRequest.fromEvent(unescaped);
    }

    pub fn extractInvoiceAmount(self: *const ZapReceipt) ?u64 {
        const bolt11 = self.bolt11 orelse return null;
        return parseBolt11Amount(bolt11);
    }
};

pub const ZapSplit = struct {
    pubkey: [32]u8,
    relay: []const u8,
    weight: u32,
};

pub fn parseZapSplits(json: []const u8, buf: []ZapSplit) usize {
    var count: usize = 0;
    var iter = utils.TagIterator.init(json, "tags") orelse return 0;

    while (iter.next()) |tag| {
        if (!std.mem.eql(u8, tag.name, "zap")) continue;
        if (count >= buf.len) break;
        if (tag.value.len != 64) continue;

        const pubkey = parseHex32(tag.value) orelse continue;
        const elements = findZapTagElements(json, tag.value);
        const weight: u32 = if (elements.weight) |w|
            std.fmt.parseInt(u32, w, 10) catch 0
        else
            0;

        buf[count] = .{
            .pubkey = pubkey,
            .relay = elements.relay orelse "",
            .weight = weight,
        };
        count += 1;
    }

    return count;
}

pub fn calculateSplitPercentages(splits: []const ZapSplit, percentages: []u32) void {
    if (splits.len == 0 or splits.len > percentages.len) return;

    var total_weight: u64 = 0;
    var has_weights = false;

    for (splits) |split| {
        if (split.weight > 0) {
            has_weights = true;
            total_weight += split.weight;
        }
    }

    if (!has_weights) {
        const equal_share: u32 = @intCast(100 / splits.len);
        var remainder: u32 = @intCast(100 % splits.len);
        for (splits, 0..) |_, i| {
            percentages[i] = equal_share + (if (remainder > 0) blk: {
                remainder -= 1;
                break :blk @as(u32, 1);
            } else 0);
        }
        return;
    }

    for (splits, 0..) |split, i| {
        if (split.weight > 0) {
            percentages[i] = @intCast((split.weight * 100) / total_weight);
        } else {
            percentages[i] = 0;
        }
    }
}

pub const ValidationError = error{
    MissingRecipient,
    MissingRelays,
    MissingBolt11,
    MissingDescription,
    AmountMismatch,
    InvalidProvider,
    MultiplePTags,
    MultipleETags,
    InvalidEventCoordinate,
};

fn parseHex32(hex_str: []const u8) ?[32]u8 {
    if (hex_str.len != 64) return null;
    var result: [32]u8 = undefined;
    hex.decode(hex_str, &result) catch return null;
    return result;
}

/// Validates event coordinate format: kind:pubkey:d-tag
/// Per NIP-01, format is "<kind>:<pubkey>:<d-tag>"
fn isValidEventCoordinate(coord: []const u8) bool {
    // Find first colon (after kind)
    const first_colon = std.mem.indexOfScalar(u8, coord, ':') orelse return false;
    if (first_colon == 0) return false;

    // Parse kind (must be valid integer)
    _ = std.fmt.parseInt(u32, coord[0..first_colon], 10) catch return false;

    // Find second colon (after pubkey)
    const rest = coord[first_colon + 1 ..];
    const second_colon = std.mem.indexOfScalar(u8, rest, ':') orelse return false;

    // Pubkey must be 64 hex chars
    if (second_colon != 64) return false;
    const pubkey_hex = rest[0..second_colon];

    // Validate hex characters
    for (pubkey_hex) |c| {
        const valid = (c >= '0' and c <= '9') or (c >= 'a' and c <= 'f') or (c >= 'A' and c <= 'F');
        if (!valid) return false;
    }

    // d-tag can be empty or any string (after the second colon)
    return true;
}

/// Unescape a JSON string value into the provided buffer.
/// Returns the unescaped slice, or null if buffer too small or invalid escape.
pub fn unescapeJsonString(input: []const u8, output: []u8) ?[]u8 {
    var out_pos: usize = 0;
    var in_pos: usize = 0;

    while (in_pos < input.len) {
        if (out_pos >= output.len) return null;

        if (input[in_pos] == '\\' and in_pos + 1 < input.len) {
            const next = input[in_pos + 1];
            const replacement: u8 = switch (next) {
                '"' => '"',
                '\\' => '\\',
                'n' => '\n',
                'r' => '\r',
                't' => '\t',
                '/' => '/',
                'b' => 0x08,
                'f' => 0x0C,
                'u' => {
                    // \uXXXX - handle basic ASCII range only
                    if (in_pos + 5 < input.len) {
                        const hex_chars = input[in_pos + 2 .. in_pos + 6];
                        const code = std.fmt.parseInt(u16, hex_chars, 16) catch {
                            in_pos += 1;
                            continue;
                        };
                        if (code < 128) {
                            output[out_pos] = @truncate(code);
                            out_pos += 1;
                            in_pos += 6;
                            continue;
                        }
                    }
                    // Non-ASCII or invalid - copy as-is
                    output[out_pos] = input[in_pos];
                    out_pos += 1;
                    in_pos += 1;
                    continue;
                },
                else => {
                    // Unknown escape, copy backslash
                    output[out_pos] = '\\';
                    out_pos += 1;
                    in_pos += 1;
                    continue;
                },
            };
            output[out_pos] = replacement;
            out_pos += 1;
            in_pos += 2;
        } else {
            output[out_pos] = input[in_pos];
            out_pos += 1;
            in_pos += 1;
        }
    }

    return output[0..out_pos];
}

fn findRelaysTag(json: []const u8) ?[]const u8 {
    const tags_start = std.mem.indexOf(u8, json, "\"tags\"") orelse return null;
    const search_region = json[tags_start..];

    const relays_marker = std.mem.indexOf(u8, search_region, "[\"relays\"") orelse return null;
    const tag_start = tags_start + relays_marker;

    var depth: i32 = 0;
    var in_string = false;
    var escape = false;
    var end = tag_start;

    for (json[tag_start..], 0..) |c, i| {
        if (escape) {
            escape = false;
            continue;
        }
        if (c == '\\' and in_string) {
            escape = true;
            continue;
        }
        if (c == '"') {
            in_string = !in_string;
            continue;
        }
        if (!in_string) {
            if (c == '[') depth += 1;
            if (c == ']') {
                depth -= 1;
                if (depth == 0) {
                    end = tag_start + i + 1;
                    break;
                }
            }
        }
    }

    return json[tag_start..end];
}

fn extractRelaysFromTags(tags_json: []const u8, buf: [][]const u8) usize {
    const relays_start = std.mem.indexOf(u8, tags_json, "[\"relays\"") orelse return 0;
    const tag_region = tags_json[relays_start..];

    var count: usize = 0;
    var pos: usize = 0;
    var found_relays = false;

    while (pos < tag_region.len) {
        if (tag_region[pos] == '"') {
            pos += 1;
            const start = pos;
            while (pos < tag_region.len and tag_region[pos] != '"') : (pos += 1) {}
            const value = tag_region[start..pos];
            pos += 1;

            if (std.mem.eql(u8, value, "relays")) {
                found_relays = true;
            } else if (found_relays and std.mem.startsWith(u8, value, "ws")) {
                if (count < buf.len) {
                    buf[count] = value;
                    count += 1;
                }
            }
        } else if (tag_region[pos] == ']') {
            break;
        } else {
            pos += 1;
        }
    }

    return count;
}

fn findDescriptionValue(json: []const u8) ?[]const u8 {
    const desc_marker = std.mem.indexOf(u8, json, "[\"description\"") orelse return null;
    const search_start = desc_marker + 14;
    if (search_start >= json.len) return null;

    var pos = search_start;
    while (pos < json.len and json[pos] != '"') : (pos += 1) {}
    if (pos >= json.len) return null;
    pos += 1;

    const value_start = pos;
    var escape = false;
    while (pos < json.len) {
        if (escape) {
            escape = false;
            pos += 1;
            continue;
        }
        if (json[pos] == '\\') {
            escape = true;
            pos += 1;
            continue;
        }
        if (json[pos] == '"') {
            return json[value_start..pos];
        }
        pos += 1;
    }
    return null;
}

fn findZapTagElements(tags_json: []const u8, pubkey_hex: []const u8) struct { relay: ?[]const u8, weight: ?[]const u8 } {
    const pubkey_pos = std.mem.indexOf(u8, tags_json, pubkey_hex) orelse return .{ .relay = null, .weight = null };

    var scan_pos = pubkey_pos + pubkey_hex.len;

    while (scan_pos < tags_json.len and tags_json[scan_pos] != '"') : (scan_pos += 1) {}
    if (scan_pos >= tags_json.len) return .{ .relay = null, .weight = null };
    scan_pos += 1;

    var relay: ?[]const u8 = null;
    var weight: ?[]const u8 = null;
    var element_count: usize = 0;

    while (scan_pos < tags_json.len) {
        while (scan_pos < tags_json.len and (tags_json[scan_pos] == ' ' or tags_json[scan_pos] == ',' or tags_json[scan_pos] == '\t')) : (scan_pos += 1) {}

        if (scan_pos >= tags_json.len or tags_json[scan_pos] == ']') break;

        if (tags_json[scan_pos] == '"') {
            scan_pos += 1;
            const elem_start = scan_pos;
            while (scan_pos < tags_json.len and tags_json[scan_pos] != '"') : (scan_pos += 1) {}
            if (scan_pos < tags_json.len) {
                const elem = tags_json[elem_start..scan_pos];
                if (element_count == 0) {
                    relay = elem;
                } else if (element_count == 1) {
                    weight = elem;
                }
                element_count += 1;
                scan_pos += 1;
            }
        } else {
            scan_pos += 1;
        }
    }

    return .{ .relay = relay, .weight = weight };
}

fn parseBolt11Amount(bolt11: []const u8) ?u64 {
    if (!std.mem.startsWith(u8, bolt11, "lnbc")) return null;

    var pos: usize = 4;
    const amount_start = pos;

    while (pos < bolt11.len and bolt11[pos] >= '0' and bolt11[pos] <= '9') : (pos += 1) {}

    if (pos == amount_start or pos >= bolt11.len) return null;

    const amount = std.fmt.parseInt(u64, bolt11[amount_start..pos], 10) catch return null;
    const multiplier = bolt11[pos];

    return switch (multiplier) {
        'm' => amount * 100_000_000,
        'u' => amount * 100_000,
        'n' => amount * 100,
        'p' => amount / 10,
        else => null,
    };
}

test "Kind constants" {
    try std.testing.expectEqual(@as(i32, 9734), Kind.zap_request);
    try std.testing.expectEqual(@as(i32, 9735), Kind.zap_receipt);
}

test "ZapRequest.fromEvent parses valid zap request" {
    const json =
        \\{"kind":9734,"content":"Zap!","tags":[["relays","wss://relay.example.com"],["amount","21000"],["p","04c915daefee38317fa734444acee390a8269fe5810b2241e5e6dd343dfbecc9"],["e","9ae37aa68f48645127299e9453eb5d908a0cbb6058ff340d528ed4d37c8994fb"]],"pubkey":"97c70a44366a6535c145b333f973ea86dfdc2d7a99da618c40c64705ad98e322","created_at":1679673265,"id":"30efed56a035b2549fcaeec0bf2c1595f9a9b3bb4b1a38abaf8ee9041c4b7d93","sig":"f2cb581a84ed10e4dc84937bd98e27acac71ab057255f6aa8dfa561808c981fe8870f4a03c1e3666784d82a9c802d3704e174371aa13d63e2aeaf24ff5374d9d"}
    ;

    const request = ZapRequest.fromEvent(json).?;

    try std.testing.expectEqualStrings("Zap!", request.content);
    try std.testing.expectEqual(@as(?u64, 21000), request.amount);
    try std.testing.expect(request.recipient_pubkey != null);
    try std.testing.expect(request.event_id != null);
    try std.testing.expect(request.sender_pubkey != null);
}

test "ZapRequest.fromEvent returns null for wrong kind" {
    const json =
        \\{"kind":1,"content":"Hello","tags":[],"pubkey":"aaa","created_at":1,"id":"bbb","sig":"ccc"}
    ;

    try std.testing.expect(ZapRequest.fromEvent(json) == null);
}

test "ZapRequest.validate requires recipient" {
    const json =
        \\{"kind":9734,"content":"","tags":[["relays","wss://r.com"]],"pubkey":"97c70a44366a6535c145b333f973ea86dfdc2d7a99da618c40c64705ad98e322","created_at":1,"id":"aaa","sig":"bbb"}
    ;

    const request = ZapRequest.fromEvent(json).?;
    try std.testing.expectError(error.MissingRecipient, request.validate());
}

test "ZapRequest.validateWithAmount checks amount match" {
    const json =
        \\{"kind":9734,"content":"","tags":[["relays","wss://r.com"],["amount","21000"],["p","04c915daefee38317fa734444acee390a8269fe5810b2241e5e6dd343dfbecc9"]],"pubkey":"aaa","created_at":1,"id":"bbb","sig":"ccc"}
    ;

    const request = ZapRequest.fromEvent(json).?;
    try request.validateWithAmount(21000);
    try std.testing.expectError(error.AmountMismatch, request.validateWithAmount(10000));
}

test "ZapRequest.getRelays extracts relay URLs" {
    const json =
        \\{"kind":9734,"content":"","tags":[["relays","wss://relay1.com","wss://relay2.com"],["p","04c915daefee38317fa734444acee390a8269fe5810b2241e5e6dd343dfbecc9"]],"pubkey":"aaa","created_at":1,"id":"bbb","sig":"ccc"}
    ;

    const request = ZapRequest.fromEvent(json).?;
    var relay_buf: [10][]const u8 = undefined;
    const count = request.getRelays(&relay_buf);

    try std.testing.expect(count >= 1);
    try std.testing.expectEqualStrings("wss://relay1.com", relay_buf[0]);
}

test "ZapReceipt.fromEvent parses valid zap receipt" {
    const json =
        \\{"id":"67b48a14fb66c60c8f9070bdeb37afdfcc3d08ad01989460448e4081eddda446","pubkey":"9630f464cca6a5147aa8a35f0bcdd3ce485324e732fd39e09233b1d848238f31","created_at":1674164545,"kind":9735,"tags":[["p","32e1827635450ebb3c5a7d12c1f8e7b2b514439ac10a67eef3d9fd9c5c68e245"],["P","97c70a44366a6535c145b333f973ea86dfdc2d7a99da618c40c64705ad98e322"],["e","3624762a1274dd9636e0c552b53086d70bc88c165bc4dc0f9e836a1eaf86c3b8"],["bolt11","lnbc10u1p3unwfusp5t9r3yymhpfqculx78u027lxspgxcr2n2987mx2j55nnfs95nxnzqpp5jmrh92pfld78spqs78v9euf2385t83uvpwk9ldrlvf6ch7tpascqhp5zvkrmemgth3tufcvflmzjzfvjt023nazlhljz2n9hattj4f8jq8qxqyjw5qcqpjrzjqtc4fc44feggv7065fqe5m4ytjarg3repr5j9el35xhmtfexc42yczarjuqqfzqqqqqqqqlgqqqqqqgq9q9qxpqysgq079nkq507a5tw7xgttmj4u990j7wfggtrasah5gd4ywfr2pjcn29383tphp4t48gquelz9z78p4cq7ml3nrrphw5w6eckhjwmhezhnqpy6gyf0"],["description","{\"kind\":9734}"],["preimage","5d006d2cf1e73c7148e7519a4c68adc81642ce0e25a432b2434c99f97344c15f"]],"content":""}
    ;

    const receipt = ZapReceipt.fromEvent(json).?;

    try std.testing.expect(receipt.recipient_pubkey != null);
    try std.testing.expect(receipt.sender_pubkey != null);
    try std.testing.expect(receipt.event_id != null);
    try std.testing.expect(receipt.bolt11 != null);
    try std.testing.expect(receipt.preimage != null);
    try std.testing.expect(receipt.provider_pubkey != null);
}

test "ZapReceipt.fromEvent returns null for wrong kind" {
    const json =
        \\{"kind":1,"content":"","tags":[],"pubkey":"aaa","created_at":1,"id":"bbb","sig":"ccc"}
    ;

    try std.testing.expect(ZapReceipt.fromEvent(json) == null);
}

test "ZapReceipt.validate requires fields" {
    const json =
        \\{"kind":9735,"content":"","tags":[],"pubkey":"9630f464cca6a5147aa8a35f0bcdd3ce485324e732fd39e09233b1d848238f31","created_at":1,"id":"aaa","sig":"bbb"}
    ;

    const receipt = ZapReceipt.fromEvent(json).?;
    try std.testing.expectError(error.MissingRecipient, receipt.validate());
}

test "ZapReceipt.validateProvider checks pubkey" {
    const json =
        \\{"kind":9735,"content":"","tags":[["p","32e1827635450ebb3c5a7d12c1f8e7b2b514439ac10a67eef3d9fd9c5c68e245"],["bolt11","lnbc1"],["description","{}"]],"pubkey":"9630f464cca6a5147aa8a35f0bcdd3ce485324e732fd39e09233b1d848238f31","created_at":1,"id":"aaa","sig":"bbb"}
    ;

    const receipt = ZapReceipt.fromEvent(json).?;

    var expected: [32]u8 = undefined;
    hex.decode("9630f464cca6a5147aa8a35f0bcdd3ce485324e732fd39e09233b1d848238f31", &expected) catch unreachable;
    try receipt.validateProvider(&expected);

    var wrong: [32]u8 = undefined;
    @memset(&wrong, 0);
    try std.testing.expectError(error.InvalidProvider, receipt.validateProvider(&wrong));
}

test "ZapReceipt.extractInvoiceAmount parses bolt11" {
    const json =
        \\{"kind":9735,"content":"","tags":[["p","32e1827635450ebb3c5a7d12c1f8e7b2b514439ac10a67eef3d9fd9c5c68e245"],["bolt11","lnbc10u1rest"],["description","{}"]],"pubkey":"aaa","created_at":1,"id":"bbb","sig":"ccc"}
    ;

    const receipt = ZapReceipt.fromEvent(json).?;
    const amount = receipt.extractInvoiceAmount();
    try std.testing.expectEqual(@as(?u64, 1_000_000), amount);
}

test "parseBolt11Amount" {
    try std.testing.expectEqual(@as(?u64, 100_000_000), parseBolt11Amount("lnbc1m1rest"));
    try std.testing.expectEqual(@as(?u64, 1_000_000), parseBolt11Amount("lnbc10u1rest"));
    try std.testing.expectEqual(@as(?u64, 100_000), parseBolt11Amount("lnbc1u1rest"));
    try std.testing.expectEqual(@as(?u64, 1000), parseBolt11Amount("lnbc10n1rest"));
    try std.testing.expectEqual(@as(?u64, 1), parseBolt11Amount("lnbc10p1rest"));
    try std.testing.expect(parseBolt11Amount("invalid") == null);
}

test "parseZapSplits" {
    const json =
        \\{"tags":[["zap","82341f882b6eabcd2ba7f1ef90aad961cf074af15b9ef44a09f9d2a8fbfbe6a2","wss://nostr.oxtr.dev","1"],["zap","fa984bd7dbb282f07e16e7ae87b26a2a7b9b90b7246a44771f0cf5ae58018f52","wss://nostr.wine/","1"],["zap","460c25e682fda7832b52d1f22d3d22b3176d972f60dcdc3212ed8c92ef85065c","wss://nos.lol/","2"]]}
    ;

    var splits: [10]ZapSplit = undefined;
    const count = parseZapSplits(json, &splits);

    try std.testing.expectEqual(@as(usize, 3), count);
    try std.testing.expectEqualStrings("wss://nostr.oxtr.dev", splits[0].relay);
    try std.testing.expectEqual(@as(u32, 1), splits[0].weight);
    try std.testing.expectEqualStrings("wss://nostr.wine/", splits[1].relay);
    try std.testing.expectEqual(@as(u32, 1), splits[1].weight);
    try std.testing.expectEqualStrings("wss://nos.lol/", splits[2].relay);
    try std.testing.expectEqual(@as(u32, 2), splits[2].weight);
}

test "calculateSplitPercentages with weights" {
    var splits = [_]ZapSplit{
        .{ .pubkey = undefined, .relay = "", .weight = 1 },
        .{ .pubkey = undefined, .relay = "", .weight = 1 },
        .{ .pubkey = undefined, .relay = "", .weight = 2 },
    };

    var percentages: [3]u32 = undefined;
    calculateSplitPercentages(&splits, &percentages);

    try std.testing.expectEqual(@as(u32, 25), percentages[0]);
    try std.testing.expectEqual(@as(u32, 25), percentages[1]);
    try std.testing.expectEqual(@as(u32, 50), percentages[2]);
}

test "calculateSplitPercentages without weights" {
    var splits = [_]ZapSplit{
        .{ .pubkey = undefined, .relay = "", .weight = 0 },
        .{ .pubkey = undefined, .relay = "", .weight = 0 },
        .{ .pubkey = undefined, .relay = "", .weight = 0 },
    };

    var percentages: [3]u32 = undefined;
    calculateSplitPercentages(&splits, &percentages);

    try std.testing.expectEqual(@as(u32, 34), percentages[0]);
    try std.testing.expectEqual(@as(u32, 33), percentages[1]);
    try std.testing.expectEqual(@as(u32, 33), percentages[2]);
}

test "isValidEventCoordinate" {
    // Valid coordinates
    try std.testing.expect(isValidEventCoordinate("30023:04c915daefee38317fa734444acee390a8269fe5810b2241e5e6dd343dfbecc9:test"));
    try std.testing.expect(isValidEventCoordinate("30023:04c915daefee38317fa734444acee390a8269fe5810b2241e5e6dd343dfbecc9:"));
    try std.testing.expect(isValidEventCoordinate("1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:identifier"));

    // Invalid coordinates
    try std.testing.expect(!isValidEventCoordinate("invalid"));
    try std.testing.expect(!isValidEventCoordinate(":pubkey:dtag"));
    try std.testing.expect(!isValidEventCoordinate("30023:short:dtag"));
    try std.testing.expect(!isValidEventCoordinate("30023:gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg:dtag"));
    try std.testing.expect(!isValidEventCoordinate("notanumber:04c915daefee38317fa734444acee390a8269fe5810b2241e5e6dd343dfbecc9:test"));
}

test "unescapeJsonString" {
    var buf: [256]u8 = undefined;

    // Basic escapes
    const result1 = unescapeJsonString("hello\\nworld", &buf).?;
    try std.testing.expectEqualStrings("hello\nworld", result1);

    const result2 = unescapeJsonString("test\\\"quote\\\"", &buf).?;
    try std.testing.expectEqualStrings("test\"quote\"", result2);

    const result3 = unescapeJsonString("back\\\\slash", &buf).?;
    try std.testing.expectEqualStrings("back\\slash", result3);

    // No escapes
    const result4 = unescapeJsonString("plain text", &buf).?;
    try std.testing.expectEqualStrings("plain text", result4);

    // Complex JSON-like content
    const result5 = unescapeJsonString("{\\\"kind\\\":9734}", &buf).?;
    try std.testing.expectEqualStrings("{\"kind\":9734}", result5);
}

test "ZapRequest.validateServer rejects multiple p tags" {
    const json =
        \\{"kind":9734,"content":"","tags":[["relays","wss://r.com"],["p","04c915daefee38317fa734444acee390a8269fe5810b2241e5e6dd343dfbecc9"],["p","32e1827635450ebb3c5a7d12c1f8e7b2b514439ac10a67eef3d9fd9c5c68e245"]],"pubkey":"aaa","created_at":1,"id":"bbb","sig":"ccc"}
    ;

    const request = ZapRequest.fromEvent(json).?;
    try std.testing.expectError(error.MultiplePTags, request.validateServer());
}

test "ZapRequest.validateServer rejects multiple e tags" {
    const json =
        \\{"kind":9734,"content":"","tags":[["relays","wss://r.com"],["p","04c915daefee38317fa734444acee390a8269fe5810b2241e5e6dd343dfbecc9"],["e","9ae37aa68f48645127299e9453eb5d908a0cbb6058ff340d528ed4d37c8994fb"],["e","3624762a1274dd9636e0c552b53086d70bc88c165bc4dc0f9e836a1eaf86c3b8"]],"pubkey":"aaa","created_at":1,"id":"bbb","sig":"ccc"}
    ;

    const request = ZapRequest.fromEvent(json).?;
    try std.testing.expectError(error.MultipleETags, request.validateServer());
}

test "ZapRequest.validateServer accepts valid request" {
    const json =
        \\{"kind":9734,"content":"","tags":[["relays","wss://r.com"],["p","04c915daefee38317fa734444acee390a8269fe5810b2241e5e6dd343dfbecc9"],["e","9ae37aa68f48645127299e9453eb5d908a0cbb6058ff340d528ed4d37c8994fb"]],"pubkey":"aaa","created_at":1,"id":"bbb","sig":"ccc"}
    ;

    const request = ZapRequest.fromEvent(json).?;
    try request.validateServer();
}

test "ZapRequest.validateServer rejects invalid a tag" {
    const json =
        \\{"kind":9734,"content":"","tags":[["relays","wss://r.com"],["p","04c915daefee38317fa734444acee390a8269fe5810b2241e5e6dd343dfbecc9"],["a","invalid_coordinate"]],"pubkey":"aaa","created_at":1,"id":"bbb","sig":"ccc"}
    ;

    const request = ZapRequest.fromEvent(json).?;
    try std.testing.expectError(error.InvalidEventCoordinate, request.validateServer());
}

test "ZapReceipt.getZapRequestBuf extracts embedded zap request" {
    // This JSON contains an escaped zap request in the description
    const json =
        \\{"kind":9735,"content":"","tags":[["p","32e1827635450ebb3c5a7d12c1f8e7b2b514439ac10a67eef3d9fd9c5c68e245"],["bolt11","lnbc1"],["description","{\"kind\":9734,\"content\":\"\",\"tags\":[[\"relays\",\"wss://r.com\"],[\"p\",\"04c915daefee38317fa734444acee390a8269fe5810b2241e5e6dd343dfbecc9\"]],\"pubkey\":\"aaa\",\"created_at\":1,\"id\":\"bbb\",\"sig\":\"ccc\"}"]],"pubkey":"9630f464cca6a5147aa8a35f0bcdd3ce485324e732fd39e09233b1d848238f31","created_at":1,"id":"aaa","sig":"bbb"}
    ;

    const receipt = ZapReceipt.fromEvent(json).?;
    var buf: [1024]u8 = undefined;
    const zap_request = receipt.getZapRequestBuf(&buf);

    try std.testing.expect(zap_request != null);
    try std.testing.expect(zap_request.?.recipient_pubkey != null);
}
