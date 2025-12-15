const std = @import("std");

pub const NonceTag = struct {
    nonce: u64,
    target_difficulty: ?u8,
};

pub fn countLeadingZeroBits(hash: *const [32]u8) u16 {
    var count: u16 = 0;
    for (hash) |byte| {
        if (byte == 0) {
            count += 8;
        } else {
            count += @clz(byte);
            break;
        }
    }
    return count;
}

pub fn getDifficulty(id_bytes: *const [32]u8) u16 {
    return countLeadingZeroBits(id_bytes);
}

pub fn checkDifficulty(id_bytes: *const [32]u8, min_difficulty: u8) bool {
    return countLeadingZeroBits(id_bytes) >= min_difficulty;
}

pub fn getNonceTag(json: []const u8) ?NonceTag {
    const parsed = std.json.parseFromSlice(std.json.Value, std.heap.page_allocator, json, .{}) catch return null;
    defer parsed.deinit();

    const root = switch (parsed.value) {
        .object => |obj| obj,
        else => return null,
    };

    const tags_val = root.get("tags") orelse return null;
    if (tags_val != .array) return null;

    for (tags_val.array.items) |tag| {
        if (tag != .array or tag.array.items.len < 2) continue;

        const tag_name = if (tag.array.items[0] == .string) tag.array.items[0].string else continue;
        if (!std.mem.eql(u8, tag_name, "nonce")) continue;

        const nonce_str = if (tag.array.items[1] == .string) tag.array.items[1].string else continue;
        const nonce = std.fmt.parseInt(u64, nonce_str, 10) catch continue;

        var target: ?u8 = null;
        if (tag.array.items.len >= 3) {
            if (tag.array.items[2] == .string) {
                target = std.fmt.parseInt(u8, tag.array.items[2].string, 10) catch null;
            }
        }

        return NonceTag{
            .nonce = nonce,
            .target_difficulty = target,
        };
    }

    return null;
}

pub fn checkCommittedDifficulty(id_bytes: *const [32]u8, json: []const u8, min_difficulty: u8) bool {
    const actual_difficulty = countLeadingZeroBits(id_bytes);
    if (actual_difficulty < min_difficulty) return false;

    if (getNonceTag(json)) |nonce_tag| {
        if (nonce_tag.target_difficulty) |committed| {
            return committed >= min_difficulty;
        }
    }

    return true;
}

test "countLeadingZeroBits - all zeros" {
    const hash = [_]u8{0} ** 32;
    try std.testing.expectEqual(@as(u16, 256), countLeadingZeroBits(&hash));
}

test "countLeadingZeroBits - example from NIP-13" {
    var hash: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&hash, "000000000e9d97a1ab09fc381030b346cdd7a142ad57e6df0b46dc9bef6c7e2d") catch unreachable;
    try std.testing.expectEqual(@as(u16, 36), countLeadingZeroBits(&hash));
}

test "countLeadingZeroBits - 002f prefix has 10 leading zeros" {
    var hash: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&hash, "002f000000000000000000000000000000000000000000000000000000000000") catch unreachable;
    try std.testing.expectEqual(@as(u16, 10), countLeadingZeroBits(&hash));
}

test "countLeadingZeroBits - 0x07 prefix" {
    var hash: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&hash, "0700000000000000000000000000000000000000000000000000000000000000") catch unreachable;
    try std.testing.expectEqual(@as(u16, 5), countLeadingZeroBits(&hash));
}

test "countLeadingZeroBits - 0x08 prefix" {
    var hash: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&hash, "0800000000000000000000000000000000000000000000000000000000000000") catch unreachable;
    try std.testing.expectEqual(@as(u16, 4), countLeadingZeroBits(&hash));
}

test "countLeadingZeroBits - no leading zeros" {
    var hash: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&hash, "ff00000000000000000000000000000000000000000000000000000000000000") catch unreachable;
    try std.testing.expectEqual(@as(u16, 0), countLeadingZeroBits(&hash));
}

test "getNonceTag - parses nonce tag" {
    const json =
        \\{"id":"000006d8c378af1779d2feebc7603a125d99eca0ccf1085959b307f64e5dd358","pubkey":"a48380f4cfcc1ad5378294fcac36439770f9c878dd880ffa94bb74ea54a6f243","created_at":1651794653,"kind":1,"tags":[["nonce","776797","20"]],"content":"test","sig":"284622fc0a3f4f1303455d5175f7ba962a3300d136085b9566801bc2e0699de0c7e31e44c81fb40ad9049173742e904713c3594a1da0fc5d2382a25c11aba977"}
    ;

    const nonce_tag = getNonceTag(json).?;
    try std.testing.expectEqual(@as(u64, 776797), nonce_tag.nonce);
    try std.testing.expectEqual(@as(u8, 20), nonce_tag.target_difficulty.?);
}

test "getNonceTag - parses nonce tag without target" {
    const json =
        \\{"id":"test","pubkey":"test","created_at":0,"kind":1,"tags":[["nonce","12345"]],"content":"test","sig":"test"}
    ;

    const nonce_tag = getNonceTag(json).?;
    try std.testing.expectEqual(@as(u64, 12345), nonce_tag.nonce);
    try std.testing.expect(nonce_tag.target_difficulty == null);
}

test "getNonceTag - returns null when no nonce tag" {
    const json =
        \\{"id":"test","pubkey":"test","created_at":0,"kind":1,"tags":[["e","test"]],"content":"test","sig":"test"}
    ;

    try std.testing.expect(getNonceTag(json) == null);
}

test "checkCommittedDifficulty - accepts matching difficulty" {
    var hash: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&hash, "000006d8c378af1779d2feebc7603a125d99eca0ccf1085959b307f64e5dd358") catch unreachable;

    const json =
        \\{"tags":[["nonce","776797","20"]]}
    ;

    try std.testing.expect(checkCommittedDifficulty(&hash, json, 20));
    try std.testing.expect(checkCommittedDifficulty(&hash, json, 15));
}

test "checkCommittedDifficulty - rejects lower committed target" {
    var hash: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&hash, "000006d8c378af1779d2feebc7603a125d99eca0ccf1085959b307f64e5dd358") catch unreachable;

    const json =
        \\{"tags":[["nonce","776797","15"]]}
    ;

    try std.testing.expect(!checkCommittedDifficulty(&hash, json, 20));
}

test "checkCommittedDifficulty - accepts when no committed target" {
    var hash: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&hash, "000006d8c378af1779d2feebc7603a125d99eca0ccf1085959b307f64e5dd358") catch unreachable;

    const json =
        \\{"tags":[["nonce","776797"]]}
    ;

    try std.testing.expect(checkCommittedDifficulty(&hash, json, 20));
}

test "NIP-13 example event verification" {
    const json =
        \\{"id":"000006d8c378af1779d2feebc7603a125d99eca0ccf1085959b307f64e5dd358","pubkey":"a48380f4cfcc1ad5378294fcac36439770f9c878dd880ffa94bb74ea54a6f243","created_at":1651794653,"kind":1,"tags":[["nonce","776797","20"]],"content":"It's just me mining my own business","sig":"284622fc0a3f4f1303455d5175f7ba962a3300d136085b9566801bc2e0699de0c7e31e44c81fb40ad9049173742e904713c3594a1da0fc5d2382a25c11aba977"}
    ;

    var id_bytes: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&id_bytes, "000006d8c378af1779d2feebc7603a125d99eca0ccf1085959b307f64e5dd358") catch unreachable;

    const difficulty = getDifficulty(&id_bytes);
    try std.testing.expect(difficulty >= 20);

    try std.testing.expect(checkDifficulty(&id_bytes, 20));
    try std.testing.expect(checkCommittedDifficulty(&id_bytes, json, 20));

    const nonce_tag = getNonceTag(json).?;
    try std.testing.expectEqual(@as(u64, 776797), nonce_tag.nonce);
    try std.testing.expectEqual(@as(?u8, 20), nonce_tag.target_difficulty);
}
