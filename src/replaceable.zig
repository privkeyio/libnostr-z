const std = @import("std");
const event_mod = @import("event.zig");

pub const Event = event_mod.Event;
pub const kindType = event_mod.kindType;

pub const Replaceable = struct {
    pub const Decision = enum { accept_new, keep_old };

    pub fn buildKey(event: *const Event, buf: *[128]u8) usize {
        var key_len: usize = 0;

        @memcpy(buf[0..32], event.pubkey());
        key_len = 32;

        const kind_be = @byteSwap(@as(u32, @bitCast(event.kind())));
        @memcpy(buf[key_len..][0..4], std.mem.asBytes(&kind_be));
        key_len += 4;

        const kt = kindType(event.kind());
        if (kt == .addressable) {
            if (event.dTag()) |d| {
                const copy_len = @min(d.len, buf.len - key_len);
                @memcpy(buf[key_len..][0..copy_len], d[0..copy_len]);
                key_len += copy_len;
            }
        }

        return key_len;
    }

    pub fn shouldReplace(existing: *const Event, new: *const Event) Decision {
        if (new.createdAt() > existing.createdAt()) return .accept_new;
        if (new.createdAt() < existing.createdAt()) return .keep_old;
        if (std.mem.order(u8, new.id(), existing.id()) == .lt) return .accept_new;
        return .keep_old;
    }
};

test "buildKey for replaceable event" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"1111111111111111111111111111111111111111111111111111111111111111","pubkey":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":10002,"created_at":1700000000,"content":"","tags":[]}
    ;

    var event = try Event.parseWithAllocator(json, std.testing.allocator);
    defer event.deinit();

    var buf: [128]u8 = undefined;
    const key_len = Replaceable.buildKey(&event, &buf);

    try std.testing.expectEqual(@as(usize, 36), key_len);
    for (buf[0..32]) |b| try std.testing.expectEqual(@as(u8, 0xaa), b);
    const kind_bytes = buf[32..36];
    try std.testing.expectEqual(@as(u32, 10002), std.mem.readInt(u32, kind_bytes, .big));
}

test "buildKey for addressable event includes d-tag" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"1111111111111111111111111111111111111111111111111111111111111111","pubkey":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":30023,"created_at":1700000000,"content":"article","tags":[["d","my-article"]]}
    ;

    var event = try Event.parseWithAllocator(json, std.testing.allocator);
    defer event.deinit();

    var buf: [128]u8 = undefined;
    const key_len = Replaceable.buildKey(&event, &buf);

    try std.testing.expectEqual(@as(usize, 46), key_len);
    for (buf[0..32]) |b| try std.testing.expectEqual(@as(u8, 0xbb), b);
    try std.testing.expectEqualStrings("my-article", buf[36..46]);
}

test "shouldReplace newer timestamp wins" {
    try event_mod.init();
    defer event_mod.cleanup();

    const old_json =
        \\{"id":"1111111111111111111111111111111111111111111111111111111111111111","pubkey":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":0,"created_at":1700000000,"content":"old","tags":[]}
    ;
    const new_json =
        \\{"id":"2222222222222222222222222222222222222222222222222222222222222222","pubkey":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":0,"created_at":1700000001,"content":"new","tags":[]}
    ;

    var old = try Event.parseWithAllocator(old_json, std.testing.allocator);
    defer old.deinit();
    var new = try Event.parseWithAllocator(new_json, std.testing.allocator);
    defer new.deinit();

    try std.testing.expectEqual(Replaceable.Decision.accept_new, Replaceable.shouldReplace(&old, &new));
}

test "shouldReplace older timestamp keeps old" {
    try event_mod.init();
    defer event_mod.cleanup();

    const old_json =
        \\{"id":"1111111111111111111111111111111111111111111111111111111111111111","pubkey":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":0,"created_at":1700000001,"content":"old","tags":[]}
    ;
    const new_json =
        \\{"id":"2222222222222222222222222222222222222222222222222222222222222222","pubkey":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":0,"created_at":1700000000,"content":"new","tags":[]}
    ;

    var old = try Event.parseWithAllocator(old_json, std.testing.allocator);
    defer old.deinit();
    var new = try Event.parseWithAllocator(new_json, std.testing.allocator);
    defer new.deinit();

    try std.testing.expectEqual(Replaceable.Decision.keep_old, Replaceable.shouldReplace(&old, &new));
}

test "shouldReplace same timestamp lower id wins" {
    try event_mod.init();
    defer event_mod.cleanup();

    const old_json =
        \\{"id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","pubkey":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":0,"created_at":1700000000,"content":"old","tags":[]}
    ;
    const new_json =
        \\{"id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","pubkey":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":0,"created_at":1700000000,"content":"new","tags":[]}
    ;

    var old = try Event.parseWithAllocator(old_json, std.testing.allocator);
    defer old.deinit();
    var new = try Event.parseWithAllocator(new_json, std.testing.allocator);
    defer new.deinit();

    try std.testing.expectEqual(Replaceable.Decision.accept_new, Replaceable.shouldReplace(&old, &new));
}

test "shouldReplace same timestamp higher id keeps old" {
    try event_mod.init();
    defer event_mod.cleanup();

    const old_json =
        \\{"id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","pubkey":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":0,"created_at":1700000000,"content":"old","tags":[]}
    ;
    const new_json =
        \\{"id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","pubkey":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":0,"created_at":1700000000,"content":"new","tags":[]}
    ;

    var old = try Event.parseWithAllocator(old_json, std.testing.allocator);
    defer old.deinit();
    var new = try Event.parseWithAllocator(new_json, std.testing.allocator);
    defer new.deinit();

    try std.testing.expectEqual(Replaceable.Decision.keep_old, Replaceable.shouldReplace(&old, &new));
}
