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
