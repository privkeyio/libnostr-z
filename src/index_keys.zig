const std = @import("std");
const event_mod = @import("event.zig");

pub const Event = event_mod.Event;

pub const IndexKeys = struct {
    pub fn created(event: *const Event, buf: *[40]u8) void {
        const created_at_be = @byteSwap(@as(u64, @bitCast(event.createdAt())));
        @memcpy(buf[0..8], std.mem.asBytes(&created_at_be));
        @memcpy(buf[8..40], event.id());
    }

    pub fn pubkey(event: *const Event, buf: *[72]u8) void {
        const created_at_be = @byteSwap(@as(u64, @bitCast(event.createdAt())));
        @memcpy(buf[0..32], event.pubkey());
        @memcpy(buf[32..40], std.mem.asBytes(&created_at_be));
        @memcpy(buf[40..72], event.id());
    }

    pub fn kind(event: *const Event, buf: *[44]u8) void {
        const kind_be = @byteSwap(@as(u32, @bitCast(event.kind())));
        const created_at_be = @byteSwap(@as(u64, @bitCast(event.createdAt())));
        @memcpy(buf[0..4], std.mem.asBytes(&kind_be));
        @memcpy(buf[4..12], std.mem.asBytes(&created_at_be));
        @memcpy(buf[12..44], event.id());
    }

    pub fn expiration(event: *const Event, buf: *[40]u8) ?*[40]u8 {
        const exp = event.expiration_val orelse return null;
        if (exp < 0) return null;
        const exp_be = @byteSwap(@as(u64, @intCast(exp)));
        @memcpy(buf[0..8], std.mem.asBytes(&exp_be));
        @memcpy(buf[8..40], event.id());
        return buf;
    }

    pub const BinaryTagKey = struct {
        data: [73]u8,

        pub fn init(letter: u8, value: *const [32]u8, created_at_be: *const [8]u8, event_id: *const [32]u8) BinaryTagKey {
            var key = BinaryTagKey{ .data = undefined };
            key.data[0] = letter;
            @memcpy(key.data[1..33], value);
            @memcpy(key.data[33..41], created_at_be);
            @memcpy(key.data[41..73], event_id);
            return key;
        }

        pub fn slice(self: *const BinaryTagKey) []const u8 {
            return &self.data;
        }
    };

    pub const StringTagKey = struct {
        data: [297]u8,
        len: usize,

        pub fn init(letter: u8, value: []const u8, created_at_be: *const [8]u8, event_id: *const [32]u8) ?StringTagKey {
            if (value.len > 256) return null;
            var key = StringTagKey{ .data = undefined, .len = 0 };
            key.data[0] = letter;
            @memcpy(key.data[1..][0..value.len], value);
            @memcpy(key.data[1 + value.len ..][0..8], created_at_be);
            @memcpy(key.data[1 + value.len + 8 ..][0..32], event_id);
            key.len = 1 + value.len + 8 + 32;
            return key;
        }

        pub fn slice(self: *const StringTagKey) []const u8 {
            return self.data[0..self.len];
        }
    };

    pub fn timestampBe(event: *const Event) [8]u8 {
        return @bitCast(@byteSwap(@as(u64, @bitCast(event.createdAt()))));
    }
};

test "IndexKeys.created" {
    const event_module = @import("event.zig");
    try event_module.init();
    defer event_module.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":1,"created_at":1700000000,"content":"test","tags":[]}
    ;
    var event = try Event.parse(json);
    defer event.deinit();

    var key: [40]u8 = undefined;
    IndexKeys.created(&event, &key);

    // Verify timestamp is big-endian
    const ts_be: u64 = @bitCast(key[0..8].*);
    const ts = @byteSwap(ts_be);
    try std.testing.expectEqual(@as(u64, 1700000000), ts);

    // Verify event ID is appended
    try std.testing.expectEqual(@as(u8, 0), key[8]);
    try std.testing.expectEqual(@as(u8, 1), key[39]);
}
