const std = @import("std");
pub const crypto = @import("crypto.zig");
const utils = @import("utils.zig");

pub const Keypair = struct {
    secret_key: [32]u8,
    public_key: [32]u8,

    pub fn generate() Keypair {
        var secret_key: [32]u8 = undefined;
        std.crypto.random.bytes(&secret_key);

        var public_key: [32]u8 = undefined;
        crypto.getPublicKey(&secret_key, &public_key) catch unreachable;

        return .{
            .secret_key = secret_key,
            .public_key = public_key,
        };
    }
};

pub const EventBuilder = struct {
    id_bytes: [32]u8 = undefined,
    pubkey_bytes: [32]u8 = undefined,
    sig_bytes: [64]u8 = undefined,
    created_at_val: i64 = 0,
    kind_val: i32 = 1,
    content_slice: []const u8 = "",
    tags_data: []const []const []const u8 = &[_][]const []const u8{},

    pub fn setKind(self: *EventBuilder, k: i32) *EventBuilder {
        self.kind_val = k;
        return self;
    }

    pub fn setContent(self: *EventBuilder, c: []const u8) *EventBuilder {
        self.content_slice = c;
        return self;
    }

    pub fn setCreatedAt(self: *EventBuilder, t: i64) *EventBuilder {
        self.created_at_val = t;
        return self;
    }

    pub fn setTags(self: *EventBuilder, t: []const []const []const u8) *EventBuilder {
        self.tags_data = t;
        return self;
    }

    pub fn sign(self: *EventBuilder, keypair: *const Keypair) !void {
        @memcpy(&self.pubkey_bytes, &keypair.public_key);

        if (self.created_at_val == 0) {
            self.created_at_val = std.time.timestamp();
        }

        var commitment_buf: [8192]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&commitment_buf);
        const writer = fbs.writer();

        try writer.writeAll("[0,\"");

        for (&keypair.public_key) |byte| {
            try writer.print("{x:0>2}", .{byte});
        }

        try writer.writeAll("\",");
        try writer.print("{d}", .{self.created_at_val});
        try writer.writeAll(",");
        try writer.print("{d}", .{self.kind_val});
        try writer.writeAll(",[");

        for (self.tags_data, 0..) |tag, i| {
            if (i > 0) try writer.writeByte(',');
            try writer.writeByte('[');
            for (tag, 0..) |elem, j| {
                if (j > 0) try writer.writeByte(',');
                try writer.writeByte('"');
                try utils.writeJsonEscaped(writer, elem);
                try writer.writeByte('"');
            }
            try writer.writeByte(']');
        }

        try writer.writeAll("],\"");
        try utils.writeJsonEscaped(writer, self.content_slice);
        try writer.writeAll("\"]");

        const commitment = fbs.getWritten();
        std.crypto.hash.sha2.Sha256.hash(commitment, &self.id_bytes, .{});

        crypto.sign(&keypair.secret_key, &self.id_bytes, &self.sig_bytes) catch {
            return error.SignatureFailed;
        };
    }

    pub fn serialize(self: *const EventBuilder, buf: []u8) ![]u8 {
        var fbs = std.io.fixedBufferStream(buf);
        const writer = fbs.writer();

        try writer.writeAll("{\"id\":\"");
        for (self.id_bytes) |b| {
            try writer.print("{x:0>2}", .{b});
        }
        try writer.writeAll("\",\"pubkey\":\"");
        for (self.pubkey_bytes) |b| {
            try writer.print("{x:0>2}", .{b});
        }
        try writer.writeAll("\",\"created_at\":");
        try writer.print("{d}", .{self.created_at_val});
        try writer.writeAll(",\"kind\":");
        try writer.print("{d}", .{self.kind_val});
        try writer.writeAll(",\"tags\":[");

        for (self.tags_data, 0..) |tag, i| {
            if (i > 0) try writer.writeByte(',');
            try writer.writeByte('[');
            for (tag, 0..) |elem, j| {
                if (j > 0) try writer.writeByte(',');
                try writer.writeByte('"');
                try utils.writeJsonEscaped(writer, elem);
                try writer.writeByte('"');
            }
            try writer.writeByte(']');
        }

        try writer.writeAll("],\"content\":\"");
        try utils.writeJsonEscaped(writer, self.content_slice);
        try writer.writeAll("\",\"sig\":\"");
        for (self.sig_bytes) |b| {
            try writer.print("{x:0>2}", .{b});
        }
        try writer.writeAll("\"}");

        return fbs.getWritten();
    }
};

test "event builder" {
    const event_mod = @import("event.zig");
    try event_mod.init();
    defer event_mod.cleanup();

    const keypair = Keypair.generate();
    var builder = EventBuilder{};
    _ = builder.setKind(1).setContent("test");
    try builder.sign(&keypair);

    var buf: [4096]u8 = undefined;
    const json = try builder.serialize(&buf);
    try std.testing.expect(json.len > 0);
}
