//! CLINK (Common Lightning Interface for Nostr Keys) protocol types.
//!
//! Implements error codes for CLINK Offers (Kind 21001) and GFY (General Failure to Yield)
//! codes for CLINK Debits (Kind 21002) and CLINK Manage (Kind 21003).

const std = @import("std");

pub const Kind = struct {
    pub const offers: i32 = 21001;
    pub const debits: i32 = 21002;
    pub const manage: i32 = 21003;
};

pub const OffersErrorCode = enum(u8) {
    invalid_offer = 1,
    temporary_failure = 2,
    expired_or_moved = 3,
    unsupported_feature = 4,
    invalid_amount = 5,

    pub fn toInt(self: OffersErrorCode) u8 {
        return @intFromEnum(self);
    }

    pub fn fromInt(code: u8) ?OffersErrorCode {
        return switch (code) {
            1 => .invalid_offer,
            2 => .temporary_failure,
            3 => .expired_or_moved,
            4 => .unsupported_feature,
            5 => .invalid_amount,
            else => null,
        };
    }

    pub fn message(self: OffersErrorCode) []const u8 {
        return switch (self) {
            .invalid_offer => "Invalid Offer",
            .temporary_failure => "Temporary Failure",
            .expired_or_moved => "Offer has expired or moved",
            .unsupported_feature => "Unsupported Feature",
            .invalid_amount => "Invalid Amount",
        };
    }
};

pub const GfyCode = enum(u8) {
    request_denied = 1,
    temporary_failure = 2,
    expired_request = 3,
    rate_limited = 4,
    invalid_amount = 5,
    invalid_request = 6,

    pub fn toInt(self: GfyCode) u8 {
        return @intFromEnum(self);
    }

    pub fn fromInt(code: u8) ?GfyCode {
        return switch (code) {
            1 => .request_denied,
            2 => .temporary_failure,
            3 => .expired_request,
            4 => .rate_limited,
            5 => .invalid_amount,
            6 => .invalid_request,
            else => null,
        };
    }

    pub fn message(self: GfyCode) []const u8 {
        return switch (self) {
            .request_denied => "Request Denied",
            .temporary_failure => "Temporary Failure",
            .expired_request => "Expired Request",
            .rate_limited => "Rate Limited",
            .invalid_amount => "Invalid Amount",
            .invalid_request => "Invalid Request",
        };
    }
};

pub const Range = struct {
    min: u64,
    max: u64,
};

pub const Delta = struct {
    max_delta_ms: u64,
    actual_delta_ms: u64,
};

pub const OffersError = struct {
    code: OffersErrorCode,
    error_msg: []const u8,
    range: ?Range = null,
    latest: ?[]const u8 = null,

    pub fn format(self: OffersError, buf: []u8) ![]u8 {
        var fbs = std.io.fixedBufferStream(buf);
        const writer = fbs.writer();

        try writer.writeAll("{\"error\":\"");
        try writer.writeAll(self.error_msg);
        try writer.print("\",\"code\":{d}", .{self.code.toInt()});

        if (self.range) |r| {
            try writer.print(",\"range\":{{\"min\":{d},\"max\":{d}}}", .{ r.min, r.max });
        }

        if (self.latest) |l| {
            try writer.writeAll(",\"latest\":\"");
            try writer.writeAll(l);
            try writer.writeByte('"');
        }

        try writer.writeByte('}');
        return fbs.getWritten();
    }
};

pub const GfyError = struct {
    code: GfyCode,
    error_msg: []const u8,
    range: ?Range = null,
    delta: ?Delta = null,
    retry_after: ?u64 = null,
    field: ?[]const u8 = null,

    pub fn format(self: GfyError, buf: []u8) ![]u8 {
        var fbs = std.io.fixedBufferStream(buf);
        const writer = fbs.writer();

        try writer.print("{{\"res\":\"GFY\",\"code\":{d},\"error\":\"", .{self.code.toInt()});
        try writer.writeAll(self.error_msg);
        try writer.writeByte('"');

        if (self.delta) |d| {
            try writer.print(",\"delta\":{{\"max_delta_ms\":{d},\"actual_delta_ms\":{d}}}", .{ d.max_delta_ms, d.actual_delta_ms });
        }

        if (self.retry_after) |ra| {
            try writer.print(",\"retry_after\":{d}", .{ra});
        }

        if (self.field) |f| {
            try writer.writeAll(",\"field\":\"");
            try writer.writeAll(f);
            try writer.writeByte('"');
        }

        if (self.range) |r| {
            try writer.print(",\"range\":{{\"min\":{d},\"max\":{d}}}", .{ r.min, r.max });
        }

        try writer.writeByte('}');
        return fbs.getWritten();
    }
};

test "OffersErrorCode conversion" {
    try std.testing.expectEqual(@as(u8, 1), OffersErrorCode.invalid_offer.toInt());
    try std.testing.expectEqual(@as(u8, 5), OffersErrorCode.invalid_amount.toInt());
    try std.testing.expectEqual(OffersErrorCode.invalid_offer, OffersErrorCode.fromInt(1).?);
    try std.testing.expectEqual(OffersErrorCode.invalid_amount, OffersErrorCode.fromInt(5).?);
    try std.testing.expectEqual(@as(?OffersErrorCode, null), OffersErrorCode.fromInt(0));
    try std.testing.expectEqual(@as(?OffersErrorCode, null), OffersErrorCode.fromInt(6));
}

test "GfyCode conversion" {
    try std.testing.expectEqual(@as(u8, 1), GfyCode.request_denied.toInt());
    try std.testing.expectEqual(@as(u8, 6), GfyCode.invalid_request.toInt());
    try std.testing.expectEqual(GfyCode.request_denied, GfyCode.fromInt(1).?);
    try std.testing.expectEqual(GfyCode.invalid_request, GfyCode.fromInt(6).?);
    try std.testing.expectEqual(@as(?GfyCode, null), GfyCode.fromInt(0));
    try std.testing.expectEqual(@as(?GfyCode, null), GfyCode.fromInt(7));
}

test "OffersError format" {
    var buf: [512]u8 = undefined;

    const err1 = OffersError{
        .code = .invalid_offer,
        .error_msg = "Invalid Offer",
    };
    const result1 = try err1.format(&buf);
    try std.testing.expectEqualStrings("{\"error\":\"Invalid Offer\",\"code\":1}", result1);

    const err2 = OffersError{
        .code = .invalid_amount,
        .error_msg = "Invalid Amount",
        .range = .{ .min = 10, .max = 10000000 },
    };
    const result2 = try err2.format(&buf);
    try std.testing.expectEqualStrings("{\"error\":\"Invalid Amount\",\"code\":5,\"range\":{\"min\":10,\"max\":10000000}}", result2);

    const err3 = OffersError{
        .code = .expired_or_moved,
        .error_msg = "Offer has been replaced",
        .latest = "noffer1abc123",
    };
    const result3 = try err3.format(&buf);
    try std.testing.expectEqualStrings("{\"error\":\"Offer has been replaced\",\"code\":3,\"latest\":\"noffer1abc123\"}", result3);
}

test "GfyError format" {
    var buf: [512]u8 = undefined;

    const err1 = GfyError{
        .code = .request_denied,
        .error_msg = "Request Denied",
    };
    const result1 = try err1.format(&buf);
    try std.testing.expectEqualStrings("{\"res\":\"GFY\",\"code\":1,\"error\":\"Request Denied\"}", result1);

    const err2 = GfyError{
        .code = .expired_request,
        .error_msg = "Expired Request",
        .delta = .{ .max_delta_ms = 30000, .actual_delta_ms = 45000 },
    };
    const result2 = try err2.format(&buf);
    try std.testing.expectEqualStrings("{\"res\":\"GFY\",\"code\":3,\"error\":\"Expired Request\",\"delta\":{\"max_delta_ms\":30000,\"actual_delta_ms\":45000}}", result2);

    const err3 = GfyError{
        .code = .rate_limited,
        .error_msg = "Rate Limited",
        .retry_after = 1700000000,
    };
    const result3 = try err3.format(&buf);
    try std.testing.expectEqualStrings("{\"res\":\"GFY\",\"code\":4,\"error\":\"Rate Limited\",\"retry_after\":1700000000}", result3);

    const err4 = GfyError{
        .code = .invalid_amount,
        .error_msg = "Invalid Amount",
        .range = .{ .min = 1000, .max = 1000000 },
    };
    const result4 = try err4.format(&buf);
    try std.testing.expectEqualStrings("{\"res\":\"GFY\",\"code\":5,\"error\":\"Invalid Amount\",\"range\":{\"min\":1000,\"max\":1000000}}", result4);

    const err5 = GfyError{
        .code = .invalid_amount,
        .error_msg = "Invalid Field/Value",
        .field = "price_sats",
        .range = .{ .min = 1000, .max = 1000000 },
    };
    const result5 = try err5.format(&buf);
    try std.testing.expectEqualStrings("{\"res\":\"GFY\",\"code\":5,\"error\":\"Invalid Field/Value\",\"field\":\"price_sats\",\"range\":{\"min\":1000,\"max\":1000000}}", result5);
}
