//! CLINK (Common Lightning Interface for Nostr Keys) protocol types.
//!
//! Implements request/response parsing for CLINK Offers (Kind 21001),
//! CLINK Debits (Kind 21002), and CLINK Manage (Kind 21003).

const std = @import("std");
const utils = @import("utils.zig");

pub const Kind = struct {
    pub const offers: i32 = 21001;
    pub const debits: i32 = 21002;
    pub const manage: i32 = 21003;
};

pub const OffersRequest = struct {
    offer: []const u8,
    amount_sats: ?u64 = null,
    payer_data: ?[]const u8 = null,
    zap: ?[]const u8 = null,
    expires_in_seconds: ?u64 = null,
    description: ?[]const u8 = null,

    pub fn parse(json: []const u8) ?OffersRequest {
        return .{
            .offer = utils.extractJsonString(json, "offer") orelse return null,
            .amount_sats = utils.extractIntField(json, "amount_sats", u64),
            .payer_data = utils.findJsonValue(json, "payer_data"),
            .zap = utils.extractJsonString(json, "zap"),
            .expires_in_seconds = utils.extractIntField(json, "expires_in_seconds", u64),
            .description = utils.extractJsonString(json, "description"),
        };
    }
};

pub const OffersResponse = struct {
    bolt11: ?[]const u8 = null,
    preimage: ?[]const u8 = null,

    pub fn parse(json: []const u8) ?OffersResponse {
        if (utils.extractJsonString(json, "error") != null) return null;
        return .{
            .bolt11 = utils.extractJsonString(json, "bolt11"),
            .preimage = utils.extractJsonString(json, "preimage"),
        };
    }

    pub fn format(self: OffersResponse, buf: []u8) ![]u8 {
        var fbs = std.io.fixedBufferStream(buf);
        const writer = fbs.writer();

        if (self.bolt11) |b| {
            try writer.writeAll("{\"bolt11\":\"");
            try utils.writeJsonEscaped(writer, b);
            try writer.writeAll("\"}");
        } else if (self.preimage) |p| {
            try writer.writeAll("{\"res\":\"ok\",\"preimage\":\"");
            try utils.writeJsonEscaped(writer, p);
            try writer.writeAll("\"}");
        } else {
            try writer.writeAll("{\"res\":\"ok\"}");
        }
        return fbs.getWritten();
    }
};

pub const Frequency = struct {
    number: u32,
    unit: Unit,

    pub const Unit = enum {
        day,
        week,
        month,

        pub fn toString(self: Unit) []const u8 {
            return switch (self) {
                .day => "day",
                .week => "week",
                .month => "month",
            };
        }

        pub fn fromString(s: []const u8) ?Unit {
            if (std.mem.eql(u8, s, "day")) return .day;
            if (std.mem.eql(u8, s, "week")) return .week;
            if (std.mem.eql(u8, s, "month")) return .month;
            return null;
        }
    };

    pub fn parse(json: []const u8) ?Frequency {
        const number = utils.extractIntField(json, "number", u32) orelse return null;
        const unit_str = utils.extractJsonString(json, "unit") orelse return null;
        const unit = Unit.fromString(unit_str) orelse return null;
        return .{ .number = number, .unit = unit };
    }
};

pub const DebitRequest = struct {
    pointer: ?[]const u8 = null,
    amount_sats: ?u64 = null,
    bolt11: ?[]const u8 = null,
    frequency: ?Frequency = null,
    description: ?[]const u8 = null,

    pub fn parse(json: []const u8) ?DebitRequest {
        const freq = if (utils.findJsonValue(json, "frequency")) |f| Frequency.parse(f) else null;
        return .{
            .pointer = utils.extractJsonString(json, "pointer"),
            .amount_sats = utils.extractIntField(json, "amount_sats", u64),
            .bolt11 = utils.extractJsonString(json, "bolt11"),
            .frequency = freq,
            .description = utils.extractJsonString(json, "description"),
        };
    }

    pub fn isDirectPayment(self: DebitRequest) bool {
        return self.bolt11 != null;
    }

    pub fn isBudgetRequest(self: DebitRequest) bool {
        return self.bolt11 == null and self.amount_sats != null;
    }
};

pub const DebitResponse = struct {
    preimage: ?[]const u8 = null,

    pub fn parse(json: []const u8) ?DebitResponse {
        const res = utils.extractJsonString(json, "res") orelse return null;
        if (!std.mem.eql(u8, res, "ok")) return null;
        return .{ .preimage = utils.extractJsonString(json, "preimage") };
    }

    pub fn format(self: DebitResponse, buf: []u8) ![]u8 {
        var fbs = std.io.fixedBufferStream(buf);
        const writer = fbs.writer();

        if (self.preimage) |p| {
            try writer.writeAll("{\"res\":\"ok\",\"preimage\":\"");
            try utils.writeJsonEscaped(writer, p);
            try writer.writeAll("\"}");
        } else {
            try writer.writeAll("{\"res\":\"ok\"}");
        }
        return fbs.getWritten();
    }
};

pub const ManageAction = enum {
    create,
    update,
    delete,
    get,
    list,

    pub fn toString(self: ManageAction) []const u8 {
        return switch (self) {
            .create => "create",
            .update => "update",
            .delete => "delete",
            .get => "get",
            .list => "list",
        };
    }

    pub fn fromString(s: []const u8) ?ManageAction {
        if (std.mem.eql(u8, s, "create")) return .create;
        if (std.mem.eql(u8, s, "update")) return .update;
        if (std.mem.eql(u8, s, "delete")) return .delete;
        if (std.mem.eql(u8, s, "get")) return .get;
        if (std.mem.eql(u8, s, "list")) return .list;
        return null;
    }
};

pub const ManageRequest = struct {
    resource: []const u8,
    pointer: ?[]const u8 = null,
    action: ManageAction,
    offer: ?[]const u8 = null,

    pub fn parse(json: []const u8) ?ManageRequest {
        const action_str = utils.extractJsonString(json, "action") orelse return null;
        return .{
            .resource = utils.extractJsonString(json, "resource") orelse return null,
            .pointer = utils.extractJsonString(json, "pointer"),
            .action = ManageAction.fromString(action_str) orelse return null,
            .offer = utils.findJsonValue(json, "offer"),
        };
    }
};

pub const ManageResponse = struct {
    resource: []const u8,
    details: ?[]const u8 = null,

    pub fn parse(json: []const u8) ?ManageResponse {
        const res = utils.extractJsonString(json, "res") orelse return null;
        if (!std.mem.eql(u8, res, "ok")) return null;
        return .{
            .resource = utils.extractJsonString(json, "resource") orelse return null,
            .details = utils.findJsonValue(json, "details"),
        };
    }

    pub fn format(self: ManageResponse, buf: []u8) ![]u8 {
        var fbs = std.io.fixedBufferStream(buf);
        const writer = fbs.writer();

        try writer.writeAll("{\"res\":\"ok\",\"resource\":\"");
        try utils.writeJsonEscaped(writer, self.resource);
        try writer.writeByte('"');

        if (self.details) |d| {
            try writer.writeAll(",\"details\":");
            try writer.writeAll(d);
        }

        try writer.writeByte('}');
        return fbs.getWritten();
    }
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
        try utils.writeJsonEscaped(writer, self.error_msg);
        try writer.print("\",\"code\":{d}", .{self.code.toInt()});

        if (self.range) |r| {
            try writer.print(",\"range\":{{\"min\":{d},\"max\":{d}}}", .{ r.min, r.max });
        }

        if (self.latest) |l| {
            try writer.writeAll(",\"latest\":\"");
            try utils.writeJsonEscaped(writer, l);
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
        try utils.writeJsonEscaped(writer, self.error_msg);
        try writer.writeByte('"');

        if (self.delta) |d| {
            try writer.print(",\"delta\":{{\"max_delta_ms\":{d},\"actual_delta_ms\":{d}}}", .{ d.max_delta_ms, d.actual_delta_ms });
        }

        if (self.retry_after) |ra| {
            try writer.print(",\"retry_after\":{d}", .{ra});
        }

        if (self.field) |f| {
            try writer.writeAll(",\"field\":\"");
            try utils.writeJsonEscaped(writer, f);
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

    const err_escaped = OffersError{
        .code = .temporary_failure,
        .error_msg = "Error with \"quotes\" and \\backslash",
    };
    const result_escaped = try err_escaped.format(&buf);
    try std.testing.expectEqualStrings("{\"error\":\"Error with \\\"quotes\\\" and \\\\backslash\",\"code\":2}", result_escaped);

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

    const err_escaped = GfyError{
        .code = .invalid_request,
        .error_msg = "Bad field: \"name\"\nline2",
        .field = "path\\to\\file",
    };
    const result_escaped = try err_escaped.format(&buf);
    try std.testing.expectEqualStrings("{\"res\":\"GFY\",\"code\":6,\"error\":\"Bad field: \\\"name\\\"\\nline2\",\"field\":\"path\\\\to\\\\file\"}", result_escaped);

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

test "OffersRequest parse" {
    const json = "{\"offer\":\"zap_default\",\"amount_sats\":1000,\"description\":\"test payment\"}";
    const req = OffersRequest.parse(json).?;
    try std.testing.expectEqualStrings("zap_default", req.offer);
    try std.testing.expectEqual(@as(u64, 1000), req.amount_sats.?);
    try std.testing.expectEqualStrings("test payment", req.description.?);
    try std.testing.expectEqual(@as(?[]const u8, null), req.zap);
}

test "OffersResponse format" {
    var buf: [256]u8 = undefined;

    const resp1 = OffersResponse{ .bolt11 = "lnbc1..." };
    const result1 = try resp1.format(&buf);
    try std.testing.expectEqualStrings("{\"bolt11\":\"lnbc1...\"}", result1);

    const resp2 = OffersResponse{ .preimage = "abc123" };
    const result2 = try resp2.format(&buf);
    try std.testing.expectEqualStrings("{\"res\":\"ok\",\"preimage\":\"abc123\"}", result2);

    const resp3 = OffersResponse{};
    const result3 = try resp3.format(&buf);
    try std.testing.expectEqualStrings("{\"res\":\"ok\"}", result3);
}

test "DebitRequest parse" {
    const direct = "{\"pointer\":\"acc1\",\"bolt11\":\"lnbc1...\",\"amount_sats\":5000}";
    const req1 = DebitRequest.parse(direct).?;
    try std.testing.expectEqualStrings("acc1", req1.pointer.?);
    try std.testing.expectEqualStrings("lnbc1...", req1.bolt11.?);
    try std.testing.expect(req1.isDirectPayment());
    try std.testing.expect(!req1.isBudgetRequest());

    const budget = "{\"amount_sats\":50000,\"frequency\":{\"number\":1,\"unit\":\"month\"}}";
    const req2 = DebitRequest.parse(budget).?;
    try std.testing.expectEqual(@as(u64, 50000), req2.amount_sats.?);
    try std.testing.expectEqual(@as(u32, 1), req2.frequency.?.number);
    try std.testing.expectEqual(Frequency.Unit.month, req2.frequency.?.unit);
    try std.testing.expect(!req2.isDirectPayment());
    try std.testing.expect(req2.isBudgetRequest());
}

test "DebitResponse format" {
    var buf: [256]u8 = undefined;

    const resp1 = DebitResponse{ .preimage = "deadbeef" };
    const result1 = try resp1.format(&buf);
    try std.testing.expectEqualStrings("{\"res\":\"ok\",\"preimage\":\"deadbeef\"}", result1);

    const resp2 = DebitResponse{};
    const result2 = try resp2.format(&buf);
    try std.testing.expectEqualStrings("{\"res\":\"ok\"}", result2);
}

test "ManageRequest parse" {
    const json = "{\"resource\":\"offer\",\"action\":\"create\",\"offer\":{\"label\":\"Test\"}}";
    const req = ManageRequest.parse(json).?;
    try std.testing.expectEqualStrings("offer", req.resource);
    try std.testing.expectEqual(ManageAction.create, req.action);
    try std.testing.expect(req.offer != null);
}

test "ManageResponse format" {
    var buf: [256]u8 = undefined;

    const resp1 = ManageResponse{ .resource = "offer", .details = "{\"id\":\"123\"}" };
    const result1 = try resp1.format(&buf);
    try std.testing.expectEqualStrings("{\"res\":\"ok\",\"resource\":\"offer\",\"details\":{\"id\":\"123\"}}", result1);

    const resp2 = ManageResponse{ .resource = "offer" };
    const result2 = try resp2.format(&buf);
    try std.testing.expectEqualStrings("{\"res\":\"ok\",\"resource\":\"offer\"}", result2);
}

test "ManageAction conversion" {
    try std.testing.expectEqualStrings("create", ManageAction.create.toString());
    try std.testing.expectEqual(ManageAction.delete, ManageAction.fromString("delete").?);
    try std.testing.expectEqual(@as(?ManageAction, null), ManageAction.fromString("invalid"));
}

test "Frequency parse" {
    const json = "{\"number\":2,\"unit\":\"week\"}";
    const freq = Frequency.parse(json).?;
    try std.testing.expectEqual(@as(u32, 2), freq.number);
    try std.testing.expectEqual(Frequency.Unit.week, freq.unit);
    try std.testing.expectEqualStrings("week", freq.unit.toString());
}
