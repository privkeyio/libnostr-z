const std = @import("std");
const utils = @import("utils.zig");

pub const Kind = struct {
    pub const pool: i32 = 2022;
};

pub const Transport = enum {
    vpn,
    tor,

    pub fn toString(self: Transport) []const u8 {
        return switch (self) {
            .vpn => "vpn",
            .tor => "tor",
        };
    }

    pub fn fromString(s: []const u8) ?Transport {
        if (std.mem.eql(u8, s, "vpn")) return .vpn;
        if (std.mem.eql(u8, s, "tor")) return .tor;
        return null;
    }
};

pub const MessageType = enum {
    new_pool,
    output,
    input,

    pub fn toString(self: MessageType) []const u8 {
        return switch (self) {
            .new_pool => "new_pool",
            .output => "output",
            .input => "input",
        };
    }

    pub fn fromString(s: []const u8) ?MessageType {
        const map = std.StaticStringMap(MessageType).initComptime(.{
            .{ "new_pool", .new_pool },
            .{ "output", .output },
            .{ "input", .input },
        });
        return map.get(s);
    }
};

pub const Pool = struct {
    id: []const u8,
    public_key: []const u8,
    denomination: i64,
    peers: i64,
    timeout: i64,
    relay: []const u8,
    fee_rate: i64,
    transport: Transport,
    vpn_gateway: ?[]const u8,

    pub fn parseJson(json: []const u8) ?Pool {
        const type_str = utils.extractJsonString(json, "type") orelse return null;
        if (!std.mem.eql(u8, type_str, "new_pool")) return null;

        const id = utils.extractJsonString(json, "id") orelse return null;
        const public_key = utils.extractJsonString(json, "public_key") orelse return null;
        const denomination = utils.extractIntField(json, "denomination", i64) orelse return null;
        const peers = utils.extractIntField(json, "peers", i64) orelse return null;
        const timeout = utils.extractIntField(json, "timeout", i64) orelse return null;
        const relay = utils.extractJsonString(json, "relay") orelse return null;
        const fee_rate = utils.extractIntField(json, "fee_rate", i64) orelse return null;
        const transport_str = utils.extractJsonString(json, "transport") orelse return null;
        const transport = Transport.fromString(transport_str) orelse return null;
        const vpn_gateway = utils.extractJsonString(json, "vpn_gateway");

        return Pool{
            .id = id,
            .public_key = public_key,
            .denomination = denomination,
            .peers = peers,
            .timeout = timeout,
            .relay = relay,
            .fee_rate = fee_rate,
            .transport = transport,
            .vpn_gateway = vpn_gateway,
        };
    }

    pub fn serialize(self: *const Pool, buf: []u8) ![]u8 {
        var fbs = std.io.fixedBufferStream(buf);
        const writer = fbs.writer();

        try writer.writeAll("{\"type\":\"new_pool\",\"id\":\"");
        try utils.writeJsonEscaped(writer, self.id);
        try writer.writeAll("\",\"public_key\":\"");
        try utils.writeJsonEscaped(writer, self.public_key);
        try writer.writeAll("\",\"denomination\":");
        try writer.print("{d}", .{self.denomination});
        try writer.writeAll(",\"peers\":");
        try writer.print("{d}", .{self.peers});
        try writer.writeAll(",\"timeout\":");
        try writer.print("{d}", .{self.timeout});
        try writer.writeAll(",\"relay\":\"");
        try utils.writeJsonEscaped(writer, self.relay);
        try writer.writeAll("\",\"fee_rate\":");
        try writer.print("{d}", .{self.fee_rate});
        try writer.writeAll(",\"transport\":\"");
        try writer.writeAll(self.transport.toString());
        try writer.writeAll("\"");
        if (self.vpn_gateway) |gateway| {
            try writer.writeAll(",\"vpn_gateway\":\"");
            try utils.writeJsonEscaped(writer, gateway);
            try writer.writeAll("\"");
        }
        try writer.writeAll("}");

        return fbs.getWritten();
    }
};

pub const OutputMessage = struct {
    address: []const u8,

    pub fn parseJson(json: []const u8) ?OutputMessage {
        const type_str = utils.extractJsonString(json, "type") orelse return null;
        if (!std.mem.eql(u8, type_str, "output")) return null;

        const address = utils.extractJsonString(json, "address") orelse return null;
        return OutputMessage{ .address = address };
    }

    pub fn serialize(self: *const OutputMessage, buf: []u8) ![]u8 {
        var fbs = std.io.fixedBufferStream(buf);
        const writer = fbs.writer();

        try writer.writeAll("{\"address\":\"");
        try utils.writeJsonEscaped(writer, self.address);
        try writer.writeAll("\",\"type\":\"output\"}");

        return fbs.getWritten();
    }
};

pub const InputMessage = struct {
    psbt: []const u8,

    pub fn parseJson(json: []const u8) ?InputMessage {
        const type_str = utils.extractJsonString(json, "type") orelse return null;
        if (!std.mem.eql(u8, type_str, "input")) return null;

        const psbt = utils.extractJsonString(json, "psbt") orelse return null;
        return InputMessage{ .psbt = psbt };
    }

    pub fn serialize(self: *const InputMessage, buf: []u8) ![]u8 {
        var fbs = std.io.fixedBufferStream(buf);
        const writer = fbs.writer();

        try writer.writeAll("{\"psbt\":\"");
        try utils.writeJsonEscaped(writer, self.psbt);
        try writer.writeAll("\",\"type\":\"input\"}");

        return fbs.getWritten();
    }
};

pub const Message = union(MessageType) {
    new_pool: Pool,
    output: OutputMessage,
    input: InputMessage,

    pub fn parseJson(json: []const u8) ?Message {
        const type_str = utils.extractJsonString(json, "type") orelse return null;
        const msg_type = MessageType.fromString(type_str) orelse return null;

        return switch (msg_type) {
            .new_pool => if (Pool.parseJson(json)) |pool| Message{ .new_pool = pool } else null,
            .output => if (OutputMessage.parseJson(json)) |output| Message{ .output = output } else null,
            .input => if (InputMessage.parseJson(json)) |input| Message{ .input = input } else null,
        };
    }

    pub fn serialize(self: *const Message, buf: []u8) ![]u8 {
        return switch (self.*) {
            .new_pool => |*pool| pool.serialize(buf),
            .output => |*output| output.serialize(buf),
            .input => |*input| input.serialize(buf),
        };
    }
};

test "Transport.fromString" {
    try std.testing.expectEqual(Transport.vpn, Transport.fromString("vpn").?);
    try std.testing.expectEqual(Transport.tor, Transport.fromString("tor").?);
    try std.testing.expect(Transport.fromString("invalid") == null);
}

test "Transport.toString" {
    try std.testing.expectEqualStrings("vpn", Transport.vpn.toString());
    try std.testing.expectEqualStrings("tor", Transport.tor.toString());
}

test "MessageType.fromString" {
    try std.testing.expectEqual(MessageType.new_pool, MessageType.fromString("new_pool").?);
    try std.testing.expectEqual(MessageType.output, MessageType.fromString("output").?);
    try std.testing.expectEqual(MessageType.input, MessageType.fromString("input").?);
    try std.testing.expect(MessageType.fromString("unknown") == null);
}

test "MessageType.toString" {
    try std.testing.expectEqualStrings("new_pool", MessageType.new_pool.toString());
    try std.testing.expectEqualStrings("output", MessageType.output.toString());
    try std.testing.expectEqualStrings("input", MessageType.input.toString());
}

test "Pool.parseJson" {
    const json =
        \\{"type":"new_pool","id":"abc123","public_key":"02abcd","denomination":100000,"peers":5,"timeout":1700000000,"relay":"wss://relay.example.com","fee_rate":10,"transport":"vpn","vpn_gateway":"vpn.riseup.net"}
    ;
    const pool = Pool.parseJson(json).?;
    try std.testing.expectEqualStrings("abc123", pool.id);
    try std.testing.expectEqualStrings("02abcd", pool.public_key);
    try std.testing.expectEqual(@as(i64, 100000), pool.denomination);
    try std.testing.expectEqual(@as(i64, 5), pool.peers);
    try std.testing.expectEqual(@as(i64, 1700000000), pool.timeout);
    try std.testing.expectEqualStrings("wss://relay.example.com", pool.relay);
    try std.testing.expectEqual(@as(i64, 10), pool.fee_rate);
    try std.testing.expectEqual(Transport.vpn, pool.transport);
    try std.testing.expectEqualStrings("vpn.riseup.net", pool.vpn_gateway.?);
}

test "Pool.parseJson without vpn_gateway" {
    const json =
        \\{"type":"new_pool","id":"xyz","public_key":"03ef","denomination":50000,"peers":3,"timeout":1700000000,"relay":"wss://r.example.com","fee_rate":5,"transport":"tor"}
    ;
    const pool = Pool.parseJson(json).?;
    try std.testing.expectEqualStrings("xyz", pool.id);
    try std.testing.expectEqual(Transport.tor, pool.transport);
    try std.testing.expect(pool.vpn_gateway == null);
}

test "Pool.parseJson invalid type" {
    const json =
        \\{"type":"invalid","id":"abc123","public_key":"02abcd","denomination":100000,"peers":5,"timeout":1700000000,"relay":"wss://relay.example.com","fee_rate":10,"transport":"vpn"}
    ;
    try std.testing.expect(Pool.parseJson(json) == null);
}

test "Pool.parseJson missing field" {
    const json =
        \\{"type":"new_pool","id":"abc123","denomination":100000,"peers":5,"timeout":1700000000,"relay":"wss://relay.example.com","fee_rate":10,"transport":"vpn"}
    ;
    try std.testing.expect(Pool.parseJson(json) == null);
}

test "Pool.serialize" {
    const pool = Pool{
        .id = "test123",
        .public_key = "02abcdef",
        .denomination = 100000,
        .peers = 4,
        .timeout = 1700000000,
        .relay = "wss://relay.example.com",
        .fee_rate = 15,
        .transport = .vpn,
        .vpn_gateway = "vpn.riseup.net",
    };
    var buf: [1024]u8 = undefined;
    const result = try pool.serialize(&buf);
    const parsed = Pool.parseJson(result).?;
    try std.testing.expectEqualStrings("test123", parsed.id);
    try std.testing.expectEqualStrings("02abcdef", parsed.public_key);
    try std.testing.expectEqual(@as(i64, 100000), parsed.denomination);
    try std.testing.expectEqual(@as(i64, 4), parsed.peers);
    try std.testing.expectEqual(@as(i64, 15), parsed.fee_rate);
    try std.testing.expectEqualStrings("vpn.riseup.net", parsed.vpn_gateway.?);
}

test "Pool.serialize without vpn_gateway" {
    const pool = Pool{
        .id = "test456",
        .public_key = "03abcdef",
        .denomination = 50000,
        .peers = 2,
        .timeout = 1700000000,
        .relay = "wss://relay.example.com",
        .fee_rate = 5,
        .transport = .tor,
        .vpn_gateway = null,
    };
    var buf: [1024]u8 = undefined;
    const result = try pool.serialize(&buf);
    const parsed = Pool.parseJson(result).?;
    try std.testing.expectEqualStrings("test456", parsed.id);
    try std.testing.expectEqual(@as(i64, 50000), parsed.denomination);
    try std.testing.expectEqual(@as(i64, 5), parsed.fee_rate);
    try std.testing.expectEqual(Transport.tor, parsed.transport);
    try std.testing.expect(parsed.vpn_gateway == null);
}

test "OutputMessage.parseJson" {
    const json =
        \\{"address":"bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh","type":"output"}
    ;
    const output = OutputMessage.parseJson(json).?;
    try std.testing.expectEqualStrings("bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh", output.address);
}

test "OutputMessage.parseJson invalid type" {
    const json =
        \\{"address":"bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh","type":"input"}
    ;
    try std.testing.expect(OutputMessage.parseJson(json) == null);
}

test "OutputMessage.serialize" {
    const output = OutputMessage{ .address = "bc1qtest" };
    var buf: [256]u8 = undefined;
    const result = try output.serialize(&buf);
    const parsed = OutputMessage.parseJson(result).?;
    try std.testing.expectEqualStrings("bc1qtest", parsed.address);
}

test "InputMessage.parseJson" {
    const json =
        \\{"psbt":"cHNidP8BAHUCAAAAASaBcT...","type":"input"}
    ;
    const input = InputMessage.parseJson(json).?;
    try std.testing.expectEqualStrings("cHNidP8BAHUCAAAAASaBcT...", input.psbt);
}

test "InputMessage.parseJson invalid type" {
    const json =
        \\{"psbt":"cHNidP8BAHUCAAAAASaBcT...","type":"output"}
    ;
    try std.testing.expect(InputMessage.parseJson(json) == null);
}

test "InputMessage.serialize" {
    const input = InputMessage{ .psbt = "cHNidP8BAHUCtest" };
    var buf: [256]u8 = undefined;
    const result = try input.serialize(&buf);
    const parsed = InputMessage.parseJson(result).?;
    try std.testing.expectEqualStrings("cHNidP8BAHUCtest", parsed.psbt);
}

test "Message.parseJson new_pool" {
    const json =
        \\{"type":"new_pool","id":"pool1","public_key":"02ab","denomination":100000,"peers":5,"timeout":1700000000,"relay":"wss://r.com","fee_rate":10,"transport":"vpn","vpn_gateway":"vpn.net"}
    ;
    const msg = Message.parseJson(json).?;
    try std.testing.expectEqual(MessageType.new_pool, std.meta.activeTag(msg));
    try std.testing.expectEqualStrings("pool1", msg.new_pool.id);
    try std.testing.expectEqual(@as(i64, 100000), msg.new_pool.denomination);
}

test "Message.parseJson output" {
    const json =
        \\{"address":"bc1qtest","type":"output"}
    ;
    const msg = Message.parseJson(json).?;
    try std.testing.expectEqual(MessageType.output, std.meta.activeTag(msg));
    try std.testing.expectEqualStrings("bc1qtest", msg.output.address);
}

test "Message.parseJson input" {
    const json =
        \\{"psbt":"cHNidP8test","type":"input"}
    ;
    const msg = Message.parseJson(json).?;
    try std.testing.expectEqual(MessageType.input, std.meta.activeTag(msg));
    try std.testing.expectEqualStrings("cHNidP8test", msg.input.psbt);
}

test "Message.parseJson invalid" {
    const json =
        \\{"type":"unknown","data":"test"}
    ;
    try std.testing.expect(Message.parseJson(json) == null);
}

test "Message.serialize new_pool" {
    const msg = Message{ .new_pool = Pool{
        .id = "p1",
        .public_key = "pk",
        .denomination = 1000,
        .peers = 2,
        .timeout = 1700000000,
        .relay = "wss://r.com",
        .fee_rate = 5,
        .transport = .tor,
        .vpn_gateway = null,
    } };
    var buf: [1024]u8 = undefined;
    const result = try msg.serialize(&buf);
    const parsed = Message.parseJson(result).?;
    try std.testing.expectEqual(MessageType.new_pool, std.meta.activeTag(parsed));
    try std.testing.expectEqualStrings("p1", parsed.new_pool.id);
    try std.testing.expectEqual(@as(i64, 1000), parsed.new_pool.denomination);
    try std.testing.expectEqual(@as(i64, 5), parsed.new_pool.fee_rate);
}

test "Message.serialize output" {
    const msg = Message{ .output = OutputMessage{ .address = "bc1qaddr" } };
    var buf: [256]u8 = undefined;
    const result = try msg.serialize(&buf);
    const parsed = Message.parseJson(result).?;
    try std.testing.expectEqual(MessageType.output, std.meta.activeTag(parsed));
    try std.testing.expectEqualStrings("bc1qaddr", parsed.output.address);
}

test "Message.serialize input" {
    const msg = Message{ .input = InputMessage{ .psbt = "psbt_data" } };
    var buf: [256]u8 = undefined;
    const result = try msg.serialize(&buf);
    const parsed = Message.parseJson(result).?;
    try std.testing.expectEqual(MessageType.input, std.meta.activeTag(parsed));
    try std.testing.expectEqualStrings("psbt_data", parsed.input.psbt);
}
