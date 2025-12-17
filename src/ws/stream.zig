const std = @import("std");
const io = std.io;
const mem = std.mem;
const assert = std.debug.assert;
const Allocator = mem.Allocator;
const utf8ValidateSlice = std.unicode.utf8ValidateSlice;

const Frame = @import("frame.zig").Frame;

pub const Message = struct {
    pub const Encoding = enum {
        text,
        binary,

        pub fn opcode(self: Encoding) Frame.Opcode {
            return if (self == .text) Frame.Opcode.text else Frame.Opcode.binary;
        }

        pub fn from(frame_opcode: Frame.Opcode) Encoding {
            return if (frame_opcode == .binary) .binary else .text;
        }
    };

    encoding: Encoding = .text,
    payload: []const u8,
    allocator: ?Allocator = null,

    const Self = @This();

    pub fn init(allocator: Allocator, encoding: Encoding, payload: []const u8) !Self {
        var self = Self{
            .allocator = allocator,
            .encoding = encoding,
            .payload = payload,
        };
        try self.validate();
        return self;
    }

    pub fn deinit(self: Self) void {
        if (self.allocator) |a| a.free(self.payload);
    }

    pub fn validate(self: Self) !void {
        if (self.encoding == .text)
            try Frame.assertValidUtf8(self.payload);
    }

    pub fn append(self: *Self, data: []const u8) !void {
        const allocator = self.allocator orelse return error.NoAllocator;
        const old_len = self.payload.len;
        const payload = try allocator.realloc(@constCast(self.payload), old_len + data.len);
        @memcpy(payload[old_len..], data);
        self.payload = payload;
    }
};

pub const Options = struct {
    per_message_deflate: bool = false,
    server_no_context_takeover: bool = false,
    client_no_context_takeover: bool = false,
    client_max_window_bits: u4 = 15,
    server_max_window_bits: u4 = 15,
    compress_threshold: usize = 126,
};

pub fn Stream(comptime ReaderType: type, comptime WriterType: type) type {
    return struct {
        const Self = @This();

        reader: Reader(ReaderType),
        writer: Writer(WriterType),

        allocator: Allocator,
        err: ?anyerror = null,

        last_frame_fragment: Frame.Fragment = .unfragmented,

        fn readDataFrame(self: *Self) !Frame {
            while (true) {
                var frame = try self.reader.frame();
                if (frame.isControl()) {
                    defer frame.deinit();
                    try self.handleControlFrame(&frame);
                } else {
                    errdefer frame.deinit();
                    try frame.assertValidContinuation(self.last_frame_fragment);
                    self.last_frame_fragment = frame.fragment();
                    return frame;
                }
            }
        }

        fn handleControlFrame(self: *Self, frame: *Frame) !void {
            switch (frame.opcode) {
                .ping => try self.writer.pong(frame.payload),
                .close => {
                    try self.writer.close(frame.closeCode(), frame.closePayload());
                    return error.EndOfStream;
                },
                .pong => {},
                else => unreachable,
            }
        }

        fn setErr(self: *Self, err: anyerror) void {
            if (err != error.EndOfStream) self.err = err;
        }

        pub fn nextMessage(self: *Self) ?Message {
            return self.readMessage() catch |err| {
                self.setErr(err);
                return null;
            };
        }

        fn readMessage(self: *Self) !Message {
            var frame = try self.readDataFrame();

            if (frame.isFin()) {
                errdefer frame.deinit();
                var msg = Message{
                    .encoding = Message.Encoding.from(frame.opcode),
                    .allocator = frame.allocator,
                    .payload = frame.payload,
                };
                try msg.validate();
                return msg;
            }

            var msg = Message{
                .encoding = Message.Encoding.from(frame.opcode),
                .allocator = self.allocator,
                .payload = try self.allocator.dupe(u8, frame.payload),
            };
            errdefer msg.deinit();
            frame.deinit();

            while (true) {
                frame = try self.readDataFrame();
                defer frame.deinit();
                try msg.append(frame.payload);
                if (frame.isFin()) break;
            }
            try msg.validate();
            return msg;
        }

        pub fn sendMessage(self: *Self, msg: Message) !void {
            try self.send(msg.encoding, msg.payload);
        }

        pub fn send(self: *Self, encoding: Message.Encoding, payload: []const u8) !void {
            try self.writer.message(encoding, payload, false);
        }

        pub fn deinit(self: *Self) void {
            self.writer.deinit();
        }
    };
}

pub fn Reader(comptime ReaderType: type) type {
    return struct {
        inner_reader: ReaderType,
        allocator: Allocator,

        const Self = @This();

        pub fn init(allocator: Allocator, inner_reader: ReaderType) Self {
            return .{
                .allocator = allocator,
                .inner_reader = inner_reader,
            };
        }

        fn readByte(self: *Self) !u8 {
            var buf: [1]u8 = undefined;
            const n = try self.inner_reader.read(&buf);
            if (n == 0) return error.EndOfStream;
            return buf[0];
        }

        fn readAll(self: *Self, buffer: []u8) !void {
            var index: usize = 0;
            while (index < buffer.len) {
                const n = try self.inner_reader.read(buffer[index..]);
                if (n == 0) return error.EndOfStream;
                index += n;
            }
        }

        fn readPayloadLen(self: *Self, first_byte: u8) !u64 {
            const payload_len: u64 = @intCast(first_byte & 0b0111_1111);
            switch (payload_len) {
                126 => {
                    var buf: [2]u8 = undefined;
                    try self.readAll(&buf);
                    return @intCast(std.mem.readInt(u16, &buf, .big));
                },
                127 => {
                    var buf: [8]u8 = undefined;
                    try self.readAll(&buf);
                    return std.mem.readInt(u64, &buf, .big);
                },
                else => return payload_len,
            }
        }

        fn readPayload(self: *Self, payload_len: u64, masked: bool) ![]u8 {
            if (payload_len == 0) return &.{};
            var masking_key = [_]u8{0} ** 4;
            if (masked) try self.readAll(&masking_key);
            const payload = try self.allocator.alloc(u8, payload_len);
            errdefer self.allocator.free(payload);
            try self.readAll(payload);
            if (masked) Frame.maskUnmask(&masking_key, payload);
            return payload;
        }

        pub fn frame(self: *Self) !Frame {
            const b0 = try self.readByte();
            const b1 = try self.readByte();

            const fin: u1 = if (b0 & 0b1000_0000 != 0) 1 else 0;
            const rsv1: u1 = if (b0 & 0b0100_0000 != 0) 1 else 0;
            const rsv2: u1 = if (b0 & 0b0010_0000 != 0) 1 else 0;
            const rsv3: u1 = if (b0 & 0b0001_0000 != 0) 1 else 0;
            try Frame.assertRsvBits(rsv2, rsv3);

            const opcode = try Frame.Opcode.decode(@intCast(b0 & 0b0000_1111));
            const mask_bit: u1 = if (b1 & 0b1000_0000 != 0) 1 else 0;
            const payload_len = try self.readPayloadLen(b1);
            const payload = try self.readPayload(payload_len, mask_bit == 1);

            var frm = Frame{
                .fin = fin,
                .rsv1 = rsv1,
                .mask = mask_bit,
                .opcode = opcode,
                .payload = payload,
                .allocator = if (payload.len > 0) self.allocator else null,
            };
            errdefer frm.deinit();
            try frm.assertValid(false);
            return frm;
        }
    };
}

pub fn Writer(comptime WriterType: type) type {
    return struct {
        writer: WriterType,
        buf: []u8,
        allocator: Allocator,

        const Self = @This();
        const writer_buffer_len = 4096;

        pub fn init(allocator: Allocator, inner_writer: WriterType) !Self {
            return .{
                .allocator = allocator,
                .buf = try allocator.alloc(u8, writer_buffer_len),
                .writer = inner_writer,
            };
        }

        pub fn pong(self: *Self, payload: []const u8) !void {
            assert(payload.len < 126);
            const frame = Frame{ .fin = 1, .opcode = .pong, .payload = payload, .mask = 1 };
            const bytes = frame.encode(self.buf, 0);
            try self.writer.writeAll(self.buf[0..bytes]);
        }

        pub fn close(self: *Self, code: u16, payload: []const u8) !void {
            assert(payload.len < 124);
            const frame = Frame{ .fin = 1, .opcode = .close, .payload = payload, .mask = 1 };
            const bytes = frame.encode(self.buf, code);
            try self.writer.writeAll(self.buf[0..bytes]);
        }

        pub fn message(self: *Self, encoding: Message.Encoding, payload: []const u8, compressed: bool) !void {
            var sent_payload: usize = 0;
            while (true) {
                const first_frame = sent_payload == 0;

                var fin: u1 = 1;
                const rsv1: u1 = if (compressed and first_frame) 1 else 0;

                var frame_payload = payload[sent_payload..];
                if (frame_payload.len + Frame.max_header > self.buf.len) {
                    frame_payload = frame_payload[0 .. self.buf.len - Frame.max_header];
                    fin = 0;
                }
                const opcode = if (first_frame) encoding.opcode() else Frame.Opcode.continuation;

                const frame = Frame{ .fin = fin, .rsv1 = rsv1, .opcode = opcode, .payload = frame_payload, .mask = 1 };
                const bytes = frame.encode(self.buf, 0);
                try self.writer.writeAll(self.buf[0..bytes]);
                sent_payload += frame_payload.len;
                if (sent_payload >= payload.len) {
                    break;
                }
            }
        }

        pub fn deinit(self: *Self) void {
            self.allocator.free(self.buf);
        }
    };
}

fn reader(allocator: Allocator, inner_reader: anytype) Reader(@TypeOf(inner_reader)) {
    return Reader(@TypeOf(inner_reader)).init(allocator, inner_reader);
}

fn writer(allocator: Allocator, inner_writer: anytype) !Writer(@TypeOf(inner_writer)) {
    return try Writer(@TypeOf(inner_writer)).init(allocator, inner_writer);
}

pub fn client(
    allocator: Allocator,
    inner_reader: anytype,
    inner_writer: anytype,
    options: Options,
) !Stream(@TypeOf(inner_reader), @TypeOf(inner_writer)) {
    _ = options;
    const S = Stream(@TypeOf(inner_reader), @TypeOf(inner_writer));
    return S{
        .allocator = allocator,
        .reader = reader(allocator, inner_reader),
        .writer = try writer(allocator, inner_writer),
    };
}

const testing = std.testing;

test "reader read close frame" {
    var input = [_]u8{ 0x88, 0x02, 0x03, 0xe8 };
    var inner_stm = std.io.fixedBufferStream(&input);
    var rdr = reader(testing.allocator, inner_stm.reader());
    var frame = try rdr.frame();
    defer frame.deinit();

    try testing.expectEqual(.close, frame.opcode);
    try testing.expectEqual(@as(u1, 1), frame.fin);
    try testing.expectEqual(@as(usize, 2), frame.payload.len);
    try testing.expectEqualSlices(u8, frame.payload, input[2..4]);
    try testing.expectEqual(@as(u16, 1000), frame.closeCode());
    try testing.expectError(error.EndOfStream, rdr.frame());
}

test "reader read masked close frame with payload" {
    var input = [_]u8{ 0x88, 0x87, 0xa, 0xb, 0xc, 0xd, 0x09, 0xe2, 0x0d, 0x0f, 0x09, 0x0f, 0x09 };
    var inner_stm = std.io.fixedBufferStream(&input);
    var rdr = reader(testing.allocator, inner_stm.reader());
    var frame = try rdr.frame();
    defer frame.deinit();

    const expected_payload = [_]u8{ 0x3, 0xe9, 0x1, 0x2, 0x3, 0x4, 0x5 };

    try testing.expectEqual(.close, frame.opcode);
    try testing.expectEqual(@as(u1, 1), frame.fin);
    try testing.expectEqual(@as(usize, 7), frame.payload.len);
    try testing.expectEqualSlices(u8, frame.payload, &expected_payload);
    try testing.expectEqual(@as(u16, 1001), frame.closeCode());
    try testing.expectError(error.EndOfStream, rdr.frame());
}
