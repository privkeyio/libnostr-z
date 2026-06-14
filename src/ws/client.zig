const std = @import("std");
const net = std.Io.net;
const mem = std.mem;
const io_mod = @import("../io.zig");
const Allocator = mem.Allocator;

const handshake = @import("handshake.zig");
const stream_mod = @import("stream.zig");
const ssl = @import("ssl.zig");

pub const Message = stream_mod.Message;
pub const Options = stream_mod.Options;

pub const Uri = struct {
    host: []const u8,
    port: u16,
    path: []const u8,
    is_tls: bool,

    pub fn parse(uri: []const u8) !Uri {
        var is_tls = false;
        var rest = uri;

        if (mem.startsWith(u8, uri, "wss://")) {
            is_tls = true;
            rest = uri[6..];
        } else if (mem.startsWith(u8, uri, "ws://")) {
            rest = uri[5..];
        }

        const path_start = mem.indexOfScalar(u8, rest, '/') orelse rest.len;
        const host_port = rest[0..path_start];
        const path = if (path_start < rest.len) rest[path_start..] else "/";

        var host: []const u8 = undefined;
        var port: u16 = undefined;

        if (mem.indexOfScalar(u8, host_port, ':')) |colon| {
            host = host_port[0..colon];
            port = std.fmt.parseInt(u16, host_port[colon + 1 ..], 10) catch return error.InvalidPort;
        } else {
            host = host_port;
            port = if (is_tls) 443 else 80;
        }

        if (host.len == 0) return error.InvalidHost;

        return .{
            .host = host,
            .port = port,
            .path = path,
            .is_tls = is_tls,
        };
    }
};

pub const Client = struct {
    allocator: Allocator,
    tcp_stream: net.Stream,
    ssl_stream: ?ssl.SslStream,
    ws_options: Options,
    is_tls: bool,
    uri: []const u8,
    /// Bytes read past the HTTP 101 upgrade response. A relay may send its first
    /// frame (e.g. a NIP-42 AUTH challenge) in the same TCP segment as the upgrade
    /// response; without preserving this tail the frame is silently dropped and a
    /// publish that depends on it hangs until the read timeout. Drained before the
    /// socket on the next read.
    overflow: []u8 = &.{},
    overflow_pos: usize = 0,

    const Self = @This();

    /// Upper bound on a single inbound frame's payload. Guards against a hostile
    /// relay advertising a multi-gigabyte length and forcing an OOM allocation.
    const max_payload_len = 16 * 1024 * 1024;

    pub fn setReadTimeout(self: *Self, timeout_ms: u32) void {
        const seconds = timeout_ms / 1000;
        const microseconds = (timeout_ms % 1000) * 1000;
        const timeval = std.posix.timeval{
            .sec = @intCast(seconds),
            .usec = @intCast(microseconds),
        };
        std.posix.setsockopt(self.tcp_stream.socket.handle, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&timeval)) catch {};
    }

    pub fn connect(allocator: Allocator, uri: []const u8) !Self {
        const parsed = try Uri.parse(uri);

        const host_name = try net.HostName.init(parsed.host);
        const tcp_stream = try host_name.connect(io_mod.io(), parsed.port, .{ .mode = .stream });
        errdefer tcp_stream.close(io_mod.io());

        // Nostr is a small-message, request/response protocol. Without TCP_NODELAY,
        // Nagle's algorithm holds a write (e.g. a REQ sent right after a CLOSE)
        // until the prior segment is ACKed, colliding with the peer's delayed ACK
        // for a ~40ms stall per round-trip. Disable it for low latency.
        const one = std.mem.toBytes(@as(c_int, 1));
        std.posix.setsockopt(tcp_stream.socket.handle, std.posix.IPPROTO.TCP, std.posix.TCP.NODELAY, &one) catch {};

        var ssl_stream: ?ssl.SslStream = null;
        if (parsed.is_tls) {
            ssl_stream = try ssl.SslStream.init(tcp_stream, parsed.host);
        }

        var self = Self{
            .allocator = allocator,
            .tcp_stream = tcp_stream,
            .ssl_stream = ssl_stream,
            .ws_options = .{},
            .is_tls = parsed.is_tls,
            .uri = uri,
        };

        self.doHandshake(uri) catch |err| {
            self.closeResources();
            return err;
        };
        return self;
    }

    fn closeResources(self: *Self) void {
        if (self.overflow.len > 0) {
            self.allocator.free(self.overflow);
            self.overflow = &.{};
            self.overflow_pos = 0;
        }
        if (self.ssl_stream) |*s| {
            s.close();
        } else {
            self.tcp_stream.close(io_mod.io());
        }
    }

    fn doHandshake(self: *Self, uri: []const u8) !void {
        const sec_key = handshake.secKey();
        var req_buf: [1024]u8 = undefined;
        const request = try handshake.requestBufPrint(&req_buf, uri, &sec_key);

        try self.writeAll(request);

        var response_buf: [4096]u8 = undefined;
        var response_len: usize = 0;

        while (response_len < response_buf.len) {
            const n = try self.read(response_buf[response_len..]);
            if (n == 0) return error.ConnectionResetByPeer;
            response_len += n;

            const rsp, const head_end = handshake.Rsp.parse(response_buf[0..response_len]) catch |err| switch (err) {
                error.SplitBuffer => continue,
                else => return err,
            };

            try rsp.validate(&sec_key);
            self.ws_options = rsp.options;
            // Preserve any frame bytes that arrived bundled with the 101 response.
            if (response_len > head_end) {
                self.overflow = try self.allocator.dupe(u8, response_buf[head_end..response_len]);
            }
            return;
        }

        return error.NotWebsocketUpgradeResponse;
    }

    pub fn read(self: *Self, buffer: []u8) !usize {
        if (self.ssl_stream) |*s| {
            return s.read(buffer);
        } else {
            return std.posix.read(self.tcp_stream.socket.handle, buffer);
        }
    }

    pub fn writeAll(self: *Self, data: []const u8) !void {
        if (self.ssl_stream) |*s| {
            try s.writeAll(data);
        } else {
            var wbuf: [4096]u8 = undefined;
            var sw = self.tcp_stream.writer(io_mod.io(), &wbuf);
            try sw.interface.writeAll(data);
            try sw.interface.flush();
        }
    }

    pub fn sendText(self: *Self, payload: []const u8) !void {
        try self.sendFrame(.text, payload);
    }

    pub fn sendBinary(self: *Self, payload: []const u8) !void {
        try self.sendFrame(.binary, payload);
    }

    fn sendFrame(self: *Self, opcode: @import("frame.zig").Frame.Opcode, payload: []const u8) !void {
        const Frame = @import("frame.zig").Frame;

        const frame = Frame{
            .fin = 1,
            .opcode = opcode,
            .payload = payload,
            .mask = 1,
        };

        const send_buf = try self.allocator.alloc(u8, frame.encodedLen());
        defer self.allocator.free(send_buf);

        _ = frame.encode(send_buf, 0);
        try self.writeAll(send_buf);
    }

    /// Reads exactly buf.len bytes, looping over short reads. A peer closing
    /// mid-read surfaces as ConnectionResetByPeer.
    fn readExact(self: *Self, buf: []u8) !void {
        var total: usize = 0;
        // Drain bytes captured past the handshake response before reading the socket.
        if (self.overflow_pos < self.overflow.len) {
            const take = @min(self.overflow.len - self.overflow_pos, buf.len);
            @memcpy(buf[0..take], self.overflow[self.overflow_pos .. self.overflow_pos + take]);
            self.overflow_pos += take;
            total = take;
            if (self.overflow_pos == self.overflow.len) {
                self.allocator.free(self.overflow);
                self.overflow = &.{};
                self.overflow_pos = 0;
            }
        }
        while (total < buf.len) {
            const n = try self.read(buf[total..]);
            if (n == 0) return error.ConnectionResetByPeer;
            total += n;
        }
    }

    pub fn recvMessage(self: *Self) !Message {
        const Frame = @import("frame.zig").Frame;

        // Read one frame at a time off the stream. Reading exactly the bytes a
        // frame needs (header, then extended length, then mask, then payload)
        // avoids over-reading into a following frame and dropping it, which a
        // single bulk read into a per-call buffer would do whenever a relay
        // sends frames back-to-back (e.g. a batch of EVENTs ending in EOSE).
        while (true) {
            var header: [2]u8 = undefined;
            try self.readExact(&header);

            if (header[0] & 0b0011_0000 != 0) return error.ReservedRsv;

            const opcode = try Frame.Opcode.decode(@intCast(header[0] & 0x0f));
            const masked = (header[1] & 0x80) != 0;

            var payload_len: u64 = header[1] & 0x7f;
            if (payload_len == 126) {
                var ext: [2]u8 = undefined;
                try self.readExact(&ext);
                payload_len = std.mem.readInt(u16, &ext, .big);
            } else if (payload_len == 127) {
                var ext: [8]u8 = undefined;
                try self.readExact(&ext);
                payload_len = std.mem.readInt(u64, &ext, .big);
            }

            var mask_key: [4]u8 = undefined;
            if (masked) try self.readExact(&mask_key);

            if (opcode.isControl()) {
                if (payload_len > 125) return error.TooBigPayloadForControlFrame;
                var ctrl_buf: [125]u8 = undefined;
                const ctrl = ctrl_buf[0..@intCast(payload_len)];
                try self.readExact(ctrl);
                if (masked) Frame.maskUnmask(&mask_key, ctrl);

                switch (opcode) {
                    .ping => {
                        try self.sendPong(ctrl);
                        continue;
                    },
                    .close => {
                        const code: u16 = if (ctrl.len >= 2) std.mem.readInt(u16, ctrl[0..2], .big) else 1000;
                        const reason = if (ctrl.len > 2) ctrl[2..] else ctrl[0..0];
                        try self.sendClose(code, reason);
                        return error.EndOfStream;
                    },
                    .pong => continue,
                    else => unreachable,
                }
            }

            if (payload_len > max_payload_len) return error.MessageTooBig;
            const payload = try self.allocator.alloc(u8, @intCast(payload_len));
            errdefer self.allocator.free(payload);
            try self.readExact(payload);
            if (masked) Frame.maskUnmask(&mask_key, payload);

            return Message{
                .encoding = Message.Encoding.from(opcode),
                .payload = payload,
                .allocator = self.allocator,
            };
        }
    }

    fn sendPong(self: *Self, payload: []const u8) !void {
        const Frame = @import("frame.zig").Frame;
        const frame = Frame{ .fin = 1, .opcode = .pong, .payload = payload, .mask = 1 };
        const buf = try self.allocator.alloc(u8, frame.encodedLen());
        defer self.allocator.free(buf);
        _ = frame.encode(buf, 0);
        try self.writeAll(buf);
    }

    fn sendClose(self: *Self, code: u16, payload: []const u8) !void {
        const Frame = @import("frame.zig").Frame;
        const frame = Frame{ .fin = 1, .opcode = .close, .payload = payload, .mask = 1 };
        const buf = try self.allocator.alloc(u8, frame.encodedLen());
        defer self.allocator.free(buf);
        _ = frame.encode(buf, code);
        try self.writeAll(buf);
    }

    pub fn close(self: *Self) void {
        self.sendClose(1000, "") catch {};
        self.closeResources();
    }
};

test "Uri.parse" {
    const testing = std.testing;

    {
        const uri = try Uri.parse("wss://relay.damus.io");
        try testing.expectEqualStrings("relay.damus.io", uri.host);
        try testing.expectEqual(@as(u16, 443), uri.port);
        try testing.expectEqualStrings("/", uri.path);
        try testing.expect(uri.is_tls);
    }

    {
        const uri = try Uri.parse("ws://localhost:8080/nostr");
        try testing.expectEqualStrings("localhost", uri.host);
        try testing.expectEqual(@as(u16, 8080), uri.port);
        try testing.expectEqualStrings("/nostr", uri.path);
        try testing.expect(!uri.is_tls);
    }

    {
        const uri = try Uri.parse("wss://relay.example.com:9443/v1");
        try testing.expectEqualStrings("relay.example.com", uri.host);
        try testing.expectEqual(@as(u16, 9443), uri.port);
        try testing.expectEqualStrings("/v1", uri.path);
        try testing.expect(uri.is_tls);
    }
}
