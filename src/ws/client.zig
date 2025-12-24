const std = @import("std");
const net = std.net;
const mem = std.mem;
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

    const Self = @This();

    pub fn setReadTimeout(self: *Self, timeout_ms: u32) void {
        const seconds = timeout_ms / 1000;
        const microseconds = (timeout_ms % 1000) * 1000;
        const timeval = std.posix.timeval{
            .sec = @intCast(seconds),
            .usec = @intCast(microseconds),
        };
        std.posix.setsockopt(self.tcp_stream.handle, std.posix.SO.RCVTIMEO, std.mem.asBytes(&timeval)) catch {};
    }

    pub fn connect(allocator: Allocator, uri: []const u8) !Self {
        const parsed = try Uri.parse(uri);

        const tcp_stream = try net.tcpConnectToHost(allocator, parsed.host, parsed.port);
        errdefer tcp_stream.close();

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
        if (self.ssl_stream) |*s| {
            s.close();
        } else {
            self.tcp_stream.close();
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

            const rsp, _ = handshake.Rsp.parse(response_buf[0..response_len]) catch |err| switch (err) {
                error.SplitBuffer => continue,
                else => return err,
            };

            try rsp.validate(&sec_key);
            self.ws_options = rsp.options;
            return;
        }

        return error.NotWebsocketUpgradeResponse;
    }

    pub fn read(self: *Self, buffer: []u8) !usize {
        if (self.ssl_stream) |*s| {
            return s.read(buffer);
        } else {
            return self.tcp_stream.read(buffer);
        }
    }

    pub fn writeAll(self: *Self, data: []const u8) !void {
        if (self.ssl_stream) |*s| {
            try s.writeAll(data);
        } else {
            try self.tcp_stream.writeAll(data);
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

    pub fn recvMessage(self: *Self) !Message {
        const Frame = @import("frame.zig").Frame;

        var recv_buf: [65536]u8 = undefined;
        var recv_len: usize = 0;

        while (true) {
            const n = try self.read(recv_buf[recv_len..]);
            if (n == 0) return error.ConnectionResetByPeer;
            recv_len += n;

            while (recv_len > 0) {
                const frame, const frame_len = Frame.parse(recv_buf[0..recv_len]) catch |err| switch (err) {
                    error.SplitBuffer => break,
                    else => return err,
                };

                defer {
                    if (frame_len < recv_len) {
                        std.mem.copyForwards(u8, recv_buf[0 .. recv_len - frame_len], recv_buf[frame_len..recv_len]);
                    }
                    recv_len -= frame_len;
                }

                if (frame.opcode == .ping) {
                    try self.sendPong(frame.payload);
                    continue;
                }

                if (frame.opcode == .close) {
                    try self.sendClose(frame.closeCode(), frame.closePayload());
                    return error.EndOfStream;
                }

                if (frame.opcode == .pong) {
                    continue;
                }

                return Message{
                    .encoding = Message.Encoding.from(frame.opcode),
                    .payload = try self.allocator.dupe(u8, frame.payload),
                    .allocator = self.allocator,
                };
            }
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
