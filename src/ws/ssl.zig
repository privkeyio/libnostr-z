const std = @import("std");
const net = std.net;
const mem = std.mem;
const Allocator = mem.Allocator;

const c = @cImport({
    @cInclude("openssl/ssl.h");
    @cInclude("openssl/err.h");
});

pub const SslError = error{
    SslInitFailed,
    SslContextFailed,
    SslNewFailed,
    SslSetFdFailed,
    SslConnectFailed,
    SslWriteFailed,
    SslReadFailed,
    SslShutdownFailed,
};

pub const SslStream = struct {
    ssl: *c.SSL,
    ctx: *c.SSL_CTX,
    tcp_stream: net.Stream,

    const Self = @This();

    pub fn init(tcp_stream: net.Stream, host: []const u8) SslError!Self {
        const method = c.TLS_client_method() orelse return error.SslInitFailed;
        const ctx = c.SSL_CTX_new(method) orelse return error.SslContextFailed;
        errdefer c.SSL_CTX_free(ctx);

        const alpn = "\x08http/1.1";
        if (c.SSL_CTX_set_alpn_protos(ctx, alpn, alpn.len) != 0) {
            return error.SslContextFailed;
        }

        const ssl = c.SSL_new(ctx) orelse return error.SslNewFailed;
        errdefer c.SSL_free(ssl);

        var host_buf: [256]u8 = undefined;
        if (host.len >= host_buf.len) {
            return error.SslContextFailed;
        }
        @memcpy(host_buf[0..host.len], host);
        host_buf[host.len] = 0;
        if (c.SSL_set_tlsext_host_name(ssl, &host_buf) != 1) {
            return error.SslContextFailed;
        }

        if (c.SSL_set_fd(ssl, tcp_stream.handle) != 1) {
            return error.SslSetFdFailed;
        }

        const connect_result = c.SSL_connect(ssl);
        if (connect_result != 1) {
            return error.SslConnectFailed;
        }

        return Self{
            .ssl = ssl,
            .ctx = ctx,
            .tcp_stream = tcp_stream,
        };
    }

    pub fn read(self: *Self, buffer: []u8) !usize {
        const result = c.SSL_read(self.ssl, buffer.ptr, @intCast(buffer.len));
        if (result <= 0) {
            const err = c.SSL_get_error(self.ssl, result);
            if (err == c.SSL_ERROR_ZERO_RETURN) {
                return 0;
            }
            return error.SslReadFailed;
        }
        return @intCast(result);
    }

    pub fn write(self: *Self, data: []const u8) !usize {
        const result = c.SSL_write(self.ssl, data.ptr, @intCast(data.len));
        if (result <= 0) {
            return error.SslWriteFailed;
        }
        return @intCast(result);
    }

    pub fn writeAll(self: *Self, data: []const u8) !void {
        var written: usize = 0;
        while (written < data.len) {
            written += try self.write(data[written..]);
        }
    }

    pub fn close(self: *Self) void {
        _ = c.SSL_shutdown(self.ssl);
        c.SSL_free(self.ssl);
        c.SSL_CTX_free(self.ctx);
        self.tcp_stream.close();
    }
};
