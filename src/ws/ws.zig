const std = @import("std");

pub const handshake = @import("handshake.zig");
pub const stream = @import("stream.zig");
pub const frame = @import("frame.zig");
pub const client_mod = @import("client.zig");

pub const Message = stream.Message;
pub const Options = stream.Options;
pub const Stream = stream.Stream;
pub const Frame = frame.Frame;

pub const Client = client_mod.Client;
pub const Uri = client_mod.Uri;

const async_mod = @import("async.zig");
pub const async_ = struct {
    pub const Server = async_mod.Server;
    pub const Client = async_mod.Client;
    pub const Conn = async_mod.Conn;
};
pub const Msg = async_mod.Msg;

pub fn connect(allocator: std.mem.Allocator, uri: []const u8) !Client {
    return Client.connect(allocator, uri);
}

test {
    _ = @import("handshake.zig");
    _ = @import("stream.zig");
    _ = @import("frame.zig");
    _ = @import("async.zig");
    _ = @import("client.zig");
}
