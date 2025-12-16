//! NIP-46 Nostr Remote Signing protocol types.
//!
//! Zero-allocation parsing returns slices into the original JSON.

const std = @import("std");
const utils = @import("utils.zig");
const hex = @import("hex.zig");
const crypto = @import("crypto.zig");

pub const Kind = struct {
    pub const request: i32 = 24133;
    pub const response: i32 = 24133;
};

pub const Method = enum {
    connect,
    sign_event,
    ping,
    get_public_key,
    nip04_encrypt,
    nip04_decrypt,
    nip44_encrypt,
    nip44_decrypt,

    pub fn toString(self: Method) []const u8 {
        return switch (self) {
            .connect => "connect",
            .sign_event => "sign_event",
            .ping => "ping",
            .get_public_key => "get_public_key",
            .nip04_encrypt => "nip04_encrypt",
            .nip04_decrypt => "nip04_decrypt",
            .nip44_encrypt => "nip44_encrypt",
            .nip44_decrypt => "nip44_decrypt",
        };
    }

    pub fn fromString(s: []const u8) ?Method {
        const map = std.StaticStringMap(Method).initComptime(.{
            .{ "connect", .connect },
            .{ "sign_event", .sign_event },
            .{ "ping", .ping },
            .{ "get_public_key", .get_public_key },
            .{ "nip04_encrypt", .nip04_encrypt },
            .{ "nip04_decrypt", .nip04_decrypt },
            .{ "nip44_encrypt", .nip44_encrypt },
            .{ "nip44_decrypt", .nip44_decrypt },
        });
        return map.get(s);
    }
};

pub const Request = struct {
    id: []const u8,
    method: Method,
    params: Params,

    pub const Params = union(Method) {
        connect: Connect,
        sign_event: SignEvent,
        ping: void,
        get_public_key: void,
        nip04_encrypt: Encrypt,
        nip04_decrypt: Decrypt,
        nip44_encrypt: Encrypt,
        nip44_decrypt: Decrypt,
    };

    pub const Connect = struct {
        remote_signer_pubkey: []const u8,
        secret: ?[]const u8 = null,
        permissions: ?[]const u8 = null,
    };

    pub const SignEvent = struct {
        event_json: []const u8,
    };

    pub const Encrypt = struct {
        third_party_pubkey: []const u8,
        plaintext: []const u8,
    };

    pub const Decrypt = struct {
        third_party_pubkey: []const u8,
        ciphertext: []const u8,
    };

    pub fn parseJson(json: []const u8) ?Request {
        const id = utils.extractJsonString(json, "id") orelse return null;
        const method_str = utils.extractJsonString(json, "method") orelse return null;
        const method = Method.fromString(method_str) orelse return null;

        const params_json = utils.findJsonValue(json, "params") orelse return null;

        return switch (method) {
            .connect => blk: {
                const arr0 = utils.findArrayElement(params_json, 0);
                const arr1 = utils.findArrayElement(params_json, 1);
                const arr2 = utils.findArrayElement(params_json, 2);
                break :blk .{
                    .id = id,
                    .method = .connect,
                    .params = .{ .connect = .{
                        .remote_signer_pubkey = if (arr0) |a| extractArrayString(a) orelse return null else return null,
                        .secret = if (arr1) |a| extractArrayString(a) else null,
                        .permissions = if (arr2) |a| extractArrayString(a) else null,
                    } },
                };
            },
            .sign_event => .{
                .id = id,
                .method = .sign_event,
                .params = .{ .sign_event = .{
                    .event_json = utils.findArrayElement(params_json, 0) orelse return null,
                } },
            },
            .ping => .{
                .id = id,
                .method = .ping,
                .params = .{ .ping = {} },
            },
            .get_public_key => .{
                .id = id,
                .method = .get_public_key,
                .params = .{ .get_public_key = {} },
            },
            .nip04_encrypt, .nip44_encrypt => blk: {
                const arr0 = utils.findArrayElement(params_json, 0);
                const arr1 = utils.findArrayElement(params_json, 1);
                const encrypt_params = Encrypt{
                    .third_party_pubkey = if (arr0) |a| extractArrayString(a) orelse return null else return null,
                    .plaintext = if (arr1) |a| extractArrayString(a) orelse return null else return null,
                };
                break :blk .{
                    .id = id,
                    .method = method,
                    .params = if (method == .nip04_encrypt)
                        .{ .nip04_encrypt = encrypt_params }
                    else
                        .{ .nip44_encrypt = encrypt_params },
                };
            },
            .nip04_decrypt, .nip44_decrypt => blk: {
                const arr0 = utils.findArrayElement(params_json, 0);
                const arr1 = utils.findArrayElement(params_json, 1);
                const decrypt_params = Decrypt{
                    .third_party_pubkey = if (arr0) |a| extractArrayString(a) orelse return null else return null,
                    .ciphertext = if (arr1) |a| extractArrayString(a) orelse return null else return null,
                };
                break :blk .{
                    .id = id,
                    .method = method,
                    .params = if (method == .nip04_decrypt)
                        .{ .nip04_decrypt = decrypt_params }
                    else
                        .{ .nip44_decrypt = decrypt_params },
                };
            },
        };
    }

    pub fn serialize(self: *const Request, buf: []u8) ![]u8 {
        var fbs = std.io.fixedBufferStream(buf);
        const writer = fbs.writer();

        try writer.writeAll("{\"id\":\"");
        try utils.writeJsonEscaped(writer, self.id);
        try writer.writeAll("\",\"method\":\"");
        try writer.writeAll(self.method.toString());
        try writer.writeAll("\",\"params\":[");

        switch (self.params) {
            .connect => |p| {
                try writer.writeAll("\"");
                try utils.writeJsonEscaped(writer, p.remote_signer_pubkey);
                try writer.writeAll("\"");
                if (p.secret) |s| {
                    try writer.writeAll(",\"");
                    try utils.writeJsonEscaped(writer, s);
                    try writer.writeAll("\"");
                    if (p.permissions) |perms| {
                        try writer.writeAll(",\"");
                        try utils.writeJsonEscaped(writer, perms);
                        try writer.writeAll("\"");
                    }
                } else if (p.permissions) |perms| {
                    try writer.writeAll(",\"\",\"");
                    try utils.writeJsonEscaped(writer, perms);
                    try writer.writeAll("\"");
                }
            },
            .sign_event => |p| {
                try writer.writeAll(p.event_json);
            },
            .ping, .get_public_key => {},
            .nip04_encrypt, .nip44_encrypt => |p| {
                try writer.writeAll("\"");
                try utils.writeJsonEscaped(writer, p.third_party_pubkey);
                try writer.writeAll("\",\"");
                try utils.writeJsonEscaped(writer, p.plaintext);
                try writer.writeAll("\"");
            },
            .nip04_decrypt, .nip44_decrypt => |p| {
                try writer.writeAll("\"");
                try utils.writeJsonEscaped(writer, p.third_party_pubkey);
                try writer.writeAll("\",\"");
                try utils.writeJsonEscaped(writer, p.ciphertext);
                try writer.writeAll("\"");
            },
        }

        try writer.writeAll("]}");
        return fbs.getWritten();
    }
};

pub const Response = struct {
    id: []const u8,
    result: ?[]const u8 = null,
    err: ?[]const u8 = null,

    pub fn parseJson(json: []const u8) ?Response {
        const id = utils.extractJsonString(json, "id") orelse return null;

        var response = Response{ .id = id };

        if (utils.findJsonValue(json, "result")) |result_json| {
            if (!std.mem.eql(u8, result_json, "null")) {
                response.result = extractResultString(result_json);
            }
        }

        if (utils.findJsonValue(json, "error")) |err_json| {
            if (!std.mem.eql(u8, err_json, "null")) {
                response.err = extractResultString(err_json);
            }
        }

        return response;
    }

    pub fn serialize(self: *const Response, buf: []u8) ![]u8 {
        var fbs = std.io.fixedBufferStream(buf);
        const writer = fbs.writer();

        try writer.writeAll("{\"id\":\"");
        try utils.writeJsonEscaped(writer, self.id);
        try writer.writeAll("\"");

        if (self.result) |r| {
            try writer.writeAll(",\"result\":\"");
            try utils.writeJsonEscaped(writer, r);
            try writer.writeAll("\"");
        } else {
            try writer.writeAll(",\"result\":null");
        }

        if (self.err) |e| {
            try writer.writeAll(",\"error\":\"");
            try utils.writeJsonEscaped(writer, e);
            try writer.writeAll("\"");
        }

        try writer.writeAll("}");
        return fbs.getWritten();
    }

    pub fn isAuthChallenge(self: *const Response) bool {
        if (self.result) |r| {
            return std.mem.eql(u8, r, "auth_url");
        }
        return false;
    }

    pub fn getAuthUrl(self: *const Response) ?[]const u8 {
        if (self.isAuthChallenge()) {
            return self.err;
        }
        return null;
    }
};

pub const BunkerUri = struct {
    remote_signer_pubkey: [32]u8,
    relays: [][]const u8,
    secret: ?[]const u8,
    allocator: std.mem.Allocator,

    pub fn parse(allocator: std.mem.Allocator, uri: []const u8) !BunkerUri {
        const prefix = "bunker://";
        if (!std.mem.startsWith(u8, uri, prefix)) return error.InvalidUri;

        const after_prefix = uri[prefix.len..];
        const query_start = std.mem.indexOf(u8, after_prefix, "?") orelse return error.InvalidUri;

        const pubkey_hex = after_prefix[0..query_start];
        if (pubkey_hex.len != 64) return error.InvalidUri;

        var remote_signer_pubkey: [32]u8 = undefined;
        _ = std.fmt.hexToBytes(&remote_signer_pubkey, pubkey_hex) catch return error.InvalidUri;

        const query = after_prefix[query_start + 1 ..];

        var secret: ?[]const u8 = null;
        var relays: std.ArrayListUnmanaged([]const u8) = .{};
        errdefer {
            for (relays.items) |r| allocator.free(r);
            relays.deinit(allocator);
            if (secret) |s| allocator.free(s);
        }

        var params = std.mem.splitScalar(u8, query, '&');
        while (params.next()) |param| {
            const eq_pos = std.mem.indexOf(u8, param, "=") orelse continue;
            const key = param[0..eq_pos];
            const value = param[eq_pos + 1 ..];

            if (std.mem.eql(u8, key, "secret")) {
                secret = try percentDecode(allocator, value);
            } else if (std.mem.eql(u8, key, "relay")) {
                const decoded = try percentDecode(allocator, value);
                try relays.append(allocator, decoded);
            }
        }

        if (relays.items.len == 0) return error.InvalidUri;

        return .{
            .remote_signer_pubkey = remote_signer_pubkey,
            .relays = try relays.toOwnedSlice(allocator),
            .secret = secret,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *BunkerUri) void {
        for (self.relays) |r| self.allocator.free(r);
        self.allocator.free(self.relays);
        if (self.secret) |s| self.allocator.free(s);
    }

    pub fn format(self: *const BunkerUri, buf: []u8) ![]u8 {
        var fbs = std.io.fixedBufferStream(buf);
        const writer = fbs.writer();

        try writer.writeAll("bunker://");
        var pk_hex: [64]u8 = undefined;
        hex.encode(&self.remote_signer_pubkey, &pk_hex);
        try writer.writeAll(&pk_hex);
        try writer.writeAll("?");

        for (self.relays, 0..) |relay, i| {
            if (i > 0) try writer.writeAll("&");
            try writer.writeAll("relay=");
            try percentEncode(writer, relay);
        }

        if (self.secret) |s| {
            try writer.writeAll("&secret=");
            try percentEncode(writer, s);
        }

        return fbs.getWritten();
    }
};

pub const NostrConnectUri = struct {
    client_pubkey: [32]u8,
    relays: [][]const u8,
    secret: []const u8,
    permissions: ?[]const u8,
    name: ?[]const u8,
    url: ?[]const u8,
    image: ?[]const u8,
    allocator: std.mem.Allocator,

    pub fn parse(allocator: std.mem.Allocator, uri: []const u8) !NostrConnectUri {
        const prefix = "nostrconnect://";
        if (!std.mem.startsWith(u8, uri, prefix)) return error.InvalidUri;

        const after_prefix = uri[prefix.len..];
        const query_start = std.mem.indexOf(u8, after_prefix, "?") orelse return error.InvalidUri;

        const pubkey_hex = after_prefix[0..query_start];
        if (pubkey_hex.len != 64) return error.InvalidUri;

        var client_pubkey: [32]u8 = undefined;
        _ = std.fmt.hexToBytes(&client_pubkey, pubkey_hex) catch return error.InvalidUri;

        const query = after_prefix[query_start + 1 ..];

        var secret: ?[]const u8 = null;
        var permissions: ?[]const u8 = null;
        var name: ?[]const u8 = null;
        var url_field: ?[]const u8 = null;
        var image: ?[]const u8 = null;
        var relays: std.ArrayListUnmanaged([]const u8) = .{};
        errdefer {
            for (relays.items) |r| allocator.free(r);
            relays.deinit(allocator);
            if (secret) |s| allocator.free(s);
            if (permissions) |p| allocator.free(p);
            if (name) |n| allocator.free(n);
            if (url_field) |u| allocator.free(u);
            if (image) |img| allocator.free(img);
        }

        var params = std.mem.splitScalar(u8, query, '&');
        while (params.next()) |param| {
            const eq_pos = std.mem.indexOf(u8, param, "=") orelse continue;
            const key = param[0..eq_pos];
            const value = param[eq_pos + 1 ..];

            if (std.mem.eql(u8, key, "secret")) {
                secret = try percentDecode(allocator, value);
            } else if (std.mem.eql(u8, key, "relay")) {
                const decoded = try percentDecode(allocator, value);
                try relays.append(allocator, decoded);
            } else if (std.mem.eql(u8, key, "perms")) {
                permissions = try percentDecode(allocator, value);
            } else if (std.mem.eql(u8, key, "name")) {
                name = try percentDecode(allocator, value);
            } else if (std.mem.eql(u8, key, "url")) {
                url_field = try percentDecode(allocator, value);
            } else if (std.mem.eql(u8, key, "image")) {
                image = try percentDecode(allocator, value);
            }
        }

        if (secret == null) return error.InvalidUri;
        if (relays.items.len == 0) return error.InvalidUri;

        return .{
            .client_pubkey = client_pubkey,
            .relays = try relays.toOwnedSlice(allocator),
            .secret = secret.?,
            .permissions = permissions,
            .name = name,
            .url = url_field,
            .image = image,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *NostrConnectUri) void {
        for (self.relays) |r| self.allocator.free(r);
        self.allocator.free(self.relays);
        self.allocator.free(self.secret);
        if (self.permissions) |p| self.allocator.free(p);
        if (self.name) |n| self.allocator.free(n);
        if (self.url) |u| self.allocator.free(u);
        if (self.image) |img| self.allocator.free(img);
    }

    pub fn format(self: *const NostrConnectUri, buf: []u8) ![]u8 {
        var fbs = std.io.fixedBufferStream(buf);
        const writer = fbs.writer();

        try writer.writeAll("nostrconnect://");
        var pk_hex: [64]u8 = undefined;
        hex.encode(&self.client_pubkey, &pk_hex);
        try writer.writeAll(&pk_hex);
        try writer.writeAll("?");

        for (self.relays, 0..) |relay, i| {
            if (i > 0) try writer.writeAll("&");
            try writer.writeAll("relay=");
            try percentEncode(writer, relay);
        }

        try writer.writeAll("&secret=");
        try percentEncode(writer, self.secret);

        if (self.permissions) |p| {
            try writer.writeAll("&perms=");
            try percentEncode(writer, p);
        }

        if (self.name) |n| {
            try writer.writeAll("&name=");
            try percentEncode(writer, n);
        }

        if (self.url) |u| {
            try writer.writeAll("&url=");
            try percentEncode(writer, u);
        }

        if (self.image) |img| {
            try writer.writeAll("&image=");
            try percentEncode(writer, img);
        }

        return fbs.getWritten();
    }
};

fn extractArrayString(json: []const u8) ?[]const u8 {
    const trimmed = std.mem.trim(u8, json, " \t\n\r");
    if (trimmed.len < 2) return null;
    if (trimmed[0] == '"' and trimmed[trimmed.len - 1] == '"') {
        return trimmed[1 .. trimmed.len - 1];
    }
    return null;
}

fn extractResultString(json: []const u8) ?[]const u8 {
    const trimmed = std.mem.trim(u8, json, " \t\n\r");
    if (trimmed.len >= 2 and trimmed[0] == '"' and trimmed[trimmed.len - 1] == '"') {
        return trimmed[1 .. trimmed.len - 1];
    }
    return trimmed;
}

fn percentDecode(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    var result: std.ArrayListUnmanaged(u8) = .{};
    errdefer result.deinit(allocator);

    var i: usize = 0;
    while (i < input.len) {
        if (input[i] == '%' and i + 2 < input.len) {
            const byte = std.fmt.parseInt(u8, input[i + 1 .. i + 3], 16) catch {
                try result.append(allocator, input[i]);
                i += 1;
                continue;
            };
            try result.append(allocator, byte);
            i += 3;
        } else if (input[i] == '+') {
            try result.append(allocator, ' ');
            i += 1;
        } else {
            try result.append(allocator, input[i]);
            i += 1;
        }
    }
    return result.toOwnedSlice(allocator);
}

fn percentEncode(writer: anytype, input: []const u8) !void {
    for (input) |c| {
        if (std.ascii.isAlphanumeric(c) or c == '-' or c == '_' or c == '.' or c == '~') {
            try writer.writeByte(c);
        } else {
            try writer.print("%{X:0>2}", .{c});
        }
    }
}

pub fn encryptRequest(
    request: *const Request,
    secret_key: *const [32]u8,
    remote_pubkey: *const [32]u8,
    allocator: std.mem.Allocator,
) ![]u8 {
    const buf = try allocator.alloc(u8, 65536);
    defer allocator.free(buf);
    const json = try request.serialize(buf);
    return crypto.nip44Encrypt(secret_key, remote_pubkey, json, allocator);
}

pub fn decryptRequest(
    encrypted: []const u8,
    secret_key: *const [32]u8,
    sender_pubkey: *const [32]u8,
    allocator: std.mem.Allocator,
) !struct { json: []u8, request: ?Request } {
    const json = try crypto.nip44Decrypt(secret_key, sender_pubkey, encrypted, allocator);
    return .{ .json = json, .request = Request.parseJson(json) };
}

pub fn encryptResponse(
    response: *const Response,
    secret_key: *const [32]u8,
    client_pubkey: *const [32]u8,
    allocator: std.mem.Allocator,
) ![]u8 {
    const buf = try allocator.alloc(u8, 65536);
    defer allocator.free(buf);
    const json = try response.serialize(buf);
    return crypto.nip44Encrypt(secret_key, client_pubkey, json, allocator);
}

pub fn decryptResponse(
    encrypted: []const u8,
    secret_key: *const [32]u8,
    signer_pubkey: *const [32]u8,
    allocator: std.mem.Allocator,
) !struct { json: []u8, response: ?Response } {
    const json = try crypto.nip44Decrypt(secret_key, signer_pubkey, encrypted, allocator);
    return .{ .json = json, .response = Response.parseJson(json) };
}

test "Method roundtrip" {
    inline for (std.meta.fields(Method)) |field| {
        const method: Method = @enumFromInt(field.value);
        const str = method.toString();
        const parsed = Method.fromString(str).?;
        try std.testing.expectEqual(method, parsed);
    }
}

test "Kind constants" {
    try std.testing.expectEqual(@as(i32, 24133), Kind.request);
    try std.testing.expectEqual(@as(i32, 24133), Kind.response);
}

test "Request.parseJson connect" {
    const json =
        \\{"id":"abc123","method":"connect","params":["fa984bd7dbb282f07e16e7ae87b26a2a7b9b90b7246a44771f0cf5ae58018f52","secret123","sign_event:1,nip44_encrypt"]}
    ;
    const req = Request.parseJson(json).?;
    try std.testing.expectEqualStrings("abc123", req.id);
    try std.testing.expectEqual(Method.connect, req.method);
    try std.testing.expectEqualStrings("fa984bd7dbb282f07e16e7ae87b26a2a7b9b90b7246a44771f0cf5ae58018f52", req.params.connect.remote_signer_pubkey);
    try std.testing.expectEqualStrings("secret123", req.params.connect.secret.?);
    try std.testing.expectEqualStrings("sign_event:1,nip44_encrypt", req.params.connect.permissions.?);
}

test "Request.parseJson sign_event" {
    const json =
        \\{"id":"req1","method":"sign_event","params":["{\"kind\":1,\"content\":\"hello\",\"tags\":[],\"created_at\":1714078911}"]}
    ;
    const req = Request.parseJson(json).?;
    try std.testing.expectEqualStrings("req1", req.id);
    try std.testing.expectEqual(Method.sign_event, req.method);
    try std.testing.expect(std.mem.indexOf(u8, req.params.sign_event.event_json, "kind") != null);
    try std.testing.expect(std.mem.indexOf(u8, req.params.sign_event.event_json, "content") != null);
}

test "Request.parseJson ping" {
    const json =
        \\{"id":"ping1","method":"ping","params":[]}
    ;
    const req = Request.parseJson(json).?;
    try std.testing.expectEqualStrings("ping1", req.id);
    try std.testing.expectEqual(Method.ping, req.method);
}

test "Request.parseJson get_public_key" {
    const json =
        \\{"id":"gpk1","method":"get_public_key","params":[]}
    ;
    const req = Request.parseJson(json).?;
    try std.testing.expectEqualStrings("gpk1", req.id);
    try std.testing.expectEqual(Method.get_public_key, req.method);
}

test "Request.parseJson nip44_encrypt" {
    const json =
        \\{"id":"enc1","method":"nip44_encrypt","params":["fa984bd7dbb282f07e16e7ae87b26a2a7b9b90b7246a44771f0cf5ae58018f52","Hello, World!"]}
    ;
    const req = Request.parseJson(json).?;
    try std.testing.expectEqualStrings("enc1", req.id);
    try std.testing.expectEqual(Method.nip44_encrypt, req.method);
    try std.testing.expectEqualStrings("fa984bd7dbb282f07e16e7ae87b26a2a7b9b90b7246a44771f0cf5ae58018f52", req.params.nip44_encrypt.third_party_pubkey);
    try std.testing.expectEqualStrings("Hello, World!", req.params.nip44_encrypt.plaintext);
}

test "Request.parseJson nip44_decrypt" {
    const json =
        \\{"id":"dec1","method":"nip44_decrypt","params":["fa984bd7dbb282f07e16e7ae87b26a2a7b9b90b7246a44771f0cf5ae58018f52","AgAAA...base64..."]}
    ;
    const req = Request.parseJson(json).?;
    try std.testing.expectEqualStrings("dec1", req.id);
    try std.testing.expectEqual(Method.nip44_decrypt, req.method);
    try std.testing.expectEqualStrings("fa984bd7dbb282f07e16e7ae87b26a2a7b9b90b7246a44771f0cf5ae58018f52", req.params.nip44_decrypt.third_party_pubkey);
    try std.testing.expectEqualStrings("AgAAA...base64...", req.params.nip44_decrypt.ciphertext);
}

test "Request.serialize connect" {
    const req = Request{
        .id = "test123",
        .method = .connect,
        .params = .{ .connect = .{
            .remote_signer_pubkey = "fa984bd7dbb282f07e16e7ae87b26a2a7b9b90b7246a44771f0cf5ae58018f52",
            .secret = "mysecret",
            .permissions = "sign_event:1",
        } },
    };

    var buf: [512]u8 = undefined;
    const json = try req.serialize(&buf);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"id\":\"test123\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"method\":\"connect\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"fa984bd7dbb282f07e16e7ae87b26a2a7b9b90b7246a44771f0cf5ae58018f52\"") != null);
}

test "Request.serialize ping" {
    const req = Request{
        .id = "ping1",
        .method = .ping,
        .params = .{ .ping = {} },
    };

    var buf: [128]u8 = undefined;
    const json = try req.serialize(&buf);
    try std.testing.expectEqualStrings("{\"id\":\"ping1\",\"method\":\"ping\",\"params\":[]}", json);
}

test "Response.parseJson success" {
    const json =
        \\{"id":"req1","result":"pong"}
    ;
    const resp = Response.parseJson(json).?;
    try std.testing.expectEqualStrings("req1", resp.id);
    try std.testing.expectEqualStrings("pong", resp.result.?);
    try std.testing.expect(resp.err == null);
}

test "Response.parseJson error" {
    const json =
        \\{"id":"req1","result":null,"error":"permission denied"}
    ;
    const resp = Response.parseJson(json).?;
    try std.testing.expectEqualStrings("req1", resp.id);
    try std.testing.expect(resp.result == null);
    try std.testing.expectEqualStrings("permission denied", resp.err.?);
}

test "Response.parseJson auth_challenge" {
    const json =
        \\{"id":"req1","result":"auth_url","error":"https://example.com/auth?challenge=xyz"}
    ;
    const resp = Response.parseJson(json).?;
    try std.testing.expect(resp.isAuthChallenge());
    try std.testing.expectEqualStrings("https://example.com/auth?challenge=xyz", resp.getAuthUrl().?);
}

test "Response.serialize" {
    const resp = Response{
        .id = "resp1",
        .result = "pong",
    };

    var buf: [128]u8 = undefined;
    const json = try resp.serialize(&buf);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"id\":\"resp1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"result\":\"pong\"") != null);
}

test "Response.serialize with error" {
    const resp = Response{
        .id = "resp1",
        .err = "not authorized",
    };

    var buf: [128]u8 = undefined;
    const json = try resp.serialize(&buf);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"id\":\"resp1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"result\":null") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"error\":\"not authorized\"") != null);
}

test "BunkerUri.parse" {
    const uri = "bunker://fa984bd7dbb282f07e16e7ae87b26a2a7b9b90b7246a44771f0cf5ae58018f52?relay=wss%3A%2F%2Frelay.example.com&secret=mysecret123";

    var bunker = try BunkerUri.parse(std.testing.allocator, uri);
    defer bunker.deinit();

    var pk_hex: [64]u8 = undefined;
    hex.encode(&bunker.remote_signer_pubkey, &pk_hex);
    try std.testing.expectEqualStrings("fa984bd7dbb282f07e16e7ae87b26a2a7b9b90b7246a44771f0cf5ae58018f52", &pk_hex);

    try std.testing.expectEqual(@as(usize, 1), bunker.relays.len);
    try std.testing.expectEqualStrings("wss://relay.example.com", bunker.relays[0]);
    try std.testing.expectEqualStrings("mysecret123", bunker.secret.?);
}

test "BunkerUri.parse multiple relays" {
    const uri = "bunker://fa984bd7dbb282f07e16e7ae87b26a2a7b9b90b7246a44771f0cf5ae58018f52?relay=wss%3A%2F%2Frelay1.example.com&relay=wss%3A%2F%2Frelay2.example.com";

    var bunker = try BunkerUri.parse(std.testing.allocator, uri);
    defer bunker.deinit();

    try std.testing.expectEqual(@as(usize, 2), bunker.relays.len);
    try std.testing.expectEqualStrings("wss://relay1.example.com", bunker.relays[0]);
    try std.testing.expectEqualStrings("wss://relay2.example.com", bunker.relays[1]);
    try std.testing.expect(bunker.secret == null);
}

test "BunkerUri.format" {
    const uri = "bunker://fa984bd7dbb282f07e16e7ae87b26a2a7b9b90b7246a44771f0cf5ae58018f52?relay=wss%3A%2F%2Frelay.example.com&secret=test";
    var bunker = try BunkerUri.parse(std.testing.allocator, uri);
    defer bunker.deinit();

    var buf: [512]u8 = undefined;
    const result = try bunker.format(&buf);
    try std.testing.expect(std.mem.startsWith(u8, result, "bunker://"));
    try std.testing.expect(std.mem.indexOf(u8, result, "relay=wss%3A%2F%2Frelay.example.com") != null);
}

test "BunkerUri invalid inputs" {
    try std.testing.expectError(error.InvalidUri, BunkerUri.parse(std.testing.allocator, "invalid"));
    try std.testing.expectError(error.InvalidUri, BunkerUri.parse(std.testing.allocator, "bunker://tooshort?relay=wss://r.com"));
    try std.testing.expectError(error.InvalidUri, BunkerUri.parse(std.testing.allocator, "bunker://fa984bd7dbb282f07e16e7ae87b26a2a7b9b90b7246a44771f0cf5ae58018f52?secret=abc"));
}

test "NostrConnectUri.parse" {
    const uri = "nostrconnect://83f3b2ae6aa368e8275397b9c26cf550101d63ebaab900d19dd4a4429f5ad8f5?relay=wss%3A%2F%2Frelay1.example.com&perms=nip44_encrypt%2Csign_event%3A1&name=My+Client&secret=0s8j2djs";

    var conn = try NostrConnectUri.parse(std.testing.allocator, uri);
    defer conn.deinit();

    var pk_hex: [64]u8 = undefined;
    hex.encode(&conn.client_pubkey, &pk_hex);
    try std.testing.expectEqualStrings("83f3b2ae6aa368e8275397b9c26cf550101d63ebaab900d19dd4a4429f5ad8f5", &pk_hex);

    try std.testing.expectEqual(@as(usize, 1), conn.relays.len);
    try std.testing.expectEqualStrings("wss://relay1.example.com", conn.relays[0]);
    try std.testing.expectEqualStrings("0s8j2djs", conn.secret);
    try std.testing.expectEqualStrings("nip44_encrypt,sign_event:1", conn.permissions.?);
    try std.testing.expectEqualStrings("My Client", conn.name.?);
}

test "NostrConnectUri.parse with all fields" {
    const uri = "nostrconnect://83f3b2ae6aa368e8275397b9c26cf550101d63ebaab900d19dd4a4429f5ad8f5?relay=wss%3A%2F%2Frelay.example.com&secret=abc123&perms=sign_event&name=TestApp&url=https%3A%2F%2Fexample.com&image=https%3A%2F%2Fexample.com%2Flogo.png";

    var conn = try NostrConnectUri.parse(std.testing.allocator, uri);
    defer conn.deinit();

    try std.testing.expectEqualStrings("abc123", conn.secret);
    try std.testing.expectEqualStrings("sign_event", conn.permissions.?);
    try std.testing.expectEqualStrings("TestApp", conn.name.?);
    try std.testing.expectEqualStrings("https://example.com", conn.url.?);
    try std.testing.expectEqualStrings("https://example.com/logo.png", conn.image.?);
}

test "NostrConnectUri.format" {
    const uri = "nostrconnect://83f3b2ae6aa368e8275397b9c26cf550101d63ebaab900d19dd4a4429f5ad8f5?relay=wss%3A%2F%2Frelay.example.com&secret=test123";
    var conn = try NostrConnectUri.parse(std.testing.allocator, uri);
    defer conn.deinit();

    var buf: [512]u8 = undefined;
    const result = try conn.format(&buf);
    try std.testing.expect(std.mem.startsWith(u8, result, "nostrconnect://"));
    try std.testing.expect(std.mem.indexOf(u8, result, "secret=test123") != null);
}

test "NostrConnectUri invalid inputs" {
    try std.testing.expectError(error.InvalidUri, NostrConnectUri.parse(std.testing.allocator, "invalid"));
    try std.testing.expectError(error.InvalidUri, NostrConnectUri.parse(std.testing.allocator, "nostrconnect://tooshort?relay=wss://r.com&secret=abc"));
    try std.testing.expectError(error.InvalidUri, NostrConnectUri.parse(std.testing.allocator, "nostrconnect://83f3b2ae6aa368e8275397b9c26cf550101d63ebaab900d19dd4a4429f5ad8f5?relay=wss://r.com"));
    try std.testing.expectError(error.InvalidUri, NostrConnectUri.parse(std.testing.allocator, "nostrconnect://83f3b2ae6aa368e8275397b9c26cf550101d63ebaab900d19dd4a4429f5ad8f5?secret=abc"));
}

test "Request.parseJson malformed returns null" {
    try std.testing.expect(Request.parseJson("not json") == null);
    try std.testing.expect(Request.parseJson("{}") == null);
    try std.testing.expect(Request.parseJson("{\"id\":\"1\",\"method\":\"unknown\",\"params\":[]}") == null);
}

test "Response.parseJson malformed returns null" {
    try std.testing.expect(Response.parseJson("not json") == null);
    try std.testing.expect(Response.parseJson("{}") == null);
}

test "Request.serialize nip44_encrypt" {
    const req = Request{
        .id = "enc1",
        .method = .nip44_encrypt,
        .params = .{ .nip44_encrypt = .{
            .third_party_pubkey = "fa984bd7dbb282f07e16e7ae87b26a2a7b9b90b7246a44771f0cf5ae58018f52",
            .plaintext = "Hello",
        } },
    };

    var buf: [256]u8 = undefined;
    const json = try req.serialize(&buf);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"method\":\"nip44_encrypt\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"fa984bd7dbb282f07e16e7ae87b26a2a7b9b90b7246a44771f0cf5ae58018f52\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"Hello\"") != null);
}

test "Request.parseJson nip04_encrypt" {
    const json =
        \\{"id":"enc1","method":"nip04_encrypt","params":["fa984bd7dbb282f07e16e7ae87b26a2a7b9b90b7246a44771f0cf5ae58018f52","Secret message"]}
    ;
    const req = Request.parseJson(json).?;
    try std.testing.expectEqualStrings("enc1", req.id);
    try std.testing.expectEqual(Method.nip04_encrypt, req.method);
    try std.testing.expectEqualStrings("fa984bd7dbb282f07e16e7ae87b26a2a7b9b90b7246a44771f0cf5ae58018f52", req.params.nip04_encrypt.third_party_pubkey);
    try std.testing.expectEqualStrings("Secret message", req.params.nip04_encrypt.plaintext);
}

test "Request.parseJson nip04_decrypt" {
    const json =
        \\{"id":"dec1","method":"nip04_decrypt","params":["fa984bd7dbb282f07e16e7ae87b26a2a7b9b90b7246a44771f0cf5ae58018f52","encrypted?iv=base64"]}
    ;
    const req = Request.parseJson(json).?;
    try std.testing.expectEqualStrings("dec1", req.id);
    try std.testing.expectEqual(Method.nip04_decrypt, req.method);
    try std.testing.expectEqualStrings("fa984bd7dbb282f07e16e7ae87b26a2a7b9b90b7246a44771f0cf5ae58018f52", req.params.nip04_decrypt.third_party_pubkey);
    try std.testing.expectEqualStrings("encrypted?iv=base64", req.params.nip04_decrypt.ciphertext);
}

test "Request.parseJson connect minimal" {
    const json =
        \\{"id":"conn1","method":"connect","params":["fa984bd7dbb282f07e16e7ae87b26a2a7b9b90b7246a44771f0cf5ae58018f52"]}
    ;
    const req = Request.parseJson(json).?;
    try std.testing.expectEqualStrings("conn1", req.id);
    try std.testing.expectEqual(Method.connect, req.method);
    try std.testing.expectEqualStrings("fa984bd7dbb282f07e16e7ae87b26a2a7b9b90b7246a44771f0cf5ae58018f52", req.params.connect.remote_signer_pubkey);
    try std.testing.expect(req.params.connect.secret == null);
    try std.testing.expect(req.params.connect.permissions == null);
}

test "Request.serialize sign_event" {
    const req = Request{
        .id = "sign1",
        .method = .sign_event,
        .params = .{ .sign_event = .{
            .event_json = "\"{\\\"kind\\\":1,\\\"content\\\":\\\"test\\\",\\\"tags\\\":[],\\\"created_at\\\":1714078911}\"",
        } },
    };

    var buf: [512]u8 = undefined;
    const json = try req.serialize(&buf);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"method\":\"sign_event\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "kind") != null);
}

test "Request sign_event roundtrip" {
    const original_json =
        \\{"id":"rt1","method":"sign_event","params":["{\"kind\":1,\"content\":\"hello\",\"tags\":[],\"created_at\":1714078911}"]}
    ;
    const parsed = Request.parseJson(original_json).?;

    var buf: [512]u8 = undefined;
    const serialized = try parsed.serialize(&buf);

    try std.testing.expectEqualStrings(original_json, serialized);
}

test "nip44 encrypt/decrypt request roundtrip" {
    const allocator = std.testing.allocator;

    var sk1: [32]u8 = undefined;
    var sk2: [32]u8 = undefined;
    @memset(&sk1, 0);
    @memset(&sk2, 0);
    sk1[31] = 1;
    sk2[31] = 2;

    var pk1: [32]u8 = undefined;
    var pk2: [32]u8 = undefined;
    try crypto.getPublicKey(&sk1, &pk1);
    try crypto.getPublicKey(&sk2, &pk2);

    const req = Request{
        .id = "test123",
        .method = .ping,
        .params = .{ .ping = {} },
    };

    const encrypted = try encryptRequest(&req, &sk1, &pk2, allocator);
    defer allocator.free(encrypted);

    const result = try decryptRequest(encrypted, &sk2, &pk1, allocator);
    defer allocator.free(result.json);

    try std.testing.expectEqualStrings("test123", result.request.?.id);
    try std.testing.expectEqual(Method.ping, result.request.?.method);
}

test "nip44 encrypt/decrypt response roundtrip" {
    const allocator = std.testing.allocator;

    var sk1: [32]u8 = undefined;
    var sk2: [32]u8 = undefined;
    @memset(&sk1, 0);
    @memset(&sk2, 0);
    sk1[31] = 1;
    sk2[31] = 2;

    var pk1: [32]u8 = undefined;
    var pk2: [32]u8 = undefined;
    try crypto.getPublicKey(&sk1, &pk1);
    try crypto.getPublicKey(&sk2, &pk2);

    const resp = Response{
        .id = "resp123",
        .result = "pong",
    };

    const encrypted = try encryptResponse(&resp, &sk2, &pk1, allocator);
    defer allocator.free(encrypted);

    const result = try decryptResponse(encrypted, &sk1, &pk2, allocator);
    defer allocator.free(result.json);

    try std.testing.expectEqualStrings("resp123", result.response.?.id);
    try std.testing.expectEqualStrings("pong", result.response.?.result.?);
}
