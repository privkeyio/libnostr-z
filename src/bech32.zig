const std = @import("std");

pub const Error = error{
    InvalidLength,
    InvalidCharacter,
    InvalidChecksum,
    InvalidPrefix,
    InvalidPadding,
    BufferTooSmall,
    MixedCase,
};

const charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

fn charValue(c: u8) ?u5 {
    return for (charset, 0..) |ch, i| {
        if (ch == c) break @intCast(i);
    } else null;
}

fn polymod(values: []const u5) u32 {
    const gen = [_]u32{ 0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3 };
    var chk: u32 = 1;
    for (values) |v| {
        const top = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ v;
        inline for (0..5) |i| {
            if ((top >> i) & 1 == 1) chk ^= gen[i];
        }
    }
    return chk;
}

fn hrpExpand(hrp: []const u8, out: []u5) void {
    for (hrp, 0..) |c, i| {
        out[i] = @truncate(c >> 5);
    }
    out[hrp.len] = 0;
    for (hrp, 0..) |c, i| {
        out[hrp.len + 1 + i] = @truncate(c & 31);
    }
}

fn verifyChecksum(hrp: []const u8, data: []const u5) bool {
    var expanded: [256]u5 = undefined;
    hrpExpand(hrp, expanded[0 .. hrp.len * 2 + 1]);
    const exp_len = hrp.len * 2 + 1;
    @memcpy(expanded[exp_len .. exp_len + data.len], data);
    return polymod(expanded[0 .. exp_len + data.len]) == 1;
}

fn convertBits(input: []const u5, out: []u8) !usize {
    var acc: u32 = 0;
    var bits: u32 = 0;
    var out_idx: usize = 0;

    for (input) |v| {
        acc = (acc << 5) | v;
        bits += 5;
        while (bits >= 8) {
            bits -= 8;
            if (out_idx >= out.len) return Error.BufferTooSmall;
            out[out_idx] = @truncate(acc >> @intCast(bits));
            out_idx += 1;
        }
    }
    if (bits > 4) return Error.InvalidPadding;
    const pad_mask = (@as(u32, 1) << @intCast(bits)) - 1;
    if ((acc & pad_mask) != 0) return Error.InvalidPadding;
    return out_idx;
}

fn convertBitsToBase5(input: []const u8, out: []u5) usize {
    var acc: u32 = 0;
    var bits: u32 = 0;
    var out_idx: usize = 0;

    for (input) |v| {
        acc = (acc << 8) | v;
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            out[out_idx] = @truncate(acc >> @intCast(bits));
            out_idx += 1;
        }
    }
    if (bits > 0) {
        out[out_idx] = @truncate(acc << @intCast(5 - bits));
        out_idx += 1;
    }
    return out_idx;
}

fn createChecksum(hrp: []const u8, data: []const u5) [6]u5 {
    var values: [256]u5 = undefined;
    hrpExpand(hrp, values[0 .. hrp.len * 2 + 1]);
    const exp_len = hrp.len * 2 + 1;
    @memcpy(values[exp_len .. exp_len + data.len], data);
    @memset(values[exp_len + data.len .. exp_len + data.len + 6], 0);
    const pm = polymod(values[0 .. exp_len + data.len + 6]) ^ 1;
    var checksum: [6]u5 = undefined;
    for (0..6) |i| {
        checksum[i] = @truncate(pm >> @intCast(5 * (5 - i)));
    }
    return checksum;
}

pub fn encode(hrp: []const u8, data: []const u8, out: []u8) !usize {
    if (hrp.len == 0 or hrp.len > 83) return Error.InvalidLength;

    const data5_len = (data.len * 8 + 4) / 5;
    if (out.len < hrp.len + 1 + data5_len + 6) return Error.BufferTooSmall;

    // Check buffer limits: data5 must fit in 256 elements, and createChecksum
    // needs hrp.len * 2 + 1 + data5_len + 6 elements in its internal buffer
    if (data5_len > 256) return Error.InvalidLength;
    if (hrp.len * 2 + 1 + data5_len + 6 > 256) return Error.InvalidLength;

    var data5: [256]u5 = undefined;
    const actual_data5_len = convertBitsToBase5(data, &data5);

    const checksum = createChecksum(hrp, data5[0..actual_data5_len]);

    var idx: usize = 0;
    for (hrp) |c| {
        out[idx] = std.ascii.toLower(c);
        idx += 1;
    }
    out[idx] = '1';
    idx += 1;
    for (data5[0..actual_data5_len]) |v| {
        out[idx] = charset[v];
        idx += 1;
    }
    for (checksum) |v| {
        out[idx] = charset[v];
        idx += 1;
    }
    return idx;
}

pub fn decode(bech32: []const u8, out_hrp: []u8, out_data: []u8) !struct { hrp_len: usize, data_len: usize } {
    if (bech32.len < 8) return Error.InvalidLength;

    var has_lower = false;
    var has_upper = false;
    for (bech32) |c| {
        if (c < 33 or c > 126) return Error.InvalidCharacter;
        if (std.ascii.isLower(c)) has_lower = true;
        if (std.ascii.isUpper(c)) has_upper = true;
    }
    if (has_lower and has_upper) return Error.MixedCase;

    const sep_pos = std.mem.lastIndexOf(u8, bech32, "1") orelse return Error.InvalidCharacter;
    if (sep_pos < 1 or sep_pos + 7 > bech32.len) return Error.InvalidLength;

    const hrp = bech32[0..sep_pos];
    if (hrp.len > out_hrp.len) return Error.BufferTooSmall;
    for (hrp, 0..) |c, i| {
        out_hrp[i] = std.ascii.toLower(c);
    }

    const data_part = bech32[sep_pos + 1 ..];
    // Check buffer limits: data5 must fit in 256 elements, and verifyChecksum
    // needs hrp.len * 2 + 1 + data_part.len elements in its internal buffer
    if (data_part.len > 256) return Error.InvalidLength;
    if (hrp.len * 2 + 1 + data_part.len > 256) return Error.InvalidLength;

    var data5: [256]u5 = undefined;
    for (data_part, 0..) |c, i| {
        data5[i] = charValue(std.ascii.toLower(c)) orelse return Error.InvalidCharacter;
    }

    if (!verifyChecksum(out_hrp[0..hrp.len], data5[0..data_part.len])) {
        return Error.InvalidChecksum;
    }

    const payload_len = data_part.len - 6;
    const data_len = try convertBits(data5[0..payload_len], out_data);

    return .{ .hrp_len = hrp.len, .data_len = data_len };
}

pub const Decoded = union(enum) {
    pubkey: [32]u8,
    seckey: [32]u8,
    event_id: [32]u8,
    profile: Profile,
    event: Event,
    addr: Addr,
    offer: Offer,
    debit: Debit,
    manage: Manage,

    pub const Profile = struct {
        pubkey: [32]u8,
        relays: []const []const u8,
    };

    pub const Event = struct {
        id: [32]u8,
        relays: []const []const u8,
        author: ?[32]u8,
        kind: ?u32,
    };

    pub const Addr = struct {
        identifier: []const u8,
        pubkey: [32]u8,
        kind: u32,
        relays: []const []const u8,
    };

    pub const PricingType = enum(u8) {
        fixed = 0,
        variable = 1,
        spontaneous = 2,
    };

    pub const Offer = struct {
        pubkey: [32]u8,
        relay: []const u8,
        offer_id: []const u8,
        pricing_type: ?PricingType = null,
        price: ?u64 = null,
        currency: ?[]const u8 = null,
    };

    pub const Debit = struct {
        pubkey: [32]u8,
        relay: []const u8,
        pointer: ?[]const u8 = null,
    };

    pub const Manage = struct {
        pubkey: [32]u8,
        relay: []const u8,
        pointer: ?[]const u8 = null,
    };

    pub fn deinit(self: Decoded, allocator: std.mem.Allocator) void {
        switch (self) {
            .profile => |p| freeRelays(allocator, p.relays),
            .event => |e| freeRelays(allocator, e.relays),
            .addr => |a| {
                allocator.free(a.identifier);
                freeRelays(allocator, a.relays);
            },
            .offer => |o| {
                allocator.free(o.relay);
                allocator.free(o.offer_id);
                if (o.currency) |c| allocator.free(c);
            },
            .debit => |d| {
                allocator.free(d.relay);
                if (d.pointer) |p| allocator.free(p);
            },
            .manage => |m| {
                allocator.free(m.relay);
                if (m.pointer) |p| allocator.free(p);
            },
            else => {},
        }
    }

    fn freeRelays(allocator: std.mem.Allocator, relays: []const []const u8) void {
        for (relays) |r| allocator.free(r);
        allocator.free(relays);
    }
};

pub fn decodeNostr(allocator: std.mem.Allocator, input: []const u8) !Decoded {
    if (input.len == 64) {
        var bytes: [32]u8 = undefined;
        for (0..32) |i| {
            bytes[i] = std.fmt.parseInt(u8, input[i * 2 .. i * 2 + 2], 16) catch return Error.InvalidCharacter;
        }
        return .{ .pubkey = bytes };
    }

    var hrp_buf: [16]u8 = undefined;
    var data_buf: [512]u8 = undefined;

    const result = try decode(input, &hrp_buf, &data_buf);
    const hrp = hrp_buf[0..result.hrp_len];
    const data = data_buf[0..result.data_len];

    if (std.mem.eql(u8, hrp, "npub")) {
        if (data.len != 32) return Error.InvalidLength;
        return .{ .pubkey = data[0..32].* };
    }
    if (std.mem.eql(u8, hrp, "nsec")) {
        if (data.len != 32) return Error.InvalidLength;
        return .{ .seckey = data[0..32].* };
    }
    if (std.mem.eql(u8, hrp, "note")) {
        if (data.len != 32) return Error.InvalidLength;
        return .{ .event_id = data[0..32].* };
    }
    if (std.mem.eql(u8, hrp, "nprofile")) {
        return decodeTlvProfile(allocator, data);
    }
    if (std.mem.eql(u8, hrp, "nevent")) {
        return decodeTlvEvent(allocator, data);
    }
    if (std.mem.eql(u8, hrp, "naddr")) {
        return decodeTlvAddr(allocator, data);
    }
    if (std.mem.eql(u8, hrp, "noffer")) {
        return decodeTlvOffer(allocator, data);
    }
    if (std.mem.eql(u8, hrp, "ndebit")) {
        return decodeTlvDebit(allocator, data);
    }
    if (std.mem.eql(u8, hrp, "nmanage")) {
        return decodeTlvManage(allocator, data);
    }

    return Error.InvalidPrefix;
}

fn decodeTlvProfile(allocator: std.mem.Allocator, data: []const u8) !Decoded {
    var pubkey: ?[32]u8 = null;
    var relays: std.ArrayListUnmanaged([]const u8) = .{};
    errdefer {
        for (relays.items) |r| allocator.free(r);
        relays.deinit(allocator);
    }

    var i: usize = 0;
    while (i + 2 <= data.len) {
        const t = data[i];
        const l = data[i + 1];
        i += 2;
        if (i + l > data.len) break;
        const v = data[i .. i + l];
        i += l;

        switch (t) {
            0 => if (l == 32) {
                pubkey = v[0..32].*;
            },
            1 => {
                const relay = try allocator.dupe(u8, v);
                errdefer allocator.free(relay);
                try relays.append(allocator, relay);
            },
            else => {},
        }
    }

    if (pubkey) |pk| {
        return .{ .profile = .{ .pubkey = pk, .relays = try relays.toOwnedSlice(allocator) } };
    }
    return Error.InvalidLength;
}

fn decodeTlvEvent(allocator: std.mem.Allocator, data: []const u8) !Decoded {
    var id: ?[32]u8 = null;
    var author: ?[32]u8 = null;
    var kind: ?u32 = null;
    var relays: std.ArrayListUnmanaged([]const u8) = .{};
    errdefer {
        for (relays.items) |r| allocator.free(r);
        relays.deinit(allocator);
    }

    var i: usize = 0;
    while (i + 2 <= data.len) {
        const t = data[i];
        const l = data[i + 1];
        i += 2;
        if (i + l > data.len) break;
        const v = data[i .. i + l];
        i += l;

        switch (t) {
            0 => if (l == 32) {
                id = v[0..32].*;
            },
            1 => {
                const relay = try allocator.dupe(u8, v);
                errdefer allocator.free(relay);
                try relays.append(allocator, relay);
            },
            2 => if (l == 32) {
                author = v[0..32].*;
            },
            3 => if (l == 4) {
                kind = std.mem.readInt(u32, v[0..4], .big);
            },
            else => {},
        }
    }

    if (id) |event_id| {
        return .{ .event = .{ .id = event_id, .relays = try relays.toOwnedSlice(allocator), .author = author, .kind = kind } };
    }
    return Error.InvalidLength;
}

fn decodeTlvAddr(allocator: std.mem.Allocator, data: []const u8) !Decoded {
    var identifier: ?[]const u8 = null;
    var pubkey: ?[32]u8 = null;
    var kind: ?u32 = null;
    var relays: std.ArrayListUnmanaged([]const u8) = .{};
    errdefer {
        if (identifier) |id| allocator.free(id);
        for (relays.items) |r| allocator.free(r);
        relays.deinit(allocator);
    }

    var i: usize = 0;
    while (i + 2 <= data.len) {
        const t = data[i];
        const l = data[i + 1];
        i += 2;
        if (i + l > data.len) break;
        const v = data[i .. i + l];
        i += l;

        switch (t) {
            0 => {
                identifier = try allocator.dupe(u8, v);
            },
            1 => {
                const relay = try allocator.dupe(u8, v);
                errdefer allocator.free(relay);
                try relays.append(allocator, relay);
            },
            2 => if (l == 32) {
                pubkey = v[0..32].*;
            },
            3 => if (l == 4) {
                kind = std.mem.readInt(u32, v[0..4], .big);
            },
            else => {},
        }
    }

    if (identifier != null and pubkey != null and kind != null) {
        return .{ .addr = .{
            .identifier = identifier.?,
            .pubkey = pubkey.?,
            .kind = kind.?,
            .relays = try relays.toOwnedSlice(allocator),
        } };
    }
    return Error.InvalidLength;
}

fn decodeTlvOffer(allocator: std.mem.Allocator, data: []const u8) !Decoded {
    var pubkey: ?[32]u8 = null;
    var relay: ?[]const u8 = null;
    var offer_id: ?[]const u8 = null;
    var pricing_type: ?Decoded.PricingType = null;
    var price: ?u64 = null;
    var currency: ?[]const u8 = null;
    errdefer {
        if (relay) |r| allocator.free(r);
        if (offer_id) |o| allocator.free(o);
        if (currency) |c| allocator.free(c);
    }

    var i: usize = 0;
    while (i + 2 <= data.len) {
        const t = data[i];
        const l = data[i + 1];
        i += 2;
        if (i + l > data.len) break;
        const v = data[i .. i + l];
        i += l;

        switch (t) {
            0 => if (l == 32) {
                pubkey = v[0..32].*;
            },
            1 => {
                const new_relay = try allocator.dupe(u8, v);
                if (relay) |r| allocator.free(r);
                relay = new_relay;
            },
            2 => {
                const new_offer_id = try allocator.dupe(u8, v);
                if (offer_id) |o| allocator.free(o);
                offer_id = new_offer_id;
            },
            3 => if (l == 1) {
                pricing_type = std.meta.intToEnum(Decoded.PricingType, v[0]) catch null;
            },
            4 => if (l == 8) {
                price = std.mem.readInt(u64, v[0..8], .big);
            },
            5 => {
                const new_currency = try allocator.dupe(u8, v);
                if (currency) |c| allocator.free(c);
                currency = new_currency;
            },
            else => {},
        }
    }

    if (pubkey != null and relay != null and offer_id != null) {
        return .{ .offer = .{
            .pubkey = pubkey.?,
            .relay = relay.?,
            .offer_id = offer_id.?,
            .pricing_type = pricing_type,
            .price = price,
            .currency = currency,
        } };
    }
    return Error.InvalidLength;
}

const PubkeyRelayPointer = struct {
    pubkey: [32]u8,
    relay: []const u8,
    pointer: ?[]const u8,
};

fn decodeTlvPubkeyRelayPointer(allocator: std.mem.Allocator, data: []const u8) !PubkeyRelayPointer {
    var pubkey: ?[32]u8 = null;
    var relay: ?[]const u8 = null;
    var pointer: ?[]const u8 = null;
    errdefer {
        if (relay) |r| allocator.free(r);
        if (pointer) |p| allocator.free(p);
    }

    var i: usize = 0;
    while (i + 2 <= data.len) {
        const t = data[i];
        const l = data[i + 1];
        i += 2;
        if (i + l > data.len) break;
        const v = data[i .. i + l];
        i += l;

        switch (t) {
            0 => if (l == 32) {
                pubkey = v[0..32].*;
            },
            1 => {
                const new_relay = try allocator.dupe(u8, v);
                if (relay) |r| allocator.free(r);
                relay = new_relay;
            },
            2 => {
                const new_pointer = try allocator.dupe(u8, v);
                if (pointer) |p| allocator.free(p);
                pointer = new_pointer;
            },
            else => {},
        }
    }

    if (pubkey != null and relay != null) {
        return .{ .pubkey = pubkey.?, .relay = relay.?, .pointer = pointer };
    }
    return Error.InvalidLength;
}

fn decodeTlvDebit(allocator: std.mem.Allocator, data: []const u8) !Decoded {
    const parsed = try decodeTlvPubkeyRelayPointer(allocator, data);
    return .{ .debit = .{ .pubkey = parsed.pubkey, .relay = parsed.relay, .pointer = parsed.pointer } };
}

fn decodeTlvManage(allocator: std.mem.Allocator, data: []const u8) !Decoded {
    const parsed = try decodeTlvPubkeyRelayPointer(allocator, data);
    return .{ .manage = .{ .pubkey = parsed.pubkey, .relay = parsed.relay, .pointer = parsed.pointer } };
}

pub fn toHex(bytes: *const [32]u8, out: *[64]u8) []const u8 {
    out.* = std.fmt.bytesToHex(bytes.*, .lower);
    return out[0..];
}

test "decode npub" {
    const npub = "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6";
    const decoded = try decodeNostr(std.testing.allocator, npub);
    var hex: [64]u8 = undefined;
    try std.testing.expectEqualStrings("3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d", toHex(&decoded.pubkey, &hex));
}

test "decode hex passthrough" {
    const hex = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";
    const decoded = try decodeNostr(std.testing.allocator, hex);
    var out: [64]u8 = undefined;
    try std.testing.expectEqualStrings(hex, toHex(&decoded.pubkey, &out));
}

test "bip173 valid lowercase" {
    var hrp: [16]u8 = undefined;
    var data: [64]u8 = undefined;
    _ = try decode("a12uel5l", &hrp, &data);
}

test "bip173 valid uppercase" {
    var hrp: [16]u8 = undefined;
    var data: [64]u8 = undefined;
    _ = try decode("A12UEL5L", &hrp, &data);
}

test "bip173 reject mixed case" {
    var hrp: [16]u8 = undefined;
    var data: [64]u8 = undefined;
    try std.testing.expectError(Error.MixedCase, decode("A12uEL5L", &hrp, &data));
}

test "bip173 reject invalid checksum" {
    var hrp: [16]u8 = undefined;
    var data: [64]u8 = undefined;
    try std.testing.expectError(Error.InvalidChecksum, decode("a12uel5m", &hrp, &data));
}

test "nip19 npub vector" {
    const decoded = try decodeNostr(std.testing.allocator, "npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg");
    var hex: [64]u8 = undefined;
    try std.testing.expectEqualStrings("7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e", toHex(&decoded.pubkey, &hex));
}

test "nip19 nsec vector" {
    const decoded = try decodeNostr(std.testing.allocator, "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5");
    var hex: [64]u8 = undefined;
    try std.testing.expectEqualStrings("67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa", toHex(&decoded.seckey, &hex));
}

test "nip19 nprofile vector" {
    const decoded = try decodeNostr(std.testing.allocator, "nprofile1qqsrhuxx8l9ex335q7he0f09aej04zpazpl0ne2cgukyawd24mayt8gpp4mhxue69uhhytnc9e3k7mgpz4mhxue69uhkg6nzv9ejuumpv34kytnrdaksjlyr9p");
    defer decoded.deinit(std.testing.allocator);
    var hex: [64]u8 = undefined;
    try std.testing.expectEqualStrings("3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d", toHex(&decoded.profile.pubkey, &hex));
    try std.testing.expectEqual(@as(usize, 2), decoded.profile.relays.len);
    try std.testing.expectEqualStrings("wss://r.x.com", decoded.profile.relays[0]);
    try std.testing.expectEqualStrings("wss://djbas.sadkb.com", decoded.profile.relays[1]);
}

test "encode npub roundtrip" {
    const pubkey = [_]u8{ 0x3b, 0xf0, 0xc6, 0x3f, 0xcb, 0x93, 0x46, 0x34, 0x07, 0xaf, 0x97, 0xa5, 0xe5, 0xee, 0x64, 0xfa, 0x88, 0x3d, 0x10, 0x7e, 0xf9, 0xe5, 0x58, 0x47, 0x2c, 0x4e, 0xb9, 0xaa, 0xae, 0xfa, 0x45, 0x9d };
    var out: [128]u8 = undefined;
    const len = try encode("npub", &pubkey, &out);
    try std.testing.expectEqualStrings("npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6", out[0..len]);
}

test "encode decode roundtrip" {
    const original = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05 };
    var encoded: [64]u8 = undefined;
    const enc_len = try encode("test", &original, &encoded);

    var hrp_buf: [16]u8 = undefined;
    var data_buf: [32]u8 = undefined;
    const result = try decode(encoded[0..enc_len], &hrp_buf, &data_buf);
    try std.testing.expectEqualStrings("test", hrp_buf[0..result.hrp_len]);
    try std.testing.expectEqualSlices(u8, &original, data_buf[0..result.data_len]);
}

test "encode rejects oversized data" {
    // Data that would overflow the 256-element internal buffer
    // (data.len * 8 + 4) / 5 > 256 when data.len > 159
    var large_data: [160]u8 = undefined;
    @memset(&large_data, 0xAB);
    var out: [512]u8 = undefined;
    try std.testing.expectError(Error.InvalidLength, encode("test", &large_data, &out));
}

test "encode rejects data too large for checksum buffer" {
    // Even with smaller data, a long HRP can overflow createChecksum's buffer
    // hrp.len * 2 + 1 + data5_len + 6 > 256
    // With hrp.len = 83 (max): 83*2 + 1 + data5_len + 6 = 173 + data5_len
    // So data5_len must be <= 83, meaning data.len <= 51
    var data: [52]u8 = undefined;
    @memset(&data, 0xAB);
    var out: [512]u8 = undefined;
    // Use a long HRP (83 chars is the max allowed)
    const long_hrp = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcde";
    try std.testing.expectError(Error.InvalidLength, encode(long_hrp, &data, &out));
}
