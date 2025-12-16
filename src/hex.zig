const std = @import("std");

const Vec16 = @Vector(16, u8);
const Vec32 = @Vector(32, u8);

const hex_chars = "0123456789abcdef".*;

pub fn encode(bytes: []const u8, out: []u8) void {
    std.debug.assert(out.len >= bytes.len * 2);

    var i: usize = 0;
    while (i + 16 <= bytes.len) : (i += 16) {
        const v: Vec16 = bytes[i..][0..16].*;
        const lo = v & @as(Vec16, @splat(0x0f));
        const hi = v >> @as(Vec16, @splat(4));
        const lo_hex = lookup16(lo);
        const hi_hex = lookup16(hi);
        interleave16(hi_hex, lo_hex, out[i * 2 ..][0..32]);
    }

    for (bytes[i..], 0..) |b, j| {
        out[(i + j) * 2] = hex_chars[b >> 4];
        out[(i + j) * 2 + 1] = hex_chars[b & 0x0f];
    }
}

pub fn decode(hex_in: []const u8, out: []u8) error{InvalidCharacter}!void {
    std.debug.assert(hex_in.len % 2 == 0);
    std.debug.assert(out.len >= hex_in.len / 2);

    var i: usize = 0;
    while (i + 32 <= hex_in.len) : (i += 32) {
        const v: Vec32 = hex_in[i..][0..32].*;
        const vals = charToNibble32(v) orelse return error.InvalidCharacter;
        const arr: [32]u8 = vals;
        deinterleave32(arr, out[i / 2 ..][0..16]);
    }

    var j = i / 2;
    while (i < hex_in.len) : (i += 2) {
        const hi = charToNibble(hex_in[i]) orelse return error.InvalidCharacter;
        const lo = charToNibble(hex_in[i + 1]) orelse return error.InvalidCharacter;
        out[j] = (hi << 4) | lo;
        j += 1;
    }
}

fn lookup16(nibbles: Vec16) Vec16 {
    const table: Vec16 = hex_chars;
    var result: [16]u8 = undefined;
    const n: [16]u8 = nibbles;
    inline for (0..16) |k| {
        result[k] = table[n[k]];
    }
    return result;
}

fn interleave16(hi: Vec16, lo: Vec16, out: *[32]u8) void {
    const h: [16]u8 = hi;
    const l: [16]u8 = lo;
    inline for (0..16) |k| {
        out[k * 2] = h[k];
        out[k * 2 + 1] = l[k];
    }
}

fn charToNibble32(v: Vec32) ?Vec32 {
    const chars: [32]u8 = v;
    var result: [32]u8 = undefined;
    inline for (0..32) |k| {
        result[k] = charToNibble(chars[k]) orelse return null;
    }
    return result;
}

fn deinterleave32(nibbles: [32]u8, out: *[16]u8) void {
    inline for (0..16) |k| {
        out[k] = (nibbles[k * 2] << 4) | nibbles[k * 2 + 1];
    }
}

inline fn charToNibble(c: u8) ?u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => null,
    };
}

test "encode 32 bytes" {
    const bytes = [_]u8{ 0x3b, 0xf0, 0xc6, 0x3f, 0xcb, 0x93, 0x46, 0x34, 0x07, 0xaf, 0x97, 0xa5, 0xe5, 0xee, 0x64, 0xfa, 0x88, 0x3d, 0x10, 0x7e, 0xf9, 0xe5, 0x58, 0x47, 0x2c, 0x4e, 0xb9, 0xaa, 0xae, 0xfa, 0x45, 0x9d };
    var out: [64]u8 = undefined;
    encode(&bytes, &out);
    try std.testing.expectEqualStrings("3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d", &out);
}

test "decode 64 hex chars" {
    const hex = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";
    var out: [32]u8 = undefined;
    try decode(hex, &out);
    const expected = [_]u8{ 0x3b, 0xf0, 0xc6, 0x3f, 0xcb, 0x93, 0x46, 0x34, 0x07, 0xaf, 0x97, 0xa5, 0xe5, 0xee, 0x64, 0xfa, 0x88, 0x3d, 0x10, 0x7e, 0xf9, 0xe5, 0x58, 0x47, 0x2c, 0x4e, 0xb9, 0xaa, 0xae, 0xfa, 0x45, 0x9d };
    try std.testing.expectEqualSlices(u8, &expected, &out);
}

test "roundtrip" {
    const original = [_]u8{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0 };
    var hex: [64]u8 = undefined;
    encode(&original, &hex);
    var decoded: [32]u8 = undefined;
    try decode(&hex, &decoded);
    try std.testing.expectEqualSlices(u8, &original, &decoded);
}

test "decode uppercase" {
    const hex = "DEADBEEF";
    var out: [4]u8 = undefined;
    try decode(hex, &out);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xde, 0xad, 0xbe, 0xef }, &out);
}

test "decode invalid char" {
    const hex = "deadbexf";
    var out: [4]u8 = undefined;
    try std.testing.expectError(error.InvalidCharacter, decode(hex, &out));
}

test "encode small" {
    const bytes = [_]u8{ 0xab, 0xcd };
    var out: [4]u8 = undefined;
    encode(&bytes, &out);
    try std.testing.expectEqualStrings("abcd", &out);
}

test "64-byte signature roundtrip" {
    var bytes: [64]u8 = undefined;
    for (&bytes, 0..) |*b, i| b.* = @truncate(i);
    var hex_out: [128]u8 = undefined;
    encode(&bytes, &hex_out);
    var decoded: [64]u8 = undefined;
    try decode(&hex_out, &decoded);
    try std.testing.expectEqualSlices(u8, &bytes, &decoded);
}

test "decode mixed case" {
    var out: [4]u8 = undefined;
    try decode("AbCdEfFe", &out);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xab, 0xcd, 0xef, 0xfe }, &out);
}
