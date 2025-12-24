const std = @import("std");
const bech32 = @import("bech32.zig");

pub const prefix = "nostr:";

pub const Error = error{
    InvalidScheme,
    SecretKeyNotAllowed,
} || bech32.Error;

pub const EntityType = enum {
    npub,
    nprofile,
    note,
    nevent,
    naddr,
    noffer,
    ndebit,
    nmanage,
};

pub fn parse(allocator: std.mem.Allocator, uri: []const u8) !bech32.Decoded {
    const identifier = try extractIdentifier(uri);
    return parseIdentifier(allocator, identifier);
}

pub fn parseIdentifier(allocator: std.mem.Allocator, identifier: []const u8) !bech32.Decoded {
    if (identifier.len >= 4 and std.ascii.eqlIgnoreCase(identifier[0..4], "nsec")) {
        return Error.SecretKeyNotAllowed;
    }
    return bech32.decodeNostr(allocator, identifier);
}

pub fn extractIdentifier(uri: []const u8) ![]const u8 {
    if (uri.len <= prefix.len) return Error.InvalidScheme;
    if (!std.ascii.eqlIgnoreCase(uri[0..prefix.len], prefix)) return Error.InvalidScheme;
    return uri[prefix.len..];
}

pub fn isValidUri(uri: []const u8) bool {
    if (uri.len <= prefix.len) return false;
    if (!std.ascii.eqlIgnoreCase(uri[0..prefix.len], prefix)) return false;
    const identifier = uri[prefix.len..];
    if (identifier.len >= 4 and std.ascii.eqlIgnoreCase(identifier[0..4], "nsec")) return false;
    var hrp_buf: [16]u8 = undefined;
    var data_buf: [512]u8 = undefined;
    _ = bech32.decode(identifier, &hrp_buf, &data_buf) catch return false;
    return true;
}

pub fn getEntityType(uri: []const u8) ?EntityType {
    const identifier = extractIdentifier(uri) catch return null;
    if (identifier.len < 4) return null;
    const hrp_end = std.mem.indexOf(u8, identifier, "1") orelse return null;
    if (hrp_end < 4 or hrp_end > 8) return null;
    const hrp = identifier[0..hrp_end];
    var lower_buf: [8]u8 = undefined;
    const lower = std.ascii.lowerString(lower_buf[0..hrp.len], hrp);
    if (std.mem.eql(u8, lower, "npub")) return .npub;
    if (std.mem.eql(u8, lower, "nprofile")) return .nprofile;
    if (std.mem.eql(u8, lower, "note")) return .note;
    if (std.mem.eql(u8, lower, "nevent")) return .nevent;
    if (std.mem.eql(u8, lower, "naddr")) return .naddr;
    if (std.mem.eql(u8, lower, "noffer")) return .noffer;
    if (std.mem.eql(u8, lower, "ndebit")) return .ndebit;
    if (std.mem.eql(u8, lower, "nmanage")) return .nmanage;
    return null;
}

test "parse nostr: npub URI" {
    const uri = "nostr:npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6";
    const decoded = try parse(std.testing.allocator, uri);
    var hex: [64]u8 = undefined;
    try std.testing.expectEqualStrings("3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d", bech32.toHex(&decoded.pubkey, &hex));
}

test "parse nostr: note URI" {
    const uri = "nostr:note1fntxtkcy9pjwucqwa9mddn7v03wwwsu9j330jj350nvhpky2tuaspk6nqc";
    const decoded = try parse(std.testing.allocator, uri);
    try std.testing.expect(decoded == .event_id);
}

test "parse nostr: nprofile URI" {
    const uri = "nostr:nprofile1qqsrhuxx8l9ex335q7he0f09aej04zpazpl0ne2cgukyawd24mayt8gpp4mhxue69uhhytnc9e3k7mgpz4mhxue69uhkg6nzv9ejuumpv34kytnrdaksjlyr9p";
    const decoded = try parse(std.testing.allocator, uri);
    defer decoded.deinit(std.testing.allocator);
    try std.testing.expect(decoded == .profile);
    try std.testing.expectEqual(@as(usize, 2), decoded.profile.relays.len);
}

test "reject nsec URI" {
    const uri = "nostr:nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5";
    try std.testing.expectError(Error.SecretKeyNotAllowed, parse(std.testing.allocator, uri));
}

test "reject uppercase NSEC URI" {
    const uri = "nostr:NSEC1VL029MGPSPEDVA04G90VLTKH6FVH240ZQTV9K0T9AF8935KE9LAQSNLFE5";
    try std.testing.expectError(Error.SecretKeyNotAllowed, parse(std.testing.allocator, uri));
}

test "reject invalid scheme" {
    try std.testing.expectError(Error.InvalidScheme, parse(std.testing.allocator, "http://example.com"));
    try std.testing.expectError(Error.InvalidScheme, parse(std.testing.allocator, "nostr"));
    try std.testing.expectError(Error.InvalidScheme, parse(std.testing.allocator, ""));
}

test "extractIdentifier" {
    const id = try extractIdentifier("nostr:npub1abc123");
    try std.testing.expectEqualStrings("npub1abc123", id);
}

test "extractIdentifier case insensitive" {
    const id = try extractIdentifier("NOSTR:npub1abc123");
    try std.testing.expectEqualStrings("npub1abc123", id);
}

test "isValidUri" {
    try std.testing.expect(isValidUri("nostr:npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6"));
    try std.testing.expect(!isValidUri("nostr:nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5"));
    try std.testing.expect(!isValidUri("http://example.com"));
    try std.testing.expect(!isValidUri("nostr:invalid"));
    try std.testing.expect(!isValidUri(""));
}

test "getEntityType" {
    try std.testing.expectEqual(EntityType.npub, getEntityType("nostr:npub1abc").?);
    try std.testing.expectEqual(EntityType.nprofile, getEntityType("nostr:nprofile1abc").?);
    try std.testing.expectEqual(EntityType.note, getEntityType("nostr:note1abc").?);
    try std.testing.expectEqual(EntityType.nevent, getEntityType("nostr:nevent1abc").?);
    try std.testing.expectEqual(EntityType.naddr, getEntityType("nostr:naddr1abc").?);
    try std.testing.expect(getEntityType("nostr:nsec1abc") == null);
    try std.testing.expect(getEntityType("invalid") == null);
}
