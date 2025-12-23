const std = @import("std");
const bech32 = @import("bech32.zig");

pub const Reference = struct {
    start: usize,
    end: usize,
    uri: []const u8,
    decoded: ?bech32.Decoded,

    pub fn deinit(self: *Reference, allocator: std.mem.Allocator) void {
        if (self.decoded) |*d| {
            d.deinit(allocator);
            self.decoded = null;
        }
    }
};

pub const ReferenceIterator = struct {
    content: []const u8,
    pos: usize,
    allocator: std.mem.Allocator,

    pub fn init(content: []const u8, allocator: std.mem.Allocator) ReferenceIterator {
        return .{ .content = content, .pos = 0, .allocator = allocator };
    }

    pub fn next(self: *ReferenceIterator) ?Reference {
        while (self.pos < self.content.len) {
            const remaining = self.content[self.pos..];
            const idx = std.mem.indexOf(u8, remaining, "nostr:") orelse return null;
            const start = self.pos + idx;
            const uri_start = start + 6;

            if (uri_start >= self.content.len) {
                self.pos = self.content.len;
                return null;
            }

            const uri_end = findUriEnd(self.content, uri_start);
            if (uri_end <= uri_start) {
                self.pos = uri_start;
                continue;
            }

            const uri = self.content[uri_start..uri_end];
            self.pos = uri_end;

            const decoded = bech32.decodeNostr(self.allocator, uri) catch null;
            return Reference{
                .start = start,
                .end = uri_end,
                .uri = uri,
                .decoded = decoded,
            };
        }
        return null;
    }
};

fn findUriEnd(content: []const u8, start: usize) usize {
    var pos = start;
    while (pos < content.len) {
        const c = content[pos];
        // Bech32 allows lowercase a-z, uppercase A-Z, and digits 0-9
        // (but not mixed case - validation happens during decode)
        if ((c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z') or (c >= '0' and c <= '9')) {
            pos += 1;
        } else {
            break;
        }
    }
    return pos;
}

pub fn findReferences(content: []const u8, allocator: std.mem.Allocator) ReferenceIterator {
    return ReferenceIterator.init(content, allocator);
}

pub fn hasReferences(content: []const u8) bool {
    return std.mem.indexOf(u8, content, "nostr:") != null;
}

pub fn countReferences(content: []const u8) usize {
    var count: usize = 0;
    var pos: usize = 0;
    while (pos < content.len) {
        const remaining = content[pos..];
        const idx = std.mem.indexOf(u8, remaining, "nostr:") orelse break;
        count += 1;
        pos += idx + 6;
    }
    return count;
}

test "find npub reference" {
    const content = "hello nostr:npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6 world";
    var iter = findReferences(content, std.testing.allocator);

    const ref = iter.next().?;
    defer {
        var r = ref;
        r.deinit(std.testing.allocator);
    }

    try std.testing.expectEqual(@as(usize, 6), ref.start);
    try std.testing.expectEqualStrings("npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6", ref.uri);
    try std.testing.expect(ref.decoded != null);

    const pk = ref.decoded.?.pubkey;
    var hex: [64]u8 = undefined;
    try std.testing.expectEqualStrings("3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d", bech32.toHex(&pk, &hex));

    try std.testing.expect(iter.next() == null);
}

test "find multiple references" {
    const content = "nostr:npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6 mentioned nostr:note1fntxtkcy9pjwucqwa9mddn7v03wwwsu9j330jj350nvhpky2tuaspk6nqc";
    var iter = findReferences(content, std.testing.allocator);

    const ref1 = iter.next().?;
    defer {
        var r = ref1;
        r.deinit(std.testing.allocator);
    }
    try std.testing.expectEqualStrings("npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6", ref1.uri);

    const ref2 = iter.next().?;
    defer {
        var r = ref2;
        r.deinit(std.testing.allocator);
    }
    try std.testing.expectEqualStrings("note1fntxtkcy9pjwucqwa9mddn7v03wwwsu9j330jj350nvhpky2tuaspk6nqc", ref2.uri);

    try std.testing.expect(iter.next() == null);
}

test "find nprofile reference" {
    const content = "hello nostr:nprofile1qqsrhuxx8l9ex335q7he0f09aej04zpazpl0ne2cgukyawd24mayt8gpp4mhxue69uhhytnc9e3k7mgpz4mhxue69uhkg6nzv9ejuumpv34kytnrdaksjlyr9p";
    var iter = findReferences(content, std.testing.allocator);

    const ref = iter.next().?;
    defer {
        var r = ref;
        r.deinit(std.testing.allocator);
    }

    try std.testing.expect(ref.decoded != null);
    const profile = ref.decoded.?.profile;
    var hex: [64]u8 = undefined;
    try std.testing.expectEqualStrings("3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d", bech32.toHex(&profile.pubkey, &hex));
    try std.testing.expectEqual(@as(usize, 2), profile.relays.len);
}

test "hasReferences" {
    try std.testing.expect(hasReferences("hello nostr:npub1... world"));
    try std.testing.expect(!hasReferences("hello world"));
}

test "countReferences" {
    try std.testing.expectEqual(@as(usize, 0), countReferences("hello world"));
    try std.testing.expectEqual(@as(usize, 1), countReferences("hello nostr:npub1abc world"));
    try std.testing.expectEqual(@as(usize, 2), countReferences("nostr:npub1a and nostr:note1b"));
}

test "no references" {
    const content = "hello world no mentions here";
    var iter = findReferences(content, std.testing.allocator);
    try std.testing.expect(iter.next() == null);
}

test "reference at end" {
    const content = "check out nostr:npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6";
    var iter = findReferences(content, std.testing.allocator);

    const ref = iter.next().?;
    defer {
        var r = ref;
        r.deinit(std.testing.allocator);
    }
    try std.testing.expect(ref.decoded != null);
    try std.testing.expect(iter.next() == null);
}

test "reference at start" {
    const content = "nostr:npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6 is cool";
    var iter = findReferences(content, std.testing.allocator);

    const ref = iter.next().?;
    defer {
        var r = ref;
        r.deinit(std.testing.allocator);
    }
    try std.testing.expectEqual(@as(usize, 0), ref.start);
    try std.testing.expect(iter.next() == null);
}

test "uppercase bech32 reference" {
    // BIP-173 allows uppercase bech32 strings
    const content = "hello nostr:NPUB180CVV07TJDRRGPA0J7J7TMNYL2YR6YR7L8J4S3EVF6U64TH6GKWSYJH6W6 world";
    var iter = findReferences(content, std.testing.allocator);

    const ref = iter.next().?;
    defer {
        var r = ref;
        r.deinit(std.testing.allocator);
    }

    try std.testing.expectEqualStrings("NPUB180CVV07TJDRRGPA0J7J7TMNYL2YR6YR7L8J4S3EVF6U64TH6GKWSYJH6W6", ref.uri);
    try std.testing.expect(ref.decoded != null);

    const pk = ref.decoded.?.pubkey;
    var hex: [64]u8 = undefined;
    try std.testing.expectEqualStrings("3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d", bech32.toHex(&pk, &hex));
}

test "mixed case bech32 rejected" {
    // BIP-173 requires all-upper or all-lower, mixed case should fail decode
    const content = "nostr:Npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6";
    var iter = findReferences(content, std.testing.allocator);

    const ref = iter.next().?;
    // Reference is found but decode fails due to mixed case
    try std.testing.expectEqualStrings("Npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6", ref.uri);
    try std.testing.expect(ref.decoded == null);
}

test "nostr: followed by space skipped" {
    // "nostr:" without a valid bech32 identifier should be skipped
    const content = "nostr: hello nostr:npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6";
    var iter = findReferences(content, std.testing.allocator);

    // The first "nostr: " is skipped, only the valid one is returned
    const ref = iter.next().?;
    defer {
        var r = ref;
        r.deinit(std.testing.allocator);
    }
    try std.testing.expectEqualStrings("npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6", ref.uri);
    try std.testing.expect(ref.decoded != null);
    try std.testing.expect(iter.next() == null);
}

test "consecutive nostr: patterns" {
    // Test that we correctly handle "nostr:nostr:npub..."
    const content = "nostr:nostr:npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6";
    var iter = findReferences(content, std.testing.allocator);

    // First match: "nostr" is parsed as URI but fails decode
    const ref1 = iter.next().?;
    try std.testing.expectEqualStrings("nostr", ref1.uri);
    try std.testing.expect(ref1.decoded == null);

    // Iterator advances past the first match, missing the nested valid reference
    // This is acceptable edge case behavior
    try std.testing.expect(iter.next() == null);
}
