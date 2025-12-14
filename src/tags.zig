const std = @import("std");

pub const TagValue = union(enum) {
    binary: [32]u8,
    string: []const u8,

    pub fn eql(self: TagValue, other: TagValue) bool {
        return switch (self) {
            .binary => |b| switch (other) {
                .binary => |ob| std.mem.eql(u8, &b, &ob),
                .string => false,
            },
            .string => |s| switch (other) {
                .binary => false,
                .string => |os| std.mem.eql(u8, s, os),
            },
        };
    }
};

pub const TagIndex = struct {
    entries: [52]std.ArrayListUnmanaged(TagValue),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) TagIndex {
        var entries: [52]std.ArrayListUnmanaged(TagValue) = undefined;
        for (&entries) |*e| {
            e.* = .{};
        }
        return .{ .entries = entries, .allocator = allocator };
    }

    pub fn deinit(self: *TagIndex) void {
        for (&self.entries) |*list| {
            for (list.items) |val| {
                switch (val) {
                    .string => |s| self.allocator.free(s),
                    .binary => {},
                }
            }
            list.deinit(self.allocator);
        }
    }

    pub fn letterIndex(letter: u8) ?usize {
        if (letter >= 'a' and letter <= 'z') return letter - 'a';
        if (letter >= 'A' and letter <= 'Z') return (letter - 'A') + 26;
        return null;
    }

    pub fn indexToLetter(idx: usize) u8 {
        if (idx < 26) return @intCast(idx + 'a');
        return @intCast((idx - 26) + 'A');
    }

    pub fn append(self: *TagIndex, tag_letter: u8, value: TagValue) !void {
        const idx = letterIndex(tag_letter) orelse return;
        try self.entries[idx].append(self.allocator, value);
    }

    pub fn get(self: *const TagIndex, tag_letter: u8) ?[]const TagValue {
        const idx = letterIndex(tag_letter) orelse return null;
        if (self.entries[idx].items.len == 0) return null;
        return self.entries[idx].items;
    }

    pub fn iterator(self: *const TagIndex) TagIterator {
        return TagIterator.init(self);
    }
};

pub const TagIterator = struct {
    index: *const TagIndex,
    letter_idx: usize = 0,
    value_idx: usize = 0,

    pub fn init(index: *const TagIndex) TagIterator {
        return .{ .index = index };
    }

    pub const Entry = struct {
        letter: u8,
        value: TagValue,
    };

    pub fn next(self: *TagIterator) ?Entry {
        while (self.letter_idx < 52) {
            const list = &self.index.entries[self.letter_idx];
            if (self.value_idx < list.items.len) {
                const entry = Entry{
                    .letter = TagIndex.indexToLetter(self.letter_idx),
                    .value = list.items[self.value_idx],
                };
                self.value_idx += 1;
                return entry;
            }
            self.letter_idx += 1;
            self.value_idx = 0;
        }
        return null;
    }
};

test "TagIndex.letterIndex maps lowercase and uppercase correctly" {
    try std.testing.expectEqual(@as(?usize, 0), TagIndex.letterIndex('a'));
    try std.testing.expectEqual(@as(?usize, 25), TagIndex.letterIndex('z'));
    try std.testing.expectEqual(@as(?usize, 4), TagIndex.letterIndex('e'));
    try std.testing.expectEqual(@as(?usize, 15), TagIndex.letterIndex('p'));

    try std.testing.expectEqual(@as(?usize, 26), TagIndex.letterIndex('A'));
    try std.testing.expectEqual(@as(?usize, 51), TagIndex.letterIndex('Z'));
    try std.testing.expectEqual(@as(?usize, 30), TagIndex.letterIndex('E'));
    try std.testing.expectEqual(@as(?usize, 41), TagIndex.letterIndex('P'));
    try std.testing.expectEqual(@as(?usize, 49), TagIndex.letterIndex('X'));

    try std.testing.expectEqual(@as(?usize, null), TagIndex.letterIndex('0'));
    try std.testing.expectEqual(@as(?usize, null), TagIndex.letterIndex('#'));
    try std.testing.expectEqual(@as(?usize, null), TagIndex.letterIndex(' '));
}

test "TagIndex.indexToLetter converts indices back to letters" {
    try std.testing.expectEqual(@as(u8, 'a'), TagIndex.indexToLetter(0));
    try std.testing.expectEqual(@as(u8, 'z'), TagIndex.indexToLetter(25));
    try std.testing.expectEqual(@as(u8, 'e'), TagIndex.indexToLetter(4));
    try std.testing.expectEqual(@as(u8, 'p'), TagIndex.indexToLetter(15));

    try std.testing.expectEqual(@as(u8, 'A'), TagIndex.indexToLetter(26));
    try std.testing.expectEqual(@as(u8, 'Z'), TagIndex.indexToLetter(51));
    try std.testing.expectEqual(@as(u8, 'E'), TagIndex.indexToLetter(30));
    try std.testing.expectEqual(@as(u8, 'P'), TagIndex.indexToLetter(41));
    try std.testing.expectEqual(@as(u8, 'X'), TagIndex.indexToLetter(49));
}

test "TagIndex stores and retrieves uppercase tags preserving case" {
    const allocator = std.testing.allocator;
    var index = TagIndex.init(allocator);
    defer index.deinit();

    try index.append('e', .{ .string = try allocator.dupe(u8, "lowercase-e") });
    try index.append('E', .{ .string = try allocator.dupe(u8, "uppercase-E") });
    try index.append('P', .{ .string = try allocator.dupe(u8, "uppercase-P") });
    try index.append('X', .{ .string = try allocator.dupe(u8, "uppercase-X") });

    const e_values = index.get('e').?;
    try std.testing.expectEqual(@as(usize, 1), e_values.len);
    try std.testing.expectEqualStrings("lowercase-e", e_values[0].string);

    const E_values = index.get('E').?;
    try std.testing.expectEqual(@as(usize, 1), E_values.len);
    try std.testing.expectEqualStrings("uppercase-E", E_values[0].string);

    const P_values = index.get('P').?;
    try std.testing.expectEqual(@as(usize, 1), P_values.len);
    try std.testing.expectEqualStrings("uppercase-P", P_values[0].string);

    const X_values = index.get('X').?;
    try std.testing.expectEqual(@as(usize, 1), X_values.len);
    try std.testing.expectEqualStrings("uppercase-X", X_values[0].string);

    try std.testing.expect(index.get('p') == null);
    try std.testing.expect(index.get('x') == null);
}

test "TagIterator yields both lowercase and uppercase entries" {
    const allocator = std.testing.allocator;
    var index = TagIndex.init(allocator);
    defer index.deinit();

    try index.append('a', .{ .string = try allocator.dupe(u8, "val-a") });
    try index.append('e', .{ .string = try allocator.dupe(u8, "val-e") });
    try index.append('A', .{ .string = try allocator.dupe(u8, "val-A") });
    try index.append('E', .{ .string = try allocator.dupe(u8, "val-E") });
    try index.append('Z', .{ .string = try allocator.dupe(u8, "val-Z") });

    var iter = index.iterator();
    var found_lowercase_a = false;
    var found_lowercase_e = false;
    var found_uppercase_A = false;
    var found_uppercase_E = false;
    var found_uppercase_Z = false;
    var count: usize = 0;

    while (iter.next()) |entry| {
        count += 1;
        if (entry.letter == 'a' and std.mem.eql(u8, entry.value.string, "val-a")) found_lowercase_a = true;
        if (entry.letter == 'e' and std.mem.eql(u8, entry.value.string, "val-e")) found_lowercase_e = true;
        if (entry.letter == 'A' and std.mem.eql(u8, entry.value.string, "val-A")) found_uppercase_A = true;
        if (entry.letter == 'E' and std.mem.eql(u8, entry.value.string, "val-E")) found_uppercase_E = true;
        if (entry.letter == 'Z' and std.mem.eql(u8, entry.value.string, "val-Z")) found_uppercase_Z = true;
    }

    try std.testing.expectEqual(@as(usize, 5), count);
    try std.testing.expect(found_lowercase_a);
    try std.testing.expect(found_lowercase_e);
    try std.testing.expect(found_uppercase_A);
    try std.testing.expect(found_uppercase_E);
    try std.testing.expect(found_uppercase_Z);
}
