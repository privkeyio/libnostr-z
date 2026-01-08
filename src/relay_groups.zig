const std = @import("std");
const event_mod = @import("event.zig");
const utils = @import("utils.zig");

pub const Event = event_mod.Event;

pub const GROUP_METADATA_KIND: i32 = 39000;
pub const GROUP_ADMINS_KIND: i32 = 39001;
pub const GROUP_MEMBERS_KIND: i32 = 39002;
pub const GROUP_ROLES_KIND: i32 = 39003;

pub const PUT_USER_KIND: i32 = 9000;
pub const REMOVE_USER_KIND: i32 = 9001;
pub const EDIT_METADATA_KIND: i32 = 9002;
pub const DELETE_EVENT_KIND: i32 = 9005;
pub const CREATE_GROUP_KIND: i32 = 9007;
pub const DELETE_GROUP_KIND: i32 = 9008;
pub const CREATE_INVITE_KIND: i32 = 9009;
pub const JOIN_REQUEST_KIND: i32 = 9021;
pub const LEAVE_REQUEST_KIND: i32 = 9022;

pub const GroupIdentifier = struct {
    host: []const u8,
    group_id: []const u8,

    pub fn parse(identifier: []const u8) ?GroupIdentifier {
        if (identifier.len == 0) return null;
        if (std.mem.indexOfScalar(u8, identifier, '\'')) |sep_pos| {
            if (sep_pos == 0) return null;
            const group_id = identifier[sep_pos + 1 ..];
            if (!isValidGroupId(group_id)) return null;
            return .{
                .host = identifier[0..sep_pos],
                .group_id = group_id,
            };
        }
        return .{
            .host = identifier,
            .group_id = "_",
        };
    }

    pub fn format(self: *const GroupIdentifier, buf: []u8) ?[]const u8 {
        if (std.mem.eql(u8, self.group_id, "_")) {
            if (self.host.len > buf.len) return null;
            @memcpy(buf[0..self.host.len], self.host);
            return buf[0..self.host.len];
        }
        const total_len = self.host.len + 1 + self.group_id.len;
        if (total_len > buf.len) return null;
        @memcpy(buf[0..self.host.len], self.host);
        buf[self.host.len] = '\'';
        @memcpy(buf[self.host.len + 1 ..][0..self.group_id.len], self.group_id);
        return buf[0..total_len];
    }
};

pub fn isValidGroupId(group_id: []const u8) bool {
    if (group_id.len == 0) return false;
    for (group_id) |c| {
        const valid = (c >= 'a' and c <= 'z') or
            (c >= '0' and c <= '9') or
            c == '-' or c == '_';
        if (!valid) return false;
    }
    return true;
}

pub const GroupStatus = enum {
    managed,
    unmanaged,
};

pub const GroupMetadata = struct {
    group_id: []const u8,
    name: ?[]const u8 = null,
    picture: ?[]const u8 = null,
    about: ?[]const u8 = null,
    is_private: bool = false,
    is_restricted: bool = false,
    is_hidden: bool = false,
    is_closed: bool = false,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *GroupMetadata) void {
        if (self.name) |n| self.allocator.free(n);
        if (self.picture) |p| self.allocator.free(p);
        if (self.about) |a| self.allocator.free(a);
        self.allocator.free(self.group_id);
    }

    pub fn fromEvent(event: *const Event, allocator: std.mem.Allocator) !GroupMetadata {
        if (event.kind() != GROUP_METADATA_KIND) {
            return error.InvalidKind;
        }

        const d_tag = event.dTag() orelse return error.MissingDTag;
        const group_id = try allocator.dupe(u8, d_tag);
        errdefer allocator.free(group_id);

        var metadata = GroupMetadata{
            .group_id = group_id,
            .allocator = allocator,
        };
        errdefer metadata.deinit();

        const tags_json = utils.findJsonValue(event.raw_json, "tags") orelse return metadata;
        var iter = GenericTagIterator.init(tags_json);

        while (iter.next()) |tag| {
            if (std.mem.eql(u8, tag.name, "name") and tag.value.len > 0) {
                metadata.name = try allocator.dupe(u8, tag.value);
            } else if (std.mem.eql(u8, tag.name, "picture") and tag.value.len > 0) {
                metadata.picture = try allocator.dupe(u8, tag.value);
            } else if (std.mem.eql(u8, tag.name, "about") and tag.value.len > 0) {
                metadata.about = try allocator.dupe(u8, tag.value);
            } else if (std.mem.eql(u8, tag.name, "private")) {
                metadata.is_private = true;
            } else if (std.mem.eql(u8, tag.name, "restricted")) {
                metadata.is_restricted = true;
            } else if (std.mem.eql(u8, tag.name, "hidden")) {
                metadata.is_hidden = true;
            } else if (std.mem.eql(u8, tag.name, "closed")) {
                metadata.is_closed = true;
            }
        }

        return metadata;
    }
};

pub const AdminInfo = struct {
    pubkey: []const u8,
    roles: []const []const u8,
};

pub const GroupAdmins = struct {
    group_id: []const u8,
    admins: std.ArrayListUnmanaged(AdminInfo),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) GroupAdmins {
        return .{
            .group_id = "",
            .admins = .{},
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *GroupAdmins) void {
        for (self.admins.items) |admin| {
            self.allocator.free(admin.pubkey);
            for (admin.roles) |role| {
                self.allocator.free(role);
            }
            self.allocator.free(admin.roles);
        }
        self.admins.deinit(self.allocator);
        if (self.group_id.len > 0) {
            self.allocator.free(self.group_id);
        }
    }

    pub fn fromEvent(event: *const Event, allocator: std.mem.Allocator) !GroupAdmins {
        if (event.kind() != GROUP_ADMINS_KIND) {
            return error.InvalidKind;
        }

        var admins = GroupAdmins.init(allocator);
        errdefer admins.deinit();

        const d_tag = event.dTag() orelse return error.MissingDTag;
        admins.group_id = try allocator.dupe(u8, d_tag);

        const tags_json = utils.findJsonValue(event.raw_json, "tags") orelse return admins;
        var iter = PTagIterator.init(tags_json);

        while (iter.next()) |entry| {
            const pubkey = try allocator.dupe(u8, entry.pubkey);
            errdefer allocator.free(pubkey);

            var roles_list: std.ArrayListUnmanaged([]const u8) = .{};
            errdefer {
                for (roles_list.items) |r| allocator.free(r);
                roles_list.deinit(allocator);
            }

            for (entry.roles) |role| {
                const role_copy = try allocator.dupe(u8, role);
                try roles_list.append(allocator, role_copy);
            }

            const roles = try roles_list.toOwnedSlice(allocator);
            errdefer {
                for (roles) |r| allocator.free(r);
                allocator.free(roles);
            }

            try admins.admins.append(allocator, .{
                .pubkey = pubkey,
                .roles = roles,
            });
        }

        return admins;
    }

    pub fn count(self: *const GroupAdmins) usize {
        return self.admins.items.len;
    }
};

pub const GroupMembers = struct {
    group_id: []const u8,
    members: std.ArrayListUnmanaged([]const u8),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) GroupMembers {
        return .{
            .group_id = "",
            .members = .{},
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *GroupMembers) void {
        for (self.members.items) |member| {
            self.allocator.free(member);
        }
        self.members.deinit(self.allocator);
        if (self.group_id.len > 0) {
            self.allocator.free(self.group_id);
        }
    }

    pub fn fromEvent(event: *const Event, allocator: std.mem.Allocator) !GroupMembers {
        if (event.kind() != GROUP_MEMBERS_KIND) {
            return error.InvalidKind;
        }

        var members = GroupMembers.init(allocator);
        errdefer members.deinit();

        const d_tag = event.dTag() orelse return error.MissingDTag;
        members.group_id = try allocator.dupe(u8, d_tag);

        const tags_json = utils.findJsonValue(event.raw_json, "tags") orelse return members;
        var iter = SimplePTagIterator.init(tags_json);

        while (iter.next()) |pubkey| {
            const pubkey_copy = try allocator.dupe(u8, pubkey);
            try members.members.append(allocator, pubkey_copy);
        }

        return members;
    }

    pub fn count(self: *const GroupMembers) usize {
        return self.members.items.len;
    }

    pub fn contains(self: *const GroupMembers, pubkey: []const u8) bool {
        for (self.members.items) |member| {
            if (std.mem.eql(u8, member, pubkey)) return true;
        }
        return false;
    }
};

pub const RoleInfo = struct {
    name: []const u8,
    description: ?[]const u8,
};

pub const GroupRoles = struct {
    group_id: []const u8,
    roles: std.ArrayListUnmanaged(RoleInfo),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) GroupRoles {
        return .{
            .group_id = "",
            .roles = .{},
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *GroupRoles) void {
        for (self.roles.items) |role| {
            self.allocator.free(role.name);
            if (role.description) |d| self.allocator.free(d);
        }
        self.roles.deinit(self.allocator);
        if (self.group_id.len > 0) {
            self.allocator.free(self.group_id);
        }
    }

    pub fn fromEvent(event: *const Event, allocator: std.mem.Allocator) !GroupRoles {
        if (event.kind() != GROUP_ROLES_KIND) {
            return error.InvalidKind;
        }

        var group_roles = GroupRoles.init(allocator);
        errdefer group_roles.deinit();

        const d_tag = event.dTag() orelse return error.MissingDTag;
        group_roles.group_id = try allocator.dupe(u8, d_tag);

        const tags_json = utils.findJsonValue(event.raw_json, "tags") orelse return group_roles;
        var iter = RoleTagIterator.init(tags_json);

        while (iter.next()) |entry| {
            const name = try allocator.dupe(u8, entry.name);
            errdefer allocator.free(name);

            var description: ?[]const u8 = null;
            if (entry.description) |d| {
                description = try allocator.dupe(u8, d);
            }
            errdefer if (description) |desc| allocator.free(desc);

            try group_roles.roles.append(allocator, .{
                .name = name,
                .description = description,
            });
        }

        return group_roles;
    }

    pub fn count(self: *const GroupRoles) usize {
        return self.roles.items.len;
    }
};

pub fn getGroupId(event: *const Event) ?[]const u8 {
    const tags_json = utils.findJsonValue(event.raw_json, "tags") orelse return null;
    var iter = GenericTagIterator.init(tags_json);
    while (iter.next()) |tag| {
        if (std.mem.eql(u8, tag.name, "h") and tag.value.len > 0) {
            return tag.value;
        }
    }
    return null;
}

pub fn getPreviousReferences(event: *const Event, buf: [][]const u8) [][]const u8 {
    const tags_json = utils.findJsonValue(event.raw_json, "tags") orelse return buf[0..0];
    var iter = PreviousTagIterator.init(tags_json);
    var count: usize = 0;
    while (iter.next()) |ref| {
        if (count >= buf.len) break;
        buf[count] = ref;
        count += 1;
    }
    return buf[0..count];
}

pub fn isGroupEvent(event: *const Event) bool {
    return getGroupId(event) != null;
}

pub fn isModerationEvent(kind: i32) bool {
    return kind >= 9000 and kind <= 9020;
}

pub fn isGroupMetadataEvent(kind: i32) bool {
    return kind >= 39000 and kind <= 39003;
}

const GenericTagIterator = struct {
    json: []const u8,
    pos: usize,

    const Entry = struct {
        name: []const u8,
        value: []const u8,
    };

    fn init(json: []const u8) GenericTagIterator {
        return .{ .json = json, .pos = 0 };
    }

    fn next(self: *GenericTagIterator) ?Entry {
        while (self.pos < self.json.len) {
            const tag_start = utils.findBracketInJson(self.json, self.pos, '[') orelse return null;
            const tag_end = utils.findBracketInJson(self.json, tag_start + 1, ']') orelse return null;
            self.pos = tag_end + 1;

            const tag_content = self.json[tag_start + 1 .. tag_end];
            if (utils.parseTagStrings(tag_content, 2)) |strings| {
                return .{ .name = strings[0], .value = if (strings[1].len > 0) strings[1] else "" };
            }
        }
        return null;
    }
};

const PTagIterator = struct {
    json: []const u8,
    pos: usize,
    role_buf: [MAX_ROLES][]const u8,

    const Entry = struct {
        pubkey: []const u8,
        roles: []const []const u8,
    };

    const MAX_ROLES = 16;

    fn init(json: []const u8) PTagIterator {
        return .{ .json = json, .pos = 0, .role_buf = undefined };
    }

    fn next(self: *PTagIterator) ?Entry {
        while (self.pos < self.json.len) {
            const tag_start = utils.findBracketInJson(self.json, self.pos, '[') orelse return null;
            const tag_end = utils.findBracketInJson(self.json, tag_start + 1, ']') orelse return null;
            self.pos = tag_end + 1;

            const tag_content = self.json[tag_start + 1 .. tag_end];
            if (self.parsePTag(tag_content)) |entry| {
                return entry;
            }
        }
        return null;
    }

    fn parsePTag(self: *PTagIterator, content: []const u8) ?Entry {
        const strings = utils.parseTagStrings(content, MAX_ROLES + 2) orelse return null;
        if (strings[1].len == 0) return null;
        if (!std.mem.eql(u8, strings[0], "p")) return null;
        if (strings[1].len != 64) return null;

        var role_count: usize = 0;
        for (2..MAX_ROLES + 2) |j| {
            if (strings[j].len == 0) break;
            self.role_buf[role_count] = strings[j];
            role_count += 1;
        }

        return .{
            .pubkey = strings[1],
            .roles = self.role_buf[0..role_count],
        };
    }
};

const SimplePTagIterator = struct {
    json: []const u8,
    pos: usize,

    fn init(json: []const u8) SimplePTagIterator {
        return .{ .json = json, .pos = 0 };
    }

    fn next(self: *SimplePTagIterator) ?[]const u8 {
        while (self.pos < self.json.len) {
            const tag_start = utils.findBracketInJson(self.json, self.pos, '[') orelse return null;
            const tag_end = utils.findBracketInJson(self.json, tag_start + 1, ']') orelse return null;
            self.pos = tag_end + 1;

            const tag_content = self.json[tag_start + 1 .. tag_end];
            const strings = utils.parseTagStrings(tag_content, 2) orelse continue;
            if (strings[1].len == 0) continue;
            if (!std.mem.eql(u8, strings[0], "p")) continue;
            if (strings[1].len != 64) continue;
            return strings[1];
        }
        return null;
    }
};

const RoleTagIterator = struct {
    json: []const u8,
    pos: usize,

    const Entry = struct {
        name: []const u8,
        description: ?[]const u8,
    };

    fn init(json: []const u8) RoleTagIterator {
        return .{ .json = json, .pos = 0 };
    }

    fn next(self: *RoleTagIterator) ?Entry {
        while (self.pos < self.json.len) {
            const tag_start = utils.findBracketInJson(self.json, self.pos, '[') orelse return null;
            const tag_end = utils.findBracketInJson(self.json, tag_start + 1, ']') orelse return null;
            self.pos = tag_end + 1;

            const tag_content = self.json[tag_start + 1 .. tag_end];
            const strings = utils.parseTagStrings(tag_content, 3) orelse continue;
            if (strings[1].len == 0) continue;
            if (!std.mem.eql(u8, strings[0], "role")) continue;

            return .{
                .name = strings[1],
                .description = if (strings[2].len > 0) strings[2] else null,
            };
        }
        return null;
    }
};

const PreviousTagIterator = struct {
    json: []const u8,
    pos: usize,
    ref_idx: usize,
    current_refs: [16][]const u8,
    current_refs_count: usize,

    fn init(json: []const u8) PreviousTagIterator {
        return .{
            .json = json,
            .pos = 0,
            .ref_idx = 0,
            .current_refs = undefined,
            .current_refs_count = 0,
        };
    }

    fn next(self: *PreviousTagIterator) ?[]const u8 {
        while (self.ref_idx < self.current_refs_count) {
            const ref = self.current_refs[self.ref_idx];
            self.ref_idx += 1;
            return ref;
        }

        while (self.pos < self.json.len) {
            const tag_start = utils.findBracketInJson(self.json, self.pos, '[') orelse return null;
            const tag_end = utils.findBracketInJson(self.json, tag_start + 1, ']') orelse return null;
            self.pos = tag_end + 1;

            const tag_content = self.json[tag_start + 1 .. tag_end];
            const strings = utils.parseTagStrings(tag_content, 17) orelse continue;
            if (!std.mem.eql(u8, strings[0], "previous")) continue;

            self.current_refs_count = 0;
            for (1..17) |j| {
                if (strings[j].len == 8 and self.current_refs_count < 16) {
                    self.current_refs[self.current_refs_count] = strings[j];
                    self.current_refs_count += 1;
                }
            }

            if (self.current_refs_count > 0) {
                self.ref_idx = 1;
                return self.current_refs[0];
            }
        }
        return null;
    }
};

test "GroupIdentifier.parse with host and group_id" {
    const id = GroupIdentifier.parse("groups.nostr.com'abcdef").?;
    try std.testing.expectEqualStrings("groups.nostr.com", id.host);
    try std.testing.expectEqualStrings("abcdef", id.group_id);
}

test "GroupIdentifier.parse with host only" {
    const id = GroupIdentifier.parse("groups.nostr.com").?;
    try std.testing.expectEqualStrings("groups.nostr.com", id.host);
    try std.testing.expectEqualStrings("_", id.group_id);
}

test "GroupIdentifier.parse rejects empty string" {
    try std.testing.expect(GroupIdentifier.parse("") == null);
}

test "GroupIdentifier.parse rejects invalid group_id characters" {
    try std.testing.expect(GroupIdentifier.parse("host'ABC") == null);
    try std.testing.expect(GroupIdentifier.parse("host'test!") == null);
    try std.testing.expect(GroupIdentifier.parse("host'test space") == null);
}

test "GroupIdentifier.parse accepts valid group_id characters" {
    const id1 = GroupIdentifier.parse("host'abc123").?;
    try std.testing.expectEqualStrings("abc123", id1.group_id);

    const id2 = GroupIdentifier.parse("host'test-group_1").?;
    try std.testing.expectEqualStrings("test-group_1", id2.group_id);
}

test "GroupIdentifier.format" {
    var buf: [128]u8 = undefined;

    const id1 = GroupIdentifier{ .host = "groups.nostr.com", .group_id = "abcdef" };
    const formatted1 = id1.format(&buf).?;
    try std.testing.expectEqualStrings("groups.nostr.com'abcdef", formatted1);

    const id2 = GroupIdentifier{ .host = "groups.nostr.com", .group_id = "_" };
    const formatted2 = id2.format(&buf).?;
    try std.testing.expectEqualStrings("groups.nostr.com", formatted2);
}

test "isValidGroupId" {
    try std.testing.expect(isValidGroupId("abc123"));
    try std.testing.expect(isValidGroupId("test-group"));
    try std.testing.expect(isValidGroupId("test_group"));
    try std.testing.expect(isValidGroupId("_"));
    try std.testing.expect(!isValidGroupId(""));
    try std.testing.expect(!isValidGroupId("ABC"));
    try std.testing.expect(!isValidGroupId("test!"));
    try std.testing.expect(!isValidGroupId("test space"));
}

test "GroupMetadata.fromEvent parses kind:39000" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":39000,"created_at":1700000000,"content":"","tags":[["d","pizza-lovers"],["name","Pizza Lovers"],["picture","https://pizza.com/pizza.png"],["about","a group for people who love pizza"],["private"],["closed"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    var metadata = try GroupMetadata.fromEvent(&event, std.testing.allocator);
    defer metadata.deinit();

    try std.testing.expectEqualStrings("pizza-lovers", metadata.group_id);
    try std.testing.expectEqualStrings("Pizza Lovers", metadata.name.?);
    try std.testing.expectEqualStrings("https://pizza.com/pizza.png", metadata.picture.?);
    try std.testing.expectEqualStrings("a group for people who love pizza", metadata.about.?);
    try std.testing.expect(metadata.is_private);
    try std.testing.expect(metadata.is_closed);
    try std.testing.expect(!metadata.is_restricted);
    try std.testing.expect(!metadata.is_hidden);
}

test "GroupMetadata.fromEvent rejects wrong kind" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":1,"created_at":1700000000,"content":"test","tags":[["d","test"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    const result = GroupMetadata.fromEvent(&event, std.testing.allocator);
    try std.testing.expectError(error.InvalidKind, result);
}

test "GroupAdmins.fromEvent parses kind:39001" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":39001,"created_at":1700000000,"content":"list of admins","tags":[["d","pizza-lovers"],["p","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","ceo"],["p","bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","secretary","gardener"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    var admins = try GroupAdmins.fromEvent(&event, std.testing.allocator);
    defer admins.deinit();

    try std.testing.expectEqualStrings("pizza-lovers", admins.group_id);
    try std.testing.expectEqual(@as(usize, 2), admins.count());

    try std.testing.expectEqualStrings("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", admins.admins.items[0].pubkey);
    try std.testing.expectEqual(@as(usize, 1), admins.admins.items[0].roles.len);
    try std.testing.expectEqualStrings("ceo", admins.admins.items[0].roles[0]);

    try std.testing.expectEqualStrings("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", admins.admins.items[1].pubkey);
    try std.testing.expectEqual(@as(usize, 2), admins.admins.items[1].roles.len);
    try std.testing.expectEqualStrings("secretary", admins.admins.items[1].roles[0]);
    try std.testing.expectEqualStrings("gardener", admins.admins.items[1].roles[1]);
}

test "GroupMembers.fromEvent parses kind:39002" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":39002,"created_at":1700000000,"content":"list of members","tags":[["d","pizza-lovers"],["p","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],["p","bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"],["p","cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    var members = try GroupMembers.fromEvent(&event, std.testing.allocator);
    defer members.deinit();

    try std.testing.expectEqualStrings("pizza-lovers", members.group_id);
    try std.testing.expectEqual(@as(usize, 3), members.count());
    try std.testing.expect(members.contains("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
    try std.testing.expect(members.contains("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"));
    try std.testing.expect(!members.contains("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"));
}

test "GroupRoles.fromEvent parses kind:39003" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":39003,"created_at":1700000000,"content":"list of roles","tags":[["d","pizza-lovers"],["role","admin","can do everything"],["role","moderator","can delete messages"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    var roles = try GroupRoles.fromEvent(&event, std.testing.allocator);
    defer roles.deinit();

    try std.testing.expectEqualStrings("pizza-lovers", roles.group_id);
    try std.testing.expectEqual(@as(usize, 2), roles.count());

    try std.testing.expectEqualStrings("admin", roles.roles.items[0].name);
    try std.testing.expectEqualStrings("can do everything", roles.roles.items[0].description.?);

    try std.testing.expectEqualStrings("moderator", roles.roles.items[1].name);
    try std.testing.expectEqualStrings("can delete messages", roles.roles.items[1].description.?);
}

test "getGroupId extracts h tag" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":9,"created_at":1700000000,"content":"hello group","tags":[["h","pizza-lovers"],["previous","12345678"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    const group_id = getGroupId(&event).?;
    try std.testing.expectEqualStrings("pizza-lovers", group_id);
    try std.testing.expect(isGroupEvent(&event));
}

test "getPreviousReferences extracts previous tag values" {
    try event_mod.init();
    defer event_mod.cleanup();

    const json =
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"0000000000000000000000000000000000000000000000000000000000000002","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003","kind":9,"created_at":1700000000,"content":"hello group","tags":[["h","pizza-lovers"],["previous","12345678","abcdef12","87654321"]]}
    ;

    var event = try Event.parse(json);
    defer event.deinit();

    var buf: [16][]const u8 = undefined;
    const refs = getPreviousReferences(&event, &buf);

    try std.testing.expectEqual(@as(usize, 3), refs.len);
    try std.testing.expectEqualStrings("12345678", refs[0]);
    try std.testing.expectEqualStrings("abcdef12", refs[1]);
    try std.testing.expectEqualStrings("87654321", refs[2]);
}

test "isModerationEvent" {
    try std.testing.expect(isModerationEvent(PUT_USER_KIND));
    try std.testing.expect(isModerationEvent(REMOVE_USER_KIND));
    try std.testing.expect(isModerationEvent(EDIT_METADATA_KIND));
    try std.testing.expect(isModerationEvent(DELETE_EVENT_KIND));
    try std.testing.expect(isModerationEvent(CREATE_GROUP_KIND));
    try std.testing.expect(isModerationEvent(DELETE_GROUP_KIND));
    try std.testing.expect(isModerationEvent(CREATE_INVITE_KIND));
    try std.testing.expect(!isModerationEvent(JOIN_REQUEST_KIND));
    try std.testing.expect(!isModerationEvent(LEAVE_REQUEST_KIND));
    try std.testing.expect(!isModerationEvent(1));
}

test "isGroupMetadataEvent" {
    try std.testing.expect(isGroupMetadataEvent(GROUP_METADATA_KIND));
    try std.testing.expect(isGroupMetadataEvent(GROUP_ADMINS_KIND));
    try std.testing.expect(isGroupMetadataEvent(GROUP_MEMBERS_KIND));
    try std.testing.expect(isGroupMetadataEvent(GROUP_ROLES_KIND));
    try std.testing.expect(!isGroupMetadataEvent(1));
    try std.testing.expect(!isGroupMetadataEvent(9000));
}

test "kind constants match NIP-29 spec" {
    try std.testing.expectEqual(@as(i32, 39000), GROUP_METADATA_KIND);
    try std.testing.expectEqual(@as(i32, 39001), GROUP_ADMINS_KIND);
    try std.testing.expectEqual(@as(i32, 39002), GROUP_MEMBERS_KIND);
    try std.testing.expectEqual(@as(i32, 39003), GROUP_ROLES_KIND);
    try std.testing.expectEqual(@as(i32, 9000), PUT_USER_KIND);
    try std.testing.expectEqual(@as(i32, 9001), REMOVE_USER_KIND);
    try std.testing.expectEqual(@as(i32, 9002), EDIT_METADATA_KIND);
    try std.testing.expectEqual(@as(i32, 9005), DELETE_EVENT_KIND);
    try std.testing.expectEqual(@as(i32, 9007), CREATE_GROUP_KIND);
    try std.testing.expectEqual(@as(i32, 9008), DELETE_GROUP_KIND);
    try std.testing.expectEqual(@as(i32, 9009), CREATE_INVITE_KIND);
    try std.testing.expectEqual(@as(i32, 9021), JOIN_REQUEST_KIND);
    try std.testing.expectEqual(@as(i32, 9022), LEAVE_REQUEST_KIND);
}
