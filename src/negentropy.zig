const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const PROTOCOL_VERSION: u8 = 0x61;
pub const ID_SIZE: usize = 32;
pub const FINGERPRINT_SIZE: usize = 16;
pub const MAX_U64: u64 = std.math.maxInt(u64);

pub const Mode = enum(u8) {
    skip = 0,
    fingerprint = 1,
    id_list = 2,
};

pub const Item = struct {
    timestamp: u64,
    id: [ID_SIZE]u8,

    pub fn init(timestamp: u64, id: *const [ID_SIZE]u8) Item {
        return .{ .timestamp = timestamp, .id = id.* };
    }

    pub fn initEmpty(timestamp: u64) Item {
        return .{ .timestamp = timestamp, .id = std.mem.zeroes([ID_SIZE]u8) };
    }

    pub fn order(a: Item, b: Item) std.math.Order {
        if (a.timestamp != b.timestamp) return std.math.order(a.timestamp, b.timestamp);
        return std.mem.order(u8, &a.id, &b.id);
    }

    pub fn lessThan(_: void, a: Item, b: Item) bool {
        return order(a, b) == .lt;
    }

    pub fn compareForLowerBound(target: Item, item: Item) std.math.Order {
        return order(target, item);
    }
};

pub const Bound = struct {
    item: Item,
    id_len: usize,

    pub fn init(timestamp: u64, id_prefix: []const u8) Bound {
        var item = Item.initEmpty(timestamp);
        if (id_prefix.len > 0) @memcpy(item.id[0..id_prefix.len], id_prefix);
        return .{ .item = item, .id_len = id_prefix.len };
    }

    pub fn fromItem(item: Item) Bound {
        return .{ .item = item, .id_len = ID_SIZE };
    }

    pub fn infinity() Bound {
        return init(MAX_U64, &.{});
    }
};

pub const Fingerprint = struct {
    buf: [FINGERPRINT_SIZE]u8,

    pub fn eql(self: Fingerprint, other: []const u8) bool {
        if (other.len != FINGERPRINT_SIZE) return false;
        return std.mem.eql(u8, &self.buf, other);
    }
};

pub const Accumulator = struct {
    buf: [ID_SIZE]u8 align(8) = std.mem.zeroes([ID_SIZE]u8),

    pub fn add(self: *Accumulator, id: *const [ID_SIZE]u8) void {
        var carry: u1 = 0;
        for (0..ID_SIZE) |i| {
            const sum: u9 = @as(u9, self.buf[i]) + @as(u9, id[i]) + @as(u9, carry);
            self.buf[i] = @truncate(sum);
            carry = @truncate(sum >> 8);
        }
    }

    pub fn addItem(self: *Accumulator, item: *const Item) void {
        self.add(&item.id);
    }

    pub fn getFingerprint(self: *const Accumulator, count: u64) Fingerprint {
        var hasher = Sha256.init(.{});
        hasher.update(&self.buf);
        var varint_buf: [10]u8 = undefined;
        const varint_len = encodeVarInt(count, &varint_buf);
        hasher.update(varint_buf[0..varint_len]);
        var hash: [32]u8 = undefined;
        hasher.final(&hash);
        var fp: Fingerprint = undefined;
        @memcpy(&fp.buf, hash[0..FINGERPRINT_SIZE]);
        return fp;
    }
};

pub fn encodeVarInt(n: u64, out: []u8) usize {
    if (out.len == 0) return 0;
    if (n == 0) {
        out[0] = 0;
        return 1;
    }
    var val = n;
    var len: usize = 0;
    var temp: [10]u8 = undefined;
    while (val > 0) : (len += 1) {
        temp[len] = @truncate(val & 0x7F);
        val >>= 7;
    }
    if (len > out.len) return 0;
    for (0..len) |i| {
        const idx = len - 1 - i;
        out[i] = temp[idx] | (if (i < len - 1) @as(u8, 0x80) else 0);
    }
    return len;
}

pub fn decodeVarInt(data: []const u8) struct { value: u64, len: usize } {
    var result: u64 = 0;
    var i: usize = 0;
    while (i < data.len and i < 10) : (i += 1) {
        if (i == 9 and data[i] > 0x01) return .{ .value = 0, .len = 0 };
        result = (result << 7) | (data[i] & 0x7F);
        if (data[i] & 0x80 == 0) return .{ .value = result, .len = i + 1 };
    }
    return .{ .value = result, .len = i };
}

pub const Storage = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        size: *const fn (*anyopaque) usize,
        getItem: *const fn (*anyopaque, usize) Item,
        fingerprint: *const fn (*anyopaque, usize, usize) Fingerprint,
        findLowerBound: *const fn (*anyopaque, usize, usize, Bound) usize,
    };

    pub fn size(self: Storage) usize {
        return self.vtable.size(self.ptr);
    }

    pub fn getItem(self: Storage, i: usize) Item {
        return self.vtable.getItem(self.ptr, i);
    }

    pub fn fingerprint(self: Storage, begin: usize, end: usize) Fingerprint {
        return self.vtable.fingerprint(self.ptr, begin, end);
    }

    pub fn findLowerBound(self: Storage, begin: usize, end: usize, bound: Bound) usize {
        return self.vtable.findLowerBound(self.ptr, begin, end, bound);
    }
};

pub const VectorStorage = struct {
    items: std.ArrayListUnmanaged(Item),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) VectorStorage {
        return .{ .items = .{}, .allocator = allocator };
    }

    pub fn deinit(self: *VectorStorage) void {
        self.items.deinit(self.allocator);
    }

    pub fn insert(self: *VectorStorage, timestamp: u64, id: *const [ID_SIZE]u8) !void {
        const item = Item.init(timestamp, id);
        const idx = std.sort.lowerBound(Item, self.items.items, item, Item.compareForLowerBound);
        try self.items.insert(self.allocator, idx, item);
    }

    pub fn seal(self: *VectorStorage) void {
        std.mem.sort(Item, self.items.items, {}, Item.lessThan);
    }

    pub fn storage(self: *VectorStorage) Storage {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = Storage.VTable{
        .size = @ptrCast(&size_),
        .getItem = @ptrCast(&getItem_),
        .fingerprint = @ptrCast(&fingerprint_),
        .findLowerBound = @ptrCast(&findLowerBound_),
    };

    fn size_(self: *VectorStorage) usize {
        return self.items.items.len;
    }

    fn getItem_(self: *VectorStorage, i: usize) Item {
        return self.items.items[i];
    }

    fn fingerprint_(self: *VectorStorage, begin: usize, end: usize) Fingerprint {
        var acc = Accumulator{};
        for (self.items.items[begin..end]) |*item| acc.addItem(item);
        return acc.getFingerprint(end - begin);
    }

    fn findLowerBound_(self: *VectorStorage, begin: usize, end: usize, bound: Bound) usize {
        const items = self.items.items[begin..end];
        const idx = std.sort.lowerBound(Item, items, bound.item, Item.compareForLowerBound);
        return begin + idx;
    }
};

pub const Negentropy = struct {
    storage: Storage,
    frame_size_limit: u64,
    is_initiator: bool = false,
    last_timestamp_in: u64 = 0,
    last_timestamp_out: u64 = 0,

    pub const Error = error{ AlreadyInitiated, NotInitiator, InvalidProtocolVersion, UnexpectedMode, ParseError, BufferTooSmall, OutOfMemory };

    pub const ReconcileResult = struct {
        output: []const u8,
        have_ids: std.ArrayListUnmanaged([ID_SIZE]u8),
        need_ids: std.ArrayListUnmanaged([ID_SIZE]u8),
        allocator: std.mem.Allocator,
        done: bool,

        pub fn deinit(self: *ReconcileResult) void {
            self.have_ids.deinit(self.allocator);
            self.need_ids.deinit(self.allocator);
        }
    };

    pub fn init(storage: Storage, frame_size_limit: u64) Negentropy {
        return .{ .storage = storage, .frame_size_limit = if (frame_size_limit > 0 and frame_size_limit < 4096) 4096 else frame_size_limit };
    }

    pub fn initiate(self: *Negentropy, out: []u8) Error![]u8 {
        if (self.is_initiator) return Error.AlreadyInitiated;
        self.is_initiator = true;
        self.last_timestamp_out = 0;

        if (out.len == 0) return Error.BufferTooSmall;
        var pos: usize = 0;
        out[pos] = PROTOCOL_VERSION;
        pos += 1;

        const range_output = self.splitRange(0, self.storage.size(), Bound.infinity(), out[pos..]) catch return Error.BufferTooSmall;
        pos += range_output.len;

        return out[0..pos];
    }

    pub fn reconcile(self: *Negentropy, query: []const u8, out: []u8, allocator: std.mem.Allocator) Error!ReconcileResult {
        self.last_timestamp_in = 0;
        self.last_timestamp_out = 0;

        var have_ids: std.ArrayListUnmanaged([ID_SIZE]u8) = .{};
        var need_ids: std.ArrayListUnmanaged([ID_SIZE]u8) = .{};

        if (out.len == 0) return Error.BufferTooSmall;
        var pos: usize = 0;
        out[pos] = PROTOCOL_VERSION;
        pos += 1;

        if (query.len == 0) return Error.ParseError;
        const protocol_version = query[0];
        if (protocol_version < 0x60 or protocol_version > 0x6F) return Error.InvalidProtocolVersion;
        if (protocol_version != PROTOCOL_VERSION) {
            if (self.is_initiator) return Error.InvalidProtocolVersion;
            return .{ .output = out[0..pos], .have_ids = have_ids, .need_ids = need_ids, .allocator = allocator, .done = true };
        }

        var q = query[1..];
        const storage_size = self.storage.size();
        var prev_bound = Bound.init(0, &.{});
        var prev_index: usize = 0;
        var skip = false;
        var skip_bound: Bound = undefined;

        while (q.len > 0) {
            const bound_result = self.decodeBound(q) catch return Error.ParseError;
            q = q[bound_result.len..];
            const curr_bound = bound_result.bound;

            const mode_result = decodeVarInt(q);
            q = q[mode_result.len..];
            const mode: Mode = @enumFromInt(@as(u8, @truncate(mode_result.value)));

            const lower = prev_index;
            const upper = self.storage.findLowerBound(prev_index, storage_size, curr_bound);

            switch (mode) {
                .skip => {
                    skip = true;
                    skip_bound = curr_bound;
                },
                .fingerprint => {
                    if (q.len < FINGERPRINT_SIZE) return Error.ParseError;
                    const their_fp = q[0..FINGERPRINT_SIZE];
                    q = q[FINGERPRINT_SIZE..];
                    const our_fp = self.storage.fingerprint(lower, upper);

                    if (!our_fp.eql(their_fp)) {
                        if (skip) {
                            const skip_len = self.encodeBound(skip_bound, out[pos..]) catch return Error.BufferTooSmall;
                            pos += skip_len;
                            if (pos >= out.len) return Error.BufferTooSmall;
                            out[pos] = @intFromEnum(Mode.skip);
                            pos += 1;
                            skip = false;
                        }
                        const range_out = self.splitRange(lower, upper, curr_bound, out[pos..]) catch return Error.BufferTooSmall;
                        pos += range_out.len;
                    } else {
                        skip = true;
                        skip_bound = curr_bound;
                    }
                },
                .id_list => {
                    const num_ids_result = decodeVarInt(q);
                    q = q[num_ids_result.len..];
                    const num_ids = num_ids_result.value;

                    if (self.is_initiator) {
                        var their_set = std.AutoHashMap([ID_SIZE]u8, void).init(allocator);
                        defer their_set.deinit();

                        for (0..num_ids) |_| {
                            if (q.len < ID_SIZE) return Error.ParseError;
                            var id: [ID_SIZE]u8 = undefined;
                            @memcpy(&id, q[0..ID_SIZE]);
                            q = q[ID_SIZE..];
                            their_set.put(id, {}) catch return Error.OutOfMemory;
                        }

                        for (lower..upper) |i| {
                            const item = self.storage.getItem(i);
                            if (their_set.contains(item.id)) {
                                _ = their_set.remove(item.id);
                            } else {
                                have_ids.append(allocator, item.id) catch return Error.OutOfMemory;
                            }
                        }

                        var it = their_set.keyIterator();
                        while (it.next()) |key| need_ids.append(allocator, key.*) catch return Error.OutOfMemory;

                        skip = true;
                        skip_bound = curr_bound;
                    } else {
                        if (skip) {
                            const skip_len = self.encodeBound(skip_bound, out[pos..]) catch return Error.BufferTooSmall;
                            pos += skip_len;
                            if (pos >= out.len) return Error.BufferTooSmall;
                            out[pos] = @intFromEnum(Mode.skip);
                            pos += 1;
                            skip = false;
                        }

                        for (0..num_ids) |_| {
                            if (q.len < ID_SIZE) return Error.ParseError;
                            q = q[ID_SIZE..];
                        }

                        const bound_len = self.encodeBound(curr_bound, out[pos..]) catch return Error.BufferTooSmall;
                        pos += bound_len;
                        if (pos >= out.len) return Error.BufferTooSmall;
                        out[pos] = @intFromEnum(Mode.id_list);
                        pos += 1;

                        const count = upper - lower;
                        const count_len = encodeVarInt(count, out[pos..]);
                        if (count_len == 0) return Error.BufferTooSmall;
                        pos += count_len;

                        for (lower..upper) |i| {
                            if (pos + ID_SIZE > out.len) return Error.BufferTooSmall;
                            const item = self.storage.getItem(i);
                            @memcpy(out[pos..][0..ID_SIZE], &item.id);
                            pos += ID_SIZE;
                        }
                    }
                },
            }

            prev_index = upper;
            prev_bound = curr_bound;
        }

        return .{ .output = out[0..pos], .have_ids = have_ids, .need_ids = need_ids, .allocator = allocator, .done = pos == 1 };
    }

    fn splitRange(self: *Negentropy, lower: usize, upper: usize, upper_bound: Bound, out: []u8) ![]u8 {
        var pos: usize = 0;
        const num_elems = upper - lower;
        const buckets: usize = 16;
        const limit = if (self.frame_size_limit > 0) @min(out.len, @as(usize, @intCast(self.frame_size_limit))) else out.len;

        if (num_elems < buckets * 2) {
            const bound_len = try self.encodeBound(upper_bound, out[pos..]);
            pos += bound_len;
            if (pos >= limit) return error.BufferTooSmall;
            out[pos] = @intFromEnum(Mode.id_list);
            pos += 1;
            const count_len = encodeVarInt(num_elems, out[pos..]);
            if (count_len == 0) return error.BufferTooSmall;
            pos += count_len;

            for (lower..upper) |i| {
                if (pos + ID_SIZE > limit) return error.BufferTooSmall;
                const item = self.storage.getItem(i);
                @memcpy(out[pos..][0..ID_SIZE], &item.id);
                pos += ID_SIZE;
            }
        } else {
            const items_per_bucket = num_elems / buckets;
            const buckets_with_extra = num_elems % buckets;
            var curr = lower;

            for (0..buckets) |i| {
                const bucket_size = items_per_bucket + (if (i < buckets_with_extra) @as(usize, 1) else 0);
                const our_fp = self.storage.fingerprint(curr, curr + bucket_size);
                curr += bucket_size;

                const next_bound = if (curr == upper) upper_bound else blk: {
                    const prev_item = self.storage.getItem(curr - 1);
                    const curr_item = self.storage.getItem(curr);
                    break :blk getMinimalBound(prev_item, curr_item);
                };

                const bound_len = try self.encodeBound(next_bound, out[pos..]);
                pos += bound_len;
                if (pos + 1 + FINGERPRINT_SIZE > limit) return error.BufferTooSmall;
                out[pos] = @intFromEnum(Mode.fingerprint);
                pos += 1;
                @memcpy(out[pos..][0..FINGERPRINT_SIZE], &our_fp.buf);
                pos += FINGERPRINT_SIZE;
            }
        }

        return out[0..pos];
    }

    fn encodeBound(self: *Negentropy, bound: Bound, out: []u8) !usize {
        var pos: usize = 0;
        const ts_len = self.encodeTimestampOut(bound.item.timestamp, out[pos..]);
        if (ts_len == 0) return error.BufferTooSmall;
        pos += ts_len;
        const id_len_len = encodeVarInt(bound.id_len, out[pos..]);
        if (id_len_len == 0) return error.BufferTooSmall;
        pos += id_len_len;
        if (bound.id_len > 0) {
            if (pos + bound.id_len > out.len) return error.BufferTooSmall;
            @memcpy(out[pos..][0..bound.id_len], bound.item.id[0..bound.id_len]);
            pos += bound.id_len;
        }
        return pos;
    }

    fn encodeTimestampOut(self: *Negentropy, timestamp: u64, out: []u8) usize {
        if (out.len == 0) return 0;
        if (timestamp == MAX_U64) {
            self.last_timestamp_out = MAX_U64;
            out[0] = 0;
            return 1;
        }
        const offset = timestamp - self.last_timestamp_out;
        self.last_timestamp_out = timestamp;
        return encodeVarInt(offset + 1, out);
    }

    fn decodeBound(self: *Negentropy, data: []const u8) !struct { bound: Bound, len: usize } {
        var pos: usize = 0;
        const ts_result = self.decodeTimestampIn(data);
        pos += ts_result.len;
        const id_len_result = decodeVarInt(data[pos..]);
        pos += id_len_result.len;
        const id_len = id_len_result.value;
        if (id_len > ID_SIZE or pos + id_len > data.len) return error.ParseError;
        const bound = Bound.init(ts_result.timestamp, data[pos..][0..id_len]);
        pos += id_len;
        return .{ .bound = bound, .len = pos };
    }

    fn decodeTimestampIn(self: *Negentropy, data: []const u8) struct { timestamp: u64, len: usize } {
        const result = decodeVarInt(data);
        var timestamp = if (result.value == 0) MAX_U64 else result.value - 1;
        timestamp +%= self.last_timestamp_in;
        if (timestamp < self.last_timestamp_in) timestamp = MAX_U64;
        self.last_timestamp_in = timestamp;
        return .{ .timestamp = timestamp, .len = result.len };
    }

    fn getMinimalBound(prev: Item, curr: Item) Bound {
        if (curr.timestamp != prev.timestamp) {
            return Bound.init(curr.timestamp, &.{});
        }
        var shared: usize = 0;
        for (0..ID_SIZE) |i| {
            if (curr.id[i] != prev.id[i]) break;
            shared += 1;
        }
        const prefix_len = @min(shared + 1, ID_SIZE);
        return Bound.init(curr.timestamp, curr.id[0..prefix_len]);
    }
};

test "varint encoding" {
    var buf: [10]u8 = undefined;

    try std.testing.expectEqual(@as(usize, 1), encodeVarInt(0, &buf));
    try std.testing.expectEqual(@as(u8, 0), buf[0]);

    try std.testing.expectEqual(@as(usize, 1), encodeVarInt(127, &buf));
    try std.testing.expectEqual(@as(u8, 127), buf[0]);

    try std.testing.expectEqual(@as(usize, 2), encodeVarInt(128, &buf));
    try std.testing.expectEqual(@as(u8, 0x81), buf[0]);
    try std.testing.expectEqual(@as(u8, 0x00), buf[1]);

    const decoded = decodeVarInt(&buf);
    try std.testing.expectEqual(@as(u64, 128), decoded.value);
    try std.testing.expectEqual(@as(usize, 2), decoded.len);
}

test "accumulator fingerprint" {
    var acc = Accumulator{};
    var id1: [ID_SIZE]u8 = undefined;
    @memset(&id1, 0x01);
    acc.add(&id1);

    var id2: [ID_SIZE]u8 = undefined;
    @memset(&id2, 0x02);
    acc.add(&id2);

    const fp = acc.getFingerprint(2);
    try std.testing.expectEqual(@as(usize, FINGERPRINT_SIZE), fp.buf.len);
}

test "vector storage" {
    const allocator = std.testing.allocator;
    var storage = VectorStorage.init(allocator);
    defer storage.deinit();

    var id1: [ID_SIZE]u8 = undefined;
    @memset(&id1, 0x01);
    try storage.insert(100, &id1);

    var id2: [ID_SIZE]u8 = undefined;
    @memset(&id2, 0x02);
    try storage.insert(200, &id2);

    const s = storage.storage();
    try std.testing.expectEqual(@as(usize, 2), s.size());

    const item0 = s.getItem(0);
    try std.testing.expectEqual(@as(u64, 100), item0.timestamp);

    const item1 = s.getItem(1);
    try std.testing.expectEqual(@as(u64, 200), item1.timestamp);
}

test "basic reconciliation" {
    const allocator = std.testing.allocator;

    var client_storage = VectorStorage.init(allocator);
    defer client_storage.deinit();

    var server_storage = VectorStorage.init(allocator);
    defer server_storage.deinit();

    var shared_id: [ID_SIZE]u8 = undefined;
    @memset(&shared_id, 0xAA);
    try client_storage.insert(100, &shared_id);
    try server_storage.insert(100, &shared_id);

    var client_only: [ID_SIZE]u8 = undefined;
    @memset(&client_only, 0xBB);
    try client_storage.insert(200, &client_only);

    var server_only: [ID_SIZE]u8 = undefined;
    @memset(&server_only, 0xCC);
    try server_storage.insert(300, &server_only);

    var client = Negentropy.init(client_storage.storage(), 0);
    var server = Negentropy.init(server_storage.storage(), 0);

    var init_buf: [4096]u8 = undefined;
    const init_msg = try client.initiate(&init_buf);

    var server_buf: [4096]u8 = undefined;
    var server_result = try server.reconcile(init_msg, &server_buf, allocator);
    defer server_result.deinit();

    var client_buf: [4096]u8 = undefined;
    var client_result = try client.reconcile(server_result.output, &client_buf, allocator);
    defer client_result.deinit();

    try std.testing.expectEqual(@as(usize, 1), client_result.have_ids.items.len);
    try std.testing.expectEqual(@as(usize, 1), client_result.need_ids.items.len);
    try std.testing.expect(std.mem.eql(u8, &client_result.have_ids.items[0], &client_only));
    try std.testing.expect(std.mem.eql(u8, &client_result.need_ids.items[0], &server_only));
}

test "Item ordering by timestamp" {
    var id1: [ID_SIZE]u8 = undefined;
    @memset(&id1, 0x01);
    var id2: [ID_SIZE]u8 = undefined;
    @memset(&id2, 0x02);

    const item1 = Item.init(100, &id1);
    const item2 = Item.init(200, &id2);

    try std.testing.expectEqual(std.math.Order.lt, Item.order(item1, item2));
    try std.testing.expectEqual(std.math.Order.gt, Item.order(item2, item1));
    try std.testing.expect(Item.lessThan({}, item1, item2));
}

test "Item ordering by id when same timestamp" {
    var id1: [ID_SIZE]u8 = undefined;
    @memset(&id1, 0x01);
    var id2: [ID_SIZE]u8 = undefined;
    @memset(&id2, 0x02);

    const item1 = Item.init(100, &id1);
    const item2 = Item.init(100, &id2);

    try std.testing.expectEqual(std.math.Order.lt, Item.order(item1, item2));
    try std.testing.expectEqual(std.math.Order.gt, Item.order(item2, item1));
}

test "Item ordering equal" {
    var id: [ID_SIZE]u8 = undefined;
    @memset(&id, 0xAB);

    const item1 = Item.init(100, &id);
    const item2 = Item.init(100, &id);

    try std.testing.expectEqual(std.math.Order.eq, Item.order(item1, item2));
}

test "varint encoding large numbers" {
    var buf: [10]u8 = undefined;

    const len = encodeVarInt(16383, &buf);
    try std.testing.expectEqual(@as(usize, 2), len);
    const decoded = decodeVarInt(&buf);
    try std.testing.expectEqual(@as(u64, 16383), decoded.value);

    const len2 = encodeVarInt(2097151, &buf);
    try std.testing.expectEqual(@as(usize, 3), len2);
    const decoded2 = decodeVarInt(&buf);
    try std.testing.expectEqual(@as(u64, 2097151), decoded2.value);
}

test "Bound infinity" {
    const inf = Bound.infinity();
    try std.testing.expectEqual(MAX_U64, inf.item.timestamp);
    try std.testing.expectEqual(@as(usize, 0), inf.id_len);
}

test "Bound fromItem" {
    var id: [ID_SIZE]u8 = undefined;
    @memset(&id, 0xAB);
    const item = Item.init(12345, &id);
    const bound = Bound.fromItem(item);

    try std.testing.expectEqual(@as(u64, 12345), bound.item.timestamp);
    try std.testing.expectEqual(@as(usize, ID_SIZE), bound.id_len);
}

test "identical storage reconciliation" {
    const allocator = std.testing.allocator;

    var storage1 = VectorStorage.init(allocator);
    defer storage1.deinit();
    var storage2 = VectorStorage.init(allocator);
    defer storage2.deinit();

    var id: [ID_SIZE]u8 = undefined;
    @memset(&id, 0xAA);
    try storage1.insert(100, &id);
    try storage2.insert(100, &id);

    var id2: [ID_SIZE]u8 = undefined;
    @memset(&id2, 0xBB);
    try storage1.insert(200, &id2);
    try storage2.insert(200, &id2);

    var client = Negentropy.init(storage1.storage(), 0);
    var server = Negentropy.init(storage2.storage(), 0);

    var init_buf: [4096]u8 = undefined;
    const init_msg = try client.initiate(&init_buf);

    var server_buf: [4096]u8 = undefined;
    var server_result = try server.reconcile(init_msg, &server_buf, allocator);
    defer server_result.deinit();

    var client_buf: [4096]u8 = undefined;
    var client_result = try client.reconcile(server_result.output, &client_buf, allocator);
    defer client_result.deinit();

    try std.testing.expectEqual(@as(usize, 0), client_result.have_ids.items.len);
    try std.testing.expectEqual(@as(usize, 0), client_result.need_ids.items.len);
}

test "empty storage reconciliation" {
    const allocator = std.testing.allocator;

    var storage1 = VectorStorage.init(allocator);
    defer storage1.deinit();
    var storage2 = VectorStorage.init(allocator);
    defer storage2.deinit();

    var client = Negentropy.init(storage1.storage(), 0);
    var server = Negentropy.init(storage2.storage(), 0);

    var init_buf: [4096]u8 = undefined;
    const init_msg = try client.initiate(&init_buf);

    var server_buf: [4096]u8 = undefined;
    var server_result = try server.reconcile(init_msg, &server_buf, allocator);
    defer server_result.deinit();

    try std.testing.expectEqual(@as(usize, 0), server_result.have_ids.items.len);
    try std.testing.expectEqual(@as(usize, 0), server_result.need_ids.items.len);
}

test "Fingerprint equality" {
    var acc = Accumulator{};
    var id: [ID_SIZE]u8 = undefined;
    @memset(&id, 0x42);
    acc.add(&id);

    const fp = acc.getFingerprint(1);
    try std.testing.expect(fp.eql(&fp.buf));

    var wrong: [FINGERPRINT_SIZE]u8 = undefined;
    @memset(&wrong, 0x00);
    try std.testing.expect(!fp.eql(&wrong));
}

test "Accumulator add is commutative" {
    var id1: [ID_SIZE]u8 = undefined;
    @memset(&id1, 0x11);
    var id2: [ID_SIZE]u8 = undefined;
    @memset(&id2, 0x22);

    var acc1 = Accumulator{};
    acc1.add(&id1);
    acc1.add(&id2);

    var acc2 = Accumulator{};
    acc2.add(&id2);
    acc2.add(&id1);

    const fp1 = acc1.getFingerprint(2);
    const fp2 = acc2.getFingerprint(2);
    try std.testing.expect(fp1.eql(&fp2.buf));
}
