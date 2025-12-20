const std = @import("std");
const Allocator = std.mem.Allocator;
const Thread = std.Thread;
const Mutex = Thread.Mutex;

const ws = @import("ws/ws.zig");
const Client = ws.Client;
const Message = ws.Message;
const MessageQueue = @import("message_queue.zig").MessageQueue;
const event_mod = @import("event.zig");
const Event = event_mod.Event;
const filter_mod = @import("filter.zig");
const Filter = filter_mod.Filter;
const messages_mod = @import("messages.zig");
const ClientMsg = messages_mod.ClientMsg;
const RelayMsgParsed = messages_mod.RelayMsgParsed;
const RelayMsgType = messages_mod.RelayMsgType;

pub const RelayStatus = enum(u8) {
    disconnected = 0,
    connecting = 1,
    connected = 2,
    failed = 3,
};

pub const PublishResult = struct {
    relay_url: []const u8,
    success: bool,
    is_duplicate: bool,
    message: []const u8,
};

pub const SubscriptionEvent = struct {
    event: Event,
    relay_url: []const u8,
    is_eose: bool,
};

pub const RelayHandle = struct {
    url: []const u8,
    client: ?Client,
    status: std.atomic.Value(RelayStatus),
    thread: ?Thread,
    should_stop: std.atomic.Value(bool),
    last_error: ?[]const u8,
    allocator: Allocator,

    pub fn init(allocator: Allocator, url: []const u8) !RelayHandle {
        return .{
            .url = try allocator.dupe(u8, url),
            .client = null,
            .status = std.atomic.Value(RelayStatus).init(.disconnected),
            .thread = null,
            .should_stop = std.atomic.Value(bool).init(false),
            .last_error = null,
            .allocator = allocator,
        };
    }

    pub fn getStatus(self: *const RelayHandle) RelayStatus {
        return self.status.load(.acquire);
    }

    pub fn setStatus(self: *RelayHandle, new_status: RelayStatus) void {
        self.status.store(new_status, .release);
    }

    pub fn deinit(self: *RelayHandle) void {
        self.disconnect();
        self.allocator.free(self.url);
        if (self.last_error) |err| {
            self.allocator.free(err);
        }
    }

    pub fn connect(self: *RelayHandle) !void {
        if (self.getStatus() == .connected) return;

        self.setStatus(.connecting);
        errdefer self.setStatus(.failed);

        self.client = try Client.connect(self.allocator, self.url);
        self.setStatus(.connected);
    }

    pub fn disconnect(self: *RelayHandle) void {
        self.should_stop.store(true, .release);

        if (self.thread) |t| {
            t.join();
            self.thread = null;
        }

        if (self.client) |*c| {
            c.close();
            self.client = null;
        }

        self.setStatus(.disconnected);
        self.should_stop.store(false, .release);
    }

    pub fn send(self: *RelayHandle, data: []const u8) !void {
        if (self.client) |*c| {
            try c.sendText(data);
        } else {
            return error.NotConnected;
        }
    }

    pub fn recv(self: *RelayHandle) !Message {
        if (self.client) |*c| {
            return try c.recvMessage();
        } else {
            return error.NotConnected;
        }
    }
};

pub const PoolOptions = struct {
    max_relays: usize = 32,
    queue_size: usize = 10000,
    connect_timeout_ms: u64 = 10000,
    dedup_cache_size: usize = 10000,
};

pub const Pool = struct {
    allocator: Allocator,
    relays: std.ArrayListUnmanaged(RelayHandle),
    seen_events: std.AutoHashMapUnmanaged([32]u8, i64),
    message_queue: MessageQueue,
    subscriptions: std.StringHashMapUnmanaged(SubscriptionState),
    mutex: Mutex,
    options: PoolOptions,
    next_relay_idx: std.atomic.Value(usize),
    active_workers: std.atomic.Value(usize),

    const SubscriptionState = struct {
        filters: []Filter,
        eose_count: usize,
        relay_count: usize,
    };

    pub fn init(allocator: Allocator) Pool {
        return initWithOptions(allocator, .{});
    }

    pub fn initWithOptions(allocator: Allocator, options: PoolOptions) Pool {
        return .{
            .allocator = allocator,
            .relays = .{},
            .seen_events = .{},
            .message_queue = MessageQueue.initWithCapacity(allocator, options.queue_size),
            .subscriptions = .{},
            .mutex = .{},
            .options = options,
            .next_relay_idx = std.atomic.Value(usize).init(0),
            .active_workers = std.atomic.Value(usize).init(0),
        };
    }

    pub fn deinit(self: *Pool) void {
        self.disconnectAll();

        for (self.relays.items) |*relay| {
            relay.deinit();
        }
        self.relays.deinit(self.allocator);

        self.seen_events.deinit(self.allocator);
        self.message_queue.deinit();

        var sub_iter = self.subscriptions.iterator();
        while (sub_iter.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            for (entry.value_ptr.filters) |*f| {
                var filter = f.*;
                filter.deinit();
            }
            self.allocator.free(entry.value_ptr.filters);
        }
        self.subscriptions.deinit(self.allocator);
    }

    pub fn addRelay(self: *Pool, url: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.relays.items) |relay| {
            if (std.mem.eql(u8, relay.url, url)) {
                return error.RelayAlreadyExists;
            }
        }

        if (self.relays.items.len >= self.options.max_relays) {
            return error.TooManyRelays;
        }

        var handle = try RelayHandle.init(self.allocator, url);
        errdefer handle.deinit();

        try self.relays.append(self.allocator, handle);
    }

    pub fn removeRelay(self: *Pool, url: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.relays.items, 0..) |*relay, i| {
            if (std.mem.eql(u8, relay.url, url)) {
                relay.deinit();
                _ = self.relays.orderedRemove(i);
                return;
            }
        }
        return error.RelayNotFound;
    }

    pub fn connectAll(self: *Pool) !usize {
        self.mutex.lock();
        defer self.mutex.unlock();

        var connected: usize = 0;
        for (self.relays.items) |*relay| {
            relay.connect() catch |err| {
                relay.setStatus(.failed);
                if (relay.last_error) |old_err| {
                    self.allocator.free(old_err);
                }
                const err_msg = @errorName(err);
                relay.last_error = self.allocator.dupe(u8, err_msg) catch null;
                continue;
            };
            connected += 1;
        }
        return connected;
    }

    pub fn disconnectAll(self: *Pool) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.relays.items) |*relay| {
            relay.disconnect();
        }
    }

    pub fn getRelayStatus(self: *Pool, url: []const u8) ?RelayStatus {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.relays.items) |*relay| {
            if (std.mem.eql(u8, relay.url, url)) {
                return relay.getStatus();
            }
        }
        return null;
    }

    pub fn connectedCount(self: *Pool) usize {
        self.mutex.lock();
        defer self.mutex.unlock();

        var count: usize = 0;
        for (self.relays.items) |*relay| {
            if (relay.getStatus() == .connected) {
                count += 1;
            }
        }
        return count;
    }

    pub fn relayCount(self: *Pool) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.relays.items.len;
    }

    pub fn publish(self: *Pool, event_json: []const u8) ![]PublishResult {
        const required_len = event_json.len + 16; // ["EVENT",] + ]
        var stack_buf: [65536]u8 = undefined;

        var msg: []const u8 = undefined;
        var heap_buf: ?[]u8 = null;
        defer if (heap_buf) |buf| self.allocator.free(buf);

        if (required_len <= stack_buf.len) {
            var fbs = std.io.fixedBufferStream(&stack_buf);
            const writer = fbs.writer();
            writer.writeAll("[\"EVENT\",") catch return error.BufferTooSmall;
            writer.writeAll(event_json) catch return error.BufferTooSmall;
            writer.writeAll("]") catch return error.BufferTooSmall;
            msg = fbs.getWritten();
        } else {
            heap_buf = try self.allocator.alloc(u8, required_len);
            var fbs = std.io.fixedBufferStream(heap_buf.?);
            const writer = fbs.writer();
            try writer.writeAll("[\"EVENT\",");
            try writer.writeAll(event_json);
            try writer.writeAll("]");
            msg = fbs.getWritten();
        }

        self.mutex.lock();
        defer self.mutex.unlock();

        var results = try self.allocator.alloc(PublishResult, self.relays.items.len);
        var result_idx: usize = 0;

        for (self.relays.items) |*relay| {
            if (relay.getStatus() != .connected) {
                results[result_idx] = .{
                    .relay_url = relay.url,
                    .success = false,
                    .is_duplicate = false,
                    .message = "not connected",
                };
                result_idx += 1;
                continue;
            }

            relay.send(msg) catch |err| {
                results[result_idx] = .{
                    .relay_url = relay.url,
                    .success = false,
                    .is_duplicate = false,
                    .message = @errorName(err),
                };
                result_idx += 1;
                continue;
            };

            results[result_idx] = .{
                .relay_url = relay.url,
                .success = true,
                .is_duplicate = false,
                .message = "",
            };
            result_idx += 1;
        }

        return results[0..result_idx];
    }

    pub fn publishToOne(self: *Pool, event_json: []const u8) !?PublishResult {
        const required_len = event_json.len + 16; // ["EVENT",] + ]
        var stack_buf: [65536]u8 = undefined;

        var msg: []const u8 = undefined;
        var heap_buf: ?[]u8 = null;
        defer if (heap_buf) |buf| self.allocator.free(buf);

        if (required_len <= stack_buf.len) {
            var fbs = std.io.fixedBufferStream(&stack_buf);
            const writer = fbs.writer();
            writer.writeAll("[\"EVENT\",") catch return error.BufferTooSmall;
            writer.writeAll(event_json) catch return error.BufferTooSmall;
            writer.writeAll("]") catch return error.BufferTooSmall;
            msg = fbs.getWritten();
        } else {
            heap_buf = try self.allocator.alloc(u8, required_len);
            var fbs = std.io.fixedBufferStream(heap_buf.?);
            const writer = fbs.writer();
            try writer.writeAll("[\"EVENT\",");
            try writer.writeAll(event_json);
            try writer.writeAll("]");
            msg = fbs.getWritten();
        }

        self.mutex.lock();
        defer self.mutex.unlock();

        const relay_count = self.relays.items.len;
        if (relay_count == 0) return null;

        const start_idx = self.next_relay_idx.fetchAdd(1, .monotonic) % relay_count;
        var attempts: usize = 0;

        while (attempts < relay_count) : (attempts += 1) {
            const idx = (start_idx + attempts) % relay_count;
            const relay = &self.relays.items[idx];

            if (relay.getStatus() != .connected) continue;

            relay.send(msg) catch continue;

            return .{
                .relay_url = relay.url,
                .success = true,
                .is_duplicate = false,
                .message = "",
            };
        }

        return null;
    }

    pub fn subscribe(self: *Pool, sub_id: []const u8, filters: []const Filter) !void {
        var msg_buf: [65536]u8 = undefined;
        const msg = try ClientMsg.reqMsg(sub_id, filters, &msg_buf);

        self.mutex.lock();
        defer self.mutex.unlock();

        var owned_filters = try self.allocator.alloc(Filter, filters.len);
        errdefer self.allocator.free(owned_filters);

        for (filters, 0..) |f, i| {
            owned_filters[i] = try f.clone(self.allocator);
        }

        const owned_id = try self.allocator.dupe(u8, sub_id);
        errdefer self.allocator.free(owned_id);

        try self.subscriptions.put(self.allocator, owned_id, .{
            .filters = owned_filters,
            .eose_count = 0,
            .relay_count = self.relays.items.len,
        });

        for (self.relays.items) |*relay| {
            if (relay.getStatus() == .connected) {
                relay.send(msg) catch continue;
            }
        }
    }

    pub fn unsubscribe(self: *Pool, sub_id: []const u8) !void {
        var msg_buf: [256]u8 = undefined;
        const msg = try ClientMsg.closeMsg(sub_id, &msg_buf);

        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.subscriptions.fetchRemove(sub_id)) |entry| {
            self.allocator.free(entry.key);
            for (entry.value.filters) |*f| {
                var filter = f.*;
                filter.deinit();
            }
            self.allocator.free(entry.value.filters);
        }

        for (self.relays.items) |*relay| {
            if (relay.getStatus() == .connected) {
                relay.send(msg) catch continue;
            }
        }
    }

    pub fn startReceiving(self: *Pool) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.relays.items) |*relay| {
            if (relay.getStatus() == .connected and relay.thread == null) {
                relay.thread = try Thread.spawn(.{}, workerThread, .{ self, relay });
                _ = self.active_workers.fetchAdd(1, .monotonic);
            }
        }
    }

    fn workerThread(pool: *Pool, relay: *RelayHandle) void {
        defer {
            _ = pool.active_workers.fetchSub(1, .monotonic);
        }

        while (!relay.should_stop.load(.acquire)) {
            const message = relay.recv() catch |err| {
                if (err == error.EndOfStream) {
                    relay.setStatus(.disconnected);
                    break;
                }
                continue;
            };
            defer message.deinit();

            pool.handleMessage(message.payload, relay.url) catch continue;
        }
    }

    fn handleMessage(self: *Pool, payload: []const u8, relay_url: []const u8) !void {
        const msg = try RelayMsgParsed.parse(payload, self.allocator);

        if (msg.msg_type == .event) {
            if (self.parseEventFromMessage(payload)) |event_data| {
                var event = try Event.parseWithAllocator(event_data, self.allocator);
                defer event.deinit();

                // Atomic check-and-mark to avoid TOCTOU race
                if (!try self.tryMarkSeen(event.id())) {
                    return; // Already seen, skip
                }

                try self.message_queue.push(payload, relay_url);
            }
        } else {
            try self.message_queue.push(payload, relay_url);
        }
    }

    fn parseEventFromMessage(_: *Pool, payload: []const u8) ?[]const u8 {
        const event_start = std.mem.indexOf(u8, payload, ",{\"") orelse return null;
        const start = event_start + 1;

        var depth: usize = 0;
        var in_string = false;
        var escape_next = false;

        for (payload[start..], 0..) |c, i| {
            if (escape_next) {
                escape_next = false;
                continue;
            }

            if (c == '\\' and in_string) {
                escape_next = true;
                continue;
            }

            if (c == '"') {
                in_string = !in_string;
                continue;
            }

            if (!in_string) {
                if (c == '{') {
                    depth += 1;
                } else if (c == '}') {
                    if (depth == 1) {
                        return payload[start .. start + i + 1];
                    }
                    depth -= 1;
                }
            }
        }

        return null;
    }

    pub fn receive(self: *Pool) ?MessageQueue.QueuedMessage {
        return self.message_queue.pop();
    }

    pub fn receiveWithTimeout(self: *Pool, timeout_ns: u64) ?MessageQueue.QueuedMessage {
        return self.message_queue.popWithTimeout(timeout_ns);
    }

    pub fn freeMessage(self: *Pool, msg: MessageQueue.QueuedMessage) void {
        self.message_queue.freeMessage(msg);
    }

    fn isDuplicate(self: *Pool, event_id: *const [32]u8) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.seen_events.contains(event_id.*);
    }

    /// Atomically checks if event_id is already seen and marks it if not.
    /// Returns true if the event was NOT seen before (i.e., newly marked).
    /// Returns false if the event was already seen (duplicate).
    fn tryMarkSeen(self: *Pool, event_id: *const [32]u8) !bool {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Check if already seen
        if (self.seen_events.contains(event_id.*)) {
            return false; // Duplicate
        }

        // Evict oldest if at capacity
        if (self.seen_events.count() >= self.options.dedup_cache_size) {
            var oldest_key: ?[32]u8 = null;
            var oldest_time: i64 = std.math.maxInt(i64);

            var iter = self.seen_events.iterator();
            while (iter.next()) |entry| {
                if (entry.value_ptr.* < oldest_time) {
                    oldest_time = entry.value_ptr.*;
                    oldest_key = entry.key_ptr.*;
                }
            }

            if (oldest_key) |key| {
                _ = self.seen_events.remove(key);
            }
        }

        try self.seen_events.put(self.allocator, event_id.*, std.time.timestamp());
        return true; // Newly seen
    }

    fn markSeen(self: *Pool, event_id: *const [32]u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.seen_events.count() >= self.options.dedup_cache_size) {
            var oldest_key: ?[32]u8 = null;
            var oldest_time: i64 = std.math.maxInt(i64);

            var iter = self.seen_events.iterator();
            while (iter.next()) |entry| {
                if (entry.value_ptr.* < oldest_time) {
                    oldest_time = entry.value_ptr.*;
                    oldest_key = entry.key_ptr.*;
                }
            }

            if (oldest_key) |key| {
                _ = self.seen_events.remove(key);
            }
        }

        try self.seen_events.put(self.allocator, event_id.*, std.time.timestamp());
    }

    pub fn clearSeenEvents(self: *Pool) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.seen_events.clearRetainingCapacity();
    }

    pub fn seenCount(self: *Pool) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.seen_events.count();
    }

    /// Returns a snapshot of relay information. Caller must free the returned slice
    /// and each url/last_error string within it using freeRelayInfo.
    pub fn getRelays(self: *Pool) ![]RelayInfo {
        self.mutex.lock();
        defer self.mutex.unlock();

        var infos = try self.allocator.alloc(RelayInfo, self.relays.items.len);
        errdefer self.allocator.free(infos);

        for (self.relays.items, 0..) |*relay, i| {
            infos[i] = .{
                .url = try self.allocator.dupe(u8, relay.url),
                .status = relay.getStatus(),
                .last_error = if (relay.last_error) |err| try self.allocator.dupe(u8, err) else null,
            };
        }
        return infos;
    }

    pub fn freeRelayInfo(self: *Pool, infos: []RelayInfo) void {
        for (infos) |info| {
            self.allocator.free(info.url);
            if (info.last_error) |err| {
                self.allocator.free(err);
            }
        }
        self.allocator.free(infos);
    }

    pub fn queryParallel(
        self: *Pool,
        sub_id: []const u8,
        filters: []const Filter,
        timeout_ms: u64,
    ) ![]Event {
        try self.subscribe(sub_id, filters);
        defer self.unsubscribe(sub_id) catch {};

        var events = std.ArrayList(Event).init(self.allocator);
        errdefer {
            for (events.items) |*e| e.deinit();
            events.deinit();
        }

        const timeout_ns = timeout_ms * std.time.ns_per_ms;
        const deadline = std.time.nanoTimestamp() + @as(i128, timeout_ns);

        var eose_count: usize = 0;

        while (std.time.nanoTimestamp() < deadline) {
            // Dynamically check current connected count to handle disconnects
            const current_connected = self.connectedCount();
            if (current_connected == 0 or eose_count >= current_connected) break;

            const remaining: u64 = @intCast(@max(0, deadline - std.time.nanoTimestamp()));
            const msg = self.receiveWithTimeout(@min(remaining, 100 * std.time.ns_per_ms)) orelse continue;
            defer self.freeMessage(msg);

            const parsed = RelayMsgParsed.parse(msg.data, self.allocator) catch continue;

            if (parsed.msg_type == .eose) {
                eose_count += 1;
            } else if (parsed.msg_type == .event) {
                if (self.parseEventFromMessage(msg.data)) |event_data| {
                    const event = Event.parseWithAllocator(event_data, self.allocator) catch continue;
                    try events.append(event);
                }
            }
        }

        return events.toOwnedSlice();
    }
};

pub const RelayInfo = struct {
    url: []const u8,
    status: RelayStatus,
    last_error: ?[]const u8,
};

pub const PoolError = error{
    RelayAlreadyExists,
    RelayNotFound,
    TooManyRelays,
    NotConnected,
    AllRelaysFailed,
};

test "pool basic operations" {
    const allocator = std.testing.allocator;
    var pool = Pool.init(allocator);
    defer pool.deinit();

    try pool.addRelay("wss://relay1.example.com");
    try pool.addRelay("wss://relay2.example.com");

    try std.testing.expectEqual(@as(usize, 2), pool.relayCount());
    try std.testing.expectEqual(@as(usize, 0), pool.connectedCount());

    try std.testing.expectError(error.RelayAlreadyExists, pool.addRelay("wss://relay1.example.com"));

    try pool.removeRelay("wss://relay1.example.com");
    try std.testing.expectEqual(@as(usize, 1), pool.relayCount());
}

test "pool deduplication" {
    const allocator = std.testing.allocator;
    var pool = Pool.initWithOptions(allocator, .{ .dedup_cache_size = 3 });
    defer pool.deinit();

    var id1: [32]u8 = undefined;
    @memset(&id1, 0x01);
    var id2: [32]u8 = undefined;
    @memset(&id2, 0x02);
    var id3: [32]u8 = undefined;
    @memset(&id3, 0x03);

    try std.testing.expect(!pool.isDuplicate(&id1));
    try pool.markSeen(&id1);
    try std.testing.expect(pool.isDuplicate(&id1));

    try pool.markSeen(&id2);
    try pool.markSeen(&id3);
    try std.testing.expectEqual(@as(usize, 3), pool.seenCount());

    var id4: [32]u8 = undefined;
    @memset(&id4, 0x04);
    try pool.markSeen(&id4);
    try std.testing.expectEqual(@as(usize, 3), pool.seenCount());

    pool.clearSeenEvents();
    try std.testing.expectEqual(@as(usize, 0), pool.seenCount());
}

test "pool max relays limit" {
    const allocator = std.testing.allocator;
    var pool = Pool.initWithOptions(allocator, .{ .max_relays = 2 });
    defer pool.deinit();

    try pool.addRelay("wss://relay1.example.com");
    try pool.addRelay("wss://relay2.example.com");
    try std.testing.expectError(error.TooManyRelays, pool.addRelay("wss://relay3.example.com"));
}

test "relay handle lifecycle" {
    const allocator = std.testing.allocator;
    var handle = try RelayHandle.init(allocator, "wss://test.relay.com");
    defer handle.deinit();

    try std.testing.expectEqual(RelayStatus.disconnected, handle.getStatus());
    try std.testing.expectEqualStrings("wss://test.relay.com", handle.url);
}

test "pool relay status" {
    const allocator = std.testing.allocator;
    var pool = Pool.init(allocator);
    defer pool.deinit();

    try pool.addRelay("wss://relay.test.com");

    const status = pool.getRelayStatus("wss://relay.test.com");
    try std.testing.expect(status != null);
    try std.testing.expectEqual(RelayStatus.disconnected, status.?);

    try std.testing.expect(pool.getRelayStatus("wss://nonexistent.com") == null);
}

test "pool load balancing index" {
    const allocator = std.testing.allocator;
    var pool = Pool.init(allocator);
    defer pool.deinit();

    const idx1 = pool.next_relay_idx.fetchAdd(1, .monotonic);
    const idx2 = pool.next_relay_idx.fetchAdd(1, .monotonic);
    const idx3 = pool.next_relay_idx.fetchAdd(1, .monotonic);

    try std.testing.expectEqual(@as(usize, 0), idx1);
    try std.testing.expectEqual(@as(usize, 1), idx2);
    try std.testing.expectEqual(@as(usize, 2), idx3);
}

test "parse event from message" {
    const allocator = std.testing.allocator;
    var pool = Pool.init(allocator);
    defer pool.deinit();

    const msg =
        \\["EVENT","sub1",{"id":"abc","pubkey":"def","content":"test"}]
    ;

    const event_json = pool.parseEventFromMessage(msg);
    try std.testing.expect(event_json != null);
    try std.testing.expect(std.mem.startsWith(u8, event_json.?, "{\"id\":"));
    try std.testing.expect(std.mem.endsWith(u8, event_json.?, "}"));
}

test "parse event from message with nested objects" {
    const allocator = std.testing.allocator;
    var pool = Pool.init(allocator);
    defer pool.deinit();

    const msg =
        \\["EVENT","sub1",{"id":"abc","tags":[["e","123"],["p","456"]],"content":"{\"nested\":true}"}]
    ;

    const event_json = pool.parseEventFromMessage(msg);
    try std.testing.expect(event_json != null);
    try std.testing.expect(std.mem.indexOf(u8, event_json.?, "\"tags\":") != null);
}

test "pool message queue integration" {
    const allocator = std.testing.allocator;
    var pool = Pool.init(allocator);
    defer pool.deinit();

    try pool.message_queue.push("test message", "wss://test.relay");
    try std.testing.expectEqual(@as(usize, 1), pool.message_queue.size());

    const msg = pool.receive();
    try std.testing.expect(msg != null);
    pool.freeMessage(msg.?);

    try std.testing.expect(pool.receive() == null);
}
