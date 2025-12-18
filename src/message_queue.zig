const std = @import("std");

pub const MessageQueue = struct {
    allocator: std.mem.Allocator,
    messages: std.ArrayListUnmanaged(QueuedMessage),
    mutex: std.Thread.Mutex,
    condition: std.Thread.Condition,
    max_size: usize,

    pub const QueuedMessage = struct {
        data: []const u8,
        relay_url: []const u8,
        received_at: i64,
    };

    pub fn init(allocator: std.mem.Allocator) MessageQueue {
        return initWithCapacity(allocator, 1000);
    }

    pub fn initWithCapacity(allocator: std.mem.Allocator, max_size: usize) MessageQueue {
        return .{
            .allocator = allocator,
            .messages = .{},
            .mutex = .{},
            .condition = .{},
            .max_size = max_size,
        };
    }

    pub fn deinit(self: *MessageQueue) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.messages.items) |item| {
            self.allocator.free(item.data);
            self.allocator.free(item.relay_url);
        }
        self.messages.deinit(self.allocator);
    }

    pub fn push(self: *MessageQueue, data: []const u8, relay_url: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.messages.items.len >= self.max_size) {
            const oldest = self.messages.orderedRemove(0);
            self.allocator.free(oldest.data);
            self.allocator.free(oldest.relay_url);
        }

        const duped_data = try self.allocator.dupe(u8, data);
        errdefer self.allocator.free(duped_data);

        const duped_url = try self.allocator.dupe(u8, relay_url);
        errdefer self.allocator.free(duped_url);

        try self.messages.append(self.allocator, .{
            .data = duped_data,
            .relay_url = duped_url,
            .received_at = std.time.timestamp(),
        });
        self.condition.signal();
    }

    pub fn pop(self: *MessageQueue) ?QueuedMessage {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.messages.items.len == 0) {
            return null;
        }

        return self.messages.orderedRemove(0);
    }

    pub fn popWithTimeout(self: *MessageQueue, timeout_ns: u64) ?QueuedMessage {
        self.mutex.lock();
        defer self.mutex.unlock();

        const start_time = std.time.nanoTimestamp();

        while (self.messages.items.len == 0) {
            const now = std.time.nanoTimestamp();
            const elapsed: u64 = if (now > start_time) @intCast(now - start_time) else 0;
            if (elapsed >= timeout_ns) {
                return null;
            }

            const remaining = timeout_ns - elapsed;
            self.condition.timedWait(&self.mutex, remaining) catch {
                return null;
            };
        }

        return self.messages.orderedRemove(0);
    }

    pub fn isEmpty(self: *MessageQueue) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.messages.items.len == 0;
    }

    pub fn size(self: *MessageQueue) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.messages.items.len;
    }

    pub fn sortByTimestamp(self: *MessageQueue) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        std.mem.sort(QueuedMessage, self.messages.items, {}, struct {
            pub fn lessThan(_: void, a: QueuedMessage, b: QueuedMessage) bool {
                return a.received_at < b.received_at;
            }
        }.lessThan);
    }

    pub fn freeMessage(self: *MessageQueue, msg: QueuedMessage) void {
        self.allocator.free(msg.data);
        self.allocator.free(msg.relay_url);
    }

    pub fn clear(self: *MessageQueue) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.messages.items) |item| {
            self.allocator.free(item.data);
            self.allocator.free(item.relay_url);
        }
        self.messages.clearRetainingCapacity();
    }
};

test "basic push and pop" {
    const allocator = std.testing.allocator;
    var queue = MessageQueue.init(allocator);
    defer queue.deinit();

    try queue.push("test message", "wss://relay.example.com");
    try std.testing.expectEqual(@as(usize, 1), queue.size());
    try std.testing.expect(!queue.isEmpty());

    const msg = queue.pop().?;
    defer queue.freeMessage(msg);

    try std.testing.expectEqualStrings("test message", msg.data);
    try std.testing.expectEqualStrings("wss://relay.example.com", msg.relay_url);
    try std.testing.expect(queue.isEmpty());
}

test "pop returns null when empty" {
    const allocator = std.testing.allocator;
    var queue = MessageQueue.init(allocator);
    defer queue.deinit();

    try std.testing.expect(queue.pop() == null);
}

test "max size drops oldest" {
    const allocator = std.testing.allocator;
    var queue = MessageQueue.initWithCapacity(allocator, 2);
    defer queue.deinit();

    try queue.push("first", "relay1");
    try queue.push("second", "relay2");
    try queue.push("third", "relay3");

    try std.testing.expectEqual(@as(usize, 2), queue.size());

    const msg1 = queue.pop().?;
    defer queue.freeMessage(msg1);
    try std.testing.expectEqualStrings("second", msg1.data);

    const msg2 = queue.pop().?;
    defer queue.freeMessage(msg2);
    try std.testing.expectEqualStrings("third", msg2.data);
}

test "sort by timestamp" {
    const allocator = std.testing.allocator;
    var queue = MessageQueue.init(allocator);
    defer queue.deinit();

    try queue.push("msg1", "relay1");
    std.Thread.sleep(1_000_000);
    try queue.push("msg2", "relay2");
    std.Thread.sleep(1_000_000);
    try queue.push("msg3", "relay3");

    queue.sortByTimestamp();

    const m1 = queue.pop().?;
    defer queue.freeMessage(m1);
    const m2 = queue.pop().?;
    defer queue.freeMessage(m2);
    const m3 = queue.pop().?;
    defer queue.freeMessage(m3);

    try std.testing.expect(m1.received_at <= m2.received_at);
    try std.testing.expect(m2.received_at <= m3.received_at);
}

test "clear empties queue" {
    const allocator = std.testing.allocator;
    var queue = MessageQueue.init(allocator);
    defer queue.deinit();

    try queue.push("msg1", "relay1");
    try queue.push("msg2", "relay2");
    try std.testing.expectEqual(@as(usize, 2), queue.size());

    queue.clear();
    try std.testing.expect(queue.isEmpty());
}

test "popWithTimeout returns null on timeout" {
    const allocator = std.testing.allocator;
    var queue = MessageQueue.init(allocator);
    defer queue.deinit();

    const result = queue.popWithTimeout(1_000_000);
    try std.testing.expect(result == null);
}

test "thread safety - concurrent push" {
    const allocator = std.testing.allocator;
    var queue = MessageQueue.init(allocator);
    defer queue.deinit();

    const num_threads = 4;
    const msgs_per_thread = 100;

    var threads: [num_threads]std.Thread = undefined;

    for (0..num_threads) |i| {
        threads[i] = try std.Thread.spawn(.{}, struct {
            fn run(q: *MessageQueue, thread_id: usize) void {
                for (0..msgs_per_thread) |_| {
                    var buf: [32]u8 = undefined;
                    const msg = std.fmt.bufPrint(&buf, "thread_{d}", .{thread_id}) catch unreachable;
                    q.push(msg, "relay") catch {};
                }
            }
        }.run, .{ &queue, i });
    }

    for (&threads) |*t| {
        t.join();
    }

    try std.testing.expectEqual(num_threads * msgs_per_thread, queue.size());
}

test "thread safety - concurrent push and pop" {
    const allocator = std.testing.allocator;
    var queue = MessageQueue.init(allocator);
    defer queue.deinit();

    var producer_done = std.atomic.Value(bool).init(false);
    var consumed = std.atomic.Value(usize).init(0);

    const producer = try std.Thread.spawn(.{}, struct {
        fn run(q: *MessageQueue, done: *std.atomic.Value(bool)) void {
            for (0..50) |i| {
                var buf: [32]u8 = undefined;
                const msg = std.fmt.bufPrint(&buf, "msg_{d}", .{i}) catch unreachable;
                q.push(msg, "relay") catch {};
                std.Thread.sleep(100_000);
            }
            done.store(true, .release);
            q.mutex.lock();
            q.condition.broadcast();
            q.mutex.unlock();
        }
    }.run, .{ &queue, &producer_done });

    const consumer = try std.Thread.spawn(.{}, struct {
        fn run(q: *MessageQueue, done: *std.atomic.Value(bool), count: *std.atomic.Value(usize)) void {
            while (!done.load(.acquire) or q.size() > 0) {
                if (q.popWithTimeout(10_000_000)) |msg| {
                    q.freeMessage(msg);
                    _ = count.fetchAdd(1, .monotonic);
                }
            }
        }
    }.run, .{ &queue, &producer_done, &consumed });

    producer.join();
    consumer.join();

    try std.testing.expectEqual(@as(usize, 50), consumed.load(.acquire));
}
