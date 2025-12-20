const std = @import("std");
const Allocator = std.mem.Allocator;
const ws = @import("ws/ws.zig");
const messages = @import("messages.zig");
const filter_mod = @import("filter.zig");
const event_mod = @import("event.zig");

pub const Filter = filter_mod.Filter;
pub const Event = event_mod.Event;
pub const RelayMsgType = messages.RelayMsgType;

pub const ConnectionState = enum {
    disconnected,
    connecting,
    connected,
    reconnecting,
};

pub const RelayError = error{
    NotConnected,
    ConnectionFailed,
    SendFailed,
    SubscriptionNotFound,
    MaxSubscriptionsReached,
    InvalidMessage,
    Timeout,
    AlreadyConnected,
};

pub const RelayMessage = struct {
    msg_type: RelayMsgType,
    subscription_id: ?[]const u8,
    event: ?Event,
    success: bool,
    message: ?[]const u8,
    count: ?u64,
    raw: []const u8,
    allocator: Allocator,

    pub fn deinit(self: *RelayMessage) void {
        if (self.subscription_id) |s| self.allocator.free(s);
        if (self.event) |*e| {
            var ev = e.*;
            ev.deinit();
        }
        if (self.message) |m| self.allocator.free(m);
        self.allocator.free(self.raw);
    }
};

pub const Subscription = struct {
    id: []const u8,
    filters: []Filter,
    eose_received: bool,
    created_at: i64,
    event_count: u64,
    allocator: Allocator,

    pub fn deinit(self: *Subscription) void {
        self.allocator.free(self.id);
        for (self.filters) |*f| {
            var filter = f.*;
            filter.deinit();
        }
        self.allocator.free(self.filters);
    }
};

pub const RelayConfig = struct {
    auto_reconnect: bool = true,
    reconnect_base_delay_ms: u32 = 1000,
    reconnect_max_delay_ms: u32 = 60000,
    reconnect_max_attempts: u32 = 0,
    ping_interval_ms: u32 = 30000,
    pong_timeout_ms: u32 = 10000,
    read_timeout_ms: u32 = 60000,
    max_subscriptions: u16 = 100,
};

pub const Relay = struct {
    allocator: Allocator,
    url: []const u8,
    config: RelayConfig,
    state: ConnectionState,
    client: ?ws.Client,
    subscriptions: std.StringHashMap(Subscription),
    reconnect_attempts: u32,
    last_message_time: i64,
    last_ping_time: i64,
    awaiting_pong: bool,
    mutex: std.Thread.Mutex,

    const Self = @This();

    pub fn init(allocator: Allocator, url: []const u8, config: RelayConfig) !Self {
        const url_copy = try allocator.dupe(u8, url);
        return Self{
            .allocator = allocator,
            .url = url_copy,
            .config = config,
            .state = .disconnected,
            .client = null,
            .subscriptions = std.StringHashMap(Subscription).init(allocator),
            .reconnect_attempts = 0,
            .last_message_time = 0,
            .last_ping_time = 0,
            .awaiting_pong = false,
            .mutex = .{},
        };
    }

    pub fn deinit(self: *Self) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        self.closeInternal();
        var iter = self.subscriptions.iterator();
        while (iter.next()) |entry| {
            var sub = entry.value_ptr.*;
            sub.deinit();
        }
        self.subscriptions.deinit();
        self.allocator.free(self.url);
    }

    pub fn connect(self: *Self) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.state == .connected) return RelayError.AlreadyConnected;

        self.state = .connecting;
        errdefer self.state = .disconnected;

        self.client = ws.Client.connect(self.allocator, self.url) catch |err| {
            self.state = .disconnected;
            return switch (err) {
                else => RelayError.ConnectionFailed,
            };
        };

        self.state = .connected;
        self.reconnect_attempts = 0;
        self.last_message_time = std.time.timestamp();
        self.last_ping_time = 0;
        self.awaiting_pong = false;
    }

    pub fn disconnect(self: *Self) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.closeInternal();
    }

    fn closeInternal(self: *Self) void {
        if (self.client) |*c| {
            c.close();
            self.client = null;
        }
        self.state = .disconnected;
    }

    pub fn reconnect(self: *Self) !void {
        self.mutex.lock();
        const config = self.config;
        const current_attempts = self.reconnect_attempts;
        self.mutex.unlock();

        if (!config.auto_reconnect) return RelayError.ConnectionFailed;
        if (config.reconnect_max_attempts > 0 and current_attempts >= config.reconnect_max_attempts) {
            return RelayError.ConnectionFailed;
        }

        self.mutex.lock();
        self.state = .reconnecting;
        self.reconnect_attempts += 1;
        if (self.client) |*c| {
            c.close();
            self.client = null;
        }
        self.mutex.unlock();

        const delay = calculateBackoff(config.reconnect_base_delay_ms, config.reconnect_max_delay_ms, current_attempts);
        std.time.sleep(delay * std.time.ns_per_ms);

        self.mutex.lock();
        if (self.state != .reconnecting) {
            self.mutex.unlock();
            return;
        }
        self.mutex.unlock();

        self.connect() catch {
            return self.reconnect();
        };

        self.resubscribeAll();
    }

    fn resubscribeAll(self: *Self) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        var iter = self.subscriptions.iterator();
        while (iter.next()) |entry| {
            const sub = entry.value_ptr.*;
            var buf: [8192]u8 = undefined;
            const msg = messages.ClientMsg.reqMsg(sub.id, sub.filters, &buf) catch continue;
            if (self.client) |*c| {
                c.sendText(msg) catch continue;
            }
        }
    }

    pub fn subscribe(self: *Self, sub_id: []const u8, filters: []const Filter) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.state != .connected) return RelayError.NotConnected;
        if (self.subscriptions.count() >= self.config.max_subscriptions) {
            return RelayError.MaxSubscriptionsReached;
        }

        const id_copy = try self.allocator.dupe(u8, sub_id);
        errdefer self.allocator.free(id_copy);

        var filters_copy = try self.allocator.alloc(Filter, filters.len);
        errdefer self.allocator.free(filters_copy);
        var copied: usize = 0;
        errdefer {
            for (filters_copy[0..copied]) |*f| {
                var filter = f.*;
                filter.deinit();
            }
        }

        for (filters, 0..) |f, i| {
            filters_copy[i] = try f.clone(self.allocator);
            copied += 1;
        }

        var buf: [8192]u8 = undefined;
        const msg = try messages.ClientMsg.reqMsg(sub_id, filters, &buf);

        if (self.client) |*c| {
            c.sendText(msg) catch return RelayError.SendFailed;
        } else {
            return RelayError.NotConnected;
        }

        try self.subscriptions.put(id_copy, .{
            .id = id_copy,
            .filters = filters_copy,
            .eose_received = false,
            .created_at = std.time.timestamp(),
            .event_count = 0,
            .allocator = self.allocator,
        });
    }

    pub fn unsubscribe(self: *Self, sub_id: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.state != .connected) return RelayError.NotConnected;

        var buf: [256]u8 = undefined;
        const msg = try messages.ClientMsg.closeMsg(sub_id, &buf);

        if (self.client) |*c| {
            c.sendText(msg) catch return RelayError.SendFailed;
        }

        if (self.subscriptions.fetchRemove(sub_id)) |kv| {
            var sub = kv.value;
            sub.deinit();
        }
    }

    pub fn publish(self: *Self, event: *const Event) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.state != .connected) return RelayError.NotConnected;

        var buf: [65536]u8 = undefined;
        const msg = try messages.ClientMsg.eventMsg(event, &buf);

        if (self.client) |*c| {
            c.sendText(msg) catch return RelayError.SendFailed;
        } else {
            return RelayError.NotConnected;
        }
    }

    pub fn receive(self: *Self) !?RelayMessage {
        self.mutex.lock();
        if (self.state != .connected or self.client == null) {
            self.mutex.unlock();
            return RelayError.NotConnected;
        }
        const client_ptr = &self.client.?;
        self.mutex.unlock();

        const ws_msg = client_ptr.recvMessage() catch |err| {
            switch (err) {
                error.EndOfStream, error.ConnectionResetByPeer => {
                    self.mutex.lock();
                    self.state = .disconnected;
                    self.client = null;
                    self.mutex.unlock();
                    if (self.config.auto_reconnect) {
                        self.reconnect() catch {};
                    }
                    return null;
                },
                else => return null,
            }
        };
        defer ws_msg.deinit();

        self.mutex.lock();
        self.last_message_time = std.time.timestamp();
        self.awaiting_pong = false;
        self.mutex.unlock();

        return self.parseRelayMessage(ws_msg.payload);
    }

    fn parseRelayMessage(self: *Self, payload: []const u8) !RelayMessage {
        const raw_copy = try self.allocator.dupe(u8, payload);
        errdefer self.allocator.free(raw_copy);

        const parsed = messages.RelayMsgParsed.parse(payload, self.allocator) catch {
            return .{
                .msg_type = .unknown,
                .subscription_id = null,
                .event = null,
                .success = false,
                .message = null,
                .count = null,
                .raw = raw_copy,
                .allocator = self.allocator,
            };
        };

        var sub_id: ?[]const u8 = null;
        errdefer if (sub_id) |s| self.allocator.free(s);

        var event_obj: ?Event = null;
        errdefer if (event_obj) |*e| {
            var ev = e.*;
            ev.deinit();
        };

        var msg_text: ?[]const u8 = null;
        errdefer if (msg_text) |m| self.allocator.free(m);

        const json_parsed = std.json.parseFromSlice(std.json.Value, self.allocator, payload, .{}) catch {
            return .{
                .msg_type = parsed.msg_type,
                .subscription_id = null,
                .event = null,
                .success = parsed.success,
                .message = null,
                .count = parsed.count_val,
                .raw = raw_copy,
                .allocator = self.allocator,
            };
        };
        defer json_parsed.deinit();

        if (json_parsed.value == .array and json_parsed.value.array.items.len > 1) {
            const arr = json_parsed.value.array.items;
            if (arr[1] == .string) {
                sub_id = try self.allocator.dupe(u8, arr[1].string);
            }

            if (parsed.msg_type == .event and arr.len > 2) {
                if (findEventJson(payload)) |event_json| {
                    event_obj = Event.parseWithAllocator(event_json, self.allocator) catch null;
                }

                if (sub_id) |sid| {
                    self.mutex.lock();
                    if (self.subscriptions.getPtr(sid)) |sub| {
                        sub.event_count += 1;
                    }
                    self.mutex.unlock();
                }
            }

            if (parsed.msg_type == .eose) {
                if (sub_id) |sid| {
                    self.mutex.lock();
                    if (self.subscriptions.getPtr(sid)) |sub| {
                        sub.eose_received = true;
                    }
                    self.mutex.unlock();
                }
            }

            if (parsed.msg_type == .closed and arr.len > 2 and arr[2] == .string) {
                msg_text = try self.allocator.dupe(u8, arr[2].string);
                if (sub_id) |sid| {
                    self.mutex.lock();
                    if (self.subscriptions.fetchRemove(sid)) |kv| {
                        var sub = kv.value;
                        sub.deinit();
                    }
                    self.mutex.unlock();
                }
            }

            if (parsed.msg_type == .ok and arr.len > 3 and arr[3] == .string) {
                msg_text = try self.allocator.dupe(u8, arr[3].string);
            }

            if (parsed.msg_type == .notice and arr.len > 1 and arr[1] == .string) {
                if (sub_id) |s| self.allocator.free(s);
                sub_id = null;
                msg_text = try self.allocator.dupe(u8, arr[1].string);
            }
        }

        return .{
            .msg_type = parsed.msg_type,
            .subscription_id = sub_id,
            .event = event_obj,
            .success = parsed.success,
            .message = msg_text,
            .count = parsed.count_val,
            .raw = raw_copy,
            .allocator = self.allocator,
        };
    }

    pub fn sendPing(self: *Self) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.state != .connected) return RelayError.NotConnected;
        if (self.client) |*c| {
            const Frame = @import("ws/frame.zig").Frame;
            const frame = Frame{ .fin = 1, .opcode = .ping, .payload = "", .mask = 1 };
            const buf = try self.allocator.alloc(u8, frame.encodedLen());
            defer self.allocator.free(buf);
            _ = frame.encode(buf, 0);
            c.writeAll(buf) catch return RelayError.SendFailed;
            self.last_ping_time = std.time.timestamp();
            self.awaiting_pong = true;
        }
    }

    pub fn checkTimeouts(self: *Self) !void {
        self.mutex.lock();
        const now = std.time.timestamp();
        const last_msg = self.last_message_time;
        const last_ping = self.last_ping_time;
        const awaiting = self.awaiting_pong;
        const config = self.config;
        const state = self.state;
        self.mutex.unlock();

        if (state != .connected) return;

        if (awaiting) {
            const pong_timeout_sec = @as(i64, @intCast(config.pong_timeout_ms)) / 1000;
            if (now - last_ping > pong_timeout_sec) {
                self.mutex.lock();
                self.state = .disconnected;
                if (self.client) |*c| {
                    c.close();
                    self.client = null;
                }
                self.mutex.unlock();
                if (config.auto_reconnect) {
                    try self.reconnect();
                }
                return;
            }
        }

        const ping_interval_sec = @as(i64, @intCast(config.ping_interval_ms)) / 1000;
        if (now - last_msg > ping_interval_sec and !awaiting) {
            self.sendPing() catch {};
        }
    }

    pub fn getState(self: *Self) ConnectionState {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.state;
    }

    pub fn isConnected(self: *Self) bool {
        return self.getState() == .connected;
    }

    pub fn getSubscription(self: *Self, sub_id: []const u8) ?Subscription {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.subscriptions.get(sub_id);
    }

    pub fn getSubscriptionCount(self: *Self) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.subscriptions.count();
    }

    pub fn hasSubscription(self: *Self, sub_id: []const u8) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.subscriptions.contains(sub_id);
    }

    pub fn isEoseReceived(self: *Self, sub_id: []const u8) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.subscriptions.get(sub_id)) |sub| {
            return sub.eose_received;
        }
        return false;
    }

    pub fn getUrl(self: *const Self) []const u8 {
        return self.url;
    }
};

fn calculateBackoff(base_ms: u32, max_ms: u32, attempt: u32) u64 {
    const capped_attempt = @min(attempt, 10);
    const multiplier = @as(u64, 1) << @intCast(capped_attempt);
    const delay = @min(@as(u64, base_ms) * multiplier, max_ms);
    return delay;
}

fn findEventJson(payload: []const u8) ?[]const u8 {
    var depth: usize = 0;
    var in_string = false;
    var escape_next = false;
    var event_start: ?usize = null;
    var found_first_bracket = false;
    var found_sub_id = false;

    for (payload, 0..) |c, i| {
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

        if (in_string) continue;

        if (c == '[') {
            if (!found_first_bracket) {
                found_first_bracket = true;
                continue;
            }
        }

        if (c == '{') {
            if (found_first_bracket and found_sub_id and event_start == null) {
                event_start = i;
            }
            depth += 1;
        } else if (c == '}') {
            if (depth > 0) depth -= 1;
            if (event_start != null and depth == 0) {
                return payload[event_start.?..i + 1];
            }
        } else if (c == ',' and found_first_bracket and !found_sub_id) {
            found_sub_id = true;
        }
    }

    return null;
}

test "calculateBackoff" {
    try std.testing.expectEqual(@as(u64, 1000), calculateBackoff(1000, 60000, 0));
    try std.testing.expectEqual(@as(u64, 2000), calculateBackoff(1000, 60000, 1));
    try std.testing.expectEqual(@as(u64, 4000), calculateBackoff(1000, 60000, 2));
    try std.testing.expectEqual(@as(u64, 8000), calculateBackoff(1000, 60000, 3));
    try std.testing.expectEqual(@as(u64, 60000), calculateBackoff(1000, 60000, 10));
    try std.testing.expectEqual(@as(u64, 60000), calculateBackoff(1000, 60000, 20));
}

test "findEventJson" {
    const payload1 =
        \\["EVENT","sub1",{"id":"abc","content":"test"}]
    ;
    const result1 = findEventJson(payload1);
    try std.testing.expect(result1 != null);
    try std.testing.expectEqualStrings("{\"id\":\"abc\",\"content\":\"test\"}", result1.?);

    const payload2 =
        \\["EOSE","sub1"]
    ;
    try std.testing.expect(findEventJson(payload2) == null);

    const payload3 =
        \\["EVENT","sub1",{"content":"nested {\"key\": \"value\"}"}]
    ;
    const result3 = findEventJson(payload3);
    try std.testing.expect(result3 != null);
}

test "RelayConfig defaults" {
    const config = RelayConfig{};
    try std.testing.expect(config.auto_reconnect);
    try std.testing.expectEqual(@as(u32, 1000), config.reconnect_base_delay_ms);
    try std.testing.expectEqual(@as(u32, 60000), config.reconnect_max_delay_ms);
    try std.testing.expectEqual(@as(u32, 30000), config.ping_interval_ms);
}

test "Relay init and deinit" {
    const allocator = std.testing.allocator;
    var relay = try Relay.init(allocator, "wss://relay.example.com", .{});
    defer relay.deinit();

    try std.testing.expectEqualStrings("wss://relay.example.com", relay.getUrl());
    try std.testing.expectEqual(ConnectionState.disconnected, relay.getState());
    try std.testing.expect(!relay.isConnected());
    try std.testing.expectEqual(@as(usize, 0), relay.getSubscriptionCount());
}

test "RelayConfig custom values" {
    const config = RelayConfig{
        .auto_reconnect = false,
        .reconnect_base_delay_ms = 500,
        .reconnect_max_delay_ms = 30000,
        .reconnect_max_attempts = 5,
        .ping_interval_ms = 15000,
        .pong_timeout_ms = 5000,
        .read_timeout_ms = 30000,
        .max_subscriptions = 50,
    };

    try std.testing.expect(!config.auto_reconnect);
    try std.testing.expectEqual(@as(u32, 500), config.reconnect_base_delay_ms);
    try std.testing.expectEqual(@as(u32, 5), config.reconnect_max_attempts);
    try std.testing.expectEqual(@as(u16, 50), config.max_subscriptions);
}

test "Relay operations when disconnected" {
    const allocator = std.testing.allocator;
    var relay = try Relay.init(allocator, "wss://relay.example.com", .{});
    defer relay.deinit();

    var filters = [_]Filter{.{}};
    try std.testing.expectError(RelayError.NotConnected, relay.subscribe("sub1", &filters));
    try std.testing.expectError(RelayError.NotConnected, relay.unsubscribe("sub1"));
}

test "Subscription struct" {
    const allocator = std.testing.allocator;

    const id = try allocator.dupe(u8, "test-sub");
    var filters = try allocator.alloc(Filter, 1);
    filters[0] = .{ .allocator = allocator };

    var sub = Subscription{
        .id = id,
        .filters = filters,
        .eose_received = false,
        .created_at = 1700000000,
        .event_count = 0,
        .allocator = allocator,
    };
    defer sub.deinit();

    try std.testing.expectEqualStrings("test-sub", sub.id);
    try std.testing.expect(!sub.eose_received);
    try std.testing.expectEqual(@as(u64, 0), sub.event_count);
}

test "RelayMessage deinit" {
    const allocator = std.testing.allocator;

    const raw = try allocator.dupe(u8, "test");
    const sub_id = try allocator.dupe(u8, "sub1");
    const msg_text = try allocator.dupe(u8, "message");

    var msg = RelayMessage{
        .msg_type = .ok,
        .subscription_id = sub_id,
        .event = null,
        .success = true,
        .message = msg_text,
        .count = null,
        .raw = raw,
        .allocator = allocator,
    };
    defer msg.deinit();

    try std.testing.expectEqual(RelayMsgType.ok, msg.msg_type);
    try std.testing.expect(msg.success);
}

test "ConnectionState enum" {
    try std.testing.expect(ConnectionState.disconnected != ConnectionState.connected);
    try std.testing.expect(ConnectionState.connecting != ConnectionState.reconnecting);
}

test "calculateBackoff edge cases" {
    try std.testing.expectEqual(@as(u64, 500), calculateBackoff(500, 60000, 0));
    try std.testing.expectEqual(@as(u64, 100), calculateBackoff(100, 100, 5));
    try std.testing.expectEqual(@as(u64, 1), calculateBackoff(1, 1000, 0));
}

test "findEventJson with complex nested content" {
    const payload =
        \\["EVENT","sub1",{"id":"abc","content":"{\"nested\":{\"deep\":true}}","kind":1}]
    ;
    const result = findEventJson(payload);
    try std.testing.expect(result != null);
    try std.testing.expect(std.mem.indexOf(u8, result.?, "\"id\":\"abc\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.?, "\"kind\":1") != null);
}

test "findEventJson with escaped quotes" {
    const payload =
        \\["EVENT","sub1",{"content":"he said \"hello\""}]
    ;
    const result = findEventJson(payload);
    try std.testing.expect(result != null);
}
