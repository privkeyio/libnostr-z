//! NIP-77 negentropy relay-to-relay sync driver.

const std = @import("std");
const ws = @import("ws/ws.zig");
const negentropy = @import("negentropy.zig");
const messages = @import("messages.zig");
const Filter = @import("filter.zig").Filter;

const SUB_ID = "noz-sync";
const FRAME_LIMIT: u64 = 60000;
const BUF = 131072;
const FETCH_BATCH = 200;
const MAX_ROUNDS = 1024;
const MAX_NEED = 500_000;

pub const SyncError = error{NegProtocolError};

/// Reconcile `filter`'s events from `src_url` into `dst_url`. Starting from an
/// empty local set, every event the source holds surfaces as a "need" during
/// reconciliation; those are fetched from the source and published to the
/// destination. Returns the number of events published.
///
/// The source is drained fully into memory before any publish to the
/// destination, so a slow destination cannot stall the source read (and the
/// source's negentropy/subscription deadlines cannot drop unread events).
pub fn syncRelays(
    allocator: std.mem.Allocator,
    src_url: []const u8,
    dst_url: []const u8,
    filter: *const Filter,
) !usize {
    var src = try ws.connect(allocator, src_url);
    defer src.close();

    var storage = negentropy.VectorStorage.init(allocator);
    defer storage.deinit();
    storage.seal();
    var neg = negentropy.Negentropy.init(storage.storage(), FRAME_LIMIT);

    var work: [BUF]u8 = undefined;
    var out_buf: [BUF]u8 = undefined;
    var query_buf: [BUF]u8 = undefined;

    const initial = try neg.initiate(&out_buf);
    try src.sendText(try messages.ClientMsg.negOpenMsg(SUB_ID, filter, initial, &work));

    var need: std.ArrayListUnmanaged([32]u8) = .empty;
    defer need.deinit(allocator);

    var rounds: usize = 0;
    while (true) {
        rounds += 1;
        if (rounds > MAX_ROUNDS) return SyncError.NegProtocolError;

        var msg = try src.recvMessage();
        defer msg.deinit();

        const verb = firstQuoted(msg.payload) orelse continue;
        if (std.mem.eql(u8, verb, "NEG-ERR")) return SyncError.NegProtocolError;
        if (!std.mem.eql(u8, verb, "NEG-MSG")) continue;

        var cm = messages.ClientMsg.parseWithAllocator(msg.payload, allocator) catch return SyncError.NegProtocolError;
        defer cm.deinit();
        if (cm.msg_type != .neg_msg) continue;
        const query = cm.getNegPayload(&query_buf) catch return SyncError.NegProtocolError;

        var result = try neg.reconcile(query, &out_buf, allocator);
        defer result.deinit();
        try need.appendSlice(allocator, result.need_ids.items);
        if (need.items.len > MAX_NEED) return SyncError.NegProtocolError;

        if (result.done) break;
        try src.sendText(try messages.ClientMsg.negMsg(SUB_ID, result.output, &work));
    }

    try src.sendText(try messages.ClientMsg.negCloseMsg(SUB_ID, &work));

    // Drain the needed events from src fully, then publish to dst.
    var events: std.ArrayListUnmanaged([]const u8) = .empty;
    defer {
        for (events.items) |e| allocator.free(e);
        events.deinit(allocator);
    }
    try fetchByIds(allocator, &src, need.items, &events);

    var dst = try ws.connect(allocator, dst_url);
    defer dst.close();

    var published: usize = 0;
    for (events.items) |ev| {
        var pbuf: [BUF]u8 = undefined;
        const m = std.fmt.bufPrint(&pbuf, "[\"EVENT\",{s}]", .{ev}) catch continue;
        dst.sendText(m) catch continue;
        var ok = dst.recvMessage() catch continue;
        defer ok.deinit();
        const parsed = messages.RelayMsgParsed.parse(ok.payload, allocator) catch continue;
        if (parsed.msg_type == .ok and parsed.success) published += 1;
    }
    return published;
}

fn fetchByIds(
    allocator: std.mem.Allocator,
    src: *ws.Client,
    ids: [][32]u8,
    out: *std.ArrayListUnmanaged([]const u8),
) !void {
    var i: usize = 0;
    while (i < ids.len) : (i += FETCH_BATCH) {
        const end = @min(i + FETCH_BATCH, ids.len);
        const batch = ids[i..end];

        var req_buf: [BUF]u8 = undefined;
        const f = Filter{ .allocator = allocator, .ids_bytes = batch };
        try src.sendText(try messages.ClientMsg.reqMsg("noz-fetch", &.{f}, &req_buf));

        var frames: usize = 0;
        while (true) {
            frames += 1;
            if (frames > FETCH_BATCH * 4) return SyncError.NegProtocolError;
            var msg = try src.recvMessage();
            defer msg.deinit();
            const verb = firstQuoted(msg.payload) orelse continue;
            if (std.mem.eql(u8, verb, "EVENT")) {
                if (out.items.len < ids.len) {
                    if (eventObject(msg.payload)) |obj| {
                        try out.append(allocator, try allocator.dupe(u8, obj));
                    }
                }
            } else if (std.mem.eql(u8, verb, "EOSE") or std.mem.eql(u8, verb, "CLOSED")) {
                break;
            }
        }

        if (messages.ClientMsg.closeMsg("noz-fetch", &req_buf)) |close| {
            src.sendText(close) catch {};
        } else |_| {}
    }
}

// The first quoted string in a relay message array, i.e. the verb. Negentropy
// payloads and sub ids contain no escaped quotes, so a plain scan is enough.
fn firstQuoted(s: []const u8) ?[]const u8 {
    const open = std.mem.indexOfScalar(u8, s, '"') orelse return null;
    const close = std.mem.indexOfScalarPos(u8, s, open + 1, '"') orelse return null;
    return s[open + 1 .. close];
}

// The event object out of ["EVENT","sub",{...}]: the outermost {...}, so first
// brace to last brace is exact even when content contains braces.
fn eventObject(s: []const u8) ?[]const u8 {
    const start = std.mem.indexOfScalar(u8, s, '{') orelse return null;
    const stop = std.mem.lastIndexOfScalar(u8, s, '}') orelse return null;
    if (stop < start) return null;
    return s[start .. stop + 1];
}

test firstQuoted {
    const m = "[\"NEG-MSG\",\"sub\",\"61abcd\"]";
    try std.testing.expectEqualStrings("NEG-MSG", firstQuoted(m).?);
}

test eventObject {
    const m = "[\"EVENT\",\"s\",{\"id\":\"x\",\"content\":\"a}b\"}]";
    try std.testing.expectEqualStrings("{\"id\":\"x\",\"content\":\"a}b\"}", eventObject(m).?);
}
