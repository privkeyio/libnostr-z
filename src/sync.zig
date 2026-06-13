//! NIP-77 negentropy relay-to-relay sync driver.

const std = @import("std");
const ws = @import("ws/ws.zig");
const negentropy = @import("negentropy.zig");
const messages = @import("messages.zig");
const Filter = @import("filter.zig").Filter;
const hex = @import("hex.zig");

const SUB_ID = "noz-sync";
const FRAME_LIMIT: u64 = 60000;
const BUF = 131072;
const FETCH_BATCH = 200;

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

    while (true) {
        var msg = try src.recvMessage();
        defer msg.deinit();

        const verb = firstQuoted(msg.payload) orelse continue;
        if (std.mem.eql(u8, verb, "NEG-ERR")) return SyncError.NegProtocolError;
        if (!std.mem.eql(u8, verb, "NEG-MSG")) continue;

        const neg_hex = nthQuoted(msg.payload, 3) orelse continue;
        const qlen = neg_hex.len / 2;
        if (qlen > query_buf.len) return SyncError.NegProtocolError;
        hex.decode(neg_hex, query_buf[0..qlen]) catch return SyncError.NegProtocolError;

        var result = try neg.reconcile(query_buf[0..qlen], &out_buf, allocator);
        defer result.deinit();
        try need.appendSlice(allocator, result.need_ids.items);

        if (result.done or result.output.len == 0) break;
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
        var ok = dst.recvMessage() catch {
            published += 1;
            continue;
        };
        ok.deinit();
        published += 1;
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

        while (true) {
            var msg = try src.recvMessage();
            defer msg.deinit();
            const verb = firstQuoted(msg.payload) orelse continue;
            if (std.mem.eql(u8, verb, "EVENT")) {
                if (eventObject(msg.payload)) |obj| {
                    try out.append(allocator, try allocator.dupe(u8, obj));
                }
            } else if (std.mem.eql(u8, verb, "EOSE") or std.mem.eql(u8, verb, "CLOSED")) {
                break;
            }
        }
    }
}

// The first quoted string in a relay message array, i.e. the verb. Negentropy
// payloads and sub ids contain no escaped quotes, so a plain scan is enough.
fn firstQuoted(s: []const u8) ?[]const u8 {
    return nthQuoted(s, 1);
}

fn nthQuoted(s: []const u8, n: usize) ?[]const u8 {
    var pos: usize = 0;
    var count: usize = 0;
    while (true) {
        const a = std.mem.indexOfScalarPos(u8, s, pos, '"') orelse return null;
        const b = std.mem.indexOfScalarPos(u8, s, a + 1, '"') orelse return null;
        count += 1;
        if (count == n) return s[a + 1 .. b];
        pos = b + 1;
    }
}

// The event object out of ["EVENT","sub",{...}]: the outermost {...}, so first
// brace to last brace is exact even when content contains braces.
fn eventObject(s: []const u8) ?[]const u8 {
    const start = std.mem.indexOfScalar(u8, s, '{') orelse return null;
    const stop = std.mem.lastIndexOfScalar(u8, s, '}') orelse return null;
    if (stop < start) return null;
    return s[start .. stop + 1];
}

test nthQuoted {
    const m = "[\"NEG-MSG\",\"sub\",\"61abcd\"]";
    try std.testing.expectEqualStrings("NEG-MSG", firstQuoted(m).?);
    try std.testing.expectEqualStrings("61abcd", nthQuoted(m, 3).?);
}

test eventObject {
    const m = "[\"EVENT\",\"s\",{\"id\":\"x\",\"content\":\"a}b\"}]";
    try std.testing.expectEqualStrings("{\"id\":\"x\",\"content\":\"a}b\"}", eventObject(m).?);
}
