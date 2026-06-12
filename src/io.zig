const std = @import("std");

var threaded: std.Io.Threaded = undefined;
var io_val: std.Io = undefined;
var ready = std.atomic.Value(bool).init(false);
var initializing = std.atomic.Value(bool).init(false);

/// Lazily-initialized process-global blocking Io for time/random.
pub fn io() std.Io {
    if (ready.load(.acquire)) return io_val;
    // Bootstrap lock: a plain spinlock, because std.Io.Mutex itself needs an
    // Io to lock and this is what produces that Io.
    while (initializing.cmpxchgWeak(false, true, .acquire, .monotonic) != null) {
        std.atomic.spinLoopHint();
    }
    defer initializing.store(false, .release);
    if (!ready.load(.acquire)) {
        threaded = std.Io.Threaded.init(std.heap.page_allocator, .{});
        io_val = threaded.io();
        ready.store(true, .release);
    }
    return io_val;
}

/// Unix time in seconds (wall clock). Replacement for std.time.timestamp().
pub fn timestamp() i64 {
    return std.Io.Timestamp.now(io(), .real).toSeconds();
}

/// Unix time in nanoseconds. Replacement for std.time.nanoTimestamp().
pub fn nanoTimestamp() i128 {
    return @intCast(std.Io.Timestamp.now(io(), .real).toNanoseconds());
}

/// Fill buffer with cryptographically-secure random bytes.
/// Replacement for std.crypto.random.bytes(). Uses randomSecure so entropy is
/// always sourced from the OS; panics if entropy is unavailable rather than
/// silently falling back to a weak seed (matches the old fail-closed behavior).
pub fn randomBytes(buf: []u8) void {
    io().randomSecure(buf) catch @panic("randomSecure: entropy unavailable");
}
