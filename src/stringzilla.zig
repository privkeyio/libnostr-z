extern fn sz_find_wrapper(haystack: [*]const u8, h_len: usize, needle: [*]const u8, n_len: usize) ?[*]const u8;
extern fn sz_sha256_init_wrapper(state: *Sha256State) void;
extern fn sz_sha256_update_wrapper(state: *Sha256State, data: [*]const u8, length: usize) void;
extern fn sz_sha256_digest_wrapper(state: *const Sha256State, digest: *[32]u8) void;

pub const Sha256State = extern struct {
    hash: [8]u32,
    block: [64]u8,
    block_length: usize,
    total_length: u64,
};

pub const Sha256 = struct {
    state: Sha256State,

    pub fn init() Sha256 {
        var self: Sha256 = undefined;
        sz_sha256_init_wrapper(&self.state);
        return self;
    }

    pub fn update(self: *Sha256, data: []const u8) void {
        sz_sha256_update_wrapper(&self.state, data.ptr, data.len);
    }

    pub fn finalResult(self: *const Sha256) [32]u8 {
        var digest: [32]u8 = undefined;
        sz_sha256_digest_wrapper(&self.state, &digest);
        return digest;
    }
};

pub fn find(haystack: []const u8, needle: []const u8) ?usize {
    const result = sz_find_wrapper(haystack.ptr, haystack.len, needle.ptr, needle.len) orelse return null;
    const value = @intFromPtr(result);
    const start = @intFromPtr(haystack.ptr);
    const end = start + haystack.len;
    if (value < start or value >= end) return null;
    return value - start;
}
