extern fn sz_find_wrapper(haystack: [*]const u8, h_len: usize, needle: [*]const u8, n_len: usize) ?[*]const u8;

pub fn find(haystack: []const u8, needle: []const u8) ?usize {
    const result = sz_find_wrapper(haystack.ptr, haystack.len, needle.ptr, needle.len) orelse return null;
    const value = @intFromPtr(result);
    const start = @intFromPtr(haystack.ptr);
    const end = start + haystack.len;
    if (value < start or value >= end) return null;
    return value - start;
}
