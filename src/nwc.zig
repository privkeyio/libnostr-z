//! NIP-47 Nostr Wallet Connect (NWC) protocol types.
//!
//! Zero-allocation parsing returns slices into the original JSON. Array fields
//! (`multi_pay_*`, `list_transactions`) return empty slices - use `std.json` if needed.

const std = @import("std");
const utils = @import("utils.zig");
const hex = @import("hex.zig");
const crypto = @import("crypto.zig");

pub const Kind = struct {
    pub const info: i32 = 13194;
    pub const request: i32 = 23194;
    pub const response: i32 = 23195;
    pub const notification_nip04: i32 = 23196;
    pub const notification: i32 = 23197;
};

pub const ErrorCode = enum {
    rate_limited,
    not_implemented,
    insufficient_balance,
    quota_exceeded,
    restricted,
    unauthorized,
    internal,
    unsupported_encryption,
    payment_failed,
    not_found,
    other,

    pub fn toString(self: ErrorCode) []const u8 {
        return switch (self) {
            .rate_limited => "RATE_LIMITED",
            .not_implemented => "NOT_IMPLEMENTED",
            .insufficient_balance => "INSUFFICIENT_BALANCE",
            .quota_exceeded => "QUOTA_EXCEEDED",
            .restricted => "RESTRICTED",
            .unauthorized => "UNAUTHORIZED",
            .internal => "INTERNAL",
            .unsupported_encryption => "UNSUPPORTED_ENCRYPTION",
            .payment_failed => "PAYMENT_FAILED",
            .not_found => "NOT_FOUND",
            .other => "OTHER",
        };
    }

    pub fn fromString(s: []const u8) ?ErrorCode {
        const map = std.StaticStringMap(ErrorCode).initComptime(.{
            .{ "RATE_LIMITED", .rate_limited },
            .{ "NOT_IMPLEMENTED", .not_implemented },
            .{ "INSUFFICIENT_BALANCE", .insufficient_balance },
            .{ "QUOTA_EXCEEDED", .quota_exceeded },
            .{ "RESTRICTED", .restricted },
            .{ "UNAUTHORIZED", .unauthorized },
            .{ "INTERNAL", .internal },
            .{ "UNSUPPORTED_ENCRYPTION", .unsupported_encryption },
            .{ "PAYMENT_FAILED", .payment_failed },
            .{ "NOT_FOUND", .not_found },
            .{ "OTHER", .other },
        });
        return map.get(s);
    }
};

pub const Method = enum {
    pay_invoice,
    multi_pay_invoice,
    pay_keysend,
    multi_pay_keysend,
    make_invoice,
    lookup_invoice,
    list_transactions,
    get_balance,
    get_info,

    pub fn toString(self: Method) []const u8 {
        return switch (self) {
            .pay_invoice => "pay_invoice",
            .multi_pay_invoice => "multi_pay_invoice",
            .pay_keysend => "pay_keysend",
            .multi_pay_keysend => "multi_pay_keysend",
            .make_invoice => "make_invoice",
            .lookup_invoice => "lookup_invoice",
            .list_transactions => "list_transactions",
            .get_balance => "get_balance",
            .get_info => "get_info",
        };
    }

    pub fn fromString(s: []const u8) ?Method {
        const map = std.StaticStringMap(Method).initComptime(.{
            .{ "pay_invoice", .pay_invoice },
            .{ "multi_pay_invoice", .multi_pay_invoice },
            .{ "pay_keysend", .pay_keysend },
            .{ "multi_pay_keysend", .multi_pay_keysend },
            .{ "make_invoice", .make_invoice },
            .{ "lookup_invoice", .lookup_invoice },
            .{ "list_transactions", .list_transactions },
            .{ "get_balance", .get_balance },
            .{ "get_info", .get_info },
        });
        return map.get(s);
    }
};

pub const NotificationType = enum {
    payment_received,
    payment_sent,

    pub fn toString(self: NotificationType) []const u8 {
        return switch (self) {
            .payment_received => "payment_received",
            .payment_sent => "payment_sent",
        };
    }

    pub fn fromString(s: []const u8) ?NotificationType {
        if (std.mem.eql(u8, s, "payment_received")) return .payment_received;
        if (std.mem.eql(u8, s, "payment_sent")) return .payment_sent;
        return null;
    }
};

pub const TransactionType = enum {
    incoming,
    outgoing,

    pub fn toString(self: TransactionType) []const u8 {
        return switch (self) {
            .incoming => "incoming",
            .outgoing => "outgoing",
        };
    }

    pub fn fromString(s: []const u8) ?TransactionType {
        if (std.mem.eql(u8, s, "incoming")) return .incoming;
        if (std.mem.eql(u8, s, "outgoing")) return .outgoing;
        return null;
    }
};

pub const TransactionState = enum {
    pending,
    settled,
    expired,
    failed,

    pub fn toString(self: TransactionState) []const u8 {
        return switch (self) {
            .pending => "pending",
            .settled => "settled",
            .expired => "expired",
            .failed => "failed",
        };
    }

    pub fn fromString(s: []const u8) ?TransactionState {
        const map = std.StaticStringMap(TransactionState).initComptime(.{
            .{ "pending", .pending },
            .{ "settled", .settled },
            .{ "expired", .expired },
            .{ "failed", .failed },
        });
        return map.get(s);
    }
};

pub const Encryption = enum {
    nip44_v2,
    nip04,

    pub fn toString(self: Encryption) []const u8 {
        return switch (self) {
            .nip44_v2 => "nip44_v2",
            .nip04 => "nip04",
        };
    }

    pub fn fromString(s: []const u8) ?Encryption {
        if (std.mem.eql(u8, s, "nip44_v2")) return .nip44_v2;
        if (std.mem.eql(u8, s, "nip04")) return .nip04;
        return null;
    }
};

pub const TlvRecord = struct {
    type_value: u64,
    value: []const u8,
};

pub const Transaction = struct {
    tx_type: TransactionType = .incoming,
    state: ?TransactionState = null,
    invoice: ?[]const u8 = null,
    description: ?[]const u8 = null,
    description_hash: ?[]const u8 = null,
    preimage: ?[]const u8 = null,
    payment_hash: ?[]const u8 = null,
    amount: ?u64 = null,
    fees_paid: ?u64 = null,
    created_at: ?i64 = null,
    expires_at: ?i64 = null,
    settled_at: ?i64 = null,
};

pub const ConnectionUri = struct {
    wallet_pubkey: [32]u8,
    secret: [32]u8,
    relays: [][]const u8,
    lud16: ?[]const u8,
    allocator: std.mem.Allocator,

    pub fn parse(allocator: std.mem.Allocator, uri: []const u8) !ConnectionUri {
        const prefix = "nostr+walletconnect://";
        if (!std.mem.startsWith(u8, uri, prefix)) return error.InvalidUri;

        const after_prefix = uri[prefix.len..];
        const query_start = std.mem.indexOf(u8, after_prefix, "?") orelse return error.InvalidUri;

        const pubkey_hex = after_prefix[0..query_start];
        if (pubkey_hex.len != 64) return error.InvalidUri;

        var wallet_pubkey: [32]u8 = undefined;
        _ = std.fmt.hexToBytes(&wallet_pubkey, pubkey_hex) catch return error.InvalidUri;

        const query = after_prefix[query_start + 1 ..];

        var secret: ?[32]u8 = null;
        var lud16: ?[]const u8 = null;
        var relays: std.ArrayListUnmanaged([]const u8) = .{};
        errdefer {
            for (relays.items) |r| allocator.free(r);
            relays.deinit(allocator);
            if (lud16) |l| allocator.free(l);
        }

        var params = std.mem.splitScalar(u8, query, '&');
        while (params.next()) |param| {
            const eq_pos = std.mem.indexOf(u8, param, "=") orelse continue;
            const key = param[0..eq_pos];
            const value = param[eq_pos + 1 ..];

            if (std.mem.eql(u8, key, "secret")) {
                if (value.len != 64) return error.InvalidUri;
                var sec: [32]u8 = undefined;
                _ = std.fmt.hexToBytes(&sec, value) catch return error.InvalidUri;
                secret = sec;
            } else if (std.mem.eql(u8, key, "relay")) {
                const decoded = try percentDecode(allocator, value);
                try relays.append(allocator, decoded);
            } else if (std.mem.eql(u8, key, "lud16")) {
                lud16 = try percentDecode(allocator, value);
            }
        }

        if (secret == null) return error.InvalidUri;
        if (relays.items.len == 0) return error.InvalidUri;

        return .{
            .wallet_pubkey = wallet_pubkey,
            .secret = secret.?,
            .relays = try relays.toOwnedSlice(allocator),
            .lud16 = lud16,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *ConnectionUri) void {
        for (self.relays) |r| self.allocator.free(r);
        self.allocator.free(self.relays);
        if (self.lud16) |l| self.allocator.free(l);
    }

    pub fn format(self: *const ConnectionUri, buf: []u8) ![]u8 {
        var fbs = std.io.fixedBufferStream(buf);
        const writer = fbs.writer();

        try writer.writeAll("nostr+walletconnect://");
        var pk_hex: [64]u8 = undefined;
        hex.encode(&self.wallet_pubkey, &pk_hex);
        try writer.writeAll(&pk_hex);
        try writer.writeAll("?");

        for (self.relays, 0..) |relay, i| {
            if (i > 0) try writer.writeAll("&");
            try writer.writeAll("relay=");
            try percentEncode(writer, relay);
        }

        try writer.writeAll("&secret=");
        var sec_hex: [64]u8 = undefined;
        hex.encode(&self.secret, &sec_hex);
        try writer.writeAll(&sec_hex);

        if (self.lud16) |l| {
            try writer.writeAll("&lud16=");
            try percentEncode(writer, l);
        }

        return fbs.getWritten();
    }
};

pub const Request = struct {
    method: Method,
    params: Params,

    pub const Params = union(Method) {
        pay_invoice: PayInvoice,
        multi_pay_invoice: MultiPayInvoice,
        pay_keysend: PayKeysend,
        multi_pay_keysend: MultiPayKeysend,
        make_invoice: MakeInvoice,
        lookup_invoice: LookupInvoice,
        list_transactions: ListTransactions,
        get_balance: void,
        get_info: void,
    };

    pub const PayInvoice = struct {
        invoice: []const u8,
        amount: ?u64 = null,
    };

    pub const MultiPayInvoice = struct {
        invoices: []const Invoice,

        pub const Invoice = struct {
            id: ?[]const u8 = null,
            invoice: []const u8,
            amount: ?u64 = null,
        };
    };

    pub const PayKeysend = struct {
        amount: u64,
        pubkey: []const u8,
        preimage: ?[]const u8 = null,
        tlv_records: ?[]const TlvRecord = null,
    };

    pub const MultiPayKeysend = struct {
        keysends: []const Keysend,

        pub const Keysend = struct {
            id: ?[]const u8 = null,
            pubkey: []const u8,
            amount: u64,
            preimage: ?[]const u8 = null,
            tlv_records: ?[]const TlvRecord = null,
        };
    };

    pub const MakeInvoice = struct {
        amount: u64,
        description: ?[]const u8 = null,
        description_hash: ?[]const u8 = null,
        expiry: ?u64 = null,
    };

    pub const LookupInvoice = struct {
        payment_hash: ?[]const u8 = null,
        invoice: ?[]const u8 = null,
    };

    pub const ListTransactions = struct {
        from: ?i64 = null,
        until: ?i64 = null,
        limit: ?u32 = null,
        offset: ?u32 = null,
        unpaid: ?bool = null,
        tx_type: ?TransactionType = null,
    };

    pub fn parseJson(json: []const u8) ?Request {
        const method_str = utils.extractJsonString(json, "method") orelse return null;
        const method = Method.fromString(method_str) orelse return null;

        const params_json = utils.findJsonValue(json, "params") orelse return null;

        return switch (method) {
            .pay_invoice => .{
                .method = .pay_invoice,
                .params = .{ .pay_invoice = .{
                    .invoice = utils.extractJsonString(params_json, "invoice") orelse return null,
                    .amount = utils.extractIntField(params_json, "amount", u64),
                } },
            },
            .make_invoice => .{
                .method = .make_invoice,
                .params = .{ .make_invoice = .{
                    .amount = utils.extractIntField(params_json, "amount", u64) orelse return null,
                    .description = utils.extractJsonString(params_json, "description"),
                    .description_hash = utils.extractJsonString(params_json, "description_hash"),
                    .expiry = utils.extractIntField(params_json, "expiry", u64),
                } },
            },
            .lookup_invoice => .{
                .method = .lookup_invoice,
                .params = .{ .lookup_invoice = .{
                    .payment_hash = utils.extractJsonString(params_json, "payment_hash"),
                    .invoice = utils.extractJsonString(params_json, "invoice"),
                } },
            },
            .list_transactions => .{
                .method = .list_transactions,
                .params = .{ .list_transactions = .{
                    .from = utils.extractIntField(params_json, "from", i64),
                    .until = utils.extractIntField(params_json, "until", i64),
                    .limit = utils.extractIntField(params_json, "limit", u32),
                    .offset = utils.extractIntField(params_json, "offset", u32),
                    .unpaid = extractBoolField(params_json, "unpaid"),
                    .tx_type = if (utils.extractJsonString(params_json, "type")) |t| TransactionType.fromString(t) else null,
                } },
            },
            .get_balance => .{ .method = .get_balance, .params = .{ .get_balance = {} } },
            .get_info => .{ .method = .get_info, .params = .{ .get_info = {} } },
            .pay_keysend => .{
                .method = .pay_keysend,
                .params = .{ .pay_keysend = .{
                    .amount = utils.extractIntField(params_json, "amount", u64) orelse return null,
                    .pubkey = utils.extractJsonString(params_json, "pubkey") orelse return null,
                    .preimage = utils.extractJsonString(params_json, "preimage"),
                    .tlv_records = null,
                } },
            },
            .multi_pay_invoice => .{
                .method = .multi_pay_invoice,
                .params = .{ .multi_pay_invoice = .{ .invoices = &.{} } },
            },
            .multi_pay_keysend => .{
                .method = .multi_pay_keysend,
                .params = .{ .multi_pay_keysend = .{ .keysends = &.{} } },
            },
        };
    }

    pub fn serialize(self: *const Request, buf: []u8) ![]u8 {
        var fbs = std.io.fixedBufferStream(buf);
        const writer = fbs.writer();

        try writer.writeAll("{\"method\":\"");
        try writer.writeAll(self.method.toString());
        try writer.writeAll("\",\"params\":{");

        switch (self.params) {
            .pay_invoice => |p| {
                try writer.writeAll("\"invoice\":\"");
                try writer.writeAll(p.invoice);
                try writer.writeAll("\"");
                if (p.amount) |a| {
                    try writer.print(",\"amount\":{d}", .{a});
                }
            },
            .make_invoice => |p| {
                try writer.print("\"amount\":{d}", .{p.amount});
                if (p.description) |d| {
                    try writer.writeAll(",\"description\":\"");
                    try utils.writeJsonEscaped(writer, d);
                    try writer.writeAll("\"");
                }
                if (p.description_hash) |h| {
                    try writer.writeAll(",\"description_hash\":\"");
                    try writer.writeAll(h);
                    try writer.writeAll("\"");
                }
                if (p.expiry) |e| {
                    try writer.print(",\"expiry\":{d}", .{e});
                }
            },
            .lookup_invoice => |p| {
                var first = true;
                if (p.payment_hash) |h| {
                    try writer.writeAll("\"payment_hash\":\"");
                    try writer.writeAll(h);
                    try writer.writeAll("\"");
                    first = false;
                }
                if (p.invoice) |i| {
                    if (!first) try writer.writeAll(",");
                    try writer.writeAll("\"invoice\":\"");
                    try writer.writeAll(i);
                    try writer.writeAll("\"");
                }
            },
            .list_transactions => |p| {
                var first = true;
                if (p.from) |f| {
                    try writer.print("\"from\":{d}", .{f});
                    first = false;
                }
                if (p.until) |u| {
                    if (!first) try writer.writeAll(",");
                    try writer.print("\"until\":{d}", .{u});
                    first = false;
                }
                if (p.limit) |l| {
                    if (!first) try writer.writeAll(",");
                    try writer.print("\"limit\":{d}", .{l});
                    first = false;
                }
                if (p.offset) |o| {
                    if (!first) try writer.writeAll(",");
                    try writer.print("\"offset\":{d}", .{o});
                    first = false;
                }
                if (p.unpaid) |unpaid| {
                    if (!first) try writer.writeAll(",");
                    try writer.print("\"unpaid\":{}", .{unpaid});
                    first = false;
                }
                if (p.tx_type) |t| {
                    if (!first) try writer.writeAll(",");
                    try writer.writeAll("\"type\":\"");
                    try writer.writeAll(t.toString());
                    try writer.writeAll("\"");
                }
            },
            .pay_keysend => |p| {
                try writer.print("\"amount\":{d},\"pubkey\":\"", .{p.amount});
                try writer.writeAll(p.pubkey);
                try writer.writeAll("\"");
                if (p.preimage) |pre| {
                    try writer.writeAll(",\"preimage\":\"");
                    try writer.writeAll(pre);
                    try writer.writeAll("\"");
                }
            },
            .get_balance, .get_info => {},
            .multi_pay_invoice => |p| {
                try writer.writeAll("\"invoices\":[");
                for (p.invoices, 0..) |inv, i| {
                    if (i > 0) try writer.writeAll(",");
                    try writer.writeAll("{\"invoice\":\"");
                    try writer.writeAll(inv.invoice);
                    try writer.writeAll("\"");
                    if (inv.id) |id| {
                        try writer.writeAll(",\"id\":\"");
                        try writer.writeAll(id);
                        try writer.writeAll("\"");
                    }
                    if (inv.amount) |a| {
                        try writer.print(",\"amount\":{d}", .{a});
                    }
                    try writer.writeAll("}");
                }
                try writer.writeAll("]");
            },
            .multi_pay_keysend => |p| {
                try writer.writeAll("\"keysends\":[");
                for (p.keysends, 0..) |ks, i| {
                    if (i > 0) try writer.writeAll(",");
                    try writer.print("{{\"pubkey\":\"{s}\",\"amount\":{d}", .{ ks.pubkey, ks.amount });
                    if (ks.id) |id| {
                        try writer.writeAll(",\"id\":\"");
                        try writer.writeAll(id);
                        try writer.writeAll("\"");
                    }
                    if (ks.preimage) |pre| {
                        try writer.writeAll(",\"preimage\":\"");
                        try writer.writeAll(pre);
                        try writer.writeAll("\"");
                    }
                    try writer.writeAll("}");
                }
                try writer.writeAll("]");
            },
        }

        try writer.writeAll("}}");
        return fbs.getWritten();
    }
};

pub const Response = struct {
    result_type: Method,
    result: ?Result = null,
    err: ?Error = null,

    pub const Error = struct {
        code: ErrorCode,
        message: []const u8,
    };

    pub const Result = union(Method) {
        pay_invoice: PaymentResult,
        multi_pay_invoice: PaymentResult,
        pay_keysend: PaymentResult,
        multi_pay_keysend: PaymentResult,
        make_invoice: Transaction,
        lookup_invoice: Transaction,
        list_transactions: TransactionList,
        get_balance: Balance,
        get_info: WalletInfo,
    };

    pub const PaymentResult = struct {
        preimage: []const u8,
        fees_paid: ?u64 = null,
    };

    pub const TransactionList = struct {
        transactions: []const Transaction,
    };

    pub const Balance = struct {
        balance: u64,
    };

    pub const WalletInfo = struct {
        alias: ?[]const u8 = null,
        color: ?[]const u8 = null,
        pubkey: ?[]const u8 = null,
        network: ?[]const u8 = null,
        block_height: ?u64 = null,
        block_hash: ?[]const u8 = null,
        methods: []const Method = &.{},
        notifications: []const NotificationType = &.{},
    };

    pub fn parseJson(json: []const u8) ?Response {
        const result_type_str = utils.extractJsonString(json, "result_type") orelse return null;
        const result_type = Method.fromString(result_type_str) orelse return null;

        var response = Response{ .result_type = result_type };

        if (utils.findJsonValue(json, "error")) |err_json| {
            if (!std.mem.eql(u8, err_json, "null")) {
                const code_str = utils.extractJsonString(err_json, "code") orelse return null;
                const code = ErrorCode.fromString(code_str) orelse return null;
                const message = utils.extractJsonString(err_json, "message") orelse "";
                response.err = .{ .code = code, .message = message };
            }
        }

        if (utils.findJsonValue(json, "result")) |result_json| {
            if (!std.mem.eql(u8, result_json, "null")) {
                const payment_result: ?PaymentResult = if (utils.extractJsonString(result_json, "preimage")) |preimage|
                    .{ .preimage = preimage, .fees_paid = utils.extractIntField(result_json, "fees_paid", u64) }
                else
                    null;

                response.result = switch (result_type) {
                    .pay_invoice => if (payment_result) |pr| .{ .pay_invoice = pr } else null,
                    .multi_pay_invoice => if (payment_result) |pr| .{ .multi_pay_invoice = pr } else null,
                    .pay_keysend => if (payment_result) |pr| .{ .pay_keysend = pr } else null,
                    .multi_pay_keysend => if (payment_result) |pr| .{ .multi_pay_keysend = pr } else null,
                    .get_balance => .{ .get_balance = .{
                        .balance = utils.extractIntField(result_json, "balance", u64) orelse 0,
                    } },
                    .get_info => .{ .get_info = .{
                        .alias = utils.extractJsonString(result_json, "alias"),
                        .color = utils.extractJsonString(result_json, "color"),
                        .pubkey = utils.extractJsonString(result_json, "pubkey"),
                        .network = utils.extractJsonString(result_json, "network"),
                        .block_height = utils.extractIntField(result_json, "block_height", u64),
                        .block_hash = utils.extractJsonString(result_json, "block_hash"),
                    } },
                    .make_invoice => .{ .make_invoice = parseTransaction(result_json) },
                    .lookup_invoice => .{ .lookup_invoice = parseTransaction(result_json) },
                    .list_transactions => .{ .list_transactions = .{ .transactions = &.{} } },
                };
            }
        }

        return response;
    }

    pub fn serialize(self: *const Response, buf: []u8) ![]u8 {
        var fbs = std.io.fixedBufferStream(buf);
        const writer = fbs.writer();

        try writer.writeAll("{\"result_type\":\"");
        try writer.writeAll(self.result_type.toString());
        try writer.writeAll("\"");

        if (self.err) |e| {
            try writer.writeAll(",\"error\":{\"code\":\"");
            try writer.writeAll(e.code.toString());
            try writer.writeAll("\",\"message\":\"");
            try utils.writeJsonEscaped(writer, e.message);
            try writer.writeAll("\"},\"result\":null");
        } else if (self.result) |r| {
            try writer.writeAll(",\"error\":null,\"result\":{");
            switch (r) {
                .pay_invoice, .multi_pay_invoice, .pay_keysend, .multi_pay_keysend => |p| {
                    try writer.writeAll("\"preimage\":\"");
                    try writer.writeAll(p.preimage);
                    try writer.writeAll("\"");
                    if (p.fees_paid) |f| {
                        try writer.print(",\"fees_paid\":{d}", .{f});
                    }
                },
                .get_balance => |b| {
                    try writer.print("\"balance\":{d}", .{b.balance});
                },
                .get_info => |info| {
                    var first = true;
                    if (info.alias) |a| {
                        try writer.writeAll("\"alias\":\"");
                        try utils.writeJsonEscaped(writer, a);
                        try writer.writeAll("\"");
                        first = false;
                    }
                    if (info.color) |c| {
                        if (!first) try writer.writeAll(",");
                        try writer.writeAll("\"color\":\"");
                        try writer.writeAll(c);
                        try writer.writeAll("\"");
                        first = false;
                    }
                    if (info.pubkey) |p| {
                        if (!first) try writer.writeAll(",");
                        try writer.writeAll("\"pubkey\":\"");
                        try writer.writeAll(p);
                        try writer.writeAll("\"");
                        first = false;
                    }
                    if (info.network) |n| {
                        if (!first) try writer.writeAll(",");
                        try writer.writeAll("\"network\":\"");
                        try writer.writeAll(n);
                        try writer.writeAll("\"");
                        first = false;
                    }
                    if (info.block_height) |h| {
                        if (!first) try writer.writeAll(",");
                        try writer.print("\"block_height\":{d}", .{h});
                        first = false;
                    }
                    if (info.block_hash) |h| {
                        if (!first) try writer.writeAll(",");
                        try writer.writeAll("\"block_hash\":\"");
                        try writer.writeAll(h);
                        try writer.writeAll("\"");
                        first = false;
                    }
                    if (info.methods.len > 0) {
                        if (!first) try writer.writeAll(",");
                        try writer.writeAll("\"methods\":[");
                        for (info.methods, 0..) |m, i| {
                            if (i > 0) try writer.writeAll(",");
                            try writer.writeAll("\"");
                            try writer.writeAll(m.toString());
                            try writer.writeAll("\"");
                        }
                        try writer.writeAll("]");
                        first = false;
                    }
                    if (info.notifications.len > 0) {
                        if (!first) try writer.writeAll(",");
                        try writer.writeAll("\"notifications\":[");
                        for (info.notifications, 0..) |n, i| {
                            if (i > 0) try writer.writeAll(",");
                            try writer.writeAll("\"");
                            try writer.writeAll(n.toString());
                            try writer.writeAll("\"");
                        }
                        try writer.writeAll("]");
                    }
                },
                .make_invoice, .lookup_invoice => |tx| {
                    try serializeTransaction(writer, tx);
                },
                .list_transactions => |list| {
                    try writer.writeAll("\"transactions\":[");
                    for (list.transactions, 0..) |tx, i| {
                        if (i > 0) try writer.writeAll(",");
                        try writer.writeAll("{");
                        try serializeTransaction(writer, tx);
                        try writer.writeAll("}");
                    }
                    try writer.writeAll("]");
                },
            }
            try writer.writeAll("}");
        } else {
            try writer.writeAll(",\"error\":null,\"result\":null");
        }

        try writer.writeAll("}");
        return fbs.getWritten();
    }
};

pub const Notification = struct {
    notification_type: NotificationType,
    notification: Transaction,

    pub fn parseJson(json: []const u8) ?Notification {
        const type_str = utils.extractJsonString(json, "notification_type") orelse return null;
        const notification_type = NotificationType.fromString(type_str) orelse return null;

        const notification_json = utils.findJsonValue(json, "notification") orelse return null;

        return .{
            .notification_type = notification_type,
            .notification = parseTransaction(notification_json),
        };
    }

    pub fn serialize(self: *const Notification, buf: []u8) ![]u8 {
        var fbs = std.io.fixedBufferStream(buf);
        const writer = fbs.writer();

        try writer.writeAll("{\"notification_type\":\"");
        try writer.writeAll(self.notification_type.toString());
        try writer.writeAll("\",\"notification\":{");
        try serializeTransaction(writer, self.notification);
        try writer.writeAll("}}");

        return fbs.getWritten();
    }
};

pub const InfoEvent = struct {
    capabilities_buf: [16]Method = undefined,
    capabilities_len: usize = 0,
    encryption: []const Encryption,
    notifications: []const NotificationType,

    pub fn parseContent(content: []const u8) InfoEvent {
        var info = InfoEvent{
            .encryption = &.{.nip44_v2},
            .notifications = &.{},
        };
        var iter = std.mem.splitScalar(u8, content, ' ');
        while (iter.next()) |cap| {
            if (Method.fromString(cap)) |m| {
                if (info.capabilities_len < 16) {
                    info.capabilities_buf[info.capabilities_len] = m;
                    info.capabilities_len += 1;
                }
            }
        }
        return info;
    }

    pub fn getCapabilities(self: *const InfoEvent) []const Method {
        return self.capabilities_buf[0..self.capabilities_len];
    }

    pub fn serializeContent(self: *const InfoEvent, buf: []u8) ![]u8 {
        var fbs = std.io.fixedBufferStream(buf);
        const writer = fbs.writer();

        for (self.getCapabilities(), 0..) |cap, i| {
            if (i > 0) try writer.writeAll(" ");
            try writer.writeAll(cap.toString());
        }

        return fbs.getWritten();
    }
};

fn parseTransaction(json: []const u8) Transaction {
    return .{
        .tx_type = if (utils.extractJsonString(json, "type")) |t| TransactionType.fromString(t) orelse .incoming else .incoming,
        .state = if (utils.extractJsonString(json, "state")) |s| TransactionState.fromString(s) else null,
        .invoice = utils.extractJsonString(json, "invoice"),
        .description = utils.extractJsonString(json, "description"),
        .description_hash = utils.extractJsonString(json, "description_hash"),
        .preimage = utils.extractJsonString(json, "preimage"),
        .payment_hash = utils.extractJsonString(json, "payment_hash"),
        .amount = utils.extractIntField(json, "amount", u64),
        .fees_paid = utils.extractIntField(json, "fees_paid", u64),
        .created_at = utils.extractIntField(json, "created_at", i64),
        .expires_at = utils.extractIntField(json, "expires_at", i64),
        .settled_at = utils.extractIntField(json, "settled_at", i64),
    };
}

fn serializeTransaction(writer: anytype, tx: Transaction) !void {
    try writer.writeAll("\"type\":\"");
    try writer.writeAll(tx.tx_type.toString());
    try writer.writeAll("\"");
    if (tx.state) |s| {
        try writer.writeAll(",\"state\":\"");
        try writer.writeAll(s.toString());
        try writer.writeAll("\"");
    }
    if (tx.invoice) |inv| {
        try writer.writeAll(",\"invoice\":\"");
        try writer.writeAll(inv);
        try writer.writeAll("\"");
    }
    if (tx.description) |d| {
        try writer.writeAll(",\"description\":\"");
        try utils.writeJsonEscaped(writer, d);
        try writer.writeAll("\"");
    }
    if (tx.description_hash) |h| {
        try writer.writeAll(",\"description_hash\":\"");
        try writer.writeAll(h);
        try writer.writeAll("\"");
    }
    if (tx.preimage) |p| {
        try writer.writeAll(",\"preimage\":\"");
        try writer.writeAll(p);
        try writer.writeAll("\"");
    }
    if (tx.payment_hash) |h| {
        try writer.writeAll(",\"payment_hash\":\"");
        try writer.writeAll(h);
        try writer.writeAll("\"");
    }
    if (tx.amount) |a| {
        try writer.print(",\"amount\":{d}", .{a});
    }
    if (tx.fees_paid) |f| {
        try writer.print(",\"fees_paid\":{d}", .{f});
    }
    if (tx.created_at) |c| {
        try writer.print(",\"created_at\":{d}", .{c});
    }
    if (tx.expires_at) |e| {
        try writer.print(",\"expires_at\":{d}", .{e});
    }
    if (tx.settled_at) |s| {
        try writer.print(",\"settled_at\":{d}", .{s});
    }
}

fn extractBoolField(json: []const u8, key: []const u8) ?bool {
    var search_buf: [68]u8 = undefined;
    const search = std.fmt.bufPrint(&search_buf, "\"{s}\":", .{key}) catch return null;
    const key_pos = std.mem.indexOf(u8, json, search) orelse return null;
    var pos = key_pos + search.len;
    while (pos < json.len and (json[pos] == ' ' or json[pos] == '\t')) : (pos += 1) {}
    if (pos >= json.len) return null;
    if (pos + 4 <= json.len and std.mem.eql(u8, json[pos..][0..4], "true")) return true;
    if (pos + 5 <= json.len and std.mem.eql(u8, json[pos..][0..5], "false")) return false;
    return null;
}

const percentDecode = utils.percentDecode;
const percentEncode = utils.percentEncode;

pub fn encryptRequest(
    request: *const Request,
    secret_key: *const [32]u8,
    wallet_pubkey: *const [32]u8,
    allocator: std.mem.Allocator,
) ![]u8 {
    const buf = try allocator.alloc(u8, 65536);
    defer allocator.free(buf);
    const json = try request.serialize(buf);
    return crypto.nip44Encrypt(secret_key, wallet_pubkey, json, allocator);
}

pub fn decryptRequest(
    encrypted: []const u8,
    secret_key: *const [32]u8,
    client_pubkey: *const [32]u8,
    allocator: std.mem.Allocator,
) !struct { json: []u8, request: ?Request } {
    const json = try crypto.nip44Decrypt(secret_key, client_pubkey, encrypted, allocator);
    return .{ .json = json, .request = Request.parseJson(json) };
}

pub fn encryptResponse(
    response: *const Response,
    secret_key: *const [32]u8,
    client_pubkey: *const [32]u8,
    allocator: std.mem.Allocator,
) ![]u8 {
    const buf = try allocator.alloc(u8, 65536);
    defer allocator.free(buf);
    const json = try response.serialize(buf);
    return crypto.nip44Encrypt(secret_key, client_pubkey, json, allocator);
}

pub fn decryptResponse(
    encrypted: []const u8,
    secret_key: *const [32]u8,
    wallet_pubkey: *const [32]u8,
    allocator: std.mem.Allocator,
) !struct { json: []u8, response: ?Response } {
    const json = try crypto.nip44Decrypt(secret_key, wallet_pubkey, encrypted, allocator);
    return .{ .json = json, .response = Response.parseJson(json) };
}

pub fn encryptNotification(
    notification: *const Notification,
    secret_key: *const [32]u8,
    client_pubkey: *const [32]u8,
    allocator: std.mem.Allocator,
) ![]u8 {
    const buf = try allocator.alloc(u8, 65536);
    defer allocator.free(buf);
    const json = try notification.serialize(buf);
    return crypto.nip44Encrypt(secret_key, client_pubkey, json, allocator);
}

pub fn decryptNotification(
    encrypted: []const u8,
    secret_key: *const [32]u8,
    wallet_pubkey: *const [32]u8,
    allocator: std.mem.Allocator,
) !struct { json: []u8, notification: ?Notification } {
    const json = try crypto.nip44Decrypt(secret_key, wallet_pubkey, encrypted, allocator);
    return .{ .json = json, .notification = Notification.parseJson(json) };
}

test "ConnectionUri.parse" {
    const uri = "nostr+walletconnect://b889ff5b1513b641e2a139f661a661364979c5beee91842f8f0ef42ab558e9d4?relay=wss%3A%2F%2Frelay.damus.io&secret=71a8c14c1407c113601079c4302dab36460f0ccd0ad506f1f2dc73b5100e4f3c";

    var conn = try ConnectionUri.parse(std.testing.allocator, uri);
    defer conn.deinit();

    var pk_hex: [64]u8 = undefined;
    hex.encode(&conn.wallet_pubkey, &pk_hex);
    try std.testing.expectEqualStrings("b889ff5b1513b641e2a139f661a661364979c5beee91842f8f0ef42ab558e9d4", &pk_hex);

    var sec_hex: [64]u8 = undefined;
    hex.encode(&conn.secret, &sec_hex);
    try std.testing.expectEqualStrings("71a8c14c1407c113601079c4302dab36460f0ccd0ad506f1f2dc73b5100e4f3c", &sec_hex);

    try std.testing.expectEqual(@as(usize, 1), conn.relays.len);
    try std.testing.expectEqualStrings("wss://relay.damus.io", conn.relays[0]);
}

test "ConnectionUri.format" {
    const uri = "nostr+walletconnect://b889ff5b1513b641e2a139f661a661364979c5beee91842f8f0ef42ab558e9d4?relay=wss%3A%2F%2Frelay.damus.io&secret=71a8c14c1407c113601079c4302dab36460f0ccd0ad506f1f2dc73b5100e4f3c";
    var conn = try ConnectionUri.parse(std.testing.allocator, uri);
    defer conn.deinit();

    var buf: [512]u8 = undefined;
    const result = try conn.format(&buf);
    try std.testing.expect(std.mem.startsWith(u8, result, "nostr+walletconnect://"));
    try std.testing.expect(std.mem.indexOf(u8, result, "relay=wss%3A%2F%2Frelay.damus.io") != null);
}

test "Request.parseJson pay_invoice" {
    const json =
        \\{"method":"pay_invoice","params":{"invoice":"lnbc50n1...","amount":1000}}
    ;
    const req = Request.parseJson(json).?;
    try std.testing.expectEqual(Method.pay_invoice, req.method);
    try std.testing.expectEqualStrings("lnbc50n1...", req.params.pay_invoice.invoice);
    try std.testing.expectEqual(@as(?u64, 1000), req.params.pay_invoice.amount);
}

test "Request.serialize pay_invoice" {
    const req = Request{
        .method = .pay_invoice,
        .params = .{ .pay_invoice = .{
            .invoice = "lnbc50n1...",
            .amount = 1000,
        } },
    };

    var buf: [256]u8 = undefined;
    const json = try req.serialize(&buf);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"method\":\"pay_invoice\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"invoice\":\"lnbc50n1...\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"amount\":1000") != null);
}

test "Response.parseJson success" {
    const json =
        \\{"result_type":"pay_invoice","error":null,"result":{"preimage":"abc123","fees_paid":10}}
    ;
    const resp = Response.parseJson(json).?;
    try std.testing.expectEqual(Method.pay_invoice, resp.result_type);
    try std.testing.expect(resp.err == null);
    try std.testing.expectEqualStrings("abc123", resp.result.?.pay_invoice.preimage);
    try std.testing.expectEqual(@as(?u64, 10), resp.result.?.pay_invoice.fees_paid);
}

test "Response.parseJson error" {
    const json =
        \\{"result_type":"pay_invoice","error":{"code":"PAYMENT_FAILED","message":"timeout"},"result":null}
    ;
    const resp = Response.parseJson(json).?;
    try std.testing.expectEqual(Method.pay_invoice, resp.result_type);
    try std.testing.expectEqual(ErrorCode.payment_failed, resp.err.?.code);
    try std.testing.expectEqualStrings("timeout", resp.err.?.message);
    try std.testing.expect(resp.result == null);
}

test "Response.serialize" {
    const resp = Response{
        .result_type = .get_balance,
        .result = .{ .get_balance = .{ .balance = 50000 } },
    };

    var buf: [256]u8 = undefined;
    const json = try resp.serialize(&buf);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"result_type\":\"get_balance\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"balance\":50000") != null);
}

test "Notification.parseJson" {
    const json =
        \\{"notification_type":"payment_received","notification":{"type":"incoming","amount":1000,"preimage":"abc"}}
    ;
    const notif = Notification.parseJson(json).?;
    try std.testing.expectEqual(NotificationType.payment_received, notif.notification_type);
    try std.testing.expectEqual(TransactionType.incoming, notif.notification.tx_type);
    try std.testing.expectEqual(@as(?u64, 1000), notif.notification.amount);
}

test "InfoEvent.parseContent" {
    const content = "pay_invoice get_balance make_invoice lookup_invoice list_transactions get_info";
    const info = InfoEvent.parseContent(content);
    const caps = info.getCapabilities();
    try std.testing.expectEqual(@as(usize, 6), caps.len);
    try std.testing.expectEqual(Method.pay_invoice, caps[0]);
    try std.testing.expectEqual(Method.get_balance, caps[1]);
}

test "Kind constants" {
    try std.testing.expectEqual(@as(i32, 13194), Kind.info);
    try std.testing.expectEqual(@as(i32, 23194), Kind.request);
    try std.testing.expectEqual(@as(i32, 23195), Kind.response);
    try std.testing.expectEqual(@as(i32, 23196), Kind.notification_nip04);
    try std.testing.expectEqual(@as(i32, 23197), Kind.notification);
}

test "ErrorCode roundtrip" {
    inline for (std.meta.fields(ErrorCode)) |field| {
        const code: ErrorCode = @enumFromInt(field.value);
        const str = code.toString();
        const parsed = ErrorCode.fromString(str).?;
        try std.testing.expectEqual(code, parsed);
    }
}

test "Method roundtrip" {
    inline for (std.meta.fields(Method)) |field| {
        const method: Method = @enumFromInt(field.value);
        const str = method.toString();
        const parsed = Method.fromString(str).?;
        try std.testing.expectEqual(method, parsed);
    }
}

test "ConnectionUri with multiple relays and lud16" {
    const uri = "nostr+walletconnect://b889ff5b1513b641e2a139f661a661364979c5beee91842f8f0ef42ab558e9d4?relay=wss%3A%2F%2Frelay1.example.com&relay=wss%3A%2F%2Frelay2.example.com&secret=71a8c14c1407c113601079c4302dab36460f0ccd0ad506f1f2dc73b5100e4f3c&lud16=user%40example.com";
    var conn = try ConnectionUri.parse(std.testing.allocator, uri);
    defer conn.deinit();

    try std.testing.expectEqual(@as(usize, 2), conn.relays.len);
    try std.testing.expectEqualStrings("wss://relay1.example.com", conn.relays[0]);
    try std.testing.expectEqualStrings("wss://relay2.example.com", conn.relays[1]);
    try std.testing.expectEqualStrings("user@example.com", conn.lud16.?);
}

test "ConnectionUri invalid inputs" {
    try std.testing.expectError(error.InvalidUri, ConnectionUri.parse(std.testing.allocator, "invalid"));
    try std.testing.expectError(error.InvalidUri, ConnectionUri.parse(std.testing.allocator, "nostr+walletconnect://tooshort?relay=wss://r.com&secret=abc"));
    try std.testing.expectError(error.InvalidUri, ConnectionUri.parse(std.testing.allocator, "nostr+walletconnect://b889ff5b1513b641e2a139f661a661364979c5beee91842f8f0ef42ab558e9d4?secret=71a8c14c1407c113601079c4302dab36460f0ccd0ad506f1f2dc73b5100e4f3c"));
}

test "Response.serialize error" {
    const resp = Response{
        .result_type = .pay_invoice,
        .err = .{ .code = .payment_failed, .message = "Network timeout" },
    };

    var buf: [256]u8 = undefined;
    const json = try resp.serialize(&buf);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"code\":\"PAYMENT_FAILED\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"message\":\"Network timeout\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"result\":null") != null);
}

test "Request.parseJson malformed returns null" {
    try std.testing.expect(Request.parseJson("not json") == null);
    try std.testing.expect(Request.parseJson("{}") == null);
    try std.testing.expect(Request.parseJson("{\"method\":\"unknown\"}") == null);
}

test "Response.parseJson malformed returns null" {
    try std.testing.expect(Response.parseJson("not json") == null);
    try std.testing.expect(Response.parseJson("{}") == null);
    try std.testing.expect(Response.parseJson("{\"result_type\":\"unknown\"}") == null);
}

test "Notification.parseJson malformed returns null" {
    try std.testing.expect(Notification.parseJson("not json") == null);
    try std.testing.expect(Notification.parseJson("{}") == null);
    try std.testing.expect(Notification.parseJson("{\"notification_type\":\"unknown\"}") == null);
}

test "Request.serialize get_info" {
    const req = Request{
        .method = .get_info,
        .params = .{ .get_info = {} },
    };

    var buf: [128]u8 = undefined;
    const json = try req.serialize(&buf);
    try std.testing.expectEqualStrings("{\"method\":\"get_info\",\"params\":{}}", json);
}

test "Request.parseJson list_transactions" {
    const json =
        \\{"method":"list_transactions","params":{"from":1693876973,"until":1703225078,"limit":10,"offset":0,"unpaid":true,"type":"incoming"}}
    ;
    const req = Request.parseJson(json).?;
    try std.testing.expectEqual(Method.list_transactions, req.method);
    try std.testing.expectEqual(@as(?i64, 1693876973), req.params.list_transactions.from);
    try std.testing.expectEqual(@as(?i64, 1703225078), req.params.list_transactions.until);
    try std.testing.expectEqual(@as(?u32, 10), req.params.list_transactions.limit);
    try std.testing.expectEqual(@as(?bool, true), req.params.list_transactions.unpaid);
    try std.testing.expectEqual(TransactionType.incoming, req.params.list_transactions.tx_type.?);
}

test "nip44 encrypt/decrypt request roundtrip" {
    const allocator = std.testing.allocator;

    var sk1: [32]u8 = undefined;
    var sk2: [32]u8 = undefined;
    @memset(&sk1, 0);
    @memset(&sk2, 0);
    sk1[31] = 1;
    sk2[31] = 2;

    var pk1: [32]u8 = undefined;
    var pk2: [32]u8 = undefined;
    try crypto.getPublicKey(&sk1, &pk1);
    try crypto.getPublicKey(&sk2, &pk2);

    const req = Request{
        .method = .get_balance,
        .params = .{ .get_balance = {} },
    };

    const encrypted = try encryptRequest(&req, &sk1, &pk2, allocator);
    defer allocator.free(encrypted);

    const result = try decryptRequest(encrypted, &sk2, &pk1, allocator);
    defer allocator.free(result.json);

    try std.testing.expectEqual(Method.get_balance, result.request.?.method);
}

test "nip44 encrypt/decrypt response roundtrip" {
    const allocator = std.testing.allocator;

    var sk1: [32]u8 = undefined;
    var sk2: [32]u8 = undefined;
    @memset(&sk1, 0);
    @memset(&sk2, 0);
    sk1[31] = 1;
    sk2[31] = 2;

    var pk1: [32]u8 = undefined;
    var pk2: [32]u8 = undefined;
    try crypto.getPublicKey(&sk1, &pk1);
    try crypto.getPublicKey(&sk2, &pk2);

    const resp = Response{
        .result_type = .get_balance,
        .result = .{ .get_balance = .{ .balance = 50000 } },
    };

    const encrypted = try encryptResponse(&resp, &sk2, &pk1, allocator);
    defer allocator.free(encrypted);

    const result = try decryptResponse(encrypted, &sk1, &pk2, allocator);
    defer allocator.free(result.json);

    try std.testing.expectEqual(Method.get_balance, result.response.?.result_type);
    try std.testing.expectEqual(@as(u64, 50000), result.response.?.result.?.get_balance.balance);
}
