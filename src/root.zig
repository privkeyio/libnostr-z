//! Nostr protocol implementation for Zig
//!
//! This is the main module that re-exports all Nostr protocol types and functions.
//! The implementation is split across several files for better organization:
//!
//! - `event.zig` - Event parsing, validation, and kind utilities
//! - `filter.zig` - Filter and matching logic
//! - `messages.zig` - Client and relay message parsing/creation
//! - `builder.zig` - Keypair and EventBuilder for creating events
//! - `tags.zig` - Tag value types and indexing
//! - `auth.zig` - NIP-42 authentication utilities
//! - `replaceable.zig` - NIP-16 replaceable event logic
//! - `index_keys.zig` - NIP-63 event indexing support
//! - `relay_metadata.zig` - NIP-65 relay list metadata
//! - `external_identities.zig` - NIP-39 external identities in profiles
//! - `relay_groups.zig` - NIP-29 relay-based groups
//! - `utils.zig` - JSON parsing utilities
//! - `crypto.zig` - Cryptographic operations
//! - `negentropy.zig` - NIP-77 negentropy protocol
//! - `pow.zig` - NIP-13 Proof of Work
//! - `nwc.zig` - NIP-47 Nostr Wallet Connect
//! - `nip17.zig` - NIP-17 Private Direct Messages
//! - `nip21.zig` - NIP-21 nostr: URI scheme
//! - `nip25.zig` - NIP-25 Reactions
//! - `nip27.zig` - NIP-27 Text Note References
//! - `nip28.zig` - NIP-28 Public Chat
//! - `nip43.zig` - NIP-43 Relay Access Metadata
//! - `nip46.zig` - NIP-46 Nostr Remote Signing
//! - `nip05.zig` - NIP-05 DNS-based internet identifier verification
//! - `nip10.zig` - NIP-10 Text Notes and Threads
//! - `nip18.zig` - NIP-18 Reposts
//! - `nip59.zig` - NIP-59 Gift Wrap
//! - `dlc_oracle.zig` - NIP-88 DLC Oracle announcements and attestations
//! - `clink.zig` - CLINK protocol types and error codes
//! - `joinstr.zig` - NIP Joinstr (Kind 2022) coinjoin pools
//! - `message_queue.zig` - Thread-safe message queue for multi-relay architecture
//! - `pool.zig` - Multi-relay pool with event deduplication and parallel queries
//! - `relay.zig` - High-level relay abstraction with connection management
//! - `signer.zig` - Abstract signer interface for NIP-07/NIP-46/hardware wallets
//! - `nip11.zig` - NIP-11 Relay Information Document
//! - `http_auth.zig` - NIP-98 HTTP Auth
//! - `zap_goal.zig` - NIP-75 Zap Goals
//! - `file_metadata.zig` - NIP-94 file metadata events
//! - `classified_listing.zig` - NIP-99 classified listings
//! - `nip04.zig` - NIP-04 Encrypted Direct Messages (deprecated)

const std = @import("std");

pub const io = @import("io.zig");
pub const crypto = @import("crypto.zig");
pub const http_auth = @import("http_auth.zig");
pub const negentropy = @import("negentropy.zig");
pub const bech32 = @import("bech32.zig");
pub const relay_metadata = @import("relay_metadata.zig");
pub const external_identities = @import("external_identities.zig");
pub const relay_groups = @import("relay_groups.zig");
pub const pow = @import("pow.zig");
pub const nwc = @import("nwc.zig");
pub const nip17 = @import("nip17.zig");
pub const nip21 = @import("nip21.zig");
pub const nip25 = @import("nip25.zig");
pub const nip27 = @import("nip27.zig");
pub const nip28 = @import("nip28.zig");
pub const nip43 = @import("nip43.zig");
pub const nip46 = @import("nip46.zig");
pub const nip05 = @import("nip05.zig");
pub const nip06 = @import("nip06.zig");
pub const nip10 = @import("nip10.zig");
pub const nip18 = @import("nip18.zig");
pub const nip49 = @import("nip49.zig");
pub const nip57 = @import("nip57.zig");
pub const nip59 = @import("nip59.zig");
pub const nip86 = @import("nip86.zig");
pub const dlc_oracle = @import("dlc_oracle.zig");
pub const clink = @import("clink.zig");
pub const joinstr = @import("joinstr.zig");
pub const custom_emoji = @import("custom_emoji.zig");
pub const ws = @import("ws/ws.zig");
pub const message_queue = @import("message_queue.zig");
pub const pool = @import("pool.zig");
pub const relay = @import("relay.zig");
pub const signer = @import("signer.zig");
pub const nip11 = @import("nip11.zig");
pub const badges = @import("badges.zig");
pub const zap_goal = @import("zap_goal.zig");
pub const file_metadata = @import("file_metadata.zig");
pub const classified_listing = @import("classified_listing.zig");
pub const nip04 = @import("nip04.zig");

const event_mod = @import("event.zig");
const filter_mod = @import("filter.zig");
const messages_mod = @import("messages.zig");
const builder_mod = @import("builder.zig");
const tags_mod = @import("tags.zig");
const auth_mod = @import("auth.zig");
const replaceable_mod = @import("replaceable.zig");
const index_keys_mod = @import("index_keys.zig");

pub const Error = event_mod.Error;
pub const errorMessage = event_mod.errorMessage;

pub const TagValue = tags_mod.TagValue;
pub const TagIndex = tags_mod.TagIndex;
pub const TagIterator = tags_mod.TagIterator;

pub const Event = event_mod.Event;
pub const Kind = event_mod.Kind;
pub const KindType = event_mod.KindType;
pub const kindType = event_mod.kindType;
pub const isExpired = event_mod.isExpired;
pub const isDeletion = event_mod.isDeletion;
pub const isProtected = event_mod.isProtected;
pub const getDeletionIds = event_mod.getDeletionIds;

pub const FilterTagEntry = filter_mod.FilterTagEntry;
pub const Filter = filter_mod.Filter;
pub const filtersMatch = filter_mod.filtersMatch;

pub const ClientMsgType = messages_mod.ClientMsgType;
pub const ClientMsg = messages_mod.ClientMsg;
pub const RelayMsgType = messages_mod.RelayMsgType;
pub const RelayMsgParsed = messages_mod.RelayMsgParsed;
pub const RelayMsg = messages_mod.RelayMsg;

pub const Keypair = builder_mod.Keypair;
pub const EventBuilder = builder_mod.EventBuilder;

pub const Auth = auth_mod.Auth;
pub const Replaceable = replaceable_mod.Replaceable;
pub const IndexKeys = index_keys_mod.IndexKeys;
pub const HttpAuth = http_auth.HttpAuth;

pub const init = event_mod.init;
pub const cleanup = event_mod.cleanup;

pub const stringzilla = @import("stringzilla.zig");
pub const utils = @import("utils.zig");
pub const hex = @import("hex.zig");

// Recursively reference every declaration so the compiler analyzes all function
// bodies, not just the ones with tests. Zig only compiles referenced code, so
// without this an untested pub fn (e.g. a relay/ws client method) can ship
// broken; CI runs `zig build test`, which exercises this. (std dropped the
// recursive variant; this reimplements it for 0.16.)
fn refAllDeclsRecursive(comptime T: type) void {
    inline for (comptime std.meta.declarations(T)) |decl| {
        if (@TypeOf(@field(T, decl.name)) == type) {
            switch (@typeInfo(@field(T, decl.name))) {
                .@"struct", .@"enum", .@"union", .@"opaque" => refAllDeclsRecursive(@field(T, decl.name)),
                else => {},
            }
        }
        _ = &@field(T, decl.name);
    }
}

test {
    @setEvalBranchQuota(1_000_000);
    refAllDeclsRecursive(@import("http_auth.zig"));
    refAllDeclsRecursive(@import("tags.zig"));
    refAllDeclsRecursive(@import("event.zig"));
    refAllDeclsRecursive(@import("filter.zig"));
    refAllDeclsRecursive(@import("messages.zig"));
    refAllDeclsRecursive(@import("builder.zig"));
    refAllDeclsRecursive(@import("auth.zig"));
    refAllDeclsRecursive(@import("replaceable.zig"));
    refAllDeclsRecursive(@import("index_keys.zig"));
    refAllDeclsRecursive(@import("bech32.zig"));
    refAllDeclsRecursive(@import("relay_metadata.zig"));
    refAllDeclsRecursive(@import("external_identities.zig"));
    refAllDeclsRecursive(@import("relay_groups.zig"));
    refAllDeclsRecursive(@import("pow.zig"));
    refAllDeclsRecursive(@import("negentropy.zig"));
    refAllDeclsRecursive(@import("stringzilla.zig"));
    refAllDeclsRecursive(@import("utils.zig"));
    refAllDeclsRecursive(@import("hex.zig"));
    refAllDeclsRecursive(@import("io.zig"));
    refAllDeclsRecursive(@import("nwc.zig"));
    refAllDeclsRecursive(@import("crypto.zig"));
    refAllDeclsRecursive(@import("nip17.zig"));
    refAllDeclsRecursive(@import("nip21.zig"));
    refAllDeclsRecursive(@import("nip25.zig"));
    refAllDeclsRecursive(@import("nip27.zig"));
    refAllDeclsRecursive(@import("nip28.zig"));
    refAllDeclsRecursive(@import("nip43.zig"));
    refAllDeclsRecursive(@import("nip46.zig"));
    refAllDeclsRecursive(@import("nip05.zig"));
    refAllDeclsRecursive(@import("nip06.zig"));
    refAllDeclsRecursive(@import("nip10.zig"));
    refAllDeclsRecursive(@import("nip18.zig"));
    refAllDeclsRecursive(@import("nip49.zig"));
    refAllDeclsRecursive(@import("nip57.zig"));
    refAllDeclsRecursive(@import("nip59.zig"));
    refAllDeclsRecursive(@import("nip86.zig"));
    refAllDeclsRecursive(@import("dlc_oracle.zig"));
    refAllDeclsRecursive(@import("clink.zig"));
    refAllDeclsRecursive(@import("joinstr.zig"));
    refAllDeclsRecursive(@import("custom_emoji.zig"));
    refAllDeclsRecursive(@import("ws/ws.zig"));
    refAllDeclsRecursive(@import("message_queue.zig"));
    refAllDeclsRecursive(@import("pool.zig"));
    refAllDeclsRecursive(@import("relay.zig"));
    refAllDeclsRecursive(@import("signer.zig"));
    refAllDeclsRecursive(@import("nip11.zig"));
    refAllDeclsRecursive(@import("badges.zig"));
    refAllDeclsRecursive(@import("zap_goal.zig"));
    refAllDeclsRecursive(@import("file_metadata.zig"));
    refAllDeclsRecursive(@import("classified_listing.zig"));
    refAllDeclsRecursive(@import("nip04.zig"));
}
