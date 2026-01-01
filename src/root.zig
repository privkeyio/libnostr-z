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
//! - `utils.zig` - JSON parsing utilities
//! - `crypto.zig` - Cryptographic operations
//! - `negentropy.zig` - NIP-77 negentropy protocol
//! - `pow.zig` - NIP-13 Proof of Work
//! - `nwc.zig` - NIP-47 Nostr Wallet Connect
//! - `nip28.zig` - NIP-28 Public Chat
//! - `nip46.zig` - NIP-46 Nostr Remote Signing
//! - `clink.zig` - CLINK protocol types and error codes
//! - `joinstr.zig` - NIP Joinstr (Kind 2022) coinjoin pools
//! - `message_queue.zig` - Thread-safe message queue for multi-relay architecture
//! - `pool.zig` - Multi-relay pool with event deduplication and parallel queries
//! - `relay.zig` - High-level relay abstraction with connection management
//! - `signer.zig` - Abstract signer interface for NIP-07/NIP-46/hardware wallets

pub const crypto = @import("crypto.zig");
pub const negentropy = @import("negentropy.zig");
pub const bech32 = @import("bech32.zig");
pub const relay_metadata = @import("relay_metadata.zig");
pub const pow = @import("pow.zig");
pub const nwc = @import("nwc.zig");
pub const nip28 = @import("nip28.zig");
pub const nip46 = @import("nip46.zig");
pub const nip06 = @import("nip06.zig");
pub const nip57 = @import("nip57.zig");
pub const nip86 = @import("nip86.zig");
pub const clink = @import("clink.zig");
pub const joinstr = @import("joinstr.zig");
pub const ws = @import("ws/ws.zig");
pub const message_queue = @import("message_queue.zig");
pub const pool = @import("pool.zig");
pub const relay = @import("relay.zig");
pub const signer = @import("signer.zig");

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

pub const init = event_mod.init;
pub const cleanup = event_mod.cleanup;

pub const stringzilla = @import("stringzilla.zig");
pub const utils = @import("utils.zig");
pub const hex = @import("hex.zig");

test {
    _ = @import("tags.zig");
    _ = @import("event.zig");
    _ = @import("filter.zig");
    _ = @import("messages.zig");
    _ = @import("builder.zig");
    _ = @import("auth.zig");
    _ = @import("replaceable.zig");
    _ = @import("index_keys.zig");
    _ = @import("bech32.zig");
    _ = @import("relay_metadata.zig");
    _ = @import("pow.zig");
    _ = @import("negentropy.zig");
    _ = @import("stringzilla.zig");
    _ = @import("utils.zig");
    _ = @import("hex.zig");
    _ = @import("nwc.zig");
    _ = @import("crypto.zig");
    _ = @import("nip28.zig");
    _ = @import("nip46.zig");
    _ = @import("nip06.zig");
    _ = @import("nip57.zig");
    _ = @import("nip86.zig");
    _ = @import("clink.zig");
    _ = @import("joinstr.zig");
    _ = @import("ws/ws.zig");
    _ = @import("message_queue.zig");
    _ = @import("pool.zig");
    _ = @import("relay.zig");
    _ = @import("signer.zig");
}
