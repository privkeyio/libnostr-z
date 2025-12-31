# libnostr-z

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Zig](https://img.shields.io/badge/Zig-0.15-orange.svg)](https://ziglang.org/)

A Zig library for the Nostr protocol.

## NIP Support

| NIP | Description | Implementation |
|-----|-------------|----------------|
| [01](https://github.com/nostr-protocol/nips/blob/master/01.md) | Basic Protocol | Events, filters, client/relay messages |
| [06](https://github.com/nostr-protocol/nips/blob/master/06.md) | Basic Key Derivation | `nip06.keypairFromMnemonic` |
| [09](https://github.com/nostr-protocol/nips/blob/master/09.md) | Event Deletion | `isDeletion`, `getDeletionIds` |
| [16](https://github.com/nostr-protocol/nips/blob/master/16.md) | Replaceable Events | `Replaceable`, `kindType` (includes addressable) |
| [19](https://github.com/nostr-protocol/nips/blob/master/19.md) | bech32 Entities | npub, nsec, nprofile, nevent, naddr |
| [40](https://github.com/nostr-protocol/nips/blob/master/40.md) | Expiration Timestamp | `isExpired` |
| [42](https://github.com/nostr-protocol/nips/blob/master/42.md) | Authentication | `Auth` utilities, AUTH message |
| [44](https://github.com/nostr-protocol/nips/blob/master/44.md) | Encrypted Payloads | `crypto.nip44Encrypt`, `crypto.nip44Decrypt` |
| [45](https://github.com/nostr-protocol/nips/blob/master/45.md) | Event Counts | COUNT message |
| [46](https://github.com/nostr-protocol/nips/blob/master/46.md) | Remote Signing | `nip46` module |
| [47](https://github.com/nostr-protocol/nips/blob/master/47.md) | Wallet Connect | `nwc` module |
| [50](https://github.com/nostr-protocol/nips/blob/master/50.md) | Search | Filter `search` field |
| [63](https://github.com/nostr-protocol/nips/blob/master/63.md) | Index Keys | `IndexKeys` utilities |
| [65](https://github.com/nostr-protocol/nips/blob/master/65.md) | Relay List Metadata | `relay_metadata` module |
| [70](https://github.com/nostr-protocol/nips/blob/master/70.md) | Protected Events | `isProtected` |
| [77](https://github.com/nostr-protocol/nips/blob/master/77.md) | Negentropy | Full protocol support |
| [86](https://github.com/nostr-protocol/nips/blob/master/86.md) | Relay Management API | `nip86` module |
| [98](https://github.com/nostr-protocol/nips/blob/master/98.md) | HTTP Auth | NIP-86 auth validation |
| [2022](https://gitlab.com/invincible-privacy/joinstr) | Joinstr Coinjoin Pools | `joinstr` module |
| [CLINK](https://github.com/shocknet/CLINK) | Common Lightning Interface for Nostr Keys | `clink` module |

## Build

```shell
zig build
```

## Test

```shell
zig build test
```

## Usage

```zig
const nostr = @import("nostr");

// Initialize crypto
try nostr.init();
defer nostr.cleanup();

// Generate keypair
const keypair = nostr.Keypair.generate();

// Or derive from mnemonic (NIP-06)
const mnemonic = "leader monkey parrot ring guide accident before fence cannon height naive bean";
const derived = try nostr.nip06.keypairFromMnemonic(mnemonic, "", 0);

// Build and sign an event
var builder = nostr.EventBuilder{};
_ = builder.setKind(1).setContent("Hello Nostr!");
try builder.sign(&keypair);

var buf: [4096]u8 = undefined;
const json = try builder.serialize(&buf);

// Parse an event
var event = try nostr.Event.parse(json);
defer event.deinit();
try event.validate();

// Parse client messages
var msg = try nostr.ClientMsg.parse(raw_json);
defer msg.deinit();

// Create relay responses
const response = try nostr.RelayMsg.ok(event.id(), true, "", &buf);

// Connect to a single relay
var relay = try nostr.Relay.init(allocator, "wss://relay.example.com", .{});
defer relay.deinit();
try relay.connect();

// Or use a pool for multiple relays
var pool = nostr.Pool.init(allocator);
defer pool.deinit();
try pool.addRelay("wss://relay1.example.com");
try pool.addRelay("wss://relay2.example.com");
_ = try pool.connectAll();
```

## Projects Using libnostr-z

- [wisp](https://github.com/privkeyio/wisp) - Fast, lightweight nostr relay
- [nostr-bench](https://github.com/privkeyio/nostr-bench) - Nostr relay benchmark tool
- [puck](https://github.com/privkeyio/puck) - NIP-47 Wallet Connect server with LNbits backend

## License

MIT - See [LICENSE](LICENSE)

## Acknowledgments

Powered by [noscrypt](https://github.com/VnUgE/noscrypt) for cryptographic operations.
