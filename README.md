# libnostr-z

[![License: LGPL v2.1](https://img.shields.io/badge/License-LGPL%20v2.1-blue.svg)](https://www.gnu.org/licenses/lgpl-2.1)
[![Zig](https://img.shields.io/badge/Zig-0.15-orange.svg)](https://ziglang.org/)

A Zig library for the Nostr protocol.

## Features

- Event parsing, validation, and serialization
- Event signing with schnorr signatures (via noscrypt)
- Filter matching with NIP-50 search support
- Client message parsing (EVENT, REQ, CLOSE, AUTH, COUNT, NEG-OPEN, NEG-MSG, NEG-CLOSE)
- Relay message serialization (EVENT, OK, EOSE, CLOSED, NOTICE, AUTH, COUNT, NEG-MSG, NEG-ERR)
- Keypair generation
- Event builder for creating signed events
- NIP-42 authentication utilities
- NIP-16 replaceable event handling
- NIP-63 index key generation
- NIP-77 negentropy protocol support
- Case-sensitive single-letter tag indexing (NIP-01)

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
```

## License

LGPL v2.1 - See [LICENSE](LICENSE)

## Acknowledgments

Powered by [noscrypt](https://github.com/VnUgE/noscrypt) for cryptographic operations.
