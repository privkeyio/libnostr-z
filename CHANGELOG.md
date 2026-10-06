# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- StringZilla is pinned by commit (`7ca3964`, the commit tag v4.5.1 points to) instead of by tag. The content hash is unchanged.

## [0.5.0] - 2026-10-06

Builds with Zig 0.17 as well as 0.16, and finishes the field-confusion fix from 0.4.0 in the client-side NIP-17, NIP-28, NIP-57, NWC and CLINK helpers. Some of their public types change, so this is a minor version bump.

### Changed

- Builds with Zig 0.17.0 as well as 0.16.0. C headers are translated through `b.addTranslateC` modules (`noscrypt_c`, `openssl_c`) instead of `@cImport`, which 0.17 removes, and array repetition (`**`) gives way to `@splat`. CI tests both compiler versions.
- **Breaking:** NIP-17 `ReceiverIterator` and `RelayIterator` and NIP-28 `ETagIterator` hold a `TagIterator` (`tags`) instead of `json`/`pos`. NIP-57 `ValidationError` gains `InvalidTags`, and `validateServer` returns it for missing or malformed tags (missing tags used to pass). NIP-17 hex tag values must be exactly 64 characters (the first 64 of a longer value were accepted), and `RelayIterator` skips an empty relay value instead of stopping.

### Security

- Client-side tag readers in NIP-17 (`parseGiftWrapRecipient`, `parseReplyTo`, `parseSubject`, `parseFileMetadata`, `ReceiverIterator`, `RelayIterator`), NIP-28 (`ETagIterator`, `parseMutedPubkey` and the channel/reply/hidden reference helpers) and NIP-57 (zap receipt `description`, zap split relay and weight) now read only the event's top-level `tags` member instead of searching the whole JSON, so a decoy member added to a validly signed event can no longer substitute the recipient, reply target, relay list, zap request description or split destination. These readers, `ZapRequest.fromEvent`, `ZapReceipt.fromEvent`, `ZapRequest.validateServer` (new `InvalidTags` error) and `parseZapSplits` also reject events whose tags are malformed. NWC `Response.parseJson` and CLINK `OffersResponse.parse` reject responses that are malformed or repeat `error`, `result`, `result_type`, `bolt11` or `preimage`, which were previously read as successful, and `OffersResponse.parse` treats any non-null `error` as a failure. `utils.findStringEnd` now scans byte-wise like `skipJsonValue` instead of skipping over a closing quote after a non-ASCII byte, and `TagIterator` gains `initStrict` and a `Tag.raw` field for reading tag elements past the second.
- NIP-57 zap requests with more than one `amount` tag, or one that is not plain digits, are rejected rather than skipping the amount check. `validateServer` rejects an escaped tag name or a `p`, `P` or `e` value that is not 64 hex characters, since those were counted differently than by a client that decodes them. Zap receipts that repeat `bolt11`, `description`, `preimage` or `P` are rejected, since clients disagree on which copy wins.

## [0.4.0] - 2026-10-05

Fixes a NIP-42 / NIP-98 authentication bypass and several ways a remote peer could crash or hang a relay, and makes `limit: 0` distinguishable as NIP-01 now requires. `Filter.limit()` changes type, so this is a minor version bump.

### Added

- NIP-86 `Method` gains `unbanpubkey`, `unallowpubkey`, `unbanevent`, `unallowevent`, `listallowedevents` and `listdisallowedkinds`, matching the current spec.

### Changed

- NIP-86 `Request.parse` reads `method` and `params` only from the request's top-level members and rejects a malformed body or duplicate keys.
- `Event.parse` rejects malformed events it used to accept: duplicate known fields (`InvalidJson`), tags that are not an array of arrays of strings (`InvalidTags`), a non-string `content` (`InvalidContent`), hex fields with trailing characters, and non-integer `kind` or `created_at`.
- `utils.findJsonValue`, `extractJsonString`, `findJsonFieldStart`, `extractHexField`, `extractIntField` and `TagIterator.init` search only the top level of the given JSON object. They return null when the input is not a well-formed object, when the key is duplicated, or when any key contains an escape.
- `TagIterator` is iterative rather than recursive, skips empty tags, and stops at the first malformed tag (it used to skip it and continue), setting `malformed`.
- `Auth.extractTags`, `Nip98Tags.extract` and `HttpAuth.extractTags` return an empty result when any tag is malformed, and the first two ignore tags whose value is an empty string.
- An event's `d` tag longer than 250 bytes is now kept. It used to become null, so relays keyed every such addressable event under an empty `d`; events stored that way keep their old key and are not replaced by newer versions.
- **Breaking:** `Filter.limit_val` is now `?u32` and `Filter.limit()` returns `?u32`, so a filter with `"limit": 0` is distinct from one with no limit. NIP-01 now requires relays to return no stored events for `limit: 0`. `serialize` emits `limit` whenever it is set, including 0. A negative `limit` is ignored.

### Fixed

- Parsing a filter no longer panics (ReleaseSafe, Debug) or invokes undefined behavior (ReleaseFast) on an out-of-range integer. A `limit` above `u32` max is clamped to it. A negative `COUNT` from a relay parses as 0.
- `kinds` entries that are out of `i32` range or not integers are dropped, and an `ids`, `authors` or `kinds` array that is non-empty but has no usable entries now matches nothing instead of being treated as absent (which matched everything).
- Negentropy `reconcile` rejects an unknown mode byte (previously a panic, or undefined behavior in ReleaseFast) and a varint that decodes to zero length (previously an infinite loop that pinned the calling thread).

### Security

- Event fields are now read only from the event's own top-level members. Previously each field was located by a substring search for its key, and the search used for the event ID hash differed from the ones used for tags, so extra members could carry decoy values: a decoy `"tags"` was read by `Auth.extractTags`, `Nip98Tags.extract` and the tag index while the signature still covered the real tags. A NIP-42 AUTH or NIP-98 event signed for another service could therefore be presented as one for this relay, and a third party could republish a signed event with altered `-`, `expiration`, `d` or `e` tags. Event parsing and the tag readers in `Auth`, `Nip98Tags`, `HttpAuth`, NIP-43 and the NIP-57 `relays` lookup now share one scanner (`utils.findTopLevelFields`) that walks only the top-level object, never looks inside strings or nested values, and rejects duplicate and escaped keys.

## [0.3.7] - 2026-08-11

### Fixed

- Loading records into a negentropy `VectorStorage` is now linear rather than quadratic. Each `insert` placed the record at its sorted position, moving every element after it, so a caller adding in descending order put every record at index 0 and shifted the whole array. Records are appended and the collection is sorted lazily instead. The ordering contract is unchanged: NIP-77 order is restored on any read, so callers that never call `seal()` are unaffected, and `seal()` still works and is idempotent (#138)

## [Unreleased before 0.2.0]

_Note: this section predates the 0.2.x and 0.3.x releases and was never moved under a version heading. Its contents shipped in those releases; the exact mapping was not recorded at the time._

### Added

- NIP-28 public chat support
- NIP-57 Lightning Zaps support
- NIP-06 mnemonic key derivation
- NIP-86 relay management protocol support
- High-level relay abstraction with connection management
- Multi-relay pool with thread-safe connection management
- Thread-safe message queue for multi-relay architecture

### Changed

- Added projects using libnostr-z to README

## [0.1.8] - 2025-12-17

### Added

- More comprehensive tests

### Fixed

- Bug fixes and improvements

## [0.1.7] - 2025-12-16

### Added

- WebSocket module with OpenSSL TLS support

## [0.1.6] - 2025-12-16

### Added

- Kind 2022 Joinstr coinjoin pool support
- CLINK error codes and GFY codes
- NIP-46 Nostr Connect support

### Changed

- Use SIMD hex.encode() instead of byte-by-byte formatting

## [0.1.5] - 2025-12-15

### Added

- NIP-44 encrypted payloads support
- NIP-47 Nostr Wallet Connect support
- SIMD-accelerated hex codec for event IDs/signatures
- StringZilla for NIP-50 search with UTF-8 fallback
- Zero-allocation JSON field extraction

### Fixed

- macOS ARM64 build by disabling NEON AES/SHA intrinsics

### Changed

- Use StringZilla SHA256 for event ID hashing

## [0.1.4] - 2025-12-15

### Added

- NIP-13 proof of work support
- NIP-65 relay list metadata support
- NIP-70 protected events support

### Changed

- Updated README for MIT license

## [0.1.3] - 2025-12-14

### Added

- Bech32/NIP-19 decoding support

### Changed

- Updated noscrypt to use static linking

## [0.1.2] - 2025-12-14

### Added

- Negentropy protocol implementation (NIP-77)

### Changed

- Renamed nostr.zig to root.zig for Zig package convention
- Reorganized nostr.zig into modular files
- Support case-sensitive single-letter tags per NIP-01

## [0.1.1] - 2025-12-13

### Added

- Relay utilities: Auth, Replaceable, IndexKeys
- GitHub CI workflow
- NIP-50 search support

## [0.1.0] - 2025-12-11

### Added

- Initial release of libnostr-z
- Core Nostr event handling and validation
- NIP-01 basic protocol support
- Cryptographic signing and verification via noscrypt
- Filter matching for subscriptions
- Event serialization and parsing

[Unreleased]: https://github.com/privkeyio/libnostr-z/compare/v0.1.8...HEAD
[0.1.8]: https://github.com/privkeyio/libnostr-z/compare/v0.1.7...v0.1.8
[0.1.7]: https://github.com/privkeyio/libnostr-z/compare/v0.1.6...v0.1.7
[0.1.6]: https://github.com/privkeyio/libnostr-z/compare/v0.1.5...v0.1.6
[0.1.5]: https://github.com/privkeyio/libnostr-z/compare/v0.1.4...v0.1.5
[0.1.4]: https://github.com/privkeyio/libnostr-z/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/privkeyio/libnostr-z/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/privkeyio/libnostr-z/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/privkeyio/libnostr-z/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/privkeyio/libnostr-z/releases/tag/0.1.0
