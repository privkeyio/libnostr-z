# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Thread-safe message queue for multi-relay architecture

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
[0.1.1]: https://github.com/privkeyio/libnostr-z/compare/0.1.0...v0.1.1
[0.1.0]: https://github.com/privkeyio/libnostr-z/releases/tag/0.1.0
