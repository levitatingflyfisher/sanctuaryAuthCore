# Changelog

All notable changes to `sanctuary_auth_core` are documented here. This package
follows [semantic versioning](https://semver.org/); until 1.0.0 the public API
may still shift between minor versions.

## 0.1.0

First consumable release — the Ghost tier in full plus the client-side Sync
tier foundations.

### Added

- **BIP39 mnemonic** — 12-word seed generation (`Random.secure`), validation,
  and PBKDF2-HMAC-SHA512 seed derivation (`OpenHearthMnemonic`).
- **HKDF-SHA256 key derivation** (`KeyDerivation` / `DerivedKeys`) — five
  domain-separated 32-byte keys from one 64-byte seed: master-encryption,
  sync, auth, recovery, and sync-channel-id. `syncKey` is deliberately
  distinct from `masterEncryptionKey` so a nonce-reuse bug in one path cannot
  compromise the other. All legacy info strings are frozen and pinned by
  known-answer vectors.
  - Optional per-app `appDomain` on `fromSeed` / `deriveSyncChannelId` shifts
    every info string to `openhearth.<appDomain>.<purpose>.v1`, isolating one
    app's keys from another's under a shared household seed. `appDomain` must
    be `[a-z0-9]+` (rejected otherwise, preventing info-string ambiguity);
    `null` reproduces the legacy derivation byte-for-byte. Threaded through
    `CryptoService.deriveKeysFromPhrase` and `AuthNotifier` via the new
    `sanctuaryAppDomainProvider` (defaults to null; apps override at root).
  - `KeyDerivation.deriveKey(secret, domain:)` — general-purpose HKDF-SHA256
    (empty salt, `info = utf8(domain)`) → 32 bytes, for non-BIP39 secrets
    (e.g. StillLife's LAN-sync code). Rejects an empty secret or domain.
- **ChaCha20-Poly1305 envelope cipher** (`EnvelopeCipher` / `CipherEnvelope`)
  — authenticated encryption with optional additional-authenticated-data,
  built on the pure-Dart `cryptography` package.
- **OHBK backup format** (`GhostBackup`) — versioned, cipher-suite-tagged
  binary blob. Wire version 2 binds `header ‖ utf8(context)` as AEAD
  additional data so a blob encrypted for one purpose can never be replayed
  into another (each app uses a distinct `<appId>-backup/v1` context). Legacy
  v1 blobs (no AAD binding) are still accepted on import for pilot-build
  compatibility. Both `export` and `import` enforce the same 10 MB ceiling —
  `export` fails closed (before encrypting) rather than producing a blob its
  own `import` would reject.
- **Sync tier foundations**
  - `threeWayMerge` — pure, deterministic full-dump 3-way last-writer-wins
    merge. Ties resolve to the local row; hostile future timestamps beyond
    `now + 24h` are clamped to `now`; an allow-list drops peer-injected
    unknown tables; merged rows are id-sorted for byte-stable re-uploads.
  - `SyncService` / `CloudflareSyncService` — an http-only encrypted-blob
    relay client (`syncServiceProvider` throws until an app overrides it; no
    relay is deployed).
  - `sync_orchestrator` (download → merge → upload) and `device_id`
    (`Random.secure` UUIDv4).
- **Secure key store** (`SecureKeyStore` / `FlutterSecureKeyStore`) — a
  `flutter_secure_storage` wrapper with versioned key names for
  forward-compatible migrations.
- **Auth state machine** (`AuthNotifier` / `AuthState` / `AuthTier`) — a
  keep-alive Riverpod notifier for ghost / token / named state, seed
  generation with re-entry confirmation, backup acknowledgement, and identity
  reset. Key material is memory-only, defensive-copied, never serialized.
- **Crypto service seam** (`CryptoService` / `DefaultCryptoService` /
  `cryptoServiceProvider`) — an injectable, mockable abstraction over the
  CPU-heavy mnemonic and derivation calls.
- **Sealed exception hierarchy** (`SanctuaryAuthException` and subclasses) so
  consumers can catch one type and show a calm, specific message.
