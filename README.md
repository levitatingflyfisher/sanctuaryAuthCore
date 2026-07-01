# sanctuary_auth_core

Ghost-tier identity primitives for the OpenHearth family app suite.

This package implements the **Ghost** tier of OpenHearth's three-tier auth
model: local-only, no account, no server contact, no PII. It provides the
building blocks every OpenHearth app needs to derive keys, encrypt local data,
and export encrypted backups — without ever requiring the user to create an
account.

Sync and Named tiers (cross-device encrypted relay and passkey-linked accounts)
will be built on top of these primitives when needed.

## The three-tier model

| Tier | Identity | Server contact | Storage | Use case |
|------|----------|---------------|---------|----------|
| **Ghost** | None | Zero | Local only | Default. No account ever required. |
| **Sync** | Shared seed phrase | Encrypted blobs only | Encrypted blob relay (vendor-agnostic) | Cross-device sync, no PII |
| **Named** | Linked email/passkey | Same UUID preserved | Same blobs + optional profile | Account recovery, family sharing |

This package covers the Ghost tier in full. Token and Named tier
implementations plug into the `CryptoService` seam when they ship.

## What's inside

- **BIP39 mnemonic** — 12-word seed generation, validation, and PBKDF2-HMAC-SHA512 seed derivation.
- **HKDF-SHA256 key derivation** — five domain-separated 32-byte keys (master-encryption, sync, auth, recovery, sync-channel-id) from one 64-byte seed. Optional per-app `appDomain` isolates one app's keys from another's under the same seed.
- **ChaCha20-Poly1305 envelope cipher** — authenticated encryption via the pure-Dart `cryptography` package, with optional AAD.
- **OHBK ghost backup format** — versioned, cipher-suite-tagged binary blob for exporting and restoring Ghost-tier state.
- **Secure key store** — `flutter_secure_storage` wrapper with versioned key names for forward-compatible migrations.
- **Auth state machine** — Riverpod `AsyncNotifier` tracking ghost / token / named state, seed generation, backup acknowledgement, and identity reset.
- **Crypto service seam** — `CryptoService` abstraction with a `DefaultCryptoService` for testable injection.

## Install

This package is not yet published to pub.dev. Use a path dependency:

```yaml
dependencies:
  sanctuary_auth_core:
    path: ../../packages/sanctuary_auth_core
```

## Quick start

Wrap your app in a `ProviderScope` and use `authNotifierProvider` to read and
mutate auth state:

```dart
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:sanctuary_auth_core/sanctuary_auth_core.dart';

void main() {
  runApp(const ProviderScope(child: MyApp()));
}

class HomeScreen extends ConsumerWidget {
  const HomeScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final authAsync = ref.watch(authNotifierProvider);

    return authAsync.when(
      loading: () => const CircularProgressIndicator(),
      error: (e, _) => Text('Auth error: $e'),
      data: (state) => switch (state.tier) {
        AuthTier.ghost => ElevatedButton(
            onPressed: () async {
              final phrase = await ref
                  .read(authNotifierProvider.notifier)
                  .generateSeedPhrase();
              // Show `phrase` to the user, have them write it down,
              // then call confirmSeedAcknowledged().
            },
            child: const Text('Enable backup'),
          ),
        AuthTier.token || AuthTier.named => const Text('Signed in'),
      },
    );
  }
}
```

### Exporting and importing a ghost backup

```dart
final cipher = EnvelopeCipher();

// Export: derive a backup key from the seed phrase, encrypt all local state.
final blob = await GhostBackup.export(localSnapshot, derivedKeys.masterEncryptionKey, cipher);
// Hand `blob` to the user — they save it anywhere (email to self, USB, etc).

// Import on a new device: user enters their 12-word phrase, same derivation
// produces the same key, same blob decrypts.
final recovered = await GhostBackup.import(blob, derivedKeys.masterEncryptionKey, cipher);
```

## Testing

Most tests are plain `flutter test` with the default key store.

Tests that need to bypass the platform keychain can override
`secureKeyStoreProvider` with a mock (this package's own test suite uses
`mocktail`):

```dart
class _MockKeyStore extends Mock implements SecureKeyStore {}

final container = ProviderContainer(overrides: [
  secureKeyStoreProvider.overrideWithValue(_MockKeyStore()),
]);
```

Run the suite:

```bash
flutter test
```

## Public API surface

Everything reachable is re-exported from `package:sanctuary_auth_core/sanctuary_auth_core.dart`.

| Area | Exports |
|------|---------|
| State | `AuthTier`, `AuthState`, `AuthNotifier`, `authNotifierProvider` |
| Storage | `SecureKeyStore`, `FlutterSecureKeyStore`, `secureKeyStoreProvider` |
| Backup | `GhostBackup` |
| Mnemonic | `OpenHearthMnemonic` |
| Crypto | `EnvelopeCipher`, `CipherEnvelope`, `KeyDerivation`, `DerivedKeys` |
| Crypto service | `CryptoService`, `DefaultCryptoService`, `cryptoServiceProvider` |
| Exceptions | `SanctuaryAuthException` and subclasses |

## Platform notes

This package is **Flutter-bound**, not pure Dart: `flutter_secure_storage`,
`flutter_riverpod`, and `riverpod_annotation` are hard dependencies, so
consumers run `flutter test`, not `dart test`. The cryptographic primitives
themselves (`cryptography`, `bip39_mnemonic`) are pure Dart and web/WASM
compatible.

**Web performance caveat.** On web there is no WebCrypto path for
ChaCha20-Poly1305, so the `cryptography` package falls back to a pure-Dart
implementation, and PBKDF2 (seed derivation) and HKDF run on the main
isolate. This is fine for user-initiated, occasional operations — generating a
seed, exporting a small backup. It will jank the UI for multi-megabyte blobs
on web; move large encrypts off the main isolate if that ever becomes a
concern.

## Status

Ghost tier: **feature complete**.
Sync tier: **client foundations complete** (3-way LWW merge, blob-relay
client, orchestrator) — the encrypted-blob relay itself (vendor-agnostic, no
BaaS) is not yet deployed.
Named tier: not started (passkeys + identity layer).

## License

MIT — Copyright (c) 2026 OpenHearth contributors. See [LICENSE](LICENSE).
