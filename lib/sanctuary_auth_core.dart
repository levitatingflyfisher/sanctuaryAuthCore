/// OpenHearth identity primitives — Ghost tier + Sync tier foundations.
///
/// Public API for consuming apps:
///   - [authNotifierProvider] — Riverpod provider for auth state
///   - [AuthNotifier] — state manager (generate seed, confirm ack, record backup)
///   - [AuthState] — immutable state model (includes [syncChannelId])
///   - [AuthTier] — ghost / token / named
///   - [SecureKeyStore] / [FlutterSecureKeyStore] — keychain abstraction (for testing overrides)
///   - [secureKeyStoreProvider] — Riverpod provider (override in tests)
///   - [GhostBackup] — export/import encrypted blob
///   - [EnvelopeCipher] / [CipherEnvelope] — raw encrypt/decrypt
///   - [OpenHearthMnemonic] — BIP39 mnemonic generate / validate / derive
///   - [DerivedKeys] / [KeyDerivation] — HKDF domain-separated keys
///   - [SyncService] / [CloudflareSyncService] — encrypted blob relay client
///   - [syncServiceProvider] — Riverpod provider (override at root ProviderScope)
library;

export 'src/state/auth_tier.dart';
export 'src/state/auth_state.dart';
export 'src/state/auth_notifier.dart';
export 'src/storage/secure_key_store.dart';
export 'src/storage/secure_key_store_provider.dart';
export 'src/exceptions.dart';
export 'src/backup/ghost_backup.dart';
export 'src/bip39/mnemonic.dart';
export 'src/crypto/envelope_cipher.dart';
export 'src/crypto/crypto_service.dart';
export 'src/crypto/key_derivation.dart';
export 'src/sync/sync_service.dart';
export 'src/sync/cloudflare_sync_service.dart';
export 'src/sync/sync_service_provider.dart';
export 'src/sync/three_way_merge.dart';
export 'src/sync/sync_orchestrator.dart';
export 'src/sync/device_id.dart';
export 'src/util/hex.dart';
