/// OpenHearth Ghost-tier identity primitives.
///
/// Public API for consuming apps:
///   - [authNotifierProvider] — Riverpod provider for auth state
///   - [AuthNotifier] — state manager (generate seed, confirm ack, record backup)
///   - [AuthState] — immutable state model
///   - [AuthTier] — ghost / token / named
///   - [SecureKeyStore] / [FlutterSecureKeyStore] — keychain abstraction (for testing overrides)
///   - [secureKeyStoreProvider] — Riverpod provider (override in tests)
///   - [GhostBackup] — export/import encrypted blob
///   - [EnvelopeCipher] / [CipherEnvelope] — raw encrypt/decrypt
///   - [SyncBackend] / [NoopSyncBackend] — sync interface
library;

export 'src/state/auth_tier.dart';
export 'src/state/auth_state.dart';
export 'src/state/auth_notifier.dart';
export 'src/storage/secure_key_store.dart';
export 'src/storage/secure_key_store_provider.dart';
export 'src/backup/ghost_backup.dart';
export 'src/crypto/envelope_cipher.dart';
export 'src/sync/sync_backend.dart';
