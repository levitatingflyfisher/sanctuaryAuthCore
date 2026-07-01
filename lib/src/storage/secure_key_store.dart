import 'package:flutter_secure_storage/flutter_secure_storage.dart';

import '../exceptions.dart';

// ---------------------------------------------------------------------------
// Keychain key naming convention & migration strategy
// ---------------------------------------------------------------------------
//
// All keys use the pattern: oh_<name>_v<N>
//
// - "oh_" prefix scopes our keys away from host-app or third-party entries.
// - The version suffix (_v1, _v2, …) enables safe format migrations.
//
// To migrate a key's format:
//   1. Introduce a new constant with an incremented version (e.g. _kFoo_v2).
//   2. In the *read* path, try the new key first; if null, read the old key,
//      convert the value to the new format, write it under the new key, and
//      delete the old key. This one-shot migration runs lazily on first access.
//   3. The *write* path always writes the latest version.
//   4. Update [clearAll] to delete both old and new keys during the transition
//      period. Once the prior version can no longer exist on any user device,
//      remove the old constant and its read fallback.
//
// To add a new key: just create it with _v1. No migration needed.
//
// To remove a key: delete it in [clearAll], remove its read/write methods,
// and leave a delete call in clearAll for one release cycle so existing
// values get cleaned up.
// ---------------------------------------------------------------------------

/// Storage key for the BIP39 mnemonic phrase.
const _kMnemonic = 'oh_mnemonic_v1';

/// Storage key for the last backup timestamp (ISO 8601).
const _kLastBackup = 'oh_last_backup_v1';

/// Storage key for seed-phrase acknowledgement flag.
const _kSeedAck = 'oh_seed_ack_v1';

/// Storage key for the unique device identifier (UUID v4).
const _kDeviceId = 'oh_device_id_v1';

/// OS-keychain abstraction for OpenHearth secret material.
///
/// All methods are asynchronous because the underlying platform APIs
/// (Keychain on iOS, EncryptedSharedPreferences on Android) are async.
abstract interface class SecureKeyStore {
  /// Persists the BIP39 mnemonic [phrase] in the OS keychain.
  Future<void> writeMnemonic(String phrase);

  /// Returns the stored mnemonic, or `null` if none has been written.
  Future<String?> readMnemonic();

  /// Records the timestamp [ts] of the most recent encrypted backup.
  Future<void> writeLastBackupAt(DateTime ts);

  /// Returns the last backup timestamp, or `null` if no backup has occurred.
  Future<DateTime?> readLastBackupAt();

  /// Marks the seed phrase as acknowledged by the user.
  Future<void> writeSeedAcknowledged();

  /// Returns `true` if the user has acknowledged the seed phrase, `false` otherwise.
  Future<bool> readSeedAcknowledged();

  /// Persists a unique [id] for this device (UUID v4 string).
  ///
  /// The device ID distinguishes "device A's dump" from "device B's dump" on
  /// the sync relay. It is NOT a user identity.
  Future<void> writeDeviceId(String id);

  /// Returns the stored device ID, or `null` if none has been written.
  Future<String?> readDeviceId();

  /// Clears auth-related keys (mnemonic, backup timestamp, seed ack) but
  /// preserves the device ID.
  ///
  /// Use this for identity resets — the device is the same device after
  /// the user re-generates their seed phrase.
  Future<void> clearAuth();

  /// Wipes ALL OpenHearth-managed values from the OS keychain, including
  /// the device ID.
  ///
  /// Use this for full factory reset or when the device is being sold.
  /// Only deletes keys with the `oh_` prefix — other keychain entries
  /// (from the host app or other packages) are left untouched.
  Future<void> clearAll();
}

/// Production [SecureKeyStore] backed by [FlutterSecureStorage].
///
/// DateTime values are stored as ISO 8601 strings. The seed-acknowledged
/// flag is stored as the literal string `'true'`.
class FlutterSecureKeyStore implements SecureKeyStore {
  final FlutterSecureStorage _storage;

  /// Creates a [FlutterSecureKeyStore].
  ///
  /// An optional [storage] instance may be provided for testing;
  /// defaults to `const FlutterSecureStorage()`.
  FlutterSecureKeyStore([FlutterSecureStorage? storage])
      : _storage = storage ?? const FlutterSecureStorage();

  @override
  Future<void> writeMnemonic(String phrase) =>
      _storage.write(key: _kMnemonic, value: phrase);

  @override
  Future<String?> readMnemonic() => _storage.read(key: _kMnemonic);

  @override
  Future<void> writeLastBackupAt(DateTime ts) =>
      _storage.write(key: _kLastBackup, value: ts.toIso8601String());

  @override
  Future<DateTime?> readLastBackupAt() async {
    final raw = await _storage.read(key: _kLastBackup);
    if (raw == null) return null;
    try {
      return DateTime.parse(raw);
    } on FormatException catch (e) {
      throw KeyStoreException(
        'Corrupt lastBackupAt value in keychain: "$raw"',
        cause: e,
      );
    }
  }

  @override
  Future<void> writeSeedAcknowledged() =>
      _storage.write(key: _kSeedAck, value: 'true');

  @override
  Future<bool> readSeedAcknowledged() async {
    final raw = await _storage.read(key: _kSeedAck);
    return raw == 'true';
  }

  @override
  Future<void> writeDeviceId(String id) =>
      _storage.write(key: _kDeviceId, value: id);

  @override
  Future<String?> readDeviceId() => _storage.read(key: _kDeviceId);

  @override
  Future<void> clearAuth() => Future.wait([
        _storage.delete(key: _kMnemonic),
        _storage.delete(key: _kLastBackup),
        _storage.delete(key: _kSeedAck),
      ]);

  @override
  Future<void> clearAll() => Future.wait([
        _storage.delete(key: _kMnemonic),
        _storage.delete(key: _kLastBackup),
        _storage.delete(key: _kSeedAck),
        _storage.delete(key: _kDeviceId),
      ]);
}
