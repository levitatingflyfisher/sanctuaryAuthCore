import 'package:flutter_secure_storage/flutter_secure_storage.dart';

/// Storage key for the BIP39 mnemonic phrase.
const _kMnemonic = 'oh_mnemonic_v1';

/// Storage key for the last backup timestamp (ISO 8601).
const _kLastBackup = 'oh_last_backup_v1';

/// Storage key for seed-phrase acknowledgement flag.
const _kSeedAck = 'oh_seed_ack_v1';

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

  /// Wipes all stored values from the OS keychain.
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
    return raw == null ? null : DateTime.parse(raw);
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
  Future<void> clearAll() => _storage.deleteAll();
}
