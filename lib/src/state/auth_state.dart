import 'package:flutter/foundation.dart';

import '../util/hex.dart';
import 'auth_tier.dart';

/// Immutable snapshot of the current auth state.
///
/// [masterEncryptionKey] and [syncKey] are memory-only — never serialized,
/// never logged. They are re-derived on each app start from the
/// keychain-stored mnemonic.
@immutable
class AuthState {
  final AuthTier tier;

  /// 32-byte key for encrypting local Ghost-tier backups (OHBK files).
  /// Null in [AuthTier.ghost] before the user has generated their seed
  /// phrase.
  ///
  /// Stored as a defensive copy — callers cannot mutate the key material
  /// after construction.
  final Uint8List? masterEncryptionKey;

  /// 32-byte key for encrypting Sync-tier blobs uploaded to the relay.
  /// Derived via HKDF from the same seed as [masterEncryptionKey] but with
  /// a distinct info string, so a nonce-reuse bug in one encryption path
  /// cannot compromise the other. Null before seed phrase generation.
  final Uint8List? syncKey;

  /// 32-byte sync channel identifier derived from the seed phrase.
  /// Hex-encoded for relay URL paths: `/{hex(syncChannelId)}/{deviceId}`.
  /// Null before the user has generated their seed phrase.
  final Uint8List? syncChannelId;

  /// The sync channel ID as a 64-character lowercase hex string,
  /// ready for use in relay URL paths. Null before seed phrase generation.
  String? get syncChannelIdHex => syncChannelId?.toHex();

  /// True once the user has confirmed they wrote down their seed phrase.
  final bool seedAcknowledged;

  /// When the user last exported a Ghost backup. Null = never.
  final DateTime? lastBackupAt;

  /// Creates an [AuthState]. Every key parameter is defensive-copied so
  /// later mutation of the caller's buffers cannot change stored state.
  AuthState({
    required this.tier,
    Uint8List? masterEncryptionKey,
    Uint8List? syncKey,
    Uint8List? syncChannelId,
    this.seedAcknowledged = false,
    this.lastBackupAt,
  })  : masterEncryptionKey = _copyOrNull(masterEncryptionKey),
        syncKey = _copyOrNull(syncKey),
        syncChannelId = _copyOrNull(syncChannelId);

  /// Ghost-tier initial state — no key material, no backup.
  const AuthState.ghost()
      : tier = AuthTier.ghost,
        masterEncryptionKey = null,
        syncKey = null,
        syncChannelId = null,
        seedAcknowledged = false,
        lastBackupAt = null;

  /// Returns true if a backup reminder should be shown.
  ///
  /// Shows if: seed is acknowledged, no backup ever, or last backup > 30 days ago.
  /// Pass [now] to override the current time (useful for testing).
  bool needsBackupReminder({DateTime? now}) {
    if (!seedAcknowledged) return false;
    if (lastBackupAt == null) return true;
    return (now ?? DateTime.now()).difference(lastBackupAt!) >
        const Duration(days: 30);
  }

  AuthState copyWith({
    AuthTier? tier,
    Uint8List? masterEncryptionKey,
    Uint8List? syncKey,
    Uint8List? syncChannelId,
    bool? seedAcknowledged,
    DateTime? lastBackupAt,
  }) {
    return AuthState(
      tier: tier ?? this.tier,
      masterEncryptionKey: masterEncryptionKey ?? this.masterEncryptionKey,
      syncKey: syncKey ?? this.syncKey,
      syncChannelId: syncChannelId ?? this.syncChannelId,
      seedAcknowledged: seedAcknowledged ?? this.seedAcknowledged,
      lastBackupAt: lastBackupAt ?? this.lastBackupAt,
    );
  }

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is AuthState &&
          tier == other.tier &&
          seedAcknowledged == other.seedAcknowledged &&
          lastBackupAt == other.lastBackupAt &&
          listEquals(masterEncryptionKey, other.masterEncryptionKey) &&
          listEquals(syncKey, other.syncKey) &&
          listEquals(syncChannelId, other.syncChannelId);

  @override
  int get hashCode => Object.hash(
        tier,
        seedAcknowledged,
        lastBackupAt,
        masterEncryptionKey == null ? null : Object.hashAll(masterEncryptionKey!),
        syncKey == null ? null : Object.hashAll(syncKey!),
        syncChannelId == null ? null : Object.hashAll(syncChannelId!),
      );

  static Uint8List? _copyOrNull(Uint8List? bytes) =>
      bytes == null ? null : Uint8List.fromList(bytes);
}
