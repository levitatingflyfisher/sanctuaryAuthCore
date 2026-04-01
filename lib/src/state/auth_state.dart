import 'package:flutter/foundation.dart';

import 'auth_tier.dart';

/// Immutable snapshot of the current auth state.
///
/// [masterEncryptionKey] is memory-only — never serialized, never logged.
/// It is derived on each app start from the keychain-stored mnemonic.
@immutable
class AuthState {
  final AuthTier tier;

  /// 32-byte key for encrypting local data. Null in [AuthTier.ghost] before
  /// the user has generated their seed phrase.
  final List<int>? masterEncryptionKey;

  /// True once the user has confirmed they wrote down their seed phrase.
  final bool seedAcknowledged;

  /// When the user last exported a Ghost backup. Null = never.
  final DateTime? lastBackupAt;

  const AuthState({
    required this.tier,
    this.masterEncryptionKey,
    this.seedAcknowledged = false,
    this.lastBackupAt,
  });

  /// Ghost-tier initial state — no key material, no backup.
  const AuthState.ghost()
      : tier = AuthTier.ghost,
        masterEncryptionKey = null,
        seedAcknowledged = false,
        lastBackupAt = null;

  /// Returns true if a backup reminder should be shown.
  ///
  /// Shows if: seed is acknowledged, no backup ever, or last backup > 30 days ago.
  bool get needsBackupReminder {
    if (!seedAcknowledged) return false;
    if (lastBackupAt == null) return true;
    return DateTime.now().difference(lastBackupAt!) > const Duration(days: 30);
  }

  AuthState copyWith({
    AuthTier? tier,
    List<int>? masterEncryptionKey,
    bool? seedAcknowledged,
    DateTime? lastBackupAt,
  }) {
    return AuthState(
      tier: tier ?? this.tier,
      masterEncryptionKey: masterEncryptionKey ?? this.masterEncryptionKey,
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
          _listEquals(masterEncryptionKey, other.masterEncryptionKey);

  @override
  int get hashCode => Object.hash(
        tier,
        seedAcknowledged,
        lastBackupAt,
        masterEncryptionKey == null ? null : Object.hashAll(masterEncryptionKey!),
      );

  static bool _listEquals(List<int>? a, List<int>? b) {
    if (identical(a, b)) return true;
    if (a == null || b == null) return false;
    if (a.length != b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }
}
