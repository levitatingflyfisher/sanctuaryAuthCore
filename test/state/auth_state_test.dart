import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:sanctuary_auth_core/src/state/auth_state.dart';
import 'package:sanctuary_auth_core/src/state/auth_tier.dart';

void main() {
  group('AuthState.needsBackupReminder', () {
    test('returns false when seedAcknowledged is false', () {
      final state = AuthState(tier: AuthTier.ghost, seedAcknowledged: false);
      expect(state.needsBackupReminder(), isFalse);
    });

    test('returns true when seedAcknowledged but no backup ever', () {
      final state = AuthState(
        tier: AuthTier.ghost,
        masterEncryptionKey: Uint8List(32),
        seedAcknowledged: true,
      );
      expect(state.needsBackupReminder(), isTrue);
    });

    test('returns false when last backup was 29 days ago', () {
      final now = DateTime(2026, 4, 11, 12, 0);
      final state = AuthState(
        tier: AuthTier.ghost,
        masterEncryptionKey: Uint8List(32),
        seedAcknowledged: true,
        lastBackupAt: now.subtract(const Duration(days: 29)),
      );
      expect(state.needsBackupReminder(now: now), isFalse);
    });

    test('returns false when last backup was exactly 30 days ago', () {
      final now = DateTime(2026, 4, 11, 12, 0);
      final state = AuthState(
        tier: AuthTier.ghost,
        masterEncryptionKey: Uint8List(32),
        seedAcknowledged: true,
        lastBackupAt: now.subtract(const Duration(days: 30)),
      );
      expect(state.needsBackupReminder(now: now), isFalse);
    });

    test('returns true when last backup was 31 days ago', () {
      final now = DateTime(2026, 4, 11, 12, 0);
      final state = AuthState(
        tier: AuthTier.ghost,
        masterEncryptionKey: Uint8List(32),
        seedAcknowledged: true,
        lastBackupAt: now.subtract(const Duration(days: 31)),
      );
      expect(state.needsBackupReminder(now: now), isTrue);
    });
  });

  group('AuthState — immutability', () {
    test('masterEncryptionKey is a defensive copy at construction', () {
      final key = Uint8List.fromList(List.generate(32, (i) => i + 100));
      final state =
          AuthState(tier: AuthTier.ghost, masterEncryptionKey: key);
      key[0] = 255;
      expect(state.masterEncryptionKey![0], equals(100));
    });

    test('syncKey is a defensive copy at construction', () {
      final key = Uint8List.fromList(List.generate(32, (i) => i + 50));
      final state = AuthState(tier: AuthTier.ghost, syncKey: key);
      key[0] = 0;
      expect(state.syncKey![0], equals(50));
    });

    test('copyWith passing a new syncKey defensive-copies it', () {
      final initial = AuthState(tier: AuthTier.ghost);
      final fresh = Uint8List.fromList(List.generate(32, (i) => 7));
      final next = initial.copyWith(syncKey: fresh);
      fresh[0] = 0;
      expect(next.syncKey![0], equals(7),
          reason:
              'copyWith must defensive-copy so the caller cannot mutate the '
              'stored state after handing it off');
    });

    test('copyWith without a new key preserves the existing defensive copy',
        () {
      final original = Uint8List.fromList(List.generate(32, (i) => i));
      final first = AuthState(
        tier: AuthTier.ghost,
        masterEncryptionKey: original,
      );
      final updated = first.copyWith(seedAcknowledged: true);
      // Mutate the source buffer — stored state must still be the copy.
      original.fillRange(0, 32, 0);
      expect(updated.masterEncryptionKey![0], equals(0));
      expect(updated.seedAcknowledged, isTrue);
    });
  });
}
