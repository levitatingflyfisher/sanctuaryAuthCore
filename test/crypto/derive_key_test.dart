import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:sanctuary_auth_core/src/crypto/key_derivation.dart';

/// General-purpose HKDF-SHA256 derivation for non-BIP39 secrets
/// (SANCTUARY-BRIEF §4.W0.3). First customer: StillLife's LAN-sync code.
void main() {
  group('KeyDerivation.deriveKey', () {
    final secret = Uint8List.fromList(utf8.encode('lan-sync-code-1234'));

    test('returns a 32-byte key', () async {
      final key = await KeyDerivation.deriveKey(secret, domain: 'stilllife.lan.v1');
      expect(key, hasLength(32));
      expect(key, isA<Uint8List>());
    });

    test('is deterministic for the same secret + domain', () async {
      final a = await KeyDerivation.deriveKey(secret, domain: 'stilllife.lan.v1');
      final b = await KeyDerivation.deriveKey(secret, domain: 'stilllife.lan.v1');
      expect(a, equals(b));
    });

    test('different domains separate the output', () async {
      final a = await KeyDerivation.deriveKey(secret, domain: 'stilllife.lan.v1');
      final b = await KeyDerivation.deriveKey(secret, domain: 'stilllife.lan.v2');
      expect(a, isNot(equals(b)));
    });

    test('different secrets separate the output', () async {
      final other = Uint8List.fromList(utf8.encode('a-different-code'));
      final a = await KeyDerivation.deriveKey(secret, domain: 'stilllife.lan.v1');
      final b = await KeyDerivation.deriveKey(other, domain: 'stilllife.lan.v1');
      expect(a, isNot(equals(b)));
    });

    test('accepts secrets of arbitrary (non-64-byte) length', () async {
      for (final len in <int>[1, 16, 100]) {
        final s = Uint8List(len)..fillRange(0, len, 7);
        final key = await KeyDerivation.deriveKey(s, domain: 'x');
        expect(key, hasLength(32));
      }
    });

    test('rejects an empty secret', () async {
      await expectLater(
        KeyDerivation.deriveKey(Uint8List(0), domain: 'stilllife.lan.v1'),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('rejects an empty domain', () async {
      await expectLater(
        KeyDerivation.deriveKey(secret, domain: ''),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('known-answer vector (frozen)', () async {
      // Computed once and frozen — pins HKDF-SHA256 + empty-salt +
      // info=utf8(domain) so a future refactor cannot silently orphan every
      // key derived through this path.
      final key = await KeyDerivation.deriveKey(
        Uint8List.fromList(utf8.encode('lan-sync-code-1234')),
        domain: 'stilllife.lan.v1',
      );
      expect(_hex(key), _deriveKeyKat, reason: 'deriveKey algorithm drifted');
    });
  });
}

// Frozen after first green run (SANCTUARY-BRIEF §4.W0.3).
const _deriveKeyKat =
    'bc1cbf55631e92c22f7850486c2907e0e23bc9ac38b70c9330b6373ac4953066';

String _hex(List<int> bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
