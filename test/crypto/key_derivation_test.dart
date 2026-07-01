import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:sanctuary_auth_core/src/bip39/mnemonic.dart';
import 'package:sanctuary_auth_core/src/crypto/key_derivation.dart';

void main() {
  group('KeyDerivation', () {
    late Uint8List fixedSeed;

    setUpAll(() {
      fixedSeed = Uint8List(64);
    });

    test('masterEncryptionKey is 32 bytes', () async {
      final keys = await KeyDerivation.fromSeed(fixedSeed);
      expect(keys.masterEncryptionKey, hasLength(32));
    });

    test('authKey is 32 bytes', () async {
      final keys = await KeyDerivation.fromSeed(fixedSeed);
      expect(keys.authKey, hasLength(32));
    });

    test('recoveryKey is 32 bytes', () async {
      final keys = await KeyDerivation.fromSeed(fixedSeed);
      expect(keys.recoveryKey, hasLength(32));
    });

    test('all derived keys are distinct', () async {
      final keys = await KeyDerivation.fromSeed(fixedSeed);
      expect(keys.masterEncryptionKey, isNot(equals(keys.authKey)));
      expect(keys.masterEncryptionKey, isNot(equals(keys.recoveryKey)));
      expect(keys.authKey, isNot(equals(keys.recoveryKey)));
      expect(keys.syncKey, isNot(equals(keys.masterEncryptionKey)),
          reason: 'syncKey must be distinct so a nonce-reuse bug in one '
              'encryption path cannot compromise the other');
      expect(keys.syncKey, isNot(equals(keys.authKey)));
      expect(keys.syncKey, isNot(equals(keys.recoveryKey)));
      expect(keys.syncKey, hasLength(32));
    });

    test('derivation is deterministic for the same seed', () async {
      final keys1 = await KeyDerivation.fromSeed(fixedSeed);
      final keys2 = await KeyDerivation.fromSeed(fixedSeed);
      expect(keys1.masterEncryptionKey, equals(keys2.masterEncryptionKey));
      expect(keys1.authKey, equals(keys2.authKey));
      expect(keys1.recoveryKey, equals(keys2.recoveryKey));
    });

    test('different seeds produce different keys', () async {
      final seed2 = Uint8List(64)..fillRange(0, 64, 1);
      final keys1 = await KeyDerivation.fromSeed(fixedSeed);
      final keys2 = await KeyDerivation.fromSeed(seed2);
      expect(keys1.masterEncryptionKey, isNot(equals(keys2.masterEncryptionKey)));
    });

    test('round-trip through BIP39 mnemonic produces the same master key', () async {
      const phrase =
          'abandon abandon abandon abandon abandon abandon '
          'abandon abandon abandon abandon abandon about';
      final seed = await OpenHearthMnemonic.deriveSeed(phrase);
      final keys1 = await KeyDerivation.fromSeed(seed);
      final keys2 = await KeyDerivation.fromSeed(seed);
      expect(keys1.masterEncryptionKey, equals(keys2.masterEncryptionKey));
    });

    test('throws ArgumentError for wrong seed length', () async {
      final badSeed = Uint8List(32);
      await expectLater(
        KeyDerivation.fromSeed(badSeed),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('known-answer vector: abandon-seed derives fixed keys (RFC 5869 HKDF-SHA256)', () async {
      // Pins HKDF-SHA256 + info strings against accidental algorithm changes.
      // If this test fails, the key derivation algorithm has silently changed
      // and all existing users will be unable to decrypt their data.
      const phrase =
          'abandon abandon abandon abandon abandon abandon '
          'abandon abandon abandon abandon abandon about';
      final seed = await OpenHearthMnemonic.deriveSeed(phrase);
      final keys = await KeyDerivation.fromSeed(seed);

      expect(
        _hex(keys.masterEncryptionKey),
        'a0e7fa41ce299cb582be43d84de04fd116489379c02c062916ed7e6fbd626aa2',
        reason: 'masterEncryptionKey drift — HKDF-SHA256 or info string changed',
      );
      expect(
        _hex(keys.authKey),
        '03e3d9d98e99ce317fc6e96ff750e5612e4f2061cca4b317e88481069e08eaae',
        reason: 'authKey drift — HKDF-SHA256 or info string changed',
      );
      expect(
        _hex(keys.recoveryKey),
        '04203889b3fdf5f1b3073a9030246711eb39b8a6f361036cd173998d56e2dcfb',
        reason: 'recoveryKey drift — HKDF-SHA256 or info string changed',
      );
    });

    test('known-answer vector: syncKey is deterministic '
        '(HKDF-SHA256, info=openhearth.sync.encryption.v1)', () async {
      // Pin: if this hex changes, the sync-encryption info string drifted
      // and every device already in a sync group will fail to decrypt
      // peer blobs on next sync.
      const phrase =
          'abandon abandon abandon abandon abandon abandon '
          'abandon abandon abandon abandon abandon about';
      final seed = await OpenHearthMnemonic.deriveSeed(phrase);
      final keys = await KeyDerivation.fromSeed(seed);

      expect(
        _hex(keys.syncKey),
        '9c34024d9a3a2f7e9537f66a180b9340011579f44bd974c118c9c2755a5770e9',
        reason: 'syncKey drift — HKDF-SHA256 or info string changed',
      );
    });
  });
}

String _hex(List<int> bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
