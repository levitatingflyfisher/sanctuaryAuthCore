import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:sanctuary_auth_core/src/bip39/mnemonic.dart';
import 'package:sanctuary_auth_core/src/crypto/key_derivation.dart';

void main() {
  group('KeyDerivation — syncChannelId', () {
    late Uint8List fixedSeed;

    setUpAll(() {
      fixedSeed = Uint8List(64);
    });

    test('syncChannelId is 32 bytes', () async {
      final keys = await KeyDerivation.fromSeed(fixedSeed);
      expect(keys.syncChannelId, hasLength(32));
    });

    test('syncChannelId is distinct from all other keys', () async {
      final keys = await KeyDerivation.fromSeed(fixedSeed);
      expect(keys.syncChannelId, isNot(equals(keys.masterEncryptionKey)));
      expect(keys.syncChannelId, isNot(equals(keys.authKey)));
      expect(keys.syncChannelId, isNot(equals(keys.recoveryKey)));
    });

    test('syncChannelId is deterministic for the same seed', () async {
      final keys1 = await KeyDerivation.fromSeed(fixedSeed);
      final keys2 = await KeyDerivation.fromSeed(fixedSeed);
      expect(keys1.syncChannelId, equals(keys2.syncChannelId));
    });

    test('different seeds produce different syncChannelIds', () async {
      final seed2 = Uint8List(64)..fillRange(0, 64, 1);
      final keys1 = await KeyDerivation.fromSeed(fixedSeed);
      final keys2 = await KeyDerivation.fromSeed(seed2);
      expect(keys1.syncChannelId, isNot(equals(keys2.syncChannelId)));
    });

    test('deriveSyncChannelId matches fromSeed().syncChannelId', () async {
      final keys = await KeyDerivation.fromSeed(fixedSeed);
      final standalone = await KeyDerivation.deriveSyncChannelId(fixedSeed);
      expect(standalone, equals(keys.syncChannelId));
    });

    test('deriveSyncChannelId throws ArgumentError for wrong seed length',
        () async {
      final badSeed = Uint8List(32);
      await expectLater(
        KeyDerivation.deriveSyncChannelId(badSeed),
        throwsA(isA<ArgumentError>()),
      );
    });

    test(
        'known-answer vector: abandon-seed derives fixed syncChannelId '
        '(HKDF-SHA256, info=openhearth.sync.channel.v1)', () async {
      const phrase =
          'abandon abandon abandon abandon abandon abandon '
          'abandon abandon abandon abandon abandon about';
      final seed = await OpenHearthMnemonic.deriveSeed(phrase);
      final keys = await KeyDerivation.fromSeed(seed);

      final hex = keys.syncChannelId
          .map((b) => b.toRadixString(16).padLeft(2, '0'))
          .join();

      // Pin: if this changes, the sync channel derivation algorithm drifted
      // and existing sync groups will be broken.
      expect(
        hex,
        'a75472ba52270a91f9a7ae74ce5b13a648ae61001758256f3dc3839fc64e6b44',
        reason: 'syncChannelId drift — HKDF-SHA256 or info string changed',
      );

      // Verify standalone method produces the same value.
      final standalone = await KeyDerivation.deriveSyncChannelId(seed);
      final standaloneHex = standalone
          .map((b) => b.toRadixString(16).padLeft(2, '0'))
          .join();
      expect(standaloneHex, equals(hex));
    });
  });
}
