import 'package:flutter_test/flutter_test.dart';
import 'package:sanctuary_auth_core/src/crypto/crypto_service.dart';

void main() {
  group('DefaultCryptoService', () {
    late DefaultCryptoService service;

    setUp(() {
      service = const DefaultCryptoService();
    });

    test('generateMnemonic returns a 12-word phrase', () {
      final phrase = service.generateMnemonic();
      expect(phrase.split(' '), hasLength(12));
    });

    test('generateMnemonic produces different phrases each call', () {
      final a = service.generateMnemonic();
      final b = service.generateMnemonic();
      expect(a, isNot(equals(b)));
    });

    test('deriveKeysFromPhrase returns 32-byte master key', () async {
      const phrase =
          'abandon abandon abandon abandon abandon abandon '
          'abandon abandon abandon abandon abandon about';
      final keys = await service.deriveKeysFromPhrase(phrase);
      expect(keys.masterEncryptionKey, hasLength(32));
    });

    test('deriveKeysFromPhrase produces three distinct keys', () async {
      const phrase =
          'abandon abandon abandon abandon abandon abandon '
          'abandon abandon abandon abandon abandon about';
      final keys = await service.deriveKeysFromPhrase(phrase);
      expect(keys.masterEncryptionKey, isNot(equals(keys.authKey)));
      expect(keys.masterEncryptionKey, isNot(equals(keys.recoveryKey)));
      expect(keys.authKey, isNot(equals(keys.recoveryKey)));
    });

    test('deriveKeysFromPhrase is deterministic', () async {
      const phrase =
          'abandon abandon abandon abandon abandon abandon '
          'abandon abandon abandon abandon abandon about';
      final a = await service.deriveKeysFromPhrase(phrase);
      final b = await service.deriveKeysFromPhrase(phrase);
      expect(a.masterEncryptionKey, equals(b.masterEncryptionKey));
    });

    test('deriveKeysFromPhrase throws on invalid phrase', () async {
      expect(
        () => service.deriveKeysFromPhrase('not a valid mnemonic'),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('deriveKeysFromPhrase threads appDomain into HKDF', () async {
      const phrase =
          'abandon abandon abandon abandon abandon abandon '
          'abandon abandon abandon abandon abandon about';
      final legacy = await service.deriveKeysFromPhrase(phrase);
      final scoped =
          await service.deriveKeysFromPhrase(phrase, appDomain: 'stilllife');
      final scopedAgain =
          await service.deriveKeysFromPhrase(phrase, appDomain: 'stilllife');

      expect(scoped.masterEncryptionKey,
          isNot(equals(legacy.masterEncryptionKey)));
      expect(scoped.masterEncryptionKey,
          equals(scopedAgain.masterEncryptionKey),
          reason: 'same phrase + same domain is deterministic');
    });

    test('deriveKeysFromPhrase rejects an invalid appDomain', () async {
      const phrase =
          'abandon abandon abandon abandon abandon abandon '
          'abandon abandon abandon abandon abandon about';
      await expectLater(
        service.deriveKeysFromPhrase(phrase, appDomain: 'Still-Life'),
        throwsA(isA<ArgumentError>()),
      );
    });
  });
}
