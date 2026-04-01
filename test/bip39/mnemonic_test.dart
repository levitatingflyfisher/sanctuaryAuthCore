import 'package:flutter_test/flutter_test.dart';
import 'package:sanctuary_auth_core/src/bip39/mnemonic.dart';

void main() {
  group('OpenHearthMnemonic', () {
    test('generate produces a 12-word phrase', () {
      final phrase = OpenHearthMnemonic.generate();
      expect(phrase.split(' '), hasLength(12));
    });

    test('generate produces different phrases each call', () {
      final a = OpenHearthMnemonic.generate();
      final b = OpenHearthMnemonic.generate();
      expect(a, isNot(equals(b)));
    });

    test('validate returns true for a valid phrase', () {
      final phrase = OpenHearthMnemonic.generate();
      expect(OpenHearthMnemonic.validate(phrase), isTrue);
    });

    test('validate returns false for a garbage phrase', () {
      expect(OpenHearthMnemonic.validate('foo bar baz'), isFalse);
    });

    test('deriveSeed returns 64 bytes', () async {
      final phrase = OpenHearthMnemonic.generate();
      final seed = await OpenHearthMnemonic.deriveSeed(phrase);
      expect(seed, hasLength(64));
    });

    test('deriveSeed is deterministic for the same phrase', () async {
      final phrase = OpenHearthMnemonic.generate();
      final seed1 = await OpenHearthMnemonic.deriveSeed(phrase);
      final seed2 = await OpenHearthMnemonic.deriveSeed(phrase);
      expect(seed1, equals(seed2));
    });

    test('deriveSeed known vector — first 4 bytes of known phrase', () async {
      // Known test vector from BIP39 spec (english, no passphrase)
      const phrase =
          'abandon abandon abandon abandon abandon abandon '
          'abandon abandon abandon abandon abandon about';
      final seed = await OpenHearthMnemonic.deriveSeed(phrase);
      // BIP39 spec seed for this phrase (no extra passphrase), first 4 bytes
      expect(seed[0], equals(0x5e));
      expect(seed[1], equals(0xb0));
      expect(seed[2], equals(0x0b));
      expect(seed[3], equals(0xbd));
    });

    test('deriveSeed throws ArgumentError for an invalid phrase', () async {
      await expectLater(
        OpenHearthMnemonic.deriveSeed('foo bar baz'),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('deriveSeed error does not leak the raw phrase', () async {
      const phrase = 'definitely not a real mnemonic phrase here';
      try {
        await OpenHearthMnemonic.deriveSeed(phrase);
        fail('expected ArgumentError');
      } on ArgumentError catch (e) {
        expect(e.toString(), isNot(contains(phrase)));
      }
    });
  });
}
