import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:sanctuary_auth_core/src/crypto/envelope_cipher.dart';
import 'package:sanctuary_auth_core/src/exceptions.dart';

void main() {
  group('EnvelopeCipher', () {
    late EnvelopeCipher cipher;
    late Uint8List key;

    setUp(() {
      cipher = EnvelopeCipher();
      key = Uint8List(32)..fillRange(0, 32, 42);
    });

    test('encrypt returns a 12-byte nonce', () async {
      final envelope = await cipher.encrypt(Uint8List.fromList([1, 2, 3]), key);
      expect(envelope.nonce, hasLength(12));
    });

    test('encrypt returns a 16-byte MAC', () async {
      final envelope = await cipher.encrypt(Uint8List.fromList([1, 2, 3]), key);
      expect(envelope.mac, hasLength(16));
    });

    test('encrypt returns ciphertext of same length as plaintext', () async {
      final plaintext = Uint8List.fromList(List<int>.generate(37, (i) => i));
      final envelope = await cipher.encrypt(plaintext, key);
      expect(envelope.ciphertext, hasLength(plaintext.length));
    });

    test('two encrypts of the same plaintext produce different nonces', () async {
      final plaintext = Uint8List.fromList([1, 2, 3, 4, 5]);
      final a = await cipher.encrypt(plaintext, key);
      final b = await cipher.encrypt(plaintext, key);
      expect(a.nonce, isNot(equals(b.nonce)));
      expect(a.ciphertext, isNot(equals(b.ciphertext)));
    });

    test('decrypt round-trips plaintext correctly', () async {
      final plaintext = Uint8List.fromList(
        List<int>.generate(128, (i) => (i * 7) & 0xff),
      );
      final envelope = await cipher.encrypt(plaintext, key);
      final recovered = await cipher.decrypt(envelope, key);
      expect(recovered, equals(plaintext));
    });

    test('decrypt throws when given the wrong key', () async {
      final plaintext = Uint8List.fromList([9, 8, 7, 6]);
      final envelope = await cipher.encrypt(plaintext, key);
      final wrongKey = Uint8List(32)..fillRange(0, 32, 99);
      expect(
        () => cipher.decrypt(envelope, wrongKey),
        throwsA(isA<CryptoException>()),
      );
    });

    test('decrypt throws when the ciphertext is tampered', () async {
      final plaintext = Uint8List.fromList([10, 20, 30, 40, 50]);
      final envelope = await cipher.encrypt(plaintext, key);
      final tampered = Uint8List.fromList(envelope.ciphertext);
      tampered[0] ^= 0x01;
      final bad = CipherEnvelope(
        nonce: envelope.nonce,
        ciphertext: tampered,
        mac: envelope.mac,
      );
      expect(
        () => cipher.decrypt(bad, key),
        throwsA(isA<CryptoException>()),
      );
    });

    test('encrypt throws ArgumentError for a non-32-byte key', () async {
      final shortKey = Uint8List(16);
      expect(
        () => cipher.encrypt(Uint8List.fromList([1, 2, 3]), shortKey),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('decrypt throws ArgumentError for a non-32-byte key', () async {
      final envelope = await cipher.encrypt(Uint8List.fromList([1, 2, 3]), key);
      final shortKey = Uint8List(16);
      expect(
        () => cipher.decrypt(envelope, shortKey),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('encrypt/decrypt round-trips with additionalData', () async {
      final plaintext = Uint8List.fromList([10, 20, 30, 40, 50]);
      final aad = Uint8List.fromList([0x4F, 0x48, 0x42, 0x4B, 0x01]);
      final envelope = await cipher.encrypt(
        plaintext,
        key,
        additionalData: aad,
      );
      final recovered = await cipher.decrypt(
        envelope,
        key,
        additionalData: aad,
      );
      expect(recovered, equals(plaintext));
    });

    test('decrypt fails when additionalData does not match', () async {
      final plaintext = Uint8List.fromList([10, 20, 30]);
      final aad = Uint8List.fromList([1, 2, 3]);
      final wrongAad = Uint8List.fromList([4, 5, 6]);
      final envelope = await cipher.encrypt(
        plaintext,
        key,
        additionalData: aad,
      );
      expect(
        () => cipher.decrypt(envelope, key, additionalData: wrongAad),
        throwsA(isA<CryptoException>()),
      );
    });

    test('decrypt fails when additionalData was expected but not provided',
        () async {
      final plaintext = Uint8List.fromList([10, 20, 30]);
      final aad = Uint8List.fromList([1, 2, 3]);
      final envelope = await cipher.encrypt(
        plaintext,
        key,
        additionalData: aad,
      );
      expect(
        () => cipher.decrypt(envelope, key),
        throwsA(isA<CryptoException>()),
      );
    });
  });
}
