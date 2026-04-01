import 'dart:ffi';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:sanctuary_auth_core/src/crypto/envelope_cipher.dart';
import 'package:sodium/sodium.dart';

void main() {
  group('EnvelopeCipher', () {
    late Sodium sodium;
    late EnvelopeCipher cipher;
    late Uint8List key;

    setUpAll(() async {
      // Load the system libsodium directly for host-side tests.
      // Production Flutter apps should pull the binary in via `sodium_libs`.
      sodium = await SodiumInit.init(
        () => DynamicLibrary.open('libsodium.so.26'),
      );
    });

    setUp(() {
      cipher = EnvelopeCipher(sodium);
      key = Uint8List(32)..fillRange(0, 32, 42);
    });

    test('encrypt returns a 24-byte nonce', () {
      final envelope = cipher.encrypt(Uint8List.fromList([1, 2, 3]), key);
      expect(envelope.nonce, hasLength(24));
    });

    test('encrypt returns ciphertext of length plaintext + 16 (Poly1305 tag)', () {
      final plaintext = Uint8List.fromList(List<int>.generate(37, (i) => i));
      final envelope = cipher.encrypt(plaintext, key);
      expect(envelope.ciphertext, hasLength(plaintext.length + 16));
    });

    test('two encrypts of the same plaintext produce different nonces and ciphertexts', () {
      final plaintext = Uint8List.fromList([1, 2, 3, 4, 5]);
      final a = cipher.encrypt(plaintext, key);
      final b = cipher.encrypt(plaintext, key);
      expect(a.nonce, isNot(equals(b.nonce)));
      expect(a.ciphertext, isNot(equals(b.ciphertext)));
    });

    test('decrypt round-trips plaintext correctly', () {
      final plaintext = Uint8List.fromList(
        List<int>.generate(128, (i) => (i * 7) & 0xff),
      );
      final envelope = cipher.encrypt(plaintext, key);
      final recovered = cipher.decrypt(envelope, key);
      expect(recovered, equals(plaintext));
    });

    test('decrypt throws when given the wrong key', () {
      final plaintext = Uint8List.fromList([9, 8, 7, 6]);
      final envelope = cipher.encrypt(plaintext, key);
      final wrongKey = Uint8List(32)..fillRange(0, 32, 99);
      expect(
        () => cipher.decrypt(envelope, wrongKey),
        throwsA(isA<SodiumException>()),
      );
    });

    test('decrypt throws when the ciphertext is tampered', () {
      final plaintext = Uint8List.fromList([10, 20, 30, 40, 50]);
      final envelope = cipher.encrypt(plaintext, key);
      // Flip a bit in the middle of the ciphertext.
      final tampered = Uint8List.fromList(envelope.ciphertext);
      tampered[0] ^= 0x01;
      final bad = CipherEnvelope(nonce: envelope.nonce, ciphertext: tampered);
      expect(
        () => cipher.decrypt(bad, key),
        throwsA(isA<SodiumException>()),
      );
    });

    test('encrypt throws ArgumentError for a non-32-byte key', () {
      final shortKey = Uint8List(16);
      expect(
        () => cipher.encrypt(Uint8List.fromList([1, 2, 3]), shortKey),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('decrypt throws ArgumentError for a non-32-byte key', () {
      final envelope = cipher.encrypt(Uint8List.fromList([1, 2, 3]), key);
      final shortKey = Uint8List(16);
      expect(
        () => cipher.decrypt(envelope, shortKey),
        throwsA(isA<ArgumentError>()),
      );
    });
  });
}
