import 'package:cryptography/cryptography.dart';
import 'package:flutter/foundation.dart';

import '../exceptions.dart';

/// A self-contained ChaCha20-Poly1305 ciphertext bundle.
///
/// Carries the random 96-bit nonce alongside the ciphertext so callers can
/// persist a single opaque blob without tracking the nonce separately.
@immutable
class CipherEnvelope {
  /// The 12-byte (96-bit) random nonce used for encryption.
  final Uint8List nonce;

  /// The ciphertext, which is `plaintext.length` bytes.
  final Uint8List ciphertext;

  /// The 16-byte Poly1305 authentication tag.
  final Uint8List mac;

  const CipherEnvelope({
    required this.nonce,
    required this.ciphertext,
    required this.mac,
  });
}

/// Authenticated encryption using ChaCha20-Poly1305 (IETF) via the pure-Dart
/// `cryptography` package.
///
/// All operations require a 32-byte key. Nonces are generated internally via
/// Dart's secure random.
class EnvelopeCipher {
  final Chacha20 _algorithm;

  /// Creates an [EnvelopeCipher] using ChaCha20-Poly1305 AEAD.
  EnvelopeCipher() : _algorithm = Chacha20.poly1305Aead();

  /// Encrypts [plaintext] with a fresh random 12-byte nonce under [key].
  ///
  /// If [additionalData] is provided, it is authenticated alongside the
  /// ciphertext (AEAD). The same [additionalData] must be passed to [decrypt].
  ///
  /// Throws [ArgumentError] if [key] is not exactly 32 bytes.
  Future<CipherEnvelope> encrypt(
    Uint8List plaintext,
    Uint8List key, {
    Uint8List? additionalData,
  }) async {
    _requireKeyLength(key);
    final secretBox = await _algorithm.encrypt(
      plaintext,
      secretKey: SecretKey(key),
      aad: additionalData ?? const [],
    );
    return CipherEnvelope(
      nonce: Uint8List.fromList(secretBox.nonce),
      ciphertext: Uint8List.fromList(secretBox.cipherText),
      mac: Uint8List.fromList(secretBox.mac.bytes),
    );
  }

  /// Decrypts [envelope] under [key], verifying the Poly1305 tag.
  ///
  /// If [additionalData] was provided during encryption, the same value must
  /// be passed here or decryption will fail.
  ///
  /// Throws [ArgumentError] if [key] is not exactly 32 bytes.
  /// Throws [CryptoException] if the key is wrong or the ciphertext has been
  /// tampered with.
  Future<Uint8List> decrypt(
    CipherEnvelope envelope,
    Uint8List key, {
    Uint8List? additionalData,
  }) async {
    _requireKeyLength(key);
    final secretBox = SecretBox(
      envelope.ciphertext,
      nonce: envelope.nonce,
      mac: Mac(envelope.mac),
    );
    try {
      final plaintext = await _algorithm.decrypt(
        secretBox,
        secretKey: SecretKey(key),
        aad: additionalData ?? const [],
      );
      return Uint8List.fromList(plaintext);
    } on SecretBoxAuthenticationError catch (e) {
      throw CryptoException('Decryption failed', cause: e);
    }
  }

  static void _requireKeyLength(Uint8List key) {
    if (key.length != 32) {
      throw ArgumentError('Key must be 32 bytes; got ${key.length}');
    }
  }
}
