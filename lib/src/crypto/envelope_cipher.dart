import 'package:flutter/foundation.dart';
import 'package:sodium/sodium.dart';

/// A self-contained XChaCha20-Poly1305 IETF ciphertext bundle.
///
/// Carries the random 192-bit nonce alongside the ciphertext (which already
/// includes the 128-bit Poly1305 authentication tag appended by libsodium).
/// Pairing the nonce with the ciphertext lets callers persist a single opaque
/// blob without tracking the nonce separately.
@immutable
class CipherEnvelope {
  /// The 24-byte (192-bit) random nonce used for encryption.
  final Uint8List nonce;

  /// The ciphertext, which is `plaintext.length + 16` bytes.
  ///
  /// The trailing 16 bytes are the Poly1305 authentication tag.
  final Uint8List ciphertext;

  const CipherEnvelope({required this.nonce, required this.ciphertext});
}

/// Thin wrapper around libsodium's XChaCha20-Poly1305 IETF AEAD.
///
/// The caller owns initialization of [Sodium] — this class simply holds a
/// reference so consumers don't have to thread the sodium instance through
/// every call site.
///
/// All operations require a 32-byte key. Nonces are generated internally via
/// libsodium's CSPRNG.
class EnvelopeCipher {
  final Sodium _sodium;

  /// Creates an [EnvelopeCipher] backed by the given [Sodium] instance.
  const EnvelopeCipher(this._sodium);

  /// Encrypts [plaintext] with a fresh random 24-byte nonce under [key].
  ///
  /// Throws [ArgumentError] if [key] is not exactly 32 bytes.
  CipherEnvelope encrypt(Uint8List plaintext, Uint8List key) {
    _requireKeyLength(key);
    final aead = _sodium.crypto.aeadXChaCha20Poly1305IETF;
    final nonce = _sodium.randombytes.buf(aead.nonceBytes);
    final ciphertext = _runWithKey(key, (secureKey) {
      return aead.encrypt(
        message: plaintext,
        nonce: nonce,
        key: secureKey,
      );
    });
    return CipherEnvelope(nonce: nonce, ciphertext: ciphertext);
  }

  /// Decrypts [envelope] under [key], verifying the Poly1305 tag.
  ///
  /// Throws [ArgumentError] if [key] is not exactly 32 bytes.
  /// Throws [SodiumException] if the key is wrong or the ciphertext has been
  /// tampered with.
  Uint8List decrypt(CipherEnvelope envelope, Uint8List key) {
    _requireKeyLength(key);
    final aead = _sodium.crypto.aeadXChaCha20Poly1305IETF;
    return _runWithKey(key, (secureKey) {
      return aead.decrypt(
        cipherText: envelope.ciphertext,
        nonce: envelope.nonce,
        key: secureKey,
      );
    });
  }

  static void _requireKeyLength(Uint8List key) {
    if (key.length != 32) {
      throw ArgumentError('Key must be 32 bytes; got ${key.length}');
    }
  }

  /// Wraps [key] in a [SecureKey] for the duration of [body], then disposes it.
  T _runWithKey<T>(Uint8List key, T Function(SecureKey secureKey) body) {
    final secureKey = SecureKey.fromList(_sodium, key);
    try {
      return body(secureKey);
    } finally {
      secureKey.dispose();
    }
  }
}
