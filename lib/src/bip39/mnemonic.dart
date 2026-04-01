import 'dart:convert';
import 'dart:typed_data';

import 'package:bip39_mnemonic/bip39_mnemonic.dart';
import 'package:cryptography/cryptography.dart';

/// BIP39 mnemonic utilities for OpenHearth key generation.
///
/// Entropy source: [Mnemonic.generate] uses [Random.secure] internally.
/// Seed derivation: PBKDF2-HMAC-SHA512, 2048 iterations, salt="mnemonic"
/// (BIP39 specification, no additional passphrase).
abstract final class OpenHearthMnemonic {
  static const _salt = 'mnemonic';
  static const _pbkdf2Iterations = 2048;
  static const _seedBits = 512;

  /// Generates a fresh 12-word BIP39 mnemonic from secure random entropy.
  static String generate() {
    final m = Mnemonic.generate(
      Language.english,
      length: MnemonicLength.words12,
    );
    return m.sentence;
  }

  /// Returns true if [phrase] is a valid BIP39 mnemonic (valid words + checksum).
  static bool validate(String phrase) {
    try {
      Mnemonic.fromSentence(phrase, Language.english);
      return true;
    } catch (_) {
      return false;
    }
  }

  /// Derives the 512-bit BIP39 seed from [phrase] via PBKDF2-HMAC-SHA512.
  ///
  /// Throws [ArgumentError] if [phrase] is not a valid BIP39 mnemonic.
  static Future<Uint8List> deriveSeed(String phrase) async {
    if (!validate(phrase)) {
      throw ArgumentError('Invalid BIP39 mnemonic (bad words or checksum)');
    }
    final pbkdf2 = Pbkdf2(
      macAlgorithm: Hmac.sha512(),
      iterations: _pbkdf2Iterations,
      bits: _seedBits,
    );
    final secretKey = await pbkdf2.deriveKey(
      secretKey: SecretKey(utf8.encode(phrase)),
      nonce: utf8.encode(_salt),
    );
    return Uint8List.fromList(await secretKey.extractBytes());
  }
}
