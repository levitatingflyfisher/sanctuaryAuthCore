import 'dart:typed_data';

import 'package:sanctuary_auth_core/src/crypto/envelope_cipher.dart';

/// Magic bytes identifying an OpenHearth Backup blob: ASCII "OHBK".
const _magic = <int>[0x4F, 0x48, 0x42, 0x4B];

/// Current wire-format version.
const _version = 0x01;

/// Length of the fixed header: 4 (magic) + 1 (version).
const _headerLength = 5;

/// XChaCha20-Poly1305 nonce length in bytes.
const _nonceLength = 24;

/// Minimum valid blob length: header + nonce + Poly1305 tag (16 bytes).
const _minBlobLength = _headerLength + _nonceLength + 16; // 45

/// Thrown when an OHBK blob fails structural validation.
class GhostBackupFormatException implements Exception {
  final String message;

  const GhostBackupFormatException(this.message);

  @override
  String toString() => 'GhostBackupFormatException: $message';
}

/// Encrypted export/import of Ghost-tier app data using the OHBK wire format.
///
/// Wire format:
/// ```
/// [4 bytes magic: 0x4F 0x48 0x42 0x4B ("OHBK")]
/// [1 byte version: 0x01]
/// [24 bytes nonce]
/// [N bytes XChaCha20-Poly1305 ciphertext]
/// ```
abstract final class GhostBackup {
  /// Encrypts [appData] under [key] and returns an OHBK blob.
  ///
  /// The returned blob contains the magic header, version byte, random nonce,
  /// and authenticated ciphertext. Pass the same [key] to [import] to recover
  /// the original data.
  static Uint8List export(
    Uint8List appData,
    Uint8List key,
    EnvelopeCipher cipher,
  ) {
    final envelope = cipher.encrypt(appData, key);
    final builder = BytesBuilder(copy: false)
      ..add(_magic)
      ..addByte(_version)
      ..add(envelope.nonce)
      ..add(envelope.ciphertext);
    return builder.toBytes();
  }

  /// Decrypts an OHBK [blob] under [key] and returns the original app data.
  ///
  /// Throws [GhostBackupFormatException] if the blob has wrong magic bytes,
  /// an unsupported version, or is too short.
  /// Throws [SodiumException] if the key is wrong or the ciphertext has been
  /// tampered with.
  // ignore: non_constant_identifier_names — matches the Dart convention for
  // factory-style static methods that mirror constructors.
  // ignore: avoid-importing-from-relative-path
  static Uint8List import(
    Uint8List blob,
    Uint8List key,
    EnvelopeCipher cipher,
  ) {
    if (blob.length < _minBlobLength) {
      throw GhostBackupFormatException(
        'Blob too short: expected at least $_minBlobLength bytes, '
        'got ${blob.length}',
      );
    }

    if (blob[0] != _magic[0] ||
        blob[1] != _magic[1] ||
        blob[2] != _magic[2] ||
        blob[3] != _magic[3]) {
      throw const GhostBackupFormatException('Invalid magic bytes');
    }

    if (blob[4] != _version) {
      throw GhostBackupFormatException(
        'Unsupported version: 0x${blob[4].toRadixString(16).padLeft(2, '0')}',
      );
    }

    final nonce = Uint8List.sublistView(blob, _headerLength, _headerLength + _nonceLength);
    final ciphertext = Uint8List.sublistView(blob, _headerLength + _nonceLength);
    final envelope = CipherEnvelope(nonce: nonce, ciphertext: ciphertext);

    return cipher.decrypt(envelope, key);
  }
}
