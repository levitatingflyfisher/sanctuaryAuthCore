import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter/foundation.dart';
import 'package:sanctuary_auth_core/src/crypto/envelope_cipher.dart';
import 'package:sanctuary_auth_core/src/exceptions.dart';

/// Magic bytes identifying an OpenHearth Backup blob: ASCII "OHBK".
const _magic = <int>[0x4F, 0x48, 0x42, 0x4B];

/// Wire-format version written by [GhostBackup.export] (current).
///
/// v2 binds the header + caller-supplied [GhostBackup.export.context] string
/// as AEAD additional-authenticated-data, preventing cross-context blob
/// substitution (e.g. replaying a ghost-tier OHBK file as a sync payload).
const _versionCurrent = 0x02;

/// Legacy wire-format version — accepted by [GhostBackup.import] for
/// backwards compatibility with blobs created before the AAD binding landed.
///
/// v1 does not bind any AAD. Never emitted by [GhostBackup.export] anymore.
const _versionLegacy = 0x01;

/// Cipher suite identifier: ChaCha20-Poly1305 IETF.
const _suiteChaCha20Poly1305 = 0x01;

/// Length of the fixed header: 4 (magic) + 1 (version) + 1 (cipher suite).
const _headerLength = 6;

/// ChaCha20-Poly1305 nonce length in bytes.
const _nonceLength = 12;

/// Poly1305 MAC length in bytes.
const _macLength = 16;

/// Minimum valid blob length: header + nonce + MAC (no ciphertext = empty plaintext).
const _minBlobLength = _headerLength + _nonceLength + _macLength; // 34

/// Maximum blob length accepted by [GhostBackup.import] (10 MB).
///
/// Prevents OOM on mobile devices if a caller passes an arbitrarily large
/// or malformed file.
const _maxBlobLength = 10 * 1024 * 1024; // 10 MB

/// Default AAD context label for ghost-tier OHBK files.
///
/// Callers creating sync blobs or any other cross-context payload MUST pass
/// a distinct label so an attacker cannot swap a ghost-tier backup for a
/// sync blob (or vice-versa) — AEAD authentication will reject the swap.
const defaultGhostBackupContext = 'ghost-backup/v1';

/// Encrypted export/import of Ghost-tier app data using the OHBK wire format.
///
/// Wire format (v2, current):
/// ```
/// [4 bytes magic: 0x4F 0x48 0x42 0x4B ("OHBK")]
/// [1 byte version: 0x02]
/// [1 byte cipher suite: 0x01 = ChaCha20-Poly1305 IETF]
/// [12 bytes nonce]
/// [16 bytes Poly1305 MAC]
/// [N bytes ciphertext]
/// ```
/// AEAD additional data = `header ‖ utf8(context)`. [import] rejects any
/// blob whose MAC does not verify against the supplied context, which binds
/// the blob to the purpose its creator intended (ghost backup vs sync dump
/// vs future use).
///
/// Wire format (v1, legacy): same layout, no AAD binding. Accepted by
/// [import] for backwards compatibility with files written by pre-hardening
/// pilot builds; never emitted by [export].
abstract final class GhostBackup {
  /// Encrypts [appData] under [key] and returns an OHBK v2 blob.
  ///
  /// [context] is an ASCII label describing the purpose of this blob. It is
  /// bound into the AEAD tag so a blob encrypted for one purpose cannot be
  /// fed to [import] with a different purpose (even if the attacker has a
  /// valid key). Defaults to [defaultGhostBackupContext]; sync/named tiers
  /// pass their own label (e.g. `'sync-dump/v1'`).
  static Future<Uint8List> export(
    Uint8List appData,
    Uint8List key,
    EnvelopeCipher cipher, {
    String context = defaultGhostBackupContext,
  }) async {
    // Fail closed at export time: the resulting blob (header + nonce + MAC +
    // ciphertext, where ciphertext length == plaintext length for the AEAD)
    // must fit the same ceiling [import] enforces, so we never hand back a
    // file our own importer would reject. Checked before the encrypt so an
    // oversized payload is rejected cheaply.
    final blobLength = _minBlobLength + appData.length;
    if (blobLength > _maxBlobLength) {
      throw BackupFormatException(
        'Backup too large: maximum $_maxBlobLength bytes, '
        'blob would be $blobLength',
      );
    }

    final header = _buildHeader(_versionCurrent);
    final aad = _buildAad(header, context);
    final envelope = await cipher.encrypt(
      appData,
      key,
      additionalData: aad,
    );
    final builder = BytesBuilder(copy: false)
      ..add(header)
      ..add(envelope.nonce)
      ..add(envelope.mac)
      ..add(envelope.ciphertext);
    return builder.toBytes();
  }

  /// Decrypts an OHBK [blob] under [key] and returns the original app data.
  ///
  /// [context] must match the label used at export time for v2 blobs. For
  /// legacy v1 blobs the label is ignored (v1 didn't bind any AAD).
  ///
  /// Throws [BackupFormatException] if the blob has wrong magic bytes,
  /// an unsupported version, or is too short / too large.
  /// Throws [CryptoException] if the key is wrong, the context does not
  /// match, or the ciphertext has been tampered with.
  static Future<Uint8List> import(
    Uint8List blob,
    Uint8List key,
    EnvelopeCipher cipher, {
    String context = defaultGhostBackupContext,
  }) async {
    if (blob.length < _minBlobLength) {
      throw BackupFormatException(
        'Blob too short: expected at least $_minBlobLength bytes, '
        'got ${blob.length}',
      );
    }

    if (blob.length > _maxBlobLength) {
      throw BackupFormatException(
        'Blob too large: maximum $_maxBlobLength bytes, '
        'got ${blob.length}',
      );
    }

    if (!listEquals(blob.sublist(0, 4), _magic)) {
      throw BackupFormatException('Invalid magic bytes');
    }

    final version = blob[4];
    if (version != _versionCurrent && version != _versionLegacy) {
      throw BackupFormatException(
        'Unsupported version: 0x${version.toRadixString(16).padLeft(2, '0')}',
      );
    }

    if (blob[5] != _suiteChaCha20Poly1305) {
      throw BackupFormatException(
        'Unsupported cipher suite: 0x${blob[5].toRadixString(16).padLeft(2, '0')}',
      );
    }

    final nonceEnd = _headerLength + _nonceLength;
    final macEnd = nonceEnd + _macLength;
    final nonce = Uint8List.sublistView(blob, _headerLength, nonceEnd);
    final mac = Uint8List.sublistView(blob, nonceEnd, macEnd);
    final ciphertext = Uint8List.sublistView(blob, macEnd);
    final envelope = CipherEnvelope(
      nonce: nonce,
      ciphertext: ciphertext,
      mac: mac,
    );

    final aad = version == _versionCurrent
        ? _buildAad(Uint8List.sublistView(blob, 0, _headerLength), context)
        : null;

    return cipher.decrypt(envelope, key, additionalData: aad);
  }

  static Uint8List _buildHeader(int version) {
    final header = Uint8List(_headerLength);
    header.setRange(0, 4, _magic);
    header[4] = version;
    header[5] = _suiteChaCha20Poly1305;
    return header;
  }

  static Uint8List _buildAad(Uint8List header, String context) {
    final ctx = utf8.encode(context);
    final builder = BytesBuilder(copy: false)
      ..add(header)
      ..add(ctx);
    return builder.toBytes();
  }
}
