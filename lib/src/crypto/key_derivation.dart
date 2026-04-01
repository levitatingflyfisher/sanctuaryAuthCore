import 'dart:convert';

import 'package:cryptography/cryptography.dart';
import 'package:flutter/foundation.dart';

/// The three domain-separated keys derived from the BIP39 seed.
///
/// [masterEncryptionKey] — encrypts local data. Never leaves the device.
/// [authKey]             — used as the server password (bcrypt hash). Token/Named only.
/// [recoveryKey]         — recovery identifier stored as a hash. Token/Named only.
@immutable
class DerivedKeys {
  final Uint8List masterEncryptionKey;
  final Uint8List authKey;
  final Uint8List recoveryKey;

  const DerivedKeys({
    required this.masterEncryptionKey,
    required this.authKey,
    required this.recoveryKey,
  });
}

/// Derives [DerivedKeys] from a 64-byte BIP39 seed using HKDF-SHA256.
///
/// Domain separation uses the `info` strings defined in the OpenHearth auth PRD §4.
/// These strings are frozen — changing them invalidates all existing derived keys.
abstract final class KeyDerivation {
  static const _infoEncryption = 'openhearth.encryption.v1';
  static const _infoAuth = 'openhearth.auth.v1';
  static const _infoRecovery = 'openhearth.recovery.v1';

  /// Derives all three purpose keys from the 512-bit [seed].
  ///
  /// Throws [ArgumentError] if [seed] is not exactly 64 bytes.
  static Future<DerivedKeys> fromSeed(Uint8List seed) async {
    if (seed.length != 64) {
      throw ArgumentError('Seed must be 64 bytes; got ${seed.length}');
    }
    // Defensive copy: `cryptography` retains a reference to the provided
    // bytes rather than copying. This lets callers safely zeroize `seed`
    // after calling fromSeed.
    final secretKey = SecretKey(Uint8List.fromList(seed));

    final masterEncryptionKey = await _expand(secretKey, _infoEncryption);
    final authKey = await _expand(secretKey, _infoAuth);
    final recoveryKey = await _expand(secretKey, _infoRecovery);

    return DerivedKeys(
      masterEncryptionKey: masterEncryptionKey,
      authKey: authKey,
      recoveryKey: recoveryKey,
    );
  }

  static Future<Uint8List> _expand(SecretKey secretKey, String info) async {
    final hkdf = Hkdf(hmac: Hmac.sha256(), outputLength: 32);
    final derived = await hkdf.deriveKey(
      secretKey: secretKey,
      nonce: const <int>[], // no salt; entropy already concentrated in seed
      info: utf8.encode(info),
    );
    return Uint8List.fromList(await derived.extractBytes());
  }
}
