import 'dart:convert';

import 'package:cryptography/cryptography.dart';
import 'package:flutter/foundation.dart';

/// The domain-separated keys derived from the BIP39 seed.
///
/// [masterEncryptionKey] — encrypts local ghost-tier backups (OHBK files).
/// [syncKey]             — encrypts sync blobs uploaded to the relay. Distinct
///                         from [masterEncryptionKey] so a nonce-reuse bug in
///                         one path cannot compromise the other.
/// [authKey]             — used as the server password (bcrypt hash). Sync/Named only.
/// [recoveryKey]         — recovery identifier stored as a hash. Sync/Named only.
/// [syncChannelId]       — 32-byte channel identifier for the encrypted blob relay.
@immutable
class DerivedKeys {
  final Uint8List masterEncryptionKey;
  final Uint8List syncKey;
  final Uint8List authKey;
  final Uint8List recoveryKey;
  final Uint8List syncChannelId;

  const DerivedKeys({
    required this.masterEncryptionKey,
    required this.syncKey,
    required this.authKey,
    required this.recoveryKey,
    required this.syncChannelId,
  });
}

/// Derives [DerivedKeys] from a 64-byte BIP39 seed using HKDF-SHA256.
///
/// Domain separation uses the `info` strings defined in the OpenHearth auth PRD §4.
/// The legacy (`appDomain == null`) strings are frozen — changing them
/// invalidates every existing derived key.
///
/// An optional per-app `appDomain` (e.g. `'sundial'`) shifts every info string
/// to `openhearth.<appDomain>.<purpose>.v1`, so two apps sharing one household
/// seed get cryptographically isolated key material. `appDomain == null`
/// reproduces the original strings byte-for-byte (backwards compatibility for
/// shipped user backups).
abstract final class KeyDerivation {
  // Legacy (appDomain == null) info strings — FROZEN. Do not edit.
  static const _infoEncryption = 'openhearth.encryption.v1';
  static const _infoSyncEncryption = 'openhearth.sync.encryption.v1';
  static const _infoAuth = 'openhearth.auth.v1';
  static const _infoRecovery = 'openhearth.recovery.v1';
  static const _infoSyncChannel = 'openhearth.sync.channel.v1';

  // Purpose suffixes used to build a per-app info string
  // (`openhearth.<appDomain>.<suffix>`).
  static const _suffixEncryption = 'encryption.v1';
  static const _suffixSyncEncryption = 'sync.encryption.v1';
  static const _suffixAuth = 'auth.v1';
  static const _suffixRecovery = 'recovery.v1';
  static const _suffixSyncChannel = 'sync.channel.v1';

  /// A valid app domain is one or more lowercase ASCII letters/digits.
  ///
  /// Restricting the alphabet prevents an app from smuggling separators or
  /// mixed case into the info string and colliding with (or being mistaken
  /// for) another app's or the legacy derivation.
  static final _appDomainPattern = RegExp(r'^[a-z0-9]+$');

  // All frozen legacy info strings, for deriving the reserved-word set
  // below. Kept in one place so the reserved set can never drift out of
  // sync with the actual frozen constants (F12).
  static const _legacyInfoStrings = <String>[
    _infoEncryption,
    _infoSyncEncryption,
    _infoAuth,
    _infoRecovery,
    _infoSyncChannel,
  ];

  /// Purpose tokens reserved from `appDomain` because they appear as a
  /// segment of a frozen legacy info string (everything between the fixed
  /// `openhearth.` prefix and `.v1` suffix, e.g. `encryption`, `sync`,
  /// `auth`, `recovery`, `channel`).
  ///
  /// Without this guard, `appDomain='sync'` builds
  /// `openhearth.sync.encryption.v1` — byte-for-byte the frozen legacy
  /// `syncKey` info string — so that app's `masterEncryptionKey` would
  /// silently equal another context's `syncKey` (F12). Derived from
  /// [_legacyInfoStrings] itself so a future legacy constant automatically
  /// contributes its reserved tokens too.
  static final Set<String> _reservedAppDomains = _legacyInfoStrings
      .expand((info) => info.split('.'))
      .where((segment) => segment != 'openhearth' && segment != 'v1')
      .toSet();

  static final _hkdf = Hkdf(hmac: Hmac.sha256(), outputLength: 32);

  /// Derives all purpose keys from the 512-bit [seed].
  ///
  /// Pass [appDomain] to isolate this app's keys from other apps sharing the
  /// same seed; leave it null for the legacy household-wide derivation.
  ///
  /// Throws [ArgumentError] if [seed] is not exactly 64 bytes, or if
  /// [appDomain] is non-null and not `^[a-z0-9]+$`.
  static Future<DerivedKeys> fromSeed(
    Uint8List seed, {
    String? appDomain,
  }) async {
    if (seed.length != 64) {
      throw ArgumentError('Seed must be 64 bytes; got ${seed.length}');
    }
    _validateAppDomain(appDomain);
    // Defensive copy: `cryptography` retains a reference to the provided
    // bytes rather than copying. This lets callers safely zeroize `seed`
    // after calling fromSeed.
    final secretKey = SecretKey(Uint8List.fromList(seed));

    final results = await Future.wait([
      _expand(secretKey, _info(_infoEncryption, _suffixEncryption, appDomain)),
      _expand(secretKey,
          _info(_infoSyncEncryption, _suffixSyncEncryption, appDomain)),
      _expand(secretKey, _info(_infoAuth, _suffixAuth, appDomain)),
      _expand(secretKey, _info(_infoRecovery, _suffixRecovery, appDomain)),
      _expand(secretKey,
          _info(_infoSyncChannel, _suffixSyncChannel, appDomain)),
    ]);

    return DerivedKeys(
      masterEncryptionKey: results[0],
      syncKey: results[1],
      authKey: results[2],
      recoveryKey: results[3],
      syncChannelId: results[4],
    );
  }

  /// Derives just the sync channel ID from a 512-bit [seed].
  ///
  /// Use this when you need the channel ID without deriving all keys
  /// (e.g. to check relay membership before a full sync). Honors [appDomain]
  /// exactly as [fromSeed] does.
  ///
  /// Throws [ArgumentError] if [seed] is not exactly 64 bytes, or if
  /// [appDomain] is non-null and not `^[a-z0-9]+$`.
  static Future<Uint8List> deriveSyncChannelId(
    Uint8List seed, {
    String? appDomain,
  }) async {
    if (seed.length != 64) {
      throw ArgumentError('Seed must be 64 bytes; got ${seed.length}');
    }
    _validateAppDomain(appDomain);
    final secretKey = SecretKey(Uint8List.fromList(seed));
    return _expand(
      secretKey,
      _info(_infoSyncChannel, _suffixSyncChannel, appDomain),
    );
  }

  /// Derives a single 32-byte key from an arbitrary [secret] using
  /// HKDF-SHA256 (empty salt, `info = utf8(domain)`).
  ///
  /// Unlike [fromSeed], this takes any non-empty byte string — it is the
  /// path for non-BIP39 secrets such as StillLife's LAN-sync pairing code.
  /// [domain] is the full HKDF info label (e.g. `'stilllife.lan.v1'`); use a
  /// distinct label per purpose so keys are domain-separated. Apps must not
  /// hand-roll their own HKDF — route it here.
  ///
  /// Throws [ArgumentError] if [secret] is empty or [domain] is empty.
  static Future<Uint8List> deriveKey(
    Uint8List secret, {
    required String domain,
  }) async {
    if (secret.isEmpty) {
      throw ArgumentError.value(secret, 'secret', 'must not be empty');
    }
    if (domain.isEmpty) {
      throw ArgumentError.value(domain, 'domain', 'must not be empty');
    }
    // Defensive copy — `cryptography` retains the reference (see [fromSeed]).
    final secretKey = SecretKey(Uint8List.fromList(secret));
    return _expand(secretKey, domain);
  }

  static void _validateAppDomain(String? appDomain) {
    if (appDomain == null) return;
    if (!_appDomainPattern.hasMatch(appDomain)) {
      throw ArgumentError.value(
        appDomain,
        'appDomain',
        'must be one or more lowercase ASCII letters/digits ([a-z0-9]+)',
      );
    }
    if (_reservedAppDomains.contains(appDomain)) {
      throw ArgumentError.value(
        appDomain,
        'appDomain',
        'is reserved (collides with a frozen legacy info-string segment); '
            'reserved values are: ${(_reservedAppDomains.toList()..sort()).join(', ')}',
      );
    }
  }

  /// Returns the frozen [legacy] info string when [appDomain] is null,
  /// otherwise `openhearth.<appDomain>.<suffix>`.
  static String _info(String legacy, String suffix, String? appDomain) =>
      appDomain == null ? legacy : 'openhearth.$appDomain.$suffix';

  static Future<Uint8List> _expand(SecretKey secretKey, String info) async {
    final derived = await _hkdf.deriveKey(
      secretKey: secretKey,
      nonce: const <int>[], // no salt; entropy already concentrated in seed
      info: utf8.encode(info),
    );
    return Uint8List.fromList(await derived.extractBytes());
  }
}
