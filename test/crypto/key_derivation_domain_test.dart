import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:sanctuary_auth_core/src/bip39/mnemonic.dart';
import 'package:sanctuary_auth_core/src/crypto/key_derivation.dart';

/// Per-app HKDF domain separation (SANCTUARY-BRIEF §4.W0.2).
///
/// `appDomain == null` must reproduce the legacy frozen derivation byte for
/// byte (the regression gate — the existing KAT vectors depend on it). A
/// non-null domain shifts every info string to `openhearth.<domain>.*.v1`,
/// so two apps under the same household seed get cryptographically isolated
/// key material.
void main() {
  group('KeyDerivation appDomain', () {
    late Uint8List seed;

    setUpAll(() async {
      const phrase =
          'abandon abandon abandon abandon abandon abandon '
          'abandon abandon abandon abandon abandon about';
      seed = await OpenHearthMnemonic.deriveSeed(phrase);
    });

    List<Uint8List> allKeys(dynamic k) => [
          k.masterEncryptionKey as Uint8List,
          k.syncKey as Uint8List,
          k.authKey as Uint8List,
          k.recoveryKey as Uint8List,
          k.syncChannelId as Uint8List,
        ];

    test('appDomain null reproduces legacy derivation byte-for-byte', () async {
      final legacy = await KeyDerivation.fromSeed(seed);
      final explicitNull = await KeyDerivation.fromSeed(seed, appDomain: null);
      expect(explicitNull.masterEncryptionKey, legacy.masterEncryptionKey);
      expect(explicitNull.syncKey, legacy.syncKey);
      expect(explicitNull.authKey, legacy.authKey);
      expect(explicitNull.recoveryKey, legacy.recoveryKey);
      expect(explicitNull.syncChannelId, legacy.syncChannelId);
    });

    test('appDomain null still matches the frozen legacy master KAT', () async {
      final keys = await KeyDerivation.fromSeed(seed, appDomain: null);
      expect(
        _hex(keys.masterEncryptionKey),
        'a0e7fa41ce299cb582be43d84de04fd116489379c02c062916ed7e6fbd626aa2',
        reason: 'null appDomain must not perturb the legacy derivation',
      );
    });

    test('same seed + same domain is deterministic', () async {
      final a = await KeyDerivation.fromSeed(seed, appDomain: 'sundial');
      final b = await KeyDerivation.fromSeed(seed, appDomain: 'sundial');
      for (var i = 0; i < 5; i++) {
        expect(allKeys(a)[i], allKeys(b)[i]);
      }
    });

    test('different domains produce all five keys distinct pairwise', () async {
      final nul = await KeyDerivation.fromSeed(seed);
      final alpha = await KeyDerivation.fromSeed(seed, appDomain: 'alpha');
      final beta = await KeyDerivation.fromSeed(seed, appDomain: 'beta');
      for (var i = 0; i < 5; i++) {
        expect(allKeys(alpha)[i], isNot(allKeys(beta)[i]),
            reason: 'key $i: alpha vs beta must differ');
        expect(allKeys(alpha)[i], isNot(allKeys(nul)[i]),
            reason: 'key $i: alpha vs null must differ');
        expect(allKeys(beta)[i], isNot(allKeys(nul)[i]),
            reason: 'key $i: beta vs null must differ');
      }
    });

    test('deriveSyncChannelId honors appDomain', () async {
      final scoped =
          await KeyDerivation.deriveSyncChannelId(seed, appDomain: 'sundial');
      final full = await KeyDerivation.fromSeed(seed, appDomain: 'sundial');
      expect(scoped, full.syncChannelId);
      final legacyChannel = await KeyDerivation.deriveSyncChannelId(seed);
      expect(scoped, isNot(legacyChannel));
    });

    test('invalid appDomain is rejected with ArgumentError', () async {
      for (final bad in <String>['', 'Sundial', 'sun-dial', 'sun.dial',
        'sun dial', 'sun_dial', 'sundial!', 'sündial']) {
        expect(
          () => KeyDerivation.fromSeed(seed, appDomain: bad),
          throwsA(isA<ArgumentError>()),
          reason: 'appDomain "$bad" must be rejected',
        );
      }
    });

    test('valid appDomain values are accepted', () async {
      for (final ok in <String>['sundial', 'stilllife', 'weatherglass',
        'app123', '0']) {
        await expectLater(
          KeyDerivation.fromSeed(seed, appDomain: ok),
          completes,
          reason: 'appDomain "$ok" must be accepted',
        );
      }
    });

    test(
        'reserved appDomain values (would collide with a frozen legacy info '
        'string) are rejected with ArgumentError', () async {
      // F12: appDomain='sync' builds 'openhearth.sync.encryption.v1', which
      // is byte-for-byte the frozen legacy syncKey info string — so that
      // app's masterEncryptionKey would equal another context's syncKey.
      // Reserved tokens are the purpose segments of every frozen legacy
      // info string (encryption, sync, auth, recovery, channel).
      for (final reserved in <String>[
        'encryption',
        'sync',
        'auth',
        'recovery',
        'channel',
      ]) {
        expect(
          () => KeyDerivation.fromSeed(seed, appDomain: reserved),
          throwsA(isA<ArgumentError>()),
          reason: 'reserved appDomain "$reserved" must be rejected',
        );
        expect(
          () => KeyDerivation.deriveSyncChannelId(seed, appDomain: reserved),
          throwsA(isA<ArgumentError>()),
          reason: 'deriveSyncChannelId must also reject reserved appDomain '
              '"$reserved"',
        );
      }
    });

    test('ordinary app domains that merely contain a reserved substring '
        'remain accepted', () async {
      // Guards against an overzealous substring-based blocklist: only exact
      // reserved-token matches should be rejected, not domains that happen
      // to contain one as a substring.
      for (final ok in <String>['synchro', 'authentica', 'resync']) {
        await expectLater(
          KeyDerivation.fromSeed(seed, appDomain: ok),
          completes,
          reason: 'appDomain "$ok" must be accepted (not a reserved word)',
        );
      }
    });

    test('known-answer vector: sundial domain pins the info-string format',
        () async {
      // Computed once and frozen. Guards the exact
      // `openhearth.sundial.encryption.v1` info-string construction against
      // silent refactors — a shift here would orphan every Sundial backup.
      final keys = await KeyDerivation.fromSeed(seed, appDomain: 'sundial');
      expect(
        _hex(keys.masterEncryptionKey),
        _sundialMasterKat,
        reason: 'sundial master-key info string drifted',
      );
      expect(
        _hex(keys.syncChannelId),
        _sundialChannelKat,
        reason: 'sundial sync-channel info string drifted',
      );
    });
  });
}

// Frozen after first green run (SANCTUARY-BRIEF §4.W0.2).
const _sundialMasterKat =
    '85a1c5b3e70cb490b10c212b98193d5997361636fa49f4a00c33ef90117c3aeb';
const _sundialChannelKat =
    '464aee8f625d46da71a9551fddf83288194126f078d15bff4e52c6397b1c2706';

String _hex(List<int> bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
