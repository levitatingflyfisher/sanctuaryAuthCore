import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
// Import the public barrel — the exact surface W2/W3 consumer apps use
// (alongside flutter_riverpod, exactly as an app would).
// Every other test reaches in via `src/...`; this is the one that would catch
// an export regression (a symbol dropped from the barrel).
import 'package:sanctuary_auth_core/sanctuary_auth_core.dart';

void main() {
  group('public barrel surface', () {
    test('exposes the per-app domain provider and its default (null)', () {
      final container = ProviderContainer();
      addTearDown(container.dispose);
      expect(container.read(sanctuaryAppDomainProvider), isNull);
    });

    test('exposes KeyDerivation.deriveKey through the barrel', () async {
      final key = await KeyDerivation.deriveKey(
        Uint8List.fromList(utf8.encode('code')),
        domain: 'stilllife.lan.v1',
      );
      expect(key, hasLength(32));
    });

    test('exposes appDomain-aware fromSeed + the OHBK round-trip', () async {
      const phrase =
          'abandon abandon abandon abandon abandon abandon '
          'abandon abandon abandon abandon abandon about';
      final keys = await const DefaultCryptoService()
          .deriveKeysFromPhrase(phrase, appDomain: 'sundial');
      final cipher = EnvelopeCipher();
      final blob = await GhostBackup.export(
        Uint8List.fromList(utf8.encode('hello')),
        keys.masterEncryptionKey,
        cipher,
        context: 'sundial-backup/v1',
      );
      final recovered = await GhostBackup.import(
        blob,
        keys.masterEncryptionKey,
        cipher,
        context: 'sundial-backup/v1',
      );
      expect(utf8.decode(recovered), 'hello');
    });
  });
}
