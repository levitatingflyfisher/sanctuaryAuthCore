import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:sanctuary_auth_core/src/backup/ghost_backup.dart';
import 'package:sanctuary_auth_core/src/bip39/mnemonic.dart';
import 'package:sanctuary_auth_core/src/crypto/envelope_cipher.dart';
import 'package:sanctuary_auth_core/src/crypto/key_derivation.dart';

void main() {
  group('End-to-end chain', () {
    late EnvelopeCipher cipher;

    setUp(() {
      cipher = EnvelopeCipher();
    });

    test(
      'generate phrase -> derive keys -> encrypt -> backup -> import -> decrypt',
      () async {
        // 1. Generate a fresh BIP39 phrase
        final phrase = OpenHearthMnemonic.generate();
        expect(phrase.split(' '), hasLength(12));

        // 2. Derive the 512-bit seed
        final seed = await OpenHearthMnemonic.deriveSeed(phrase);
        expect(seed, hasLength(64));

        // 3. Derive domain-separated keys
        final keys = await KeyDerivation.fromSeed(seed);
        expect(keys.masterEncryptionKey, hasLength(32));

        // 4. Encrypt some app data
        final appData = Uint8List.fromList(
          List<int>.generate(500, (i) => (i * 7 + 13) & 0xff),
        );

        // 5. Export to OHBK backup blob
        final blob = await GhostBackup.export(
          appData,
          keys.masterEncryptionKey,
          cipher,
        );
        expect(blob.length, greaterThan(34));

        // 6. Simulate recovery: re-derive keys from the same phrase
        final recoveredSeed = await OpenHearthMnemonic.deriveSeed(phrase);
        final recoveredKeys = await KeyDerivation.fromSeed(recoveredSeed);
        expect(
          recoveredKeys.masterEncryptionKey,
          equals(keys.masterEncryptionKey),
        );

        // 7. Import the backup and verify round-trip
        final recovered = await GhostBackup.import(
          blob,
          recoveredKeys.masterEncryptionKey,
          cipher,
        );
        expect(recovered, equals(appData));
      },
    );

    test(
      'recovery from paper backup: phrase -> keys -> decrypt existing backup',
      () async {
        final originalPhrase = OpenHearthMnemonic.generate();
        final originalSeed =
            await OpenHearthMnemonic.deriveSeed(originalPhrase);
        final originalKeys = await KeyDerivation.fromSeed(originalSeed);

        final appData = Uint8List.fromList([
          for (var i = 0; i < 100; i++) i,
        ]);
        final blob = await GhostBackup.export(
          appData,
          originalKeys.masterEncryptionKey,
          cipher,
        );

        // --- device lost, user enters phrase on new device ---

        final restoredSeed =
            await OpenHearthMnemonic.deriveSeed(originalPhrase);
        final restoredKeys = await KeyDerivation.fromSeed(restoredSeed);

        final restoredData = await GhostBackup.import(
          blob,
          restoredKeys.masterEncryptionKey,
          cipher,
        );

        expect(restoredData, equals(appData));
      },
    );
  });
}
