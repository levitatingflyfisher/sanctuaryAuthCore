import 'dart:ffi';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:sanctuary_auth_core/src/backup/ghost_backup.dart';
import 'package:sanctuary_auth_core/src/crypto/envelope_cipher.dart';
import 'package:sodium/sodium.dart';

void main() {
  group('GhostBackup', () {
    late Sodium sodium;
    late EnvelopeCipher cipher;
    late Uint8List key;

    setUpAll(() async {
      sodium = await SodiumInit.init(
        () => DynamicLibrary.open('libsodium.so.26'),
      );
      cipher = EnvelopeCipher(sodium);
      key = sodium.randombytes.buf(32);
    });

    test('export returns blob starting with OHBK magic bytes', () {
      final blob = GhostBackup.export(Uint8List(0), key, cipher);
      expect(blob[0], equals(0x4F));
      expect(blob[1], equals(0x48));
      expect(blob[2], equals(0x42));
      expect(blob[3], equals(0x4B));
    });

    test('export returns blob with version byte 0x01 at position [4]', () {
      final blob = GhostBackup.export(Uint8List(0), key, cipher);
      expect(blob[4], equals(0x01));
    });

    test('export blob is at least 45 bytes for empty plaintext', () {
      final blob = GhostBackup.export(Uint8List(0), key, cipher);
      expect(blob.length, greaterThanOrEqualTo(45));
    });

    test('import round-trips original app data', () {
      final appData = Uint8List.fromList(
        List<int>.generate(256, (i) => (i * 13) & 0xff),
      );
      final blob = GhostBackup.export(appData, key, cipher);
      final recovered = GhostBackup.import(blob, key, cipher);
      expect(recovered, equals(appData));
    });

    test('import throws on wrong key', () {
      final appData = Uint8List.fromList([1, 2, 3, 4, 5]);
      final blob = GhostBackup.export(appData, key, cipher);
      final wrongKey = sodium.randombytes.buf(32);
      expect(
        () => GhostBackup.import(blob, wrongKey, cipher),
        throwsA(isA<Exception>()),
      );
    });

    test('import throws GhostBackupFormatException on wrong magic bytes', () {
      final bad = Uint8List(45); // all zeros — wrong magic
      bad[4] = 0x01; // valid version but invalid magic
      expect(
        () => GhostBackup.import(bad, key, cipher),
        throwsA(isA<GhostBackupFormatException>()),
      );
    });

    test('import throws GhostBackupFormatException on unsupported version', () {
      final blob = GhostBackup.export(Uint8List(0), key, cipher);
      blob[4] = 0xFF; // corrupt version byte
      expect(
        () => GhostBackup.import(blob, key, cipher),
        throwsA(isA<GhostBackupFormatException>()),
      );
    });

    test('import throws GhostBackupFormatException on truncated blob', () {
      final truncated = Uint8List(44); // one byte short of minimum
      expect(
        () => GhostBackup.import(truncated, key, cipher),
        throwsA(isA<GhostBackupFormatException>()),
      );
    });
  });
}
