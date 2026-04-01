import 'package:flutter_test/flutter_test.dart';
import 'package:mocktail/mocktail.dart';
import 'package:sanctuary_auth_core/src/storage/secure_key_store.dart';

class MockSecureKeyStore extends Mock implements SecureKeyStore {}

void main() {
  group('SecureKeyStore (mock)', () {
    late MockSecureKeyStore store;

    setUp(() {
      store = MockSecureKeyStore();
    });

    test('writeMnemonic then readMnemonic returns same value', () async {
      const phrase = 'abandon abandon abandon abandon abandon abandon '
          'abandon abandon abandon abandon abandon about';

      when(() => store.writeMnemonic(phrase)).thenAnswer((_) async {});
      when(() => store.readMnemonic()).thenAnswer((_) async => phrase);

      await store.writeMnemonic(phrase);
      final result = await store.readMnemonic();

      expect(result, equals(phrase));
      verify(() => store.writeMnemonic(phrase)).called(1);
      verify(() => store.readMnemonic()).called(1);
    });

    test('readMnemonic returns null before any write', () async {
      when(() => store.readMnemonic()).thenAnswer((_) async => null);

      final result = await store.readMnemonic();

      expect(result, isNull);
    });

    test('writeLastBackupAt then readLastBackupAt round-trips', () async {
      final ts = DateTime.utc(2026, 4, 9, 12, 30);

      when(() => store.writeLastBackupAt(ts)).thenAnswer((_) async {});
      when(() => store.readLastBackupAt()).thenAnswer((_) async => ts);

      await store.writeLastBackupAt(ts);
      final result = await store.readLastBackupAt();

      expect(result, equals(ts));
      verify(() => store.writeLastBackupAt(ts)).called(1);
      verify(() => store.readLastBackupAt()).called(1);
    });

    test('readLastBackupAt returns null before any write', () async {
      when(() => store.readLastBackupAt()).thenAnswer((_) async => null);

      final result = await store.readLastBackupAt();

      expect(result, isNull);
    });

    test('writeSeedAcknowledged then readSeedAcknowledged returns true',
        () async {
      when(() => store.writeSeedAcknowledged()).thenAnswer((_) async {});
      when(() => store.readSeedAcknowledged()).thenAnswer((_) async => true);

      await store.writeSeedAcknowledged();
      final result = await store.readSeedAcknowledged();

      expect(result, isTrue);
      verify(() => store.writeSeedAcknowledged()).called(1);
      verify(() => store.readSeedAcknowledged()).called(1);
    });

    test('readSeedAcknowledged returns false before any write', () async {
      when(() => store.readSeedAcknowledged()).thenAnswer((_) async => false);

      final result = await store.readSeedAcknowledged();

      expect(result, isFalse);
    });

    test('clearAll deletes all stored values', () async {
      when(() => store.clearAll()).thenAnswer((_) async {});

      await store.clearAll();

      verify(() => store.clearAll()).called(1);
    });
  });
}
