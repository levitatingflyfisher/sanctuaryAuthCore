import 'package:flutter_test/flutter_test.dart';
import 'package:mocktail/mocktail.dart';
import 'package:sanctuary_auth_core/src/storage/secure_key_store.dart';
import 'package:sanctuary_auth_core/src/sync/device_id.dart';

class MockSecureKeyStore extends Mock implements SecureKeyStore {}

void main() {
  late MockSecureKeyStore store;

  setUp(() {
    store = MockSecureKeyStore();
  });

  group('ensureDeviceId', () {
    test('returns existing device ID if already stored', () async {
      when(() => store.readDeviceId())
          .thenAnswer((_) async => 'existing-uuid');

      final id = await ensureDeviceId(store);

      expect(id, equals('existing-uuid'));
      verifyNever(() => store.writeDeviceId(any()));
    });

    test('generates and stores a new UUID v4 if none exists', () async {
      when(() => store.readDeviceId()).thenAnswer((_) async => null);
      when(() => store.writeDeviceId(any())).thenAnswer((_) async {});

      final id = await ensureDeviceId(store);

      // UUID v4 format: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
      expect(id, hasLength(36));
      expect(id[14], equals('4')); // version nibble
      expect('89ab', contains(id[19])); // variant nibble
      verify(() => store.writeDeviceId(id)).called(1);
    });

    test('generates unique IDs on each call when store is empty', () async {
      when(() => store.readDeviceId()).thenAnswer((_) async => null);
      when(() => store.writeDeviceId(any())).thenAnswer((_) async {});

      final id1 = await ensureDeviceId(store);

      // Simulate that after first call, the ID is stored
      when(() => store.readDeviceId()).thenAnswer((_) async => null);
      final id2 = await ensureDeviceId(store);

      // Both should be valid UUIDs but different
      expect(id1, isNot(equals(id2)));
    });

    test('generated ID matches UUID v4 regex', () async {
      when(() => store.readDeviceId()).thenAnswer((_) async => null);
      when(() => store.writeDeviceId(any())).thenAnswer((_) async {});

      final id = await ensureDeviceId(store);

      final uuidV4Regex = RegExp(
        r'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$',
      );
      expect(uuidV4Regex.hasMatch(id), isTrue, reason: 'ID "$id" is not a valid UUID v4');
    });
  });
}
