import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mocktail/mocktail.dart';
import 'package:sanctuary_auth_core/src/state/auth_notifier.dart';
import 'package:sanctuary_auth_core/src/storage/secure_key_store.dart';
import 'package:sanctuary_auth_core/src/storage/secure_key_store_provider.dart';

class MockSecureKeyStore extends Mock implements SecureKeyStore {}

ProviderContainer makeContainer(SecureKeyStore store) {
  return ProviderContainer(
    overrides: [secureKeyStoreProvider.overrideWithValue(store)],
  );
}

void main() {
  late MockSecureKeyStore store;

  setUpAll(() {
    registerFallbackValue(DateTime(2000));
  });

  setUp(() {
    store = MockSecureKeyStore();
  });

  group('AuthNotifier — syncChannelId propagation', () {
    test('syncChannelId is populated when mnemonic exists', () async {
      const phrase =
          'abandon abandon abandon abandon abandon abandon '
          'abandon abandon abandon abandon abandon about';
      when(() => store.readMnemonic()).thenAnswer((_) async => phrase);
      when(() => store.readSeedAcknowledged()).thenAnswer((_) async => false);
      when(() => store.readLastBackupAt()).thenAnswer((_) async => null);

      final container = makeContainer(store);
      addTearDown(container.dispose);

      final state = await container.read(authNotifierProvider.future);
      expect(state.syncChannelId, isNotNull);
      expect(state.syncChannelId, hasLength(32));
    });

    test('syncChannelId is null when no mnemonic exists', () async {
      when(() => store.readMnemonic()).thenAnswer((_) async => null);
      when(() => store.readSeedAcknowledged()).thenAnswer((_) async => false);
      when(() => store.readLastBackupAt()).thenAnswer((_) async => null);

      final container = makeContainer(store);
      addTearDown(container.dispose);

      final state = await container.read(authNotifierProvider.future);
      expect(state.syncChannelId, isNull);
    });

    test('syncChannelId is populated after generateSeedPhrase', () async {
      when(() => store.readMnemonic()).thenAnswer((_) async => null);
      when(() => store.readSeedAcknowledged()).thenAnswer((_) async => false);
      when(() => store.readLastBackupAt()).thenAnswer((_) async => null);
      when(() => store.writeMnemonic(any())).thenAnswer((_) async {});

      final container = makeContainer(store);
      addTearDown(container.dispose);

      container.listen(authNotifierProvider, (_, _) {});
      await container.read(authNotifierProvider.future);

      await container
          .read(authNotifierProvider.notifier)
          .generateSeedPhrase();
      final state = await container.read(authNotifierProvider.future);
      expect(state.syncChannelId, isNotNull);
      expect(state.syncChannelId, hasLength(32));
    });

    test('syncChannelId is null after resetIdentity', () async {
      const phrase =
          'abandon abandon abandon abandon abandon abandon '
          'abandon abandon abandon abandon abandon about';
      when(() => store.readMnemonic()).thenAnswer((_) async => phrase);
      when(() => store.readSeedAcknowledged()).thenAnswer((_) async => true);
      when(() => store.readLastBackupAt()).thenAnswer((_) async => null);
      when(() => store.clearAuth()).thenAnswer((_) async {});

      final container = makeContainer(store);
      addTearDown(container.dispose);

      container.listen(authNotifierProvider, (_, _) {});
      final before = await container.read(authNotifierProvider.future);
      expect(before.syncChannelId, isNotNull);

      await container.read(authNotifierProvider.notifier).resetIdentity();
      final after = await container.read(authNotifierProvider.future);
      expect(after.syncChannelId, isNull);
    });

    test('same phrase produces same syncChannelId across loads', () async {
      const phrase =
          'abandon abandon abandon abandon abandon abandon '
          'abandon abandon abandon abandon abandon about';
      when(() => store.readMnemonic()).thenAnswer((_) async => phrase);
      when(() => store.readSeedAcknowledged()).thenAnswer((_) async => false);
      when(() => store.readLastBackupAt()).thenAnswer((_) async => null);

      final container1 = makeContainer(store);
      addTearDown(container1.dispose);
      final state1 = await container1.read(authNotifierProvider.future);

      final container2 = makeContainer(store);
      addTearDown(container2.dispose);
      final state2 = await container2.read(authNotifierProvider.future);

      expect(state1.syncChannelId, equals(state2.syncChannelId));
    });
  });

  group('SecureKeyStore — deviceId', () {
    test('writeDeviceId then readDeviceId returns same value', () async {
      const id = 'f47ac10b-58cc-4372-a567-0e02b2c3d479';

      when(() => store.writeDeviceId(id)).thenAnswer((_) async {});
      when(() => store.readDeviceId()).thenAnswer((_) async => id);

      await store.writeDeviceId(id);
      final result = await store.readDeviceId();

      expect(result, equals(id));
      verify(() => store.writeDeviceId(id)).called(1);
      verify(() => store.readDeviceId()).called(1);
    });

    test('readDeviceId returns null before any write', () async {
      when(() => store.readDeviceId()).thenAnswer((_) async => null);

      final result = await store.readDeviceId();
      expect(result, isNull);
    });
  });
}
