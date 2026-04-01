import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mocktail/mocktail.dart';
import 'package:sanctuary_auth_core/src/state/auth_notifier.dart';
import 'package:sanctuary_auth_core/src/state/auth_tier.dart';
import 'package:sanctuary_auth_core/src/storage/secure_key_store.dart';
import 'package:sanctuary_auth_core/src/storage/secure_key_store_provider.dart';

class MockSecureKeyStore extends Mock implements SecureKeyStore {}

/// Returns a [ProviderContainer] with [store] injected.
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

  group('AuthNotifier — initialization', () {
    test('starts in Ghost tier when keychain has no mnemonic', () async {
      when(() => store.readMnemonic()).thenAnswer((_) async => null);
      when(() => store.readSeedAcknowledged()).thenAnswer((_) async => false);
      when(() => store.readLastBackupAt()).thenAnswer((_) async => null);

      final container = makeContainer(store);
      addTearDown(container.dispose);

      final state = await container.read(authNotifierProvider.future);
      expect(state.tier, equals(AuthTier.ghost));
      expect(state.masterEncryptionKey, isNull);
      expect(state.seedAcknowledged, isFalse);
    });

    test('restores key material when keychain has a mnemonic', () async {
      const phrase =
          'abandon abandon abandon abandon abandon abandon '
          'abandon abandon abandon abandon abandon about';
      when(() => store.readMnemonic()).thenAnswer((_) async => phrase);
      when(() => store.readSeedAcknowledged()).thenAnswer((_) async => true);
      when(() => store.readLastBackupAt()).thenAnswer((_) async => null);

      final container = makeContainer(store);
      addTearDown(container.dispose);

      final state = await container.read(authNotifierProvider.future);
      expect(state.masterEncryptionKey, isNotNull);
      expect(state.masterEncryptionKey, hasLength(32));
      expect(state.tier, equals(AuthTier.ghost));
    });
  });

  group('AuthNotifier — generateSeedPhrase', () {
    test('returns a 12-word phrase', () async {
      when(() => store.readMnemonic()).thenAnswer((_) async => null);
      when(() => store.readSeedAcknowledged()).thenAnswer((_) async => false);
      when(() => store.readLastBackupAt()).thenAnswer((_) async => null);
      when(() => store.writeMnemonic(any())).thenAnswer((_) async {});

      final container = makeContainer(store);
      addTearDown(container.dispose);
      await container.read(authNotifierProvider.future);

      final phrase = await container
          .read(authNotifierProvider.notifier)
          .generateSeedPhrase();
      expect(phrase.split(' '), hasLength(12));
    });

    test('persists the mnemonic to keychain', () async {
      when(() => store.readMnemonic()).thenAnswer((_) async => null);
      when(() => store.readSeedAcknowledged()).thenAnswer((_) async => false);
      when(() => store.readLastBackupAt()).thenAnswer((_) async => null);
      when(() => store.writeMnemonic(any())).thenAnswer((_) async {});

      final container = makeContainer(store);
      addTearDown(container.dispose);
      await container.read(authNotifierProvider.future);

      await container
          .read(authNotifierProvider.notifier)
          .generateSeedPhrase();
      verify(() => store.writeMnemonic(any())).called(1);
    });
  });

  group('AuthNotifier — confirmSeedAcknowledged', () {
    test('sets seedAcknowledged = true in state', () async {
      const phrase =
          'abandon abandon abandon abandon abandon abandon '
          'abandon abandon abandon abandon abandon about';
      when(() => store.readMnemonic()).thenAnswer((_) async => phrase);
      when(() => store.readSeedAcknowledged()).thenAnswer((_) async => false);
      when(() => store.readLastBackupAt()).thenAnswer((_) async => null);
      when(() => store.writeSeedAcknowledged()).thenAnswer((_) async {});

      final container = makeContainer(store);
      addTearDown(container.dispose);

      // Keep a listener alive so auto-dispose doesn't discard the notifier.
      container.listen(authNotifierProvider, (_, _) {});
      await container.read(authNotifierProvider.future);

      await container
          .read(authNotifierProvider.notifier)
          .confirmSeedAcknowledged();
      final state = await container.read(authNotifierProvider.future);
      expect(state.seedAcknowledged, isTrue);
    });
  });

  group('AuthNotifier — recordBackupCompleted', () {
    test('updates lastBackupAt and needsBackupReminder becomes false',
        () async {
      const phrase =
          'abandon abandon abandon abandon abandon abandon '
          'abandon abandon abandon abandon abandon about';
      when(() => store.readMnemonic()).thenAnswer((_) async => phrase);
      when(() => store.readSeedAcknowledged()).thenAnswer((_) async => true);
      when(() => store.readLastBackupAt()).thenAnswer((_) async => null);
      when(() => store.writeLastBackupAt(any())).thenAnswer((_) async {});

      final container = makeContainer(store);
      addTearDown(container.dispose);

      // Keep a listener alive so auto-dispose doesn't discard the notifier.
      container.listen(authNotifierProvider, (_, _) {});
      await container.read(authNotifierProvider.future);

      await container
          .read(authNotifierProvider.notifier)
          .recordBackupCompleted();
      final state = await container.read(authNotifierProvider.future);
      expect(state.lastBackupAt, isNotNull);
      expect(state.needsBackupReminder, isFalse);
    });
  });
}
