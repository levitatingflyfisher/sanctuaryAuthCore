import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mocktail/mocktail.dart';
import 'package:sanctuary_auth_core/src/exceptions.dart';
import 'package:sanctuary_auth_core/src/crypto/crypto_service.dart';
import 'package:sanctuary_auth_core/src/state/auth_notifier.dart';
import 'package:sanctuary_auth_core/src/state/auth_tier.dart';
import 'package:sanctuary_auth_core/src/storage/secure_key_store.dart';
import 'package:sanctuary_auth_core/src/storage/secure_key_store_provider.dart';

class MockSecureKeyStore extends Mock implements SecureKeyStore {}

/// Returns a [ProviderContainer] with [store] injected, plus optional extra
/// [overrides] (e.g. [sanctuaryAppDomainProvider]).
ProviderContainer makeContainer(
  SecureKeyStore store, {
  List<Override> overrides = const [],
}) {
  return ProviderContainer(
    overrides: [
      secureKeyStoreProvider.overrideWithValue(store),
      ...overrides,
    ],
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
      expect(state.syncKey, isNotNull);
      expect(state.syncKey, hasLength(32));
      expect(state.syncKey, isNot(equals(state.masterEncryptionKey)),
          reason: 'syncKey must be HKDF-separated from masterEncryptionKey');
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

    test('throws StateError if phrase already exists', () async {
      const existing =
          'abandon abandon abandon abandon abandon abandon '
          'abandon abandon abandon abandon abandon about';
      // build() loads the existing phrase
      when(() => store.readMnemonic()).thenAnswer((_) async => existing);
      when(() => store.readSeedAcknowledged()).thenAnswer((_) async => false);
      when(() => store.readLastBackupAt()).thenAnswer((_) async => null);

      final container = makeContainer(store);
      addTearDown(container.dispose);
      await container.read(authNotifierProvider.future);

      expect(
        () => container
            .read(authNotifierProvider.notifier)
            .generateSeedPhrase(),
        throwsA(isA<StateError>()),
      );
    });

    test('force: true overwrites existing phrase', () async {
      const existing =
          'abandon abandon abandon abandon abandon abandon '
          'abandon abandon abandon abandon abandon about';
      // build() loads the existing phrase
      when(() => store.readMnemonic()).thenAnswer((_) async => existing);
      when(() => store.readSeedAcknowledged()).thenAnswer((_) async => false);
      when(() => store.readLastBackupAt()).thenAnswer((_) async => null);
      when(() => store.writeMnemonic(any())).thenAnswer((_) async {});

      final container = makeContainer(store);
      addTearDown(container.dispose);
      await container.read(authNotifierProvider.future);

      final phrase = await container
          .read(authNotifierProvider.notifier)
          .generateSeedPhrase(force: true);
      expect(phrase.split(' '), hasLength(12));
      verify(() => store.writeMnemonic(any())).called(1);
    });
  });

  group('AuthNotifier — confirmSeedAcknowledged', () {
    const phrase =
        'abandon abandon abandon abandon abandon abandon '
        'abandon abandon abandon abandon abandon about';

    test('sets seedAcknowledged = true when re-entry matches', () async {
      when(() => store.readMnemonic()).thenAnswer((_) async => phrase);
      when(() => store.readSeedAcknowledged()).thenAnswer((_) async => false);
      when(() => store.readLastBackupAt()).thenAnswer((_) async => null);
      when(() => store.writeSeedAcknowledged()).thenAnswer((_) async {});

      final container = makeContainer(store);
      addTearDown(container.dispose);
      container.listen(authNotifierProvider, (_, _) {});
      await container.read(authNotifierProvider.future);

      await container
          .read(authNotifierProvider.notifier)
          .confirmSeedAcknowledged(reEntryPhrase: phrase);
      final state = await container.read(authNotifierProvider.future);
      expect(state.seedAcknowledged, isTrue);
      verify(() => store.writeSeedAcknowledged()).called(1);
    });

    test('throws SeedPhraseMismatchException when re-entry is wrong',
        () async {
      when(() => store.readMnemonic()).thenAnswer((_) async => phrase);
      when(() => store.readSeedAcknowledged()).thenAnswer((_) async => false);
      when(() => store.readLastBackupAt()).thenAnswer((_) async => null);

      final container = makeContainer(store);
      addTearDown(container.dispose);
      container.listen(authNotifierProvider, (_, _) {});
      await container.read(authNotifierProvider.future);

      // Swap the last word for a different valid BIP39 word.
      final wrong = phrase.replaceAll('about', 'ability');
      await expectLater(
        container
            .read(authNotifierProvider.notifier)
            .confirmSeedAcknowledged(reEntryPhrase: wrong),
        throwsA(isA<SeedPhraseMismatchException>()),
      );
      verifyNever(() => store.writeSeedAcknowledged());
    });

    test('tolerates extra whitespace and case differences', () async {
      when(() => store.readMnemonic()).thenAnswer((_) async => phrase);
      when(() => store.readSeedAcknowledged()).thenAnswer((_) async => false);
      when(() => store.readLastBackupAt()).thenAnswer((_) async => null);
      when(() => store.writeSeedAcknowledged()).thenAnswer((_) async {});

      final container = makeContainer(store);
      addTearDown(container.dispose);
      container.listen(authNotifierProvider, (_, _) {});
      await container.read(authNotifierProvider.future);

      // Real users: wrap lines, capitalise first word, add tabs/newlines.
      final sloppy =
          '  Abandon\tabandon abandon  abandon abandon abandon\n'
          'abandon abandon abandon abandon abandon ABOUT  ';
      await container
          .read(authNotifierProvider.notifier)
          .confirmSeedAcknowledged(reEntryPhrase: sloppy);
      final state = await container.read(authNotifierProvider.future);
      expect(state.seedAcknowledged, isTrue);
    });

    test('throws StateError when no phrase exists yet', () async {
      when(() => store.readMnemonic()).thenAnswer((_) async => null);
      when(() => store.readSeedAcknowledged()).thenAnswer((_) async => false);
      when(() => store.readLastBackupAt()).thenAnswer((_) async => null);

      final container = makeContainer(store);
      addTearDown(container.dispose);
      container.listen(authNotifierProvider, (_, _) {});
      await container.read(authNotifierProvider.future);

      await expectLater(
        container
            .read(authNotifierProvider.notifier)
            .confirmSeedAcknowledged(reEntryPhrase: phrase),
        throwsA(isA<StateError>()),
      );
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
      expect(state.needsBackupReminder(), isFalse);
    });
  });

  group('AuthNotifier — resetIdentity', () {
    test('clears keychain and resets to Ghost tier', () async {
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
      expect(before.masterEncryptionKey, isNotNull);

      await container.read(authNotifierProvider.notifier).resetIdentity();
      final after = await container.read(authNotifierProvider.future);
      expect(after.tier, equals(AuthTier.ghost));
      expect(after.masterEncryptionKey, isNull);
      expect(after.seedAcknowledged, isFalse);
      verify(() => store.clearAuth()).called(1);
    });
  });

  group('AuthNotifier — per-app HKDF domain', () {
    const phrase =
        'abandon abandon abandon abandon abandon abandon '
        'abandon abandon abandon abandon abandon about';

    setUp(() {
      when(() => store.readMnemonic()).thenAnswer((_) async => phrase);
      when(() => store.readSeedAcknowledged()).thenAnswer((_) async => false);
      when(() => store.readLastBackupAt()).thenAnswer((_) async => null);
    });

    test('sanctuaryAppDomainProvider isolates derived key material', () async {
      final legacy = makeContainer(store);
      addTearDown(legacy.dispose);
      final scoped = makeContainer(store, overrides: [
        sanctuaryAppDomainProvider.overrideWithValue('sundial'),
      ]);
      addTearDown(scoped.dispose);

      final legacyState = await legacy.read(authNotifierProvider.future);
      final scopedState = await scoped.read(authNotifierProvider.future);

      expect(scopedState.masterEncryptionKey, isNotNull);
      expect(
        scopedState.masterEncryptionKey,
        isNot(equals(legacyState.masterEncryptionKey)),
        reason: 'a non-null appDomain must derive distinct key material',
      );
      expect(
        scopedState.syncChannelId,
        isNot(equals(legacyState.syncChannelId)),
      );
    });

    test('default (unoverridden) app domain reproduces legacy derivation',
        () async {
      final a = makeContainer(store);
      addTearDown(a.dispose);
      final b = makeContainer(store, overrides: [
        sanctuaryAppDomainProvider.overrideWithValue(null),
      ]);
      addTearDown(b.dispose);

      final sa = await a.read(authNotifierProvider.future);
      final sb = await b.read(authNotifierProvider.future);
      expect(sa.masterEncryptionKey, equals(sb.masterEncryptionKey));
    });
  });
}
