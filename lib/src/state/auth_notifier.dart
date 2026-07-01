import 'package:riverpod_annotation/riverpod_annotation.dart';

import '../crypto/crypto_service.dart';
import '../exceptions.dart';
import '../storage/secure_key_store.dart';
import '../storage/secure_key_store_provider.dart';
import 'auth_state.dart';
import 'auth_tier.dart';

part 'auth_notifier.g.dart';

@Riverpod(keepAlive: true)
class AuthNotifier extends _$AuthNotifier {
  late SecureKeyStore _store;
  late CryptoService _crypto;
  String? _appDomain;

  @override
  Future<AuthState> build() async {
    _store = ref.read(secureKeyStoreProvider);
    _crypto = ref.read(cryptoServiceProvider);
    _appDomain = ref.read(sanctuaryAppDomainProvider);
    return _loadFromKeychain();
  }

  Future<AuthState> _loadFromKeychain() async {
    final phrase = await _store.readMnemonic();
    final seedAcknowledged = await _store.readSeedAcknowledged();
    final lastBackupAt = await _store.readLastBackupAt();

    if (phrase == null) {
      return const AuthState.ghost();
    }

    final keys = await _crypto.deriveKeysFromPhrase(phrase, appDomain: _appDomain);

    return AuthState(
      tier: AuthTier.ghost,
      masterEncryptionKey: keys.masterEncryptionKey,
      syncKey: keys.syncKey,
      syncChannelId: keys.syncChannelId,
      seedAcknowledged: seedAcknowledged,
      lastBackupAt: lastBackupAt,
    );
  }

  /// Generates and stores a new BIP39 seed phrase.
  ///
  /// Returns the phrase for one-time display. The phrase is stored in the
  /// OS keychain immediately — the user should write it down, then call
  /// [confirmSeedAcknowledged].
  ///
  /// Throws [StateError] if a seed phrase already exists in the keychain.
  /// Pass [force] = `true` to overwrite an existing phrase (e.g. explicit
  /// user-initiated identity reset). **All data encrypted with the old key
  /// becomes permanently unrecoverable.**
  Future<String> generateSeedPhrase({bool force = false}) async {
    if (!force) {
      final existing = await _store.readMnemonic();
      if (existing != null) {
        throw StateError(
          'A seed phrase already exists. '
          'Pass force: true to overwrite (this destroys the old identity).',
        );
      }
    }

    final phrase = _crypto.generateMnemonic();
    await _store.writeMnemonic(phrase);

    final keys = await _crypto.deriveKeysFromPhrase(phrase, appDomain: _appDomain);

    state = AsyncData(AuthState(
      tier: AuthTier.ghost,
      masterEncryptionKey: keys.masterEncryptionKey,
      syncKey: keys.syncKey,
      syncChannelId: keys.syncChannelId,
      seedAcknowledged: false,
      lastBackupAt: null,
    ));

    return phrase;
  }

  /// Records that the user has written down their seed phrase, but only if
  /// [reEntryPhrase] matches the phrase stored in the keychain.
  ///
  /// The re-entry requirement converts a UX assertion ("I clicked 'got it'")
  /// into a cryptographic check ("I can reproduce the phrase"). Without it,
  /// the user can silently lie to themselves and lose all their data when
  /// they get a new phone. With it, acknowledging requires demonstrating
  /// that the phrase has actually been captured somewhere outside the app.
  ///
  /// Matching is whitespace-insensitive and case-insensitive — BIP39 words
  /// are lowercase by convention, but users commonly re-enter them with
  /// extra spaces or capitalisation.
  ///
  /// Throws:
  ///   - [SeedPhraseMismatchException] if the re-entered phrase does not
  ///     match the stored phrase.
  ///   - [StateError] if no seed phrase has been generated yet.
  Future<void> confirmSeedAcknowledged({
    required String reEntryPhrase,
  }) async {
    final stored = await _store.readMnemonic();
    if (stored == null) {
      throw StateError(
        'No seed phrase exists to acknowledge. '
        'Call generateSeedPhrase first.',
      );
    }

    if (_normalise(reEntryPhrase) != _normalise(stored)) {
      throw SeedPhraseMismatchException();
    }

    await _store.writeSeedAcknowledged();
    final current = state.valueOrNull;
    if (current != null) {
      state = AsyncData(current.copyWith(seedAcknowledged: true));
    }
  }

  static String _normalise(String phrase) =>
      phrase.trim().toLowerCase().split(RegExp(r'\s+')).join(' ');

  /// Records that the user completed a backup export.
  Future<void> recordBackupCompleted() async {
    final now = DateTime.now();
    await _store.writeLastBackupAt(now);
    final current = state.valueOrNull;
    if (current != null) {
      state = AsyncData(current.copyWith(lastBackupAt: now));
    }
  }

  /// Wipes auth key material from the keychain and resets state to Ghost.
  ///
  /// Preserves the device ID — the device is the same device after an
  /// identity reset. Use [SecureKeyStore.clearAll] directly if you need
  /// to wipe everything (e.g. selling the device).
  ///
  /// **All data encrypted with the current key becomes permanently
  /// unrecoverable.** Callers should confirm with the user before invoking.
  Future<void> resetIdentity() async {
    await _store.clearAuth();
    state = const AsyncData(AuthState.ghost());
  }
}
