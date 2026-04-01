import 'package:riverpod_annotation/riverpod_annotation.dart';

import '../bip39/mnemonic.dart';
import '../crypto/key_derivation.dart';
import '../storage/secure_key_store.dart';
import '../storage/secure_key_store_provider.dart';
import 'auth_state.dart';
import 'auth_tier.dart';

part 'auth_notifier.g.dart';

@Riverpod(keepAlive: true)
class AuthNotifier extends _$AuthNotifier {
  late SecureKeyStore _store;

  @override
  Future<AuthState> build() async {
    _store = ref.read(secureKeyStoreProvider);
    return _loadFromKeychain();
  }

  Future<AuthState> _loadFromKeychain() async {
    final phrase = await _store.readMnemonic();
    final seedAcknowledged = await _store.readSeedAcknowledged();
    final lastBackupAt = await _store.readLastBackupAt();

    if (phrase == null) {
      return const AuthState.ghost();
    }

    final seed = await OpenHearthMnemonic.deriveSeed(phrase);
    final keys = await KeyDerivation.fromSeed(seed);

    return AuthState(
      tier: AuthTier.ghost,
      masterEncryptionKey: keys.masterEncryptionKey,
      seedAcknowledged: seedAcknowledged,
      lastBackupAt: lastBackupAt,
    );
  }

  /// Generates and stores a new BIP39 seed phrase.
  ///
  /// Returns the phrase for one-time display. The phrase is stored in the
  /// OS keychain immediately — the user should write it down, then call
  /// [confirmSeedAcknowledged].
  Future<String> generateSeedPhrase() async {
    final phrase = OpenHearthMnemonic.generate();
    await _store.writeMnemonic(phrase);

    final seed = await OpenHearthMnemonic.deriveSeed(phrase);
    final keys = await KeyDerivation.fromSeed(seed);

    state = AsyncData(AuthState(
      tier: AuthTier.ghost,
      masterEncryptionKey: keys.masterEncryptionKey,
      seedAcknowledged: false,
      lastBackupAt: null,
    ));

    return phrase;
  }

  /// Records that the user has written down their seed phrase.
  Future<void> confirmSeedAcknowledged() async {
    await _store.writeSeedAcknowledged();
    final current = state.valueOrNull;
    if (current != null) {
      state = AsyncData(current.copyWith(seedAcknowledged: true));
    }
  }

  /// Records that the user completed a backup export.
  Future<void> recordBackupCompleted() async {
    final now = DateTime.now();
    await _store.writeLastBackupAt(now);
    final current = state.valueOrNull;
    if (current != null) {
      state = AsyncData(current.copyWith(lastBackupAt: now));
    }
  }
}
