import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../bip39/mnemonic.dart';
import 'key_derivation.dart';

/// Abstraction over the CPU-heavy cryptographic operations that
/// [AuthNotifier] depends on: mnemonic generation and key derivation.
///
/// Injecting this through Riverpod gives us a testable seam — mock it
/// for fast unit tests without running real PBKDF2.
abstract class CryptoService {
  /// Generates a fresh 12-word BIP39 mnemonic.
  String generateMnemonic();

  /// Derives the domain-separated keys from [phrase].
  ///
  /// Internally runs PBKDF2-HMAC-SHA512 (BIP39 seed) then
  /// HKDF-SHA256 (domain separation). Pass [appDomain] to isolate this app's
  /// keys from other apps sharing the same seed; null = the legacy
  /// household-wide derivation.
  Future<DerivedKeys> deriveKeysFromPhrase(String phrase, {String? appDomain});
}

/// Default implementation that delegates to [OpenHearthMnemonic] and
/// [KeyDerivation] on the current isolate.
class DefaultCryptoService implements CryptoService {
  const DefaultCryptoService();

  @override
  String generateMnemonic() => OpenHearthMnemonic.generate();

  @override
  Future<DerivedKeys> deriveKeysFromPhrase(
    String phrase, {
    String? appDomain,
  }) async {
    final seed = await OpenHearthMnemonic.deriveSeed(phrase);
    return KeyDerivation.fromSeed(seed, appDomain: appDomain);
  }
}

/// Riverpod provider for [CryptoService].
///
/// Override this in tests to inject a mock or stub.
final cryptoServiceProvider = Provider<CryptoService>(
  (_) => const DefaultCryptoService(),
);

/// The per-app HKDF domain used for all key derivation in this app.
///
/// Defaults to null (the legacy household-wide derivation, used by Lullaby's
/// already-shipped backups). Apps wanting isolated key material override this
/// at the root [ProviderScope] with their own domain string (lowercase
/// `[a-z0-9]+`), e.g. `sanctuaryAppDomainProvider.overrideWithValue('sundial')`.
final sanctuaryAppDomainProvider = Provider<String?>((_) => null);
