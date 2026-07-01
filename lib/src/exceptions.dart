/// Base exception type for all sanctuary_auth_core errors.
///
/// Consuming apps can catch this type to handle any library error uniformly:
/// ```dart
/// try {
///   await backup.import(blob, key, cipher);
/// } on SanctuaryAuthException catch (e) {
///   showError(e.message);
/// }
/// ```
sealed class SanctuaryAuthException implements Exception {
  /// Human-readable error description. Never contains key material.
  String get message;
}

/// Thrown when an OHBK backup blob fails structural validation.
class BackupFormatException extends SanctuaryAuthException {
  @override
  final String message;

  BackupFormatException(this.message);

  @override
  String toString() => 'BackupFormatException: $message';
}

/// Thrown when a keychain read/write operation fails.
class KeyStoreException extends SanctuaryAuthException {
  @override
  final String message;

  /// The underlying platform exception, if available.
  final Object? cause;

  KeyStoreException(this.message, {this.cause});

  @override
  String toString() => 'KeyStoreException: $message';
}

/// Thrown when a cryptographic operation fails (bad key, tampered data, etc.).
class CryptoException extends SanctuaryAuthException {
  @override
  final String message;

  /// The underlying exception from the crypto library.
  final Object? cause;

  CryptoException(this.message, {this.cause});

  @override
  String toString() => 'CryptoException: $message';
}

/// Thrown by [AuthNotifier.confirmSeedAcknowledged] when the re-entered
/// phrase does not match the phrase stored in the keychain.
///
/// The message is deliberately generic — it does not disclose which words
/// were wrong or how close the guess was. Callers should prompt the user
/// to try again without hinting at the correct answer.
class SeedPhraseMismatchException extends SanctuaryAuthException {
  @override
  final String message;

  SeedPhraseMismatchException([
    this.message =
        'The re-entered seed phrase does not match the stored phrase.',
  ]);

  @override
  String toString() => 'SeedPhraseMismatchException: $message';
}

/// Thrown when a sync relay operation fails (network error, unexpected status, etc.).
class SyncException extends SanctuaryAuthException {
  @override
  final String message;

  /// HTTP status code from the relay, if available.
  final int? statusCode;

  /// The underlying exception (e.g. [SocketException]).
  final Object? cause;

  SyncException(this.message, {this.statusCode, this.cause});

  @override
  String toString() => 'SyncException: $message'
      '${statusCode != null ? ' (HTTP $statusCode)' : ''}';
}
