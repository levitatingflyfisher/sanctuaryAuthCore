import 'dart:math';

import '../storage/secure_key_store.dart';

/// Ensures a stable device ID exists in [store], creating one if absent.
///
/// The device ID is a UUID v4 string that identifies this device on the
/// sync relay. It is NOT a user identity — it persists across identity
/// resets (unlike the mnemonic or encryption keys).
///
/// Call this once per app launch before any sync operation.
Future<String> ensureDeviceId(SecureKeyStore store) async {
  final existing = await store.readDeviceId();
  if (existing != null) return existing;

  final id = _generateUuidV4();
  await store.writeDeviceId(id);
  return id;
}

/// Generates a UUID v4 using [Random.secure].
///
/// Format: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
/// where x is random hex and y is one of {8, 9, a, b}.
String _generateUuidV4() {
  final rng = Random.secure();
  final bytes = List<int>.generate(16, (_) => rng.nextInt(256));

  // Set version (4) in byte 6: 0100xxxx
  bytes[6] = (bytes[6] & 0x0F) | 0x40;
  // Set variant (10xx) in byte 8: 10xxxxxx
  bytes[8] = (bytes[8] & 0x3F) | 0x80;

  String hex(int byte) => byte.toRadixString(16).padLeft(2, '0');

  return '${hex(bytes[0])}${hex(bytes[1])}${hex(bytes[2])}${hex(bytes[3])}-'
      '${hex(bytes[4])}${hex(bytes[5])}-'
      '${hex(bytes[6])}${hex(bytes[7])}-'
      '${hex(bytes[8])}${hex(bytes[9])}-'
      '${hex(bytes[10])}${hex(bytes[11])}${hex(bytes[12])}'
      '${hex(bytes[13])}${hex(bytes[14])}${hex(bytes[15])}';
}
