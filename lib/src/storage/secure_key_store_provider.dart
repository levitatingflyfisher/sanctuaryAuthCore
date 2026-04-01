import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'secure_key_store.dart';

/// Production provider — override in tests with a mock.
final secureKeyStoreProvider = Provider<SecureKeyStore>(
  (ref) => FlutterSecureKeyStore(),
);
