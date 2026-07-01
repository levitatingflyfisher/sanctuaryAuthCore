import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'sync_service.dart';

/// Riverpod provider for [SyncService].
///
/// Apps must override this at their root [ProviderScope] with a concrete
/// implementation (e.g. [CloudflareSyncService]). The default throws
/// [UnimplementedError] so that apps that don't use sync are unaffected.
///
/// ```dart
/// ProviderScope(
///   overrides: [
///     syncServiceProvider.overrideWithValue(
///       CloudflareSyncService(baseUrl: Uri.parse('https://your-worker.workers.dev')),
///     ),
///   ],
///   child: MyApp(),
/// )
/// ```
final syncServiceProvider = Provider<SyncService>(
  (_) => throw UnimplementedError(
    'syncServiceProvider must be overridden with a concrete SyncService '
    '(e.g. CloudflareSyncService). Add an override to your root ProviderScope.',
  ),
);
