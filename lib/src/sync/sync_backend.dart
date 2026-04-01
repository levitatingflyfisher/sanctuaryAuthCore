import 'dart:typed_data';

/// Pluggable encrypted blob sync interface.
///
/// Implementations: [NoopSyncBackend] (Ghost), SupabaseSyncBackend (Token — Phase 2).
/// All data passed here is already encrypted — the backend is a dumb relay.
abstract interface class SyncBackend {
  Future<void> uploadBlob(
    String id,
    Uint8List ciphertext,
    Map<String, dynamic> metadata,
  );
  Future<Uint8List> downloadBlob(String id);
  Stream<SyncEvent> changes();
  Future<void> deleteBlob(String id);
}

/// Describes a remote change notification from [SyncBackend.changes].
sealed class SyncEvent {
  const SyncEvent();
}

class BlobUpdated extends SyncEvent {
  final String id;
  const BlobUpdated(this.id);
}

class BlobDeleted extends SyncEvent {
  final String id;
  const BlobDeleted(this.id);
}

/// No-op sync backend for Ghost-tier apps — all operations are silent.
class NoopSyncBackend implements SyncBackend {
  const NoopSyncBackend();

  @override
  Future<void> uploadBlob(
    String id,
    Uint8List ciphertext,
    Map<String, dynamic> metadata,
  ) async {}

  @override
  Future<Uint8List> downloadBlob(String id) async => Uint8List(0);

  @override
  Stream<SyncEvent> changes() => const Stream.empty();

  @override
  Future<void> deleteBlob(String id) async {}
}
