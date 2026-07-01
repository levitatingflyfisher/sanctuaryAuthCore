import 'package:flutter/foundation.dart';

/// Metadata about a device's blob on the sync relay.
@immutable
class SyncDeviceInfo {
  /// The device's UUID.
  final String deviceId;

  /// The schema version of the last uploaded blob.
  final int schemaVersion;

  /// When the blob was last uploaded (UTC).
  final DateTime uploadedAt;

  /// Size of the encrypted blob in bytes.
  final int blobSizeBytes;

  const SyncDeviceInfo({
    required this.deviceId,
    required this.schemaVersion,
    required this.uploadedAt,
    required this.blobSizeBytes,
  });
}

/// Abstraction over the encrypted blob relay.
///
/// The relay is a "dumb blob store" — it never decrypts, interprets, or
/// queries the payload. It stores and returns opaque ciphertext.
///
/// See `SYNC_TIER_SPEC.md` for the full relay API contract.
abstract class SyncService {
  /// Uploads an encrypted blob for [deviceId] to [channelId].
  ///
  /// [schemaVersion] is stored as metadata so other devices can detect
  /// version mismatches before attempting a merge.
  ///
  /// Throws [SyncException] on network or relay errors.
  Future<void> uploadDump({
    required String channelId,
    required String deviceId,
    required int schemaVersion,
    required Uint8List blob,
  });

  /// Downloads the encrypted blob for [deviceId] from [channelId].
  ///
  /// Returns `null` if no blob exists (404).
  /// The returned [SyncBlob] includes the ETag for conditional requests.
  ///
  /// Pass [ifNoneMatch] to skip download if the blob hasn't changed
  /// since the last fetch (returns `null` on 304).
  ///
  /// Throws [SyncException] on network or relay errors.
  Future<SyncBlob?> downloadDump({
    required String channelId,
    required String deviceId,
    String? ifNoneMatch,
  });

  /// Lists all devices that have uploaded blobs to [channelId].
  ///
  /// Throws [SyncException] on network or relay errors.
  Future<List<SyncDeviceInfo>> listDevices({
    required String channelId,
  });

  /// Removes a device's blob from [channelId].
  ///
  /// Returns `true` if the device existed and was removed, `false` if
  /// it was already absent.
  ///
  /// Throws [SyncException] on network or relay errors.
  Future<bool> deleteDevice({
    required String channelId,
    required String deviceId,
  });
}

/// An encrypted blob downloaded from the relay, with its ETag for
/// conditional follow-up requests.
@immutable
class SyncBlob {
  /// The encrypted blob bytes (OHBK format).
  final Uint8List data;

  /// ETag from the relay response. Pass as [ifNoneMatch] on the next
  /// download to get a 304 if unchanged.
  final String? etag;

  /// Schema version from the relay metadata header.
  final int schemaVersion;

  const SyncBlob({
    required this.data,
    this.etag,
    required this.schemaVersion,
  });
}
