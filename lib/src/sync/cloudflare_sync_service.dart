import 'dart:convert';
import 'dart:typed_data';

import 'package:http/http.dart' as http;

import '../exceptions.dart';
import 'sync_service.dart';

/// [SyncService] backed by a Cloudflare Worker + R2 relay.
///
/// Endpoints:
/// ```
/// PUT    /sync/{channelId}/{deviceId}   — upload blob
/// GET    /sync/{channelId}/{deviceId}   — download blob
/// GET    /sync/{channelId}/devices      — list devices
/// DELETE /sync/{channelId}/{deviceId}   — remove device
/// ```
class CloudflareSyncService implements SyncService {
  final Uri _baseUrl;
  final http.Client _client;

  /// Creates a [CloudflareSyncService] pointing at [baseUrl].
  ///
  /// An optional [client] may be provided for testing; defaults to a new
  /// [http.Client].
  CloudflareSyncService({
    required Uri baseUrl,
    http.Client? client,
  })  : _baseUrl = baseUrl,
        _client = client ?? http.Client();

  Uri _syncUri(String channelId, [String? path]) {
    final segments = ['sync', channelId];
    if (path != null) segments.add(path);
    return _baseUrl.replace(pathSegments: [
      ..._baseUrl.pathSegments,
      ...segments,
    ]);
  }

  @override
  Future<void> uploadDump({
    required String channelId,
    required String deviceId,
    required int schemaVersion,
    required Uint8List blob,
  }) async {
    final uri = _syncUri(channelId, deviceId);
    final http.Response response;
    try {
      response = await _client.put(
        uri,
        headers: {
          'Content-Type': 'application/octet-stream',
          'X-Schema-Version': schemaVersion.toString(),
        },
        body: blob,
      );
    } on Exception catch (e) {
      throw SyncException('Failed to upload dump', cause: e);
    }

    if (response.statusCode == 413) {
      throw SyncException(
        'Blob too large (max 10MB)',
        statusCode: 413,
      );
    }
    if (response.statusCode != 200) {
      throw SyncException(
        'Upload failed: ${response.reasonPhrase}',
        statusCode: response.statusCode,
      );
    }
  }

  @override
  Future<SyncBlob?> downloadDump({
    required String channelId,
    required String deviceId,
    String? ifNoneMatch,
  }) async {
    final uri = _syncUri(channelId, deviceId);
    final headers = <String, String>{};
    if (ifNoneMatch != null) {
      headers['If-None-Match'] = ifNoneMatch;
    }

    final http.Response response;
    try {
      response = await _client.get(uri, headers: headers);
    } on Exception catch (e) {
      throw SyncException('Failed to download dump', cause: e);
    }

    if (response.statusCode == 404 || response.statusCode == 304) {
      return null;
    }
    if (response.statusCode != 200) {
      throw SyncException(
        'Download failed: ${response.reasonPhrase}',
        statusCode: response.statusCode,
      );
    }

    final schemaVersion =
        int.tryParse(response.headers['x-schema-version'] ?? '') ?? 0;

    return SyncBlob(
      data: response.bodyBytes,
      etag: response.headers['etag'],
      schemaVersion: schemaVersion,
    );
  }

  @override
  Future<List<SyncDeviceInfo>> listDevices({
    required String channelId,
  }) async {
    final uri = _syncUri(channelId, 'devices');
    final http.Response response;
    try {
      response = await _client.get(uri);
    } on Exception catch (e) {
      throw SyncException('Failed to list devices', cause: e);
    }

    if (response.statusCode != 200) {
      throw SyncException(
        'List devices failed: ${response.reasonPhrase}',
        statusCode: response.statusCode,
      );
    }

    final List<dynamic> items;
    try {
      items = jsonDecode(response.body) as List<dynamic>;
    } on FormatException catch (e) {
      throw SyncException('Invalid JSON in device list response', cause: e);
    }

    return items.map((item) {
      final map = item as Map<String, dynamic>;
      return SyncDeviceInfo(
        deviceId: map['deviceId'] as String,
        schemaVersion: map['schemaVersion'] as int,
        uploadedAt: DateTime.parse(map['uploadedAt'] as String),
        blobSizeBytes: map['blobSize'] as int,
      );
    }).toList();
  }

  @override
  Future<bool> deleteDevice({
    required String channelId,
    required String deviceId,
  }) async {
    final uri = _syncUri(channelId, deviceId);
    final http.Response response;
    try {
      response = await _client.delete(uri);
    } on Exception catch (e) {
      throw SyncException('Failed to delete device', cause: e);
    }

    if (response.statusCode == 404) return false;
    if (response.statusCode != 200) {
      throw SyncException(
        'Delete failed: ${response.reasonPhrase}',
        statusCode: response.statusCode,
      );
    }
    return true;
  }
}
