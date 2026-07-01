import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart' as http_testing;
import 'package:sanctuary_auth_core/src/exceptions.dart';
import 'package:sanctuary_auth_core/src/sync/cloudflare_sync_service.dart';

void main() {
  const channelId = 'abc123';
  const deviceId = 'device-A';
  final baseUrl = Uri.parse('https://relay.example.com');

  CloudflareSyncService makeService(
    http_testing.MockClientHandler handler,
  ) {
    return CloudflareSyncService(
      baseUrl: baseUrl,
      client: http_testing.MockClient(handler),
    );
  }

  group('CloudflareSyncService — uploadDump', () {
    test('sends PUT with correct path and headers', () async {
      late Uri capturedUri;
      late Map<String, String> capturedHeaders;

      final service = makeService((request) async {
        capturedUri = request.url;
        capturedHeaders = request.headers;
        return http.Response('', 200);
      });

      await service.uploadDump(
        channelId: channelId,
        deviceId: deviceId,
        schemaVersion: 7,
        blob: Uint8List.fromList([1, 2, 3]),
      );

      expect(capturedUri.path, contains('/sync/$channelId/$deviceId'));
      expect(capturedHeaders['x-schema-version'], equals('7'));
      expect(capturedHeaders['content-type'], contains('application/octet-stream'));
    });

    test('throws SyncException on 413', () async {
      final service = makeService((_) async {
        return http.Response('Payload Too Large', 413);
      });

      await expectLater(
        service.uploadDump(
          channelId: channelId,
          deviceId: deviceId,
          schemaVersion: 1,
          blob: Uint8List(100),
        ),
        throwsA(isA<SyncException>()),
      );
    });

    test('throws SyncException on 500', () async {
      final service = makeService((_) async {
        return http.Response('Internal Server Error', 500);
      });

      await expectLater(
        service.uploadDump(
          channelId: channelId,
          deviceId: deviceId,
          schemaVersion: 1,
          blob: Uint8List(10),
        ),
        throwsA(isA<SyncException>()),
      );
    });

    test('throws SyncException on network error', () async {
      final service = makeService((_) async {
        throw Exception('Connection refused');
      });

      await expectLater(
        service.uploadDump(
          channelId: channelId,
          deviceId: deviceId,
          schemaVersion: 1,
          blob: Uint8List(10),
        ),
        throwsA(isA<SyncException>()),
      );
    });
  });

  group('CloudflareSyncService — downloadDump', () {
    test('returns SyncBlob on 200', () async {
      final service = makeService((_) async {
        return http.Response.bytes(
          [10, 20, 30],
          200,
          headers: {
            'etag': '"abc"',
            'x-schema-version': '5',
          },
        );
      });

      final blob = await service.downloadDump(
        channelId: channelId,
        deviceId: deviceId,
      );

      expect(blob, isNotNull);
      expect(blob!.data, equals([10, 20, 30]));
      expect(blob.etag, equals('"abc"'));
      expect(blob.schemaVersion, equals(5));
    });

    test('returns null on 404', () async {
      final service = makeService((_) async {
        return http.Response('Not Found', 404);
      });

      final blob = await service.downloadDump(
        channelId: channelId,
        deviceId: deviceId,
      );

      expect(blob, isNull);
    });

    test('returns null on 304 (not modified)', () async {
      final service = makeService((_) async {
        return http.Response('', 304);
      });

      final blob = await service.downloadDump(
        channelId: channelId,
        deviceId: deviceId,
        ifNoneMatch: '"abc"',
      );

      expect(blob, isNull);
    });

    test('sends If-None-Match header when etag provided', () async {
      late Map<String, String> capturedHeaders;

      final service = makeService((request) async {
        capturedHeaders = request.headers;
        return http.Response('', 304);
      });

      await service.downloadDump(
        channelId: channelId,
        deviceId: deviceId,
        ifNoneMatch: '"etag123"',
      );

      expect(capturedHeaders['if-none-match'], equals('"etag123"'));
    });

    test('throws SyncException on 500', () async {
      final service = makeService((_) async {
        return http.Response('Internal Server Error', 500);
      });

      await expectLater(
        service.downloadDump(channelId: channelId, deviceId: deviceId),
        throwsA(isA<SyncException>()),
      );
    });
  });

  group('CloudflareSyncService — listDevices', () {
    test('parses device list from JSON', () async {
      final service = makeService((_) async {
        return http.Response(
          jsonEncode([
            {
              'deviceId': 'device-A',
              'schemaVersion': 5,
              'uploadedAt': '2026-04-16T12:00:00.000Z',
              'blobSize': 1024,
            },
            {
              'deviceId': 'device-B',
              'schemaVersion': 5,
              'uploadedAt': '2026-04-16T13:00:00.000Z',
              'blobSize': 2048,
            },
          ]),
          200,
        );
      });

      final devices = await service.listDevices(channelId: channelId);

      expect(devices, hasLength(2));
      expect(devices[0].deviceId, equals('device-A'));
      expect(devices[0].schemaVersion, equals(5));
      expect(devices[0].blobSizeBytes, equals(1024));
      expect(devices[1].deviceId, equals('device-B'));
    });

    test('returns empty list for empty JSON array', () async {
      final service = makeService((_) async {
        return http.Response('[]', 200);
      });

      final devices = await service.listDevices(channelId: channelId);
      expect(devices, isEmpty);
    });

    test('throws SyncException on invalid JSON', () async {
      final service = makeService((_) async {
        return http.Response('not json', 200);
      });

      await expectLater(
        service.listDevices(channelId: channelId),
        throwsA(isA<SyncException>()),
      );
    });

    test('throws SyncException on 500', () async {
      final service = makeService((_) async {
        return http.Response('Internal Server Error', 500);
      });

      await expectLater(
        service.listDevices(channelId: channelId),
        throwsA(isA<SyncException>()),
      );
    });
  });

  group('CloudflareSyncService — deleteDevice', () {
    test('returns true on 200', () async {
      final service = makeService((_) async {
        return http.Response('', 200);
      });

      final result = await service.deleteDevice(
        channelId: channelId,
        deviceId: deviceId,
      );
      expect(result, isTrue);
    });

    test('returns false on 404', () async {
      final service = makeService((_) async {
        return http.Response('Not Found', 404);
      });

      final result = await service.deleteDevice(
        channelId: channelId,
        deviceId: deviceId,
      );
      expect(result, isFalse);
    });

    test('throws SyncException on 500', () async {
      final service = makeService((_) async {
        return http.Response('Internal Server Error', 500);
      });

      await expectLater(
        service.deleteDevice(channelId: channelId, deviceId: deviceId),
        throwsA(isA<SyncException>()),
      );
    });
  });
}
