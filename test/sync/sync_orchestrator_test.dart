import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:mocktail/mocktail.dart';
import 'package:sanctuary_auth_core/src/backup/ghost_backup.dart';
import 'package:sanctuary_auth_core/src/crypto/envelope_cipher.dart';
import 'package:sanctuary_auth_core/src/exceptions.dart';
import 'package:sanctuary_auth_core/src/sync/sync_orchestrator.dart';
import 'package:sanctuary_auth_core/src/sync/sync_service.dart';

class MockSyncService extends Mock implements SyncService {}

// Fixed 32-byte key for testing
final _testKey = Uint8List.fromList(List.generate(32, (i) => i));

const _channelId = 'abc123';
const _myDeviceId = 'device-mine';
const _theirDeviceId = 'device-theirs';
const _schemaVersion = 5;

Uint8List _makePayload(Map<String, List<Map<String, dynamic>>> tables,
    {int schemaVersion = _schemaVersion}) {
  final payload = {
    'schemaVersion': schemaVersion,
    'exportedAt': '2026-04-16T12:00:00.000Z',
    'tables': tables,
  };
  return Uint8List.fromList(utf8.encode(jsonEncode(payload)));
}

Future<Uint8List> _encrypt(Uint8List plaintext) async {
  // Peer blobs must use the sync-tier AAD context so the orchestrator
  // accepts them — ghost-tier blobs are rejected by AEAD verification.
  return GhostBackup.export(
    plaintext,
    _testKey,
    EnvelopeCipher(),
    context: syncBackupContext,
  );
}

void main() {
  late MockSyncService syncService;
  late SyncOrchestrator orchestrator;
  late EnvelopeCipher cipher;

  setUpAll(() {
    registerFallbackValue(Uint8List(0));
  });

  setUp(() {
    syncService = MockSyncService();
    cipher = EnvelopeCipher();
    orchestrator = SyncOrchestrator(
      syncService: syncService,
      cipher: cipher,
    );
  });

  group('SyncOrchestrator', () {
    test('uploads local dump when no other devices exist', () async {
      when(() => syncService.listDevices(channelId: _channelId))
          .thenAnswer((_) async => []);
      when(() => syncService.uploadDump(
            channelId: any(named: 'channelId'),
            deviceId: any(named: 'deviceId'),
            schemaVersion: any(named: 'schemaVersion'),
            blob: any(named: 'blob'),
          )).thenAnswer((_) async {});

      final myDump = _makePayload({
        'babies': [
          {'id': 'a', 'modifiedAt': 100, 'name': 'Alice'},
        ],
      });

      final result = await orchestrator.sync(
        channelId: _channelId,
        deviceId: _myDeviceId,
        schemaVersion: _schemaVersion,
        syncKey: _testKey,
        dumpAll: () async => myDump,
        restoreAll: (_) async {},
        readBase: () async => null,
        writeBase: (_) async {},
        allowedTables: {'babies'},
      );

      expect(result.didMerge, isFalse);
      verify(() => syncService.uploadDump(
            channelId: _channelId,
            deviceId: _myDeviceId,
            schemaVersion: _schemaVersion,
            blob: any(named: 'blob'),
          )).called(1);
    });

    test('merges data from one peer and uploads result', () async {
      final myDump = _makePayload({
        'babies': [
          {'id': 'a', 'modifiedAt': 100, 'name': 'Alice'},
        ],
      });
      final theirDump = _makePayload({
        'babies': [
          {'id': 'b', 'modifiedAt': 200, 'name': 'Bob'},
        ],
      });
      final theirBlob = await _encrypt(theirDump);

      when(() => syncService.listDevices(channelId: _channelId))
          .thenAnswer((_) async => [
                SyncDeviceInfo(
                  deviceId: _theirDeviceId,
                  schemaVersion: _schemaVersion,
                  uploadedAt: DateTime.utc(2026, 4, 16),
                  blobSizeBytes: theirBlob.length,
                ),
              ]);
      when(() => syncService.downloadDump(
            channelId: _channelId,
            deviceId: _theirDeviceId,
          )).thenAnswer((_) async => SyncBlob(
            data: theirBlob,
            schemaVersion: _schemaVersion,
          ));
      when(() => syncService.uploadDump(
            channelId: any(named: 'channelId'),
            deviceId: any(named: 'deviceId'),
            schemaVersion: any(named: 'schemaVersion'),
            blob: any(named: 'blob'),
          )).thenAnswer((_) async {});

      Uint8List? restoredData;
      Uint8List? savedBase;

      final result = await orchestrator.sync(
        channelId: _channelId,
        deviceId: _myDeviceId,
        schemaVersion: _schemaVersion,
        syncKey: _testKey,
        dumpAll: () async => myDump,
        restoreAll: (data) async => restoredData = data,
        readBase: () async => null, // first sync
        writeBase: (data) async => savedBase = data,
        allowedTables: {'babies'},
      );

      expect(result.didMerge, isTrue);
      expect(result.mergedDevices, contains(_theirDeviceId));

      // Verify merged data contains both babies
      final restored =
          jsonDecode(utf8.decode(restoredData!)) as Map<String, dynamic>;
      final babies =
          (restored['tables'] as Map<String, dynamic>)['babies'] as List;
      final ids = babies.map((r) => (r as Map)['id']).toSet();
      expect(ids, equals({'a', 'b'}));

      // Base was saved
      expect(savedBase, isNotNull);

      // Upload was called
      verify(() => syncService.uploadDump(
            channelId: _channelId,
            deviceId: _myDeviceId,
            schemaVersion: _schemaVersion,
            blob: any(named: 'blob'),
          )).called(1);
    });

    test('skips devices with newer schema version', () async {
      when(() => syncService.listDevices(channelId: _channelId))
          .thenAnswer((_) async => [
                SyncDeviceInfo(
                  deviceId: _theirDeviceId,
                  schemaVersion: _schemaVersion + 1, // newer than ours
                  uploadedAt: DateTime.utc(2026, 4, 16),
                  blobSizeBytes: 100,
                ),
              ]);
      when(() => syncService.uploadDump(
            channelId: any(named: 'channelId'),
            deviceId: any(named: 'deviceId'),
            schemaVersion: any(named: 'schemaVersion'),
            blob: any(named: 'blob'),
          )).thenAnswer((_) async {});

      final myDump = _makePayload({'babies': []});

      final result = await orchestrator.sync(
        channelId: _channelId,
        deviceId: _myDeviceId,
        schemaVersion: _schemaVersion,
        syncKey: _testKey,
        dumpAll: () async => myDump,
        restoreAll: (_) async {},
        readBase: () async => null,
        writeBase: (_) async {},
        allowedTables: {'babies'},
      );

      expect(result.didMerge, isFalse);
      expect(result.skippedDevices, contains(_theirDeviceId));
    });

    test('handles download failure for one device gracefully', () async {
      when(() => syncService.listDevices(channelId: _channelId))
          .thenAnswer((_) async => [
                SyncDeviceInfo(
                  deviceId: _theirDeviceId,
                  schemaVersion: _schemaVersion,
                  uploadedAt: DateTime.utc(2026, 4, 16),
                  blobSizeBytes: 100,
                ),
              ]);
      when(() => syncService.downloadDump(
            channelId: _channelId,
            deviceId: _theirDeviceId,
          )).thenThrow(SyncException('Connection refused'));
      when(() => syncService.uploadDump(
            channelId: any(named: 'channelId'),
            deviceId: any(named: 'deviceId'),
            schemaVersion: any(named: 'schemaVersion'),
            blob: any(named: 'blob'),
          )).thenAnswer((_) async {});

      final myDump = _makePayload({'babies': []});

      final result = await orchestrator.sync(
        channelId: _channelId,
        deviceId: _myDeviceId,
        schemaVersion: _schemaVersion,
        syncKey: _testKey,
        dumpAll: () async => myDump,
        restoreAll: (_) async {},
        readBase: () async => null,
        writeBase: (_) async {},
        allowedTables: {'babies'},
      );

      expect(result.didMerge, isFalse);
      expect(result.deviceErrors, containsPair(_theirDeviceId, 'Connection refused'));
    });

    test('uses base state for 3-way merge on subsequent syncs', () async {
      // Base has row 'c', mine deleted it, theirs still has it
      // With base → deletion is honored. Without base → it would be kept.
      final baseDump = _makePayload({
        'babies': [
          {'id': 'a', 'modifiedAt': 100, 'name': 'Alice'},
          {'id': 'c', 'modifiedAt': 100, 'name': 'Charlie'},
        ],
      });
      final myDump = _makePayload({
        'babies': [
          {'id': 'a', 'modifiedAt': 100, 'name': 'Alice'},
          // 'c' deleted by me
        ],
      });
      final theirDump = _makePayload({
        'babies': [
          {'id': 'a', 'modifiedAt': 100, 'name': 'Alice'},
          {'id': 'c', 'modifiedAt': 100, 'name': 'Charlie'}, // they still have it
        ],
      });
      final theirBlob = await _encrypt(theirDump);

      when(() => syncService.listDevices(channelId: _channelId))
          .thenAnswer((_) async => [
                SyncDeviceInfo(
                  deviceId: _theirDeviceId,
                  schemaVersion: _schemaVersion,
                  uploadedAt: DateTime.utc(2026, 4, 16),
                  blobSizeBytes: theirBlob.length,
                ),
              ]);
      when(() => syncService.downloadDump(
            channelId: _channelId,
            deviceId: _theirDeviceId,
          )).thenAnswer((_) async => SyncBlob(
            data: theirBlob,
            schemaVersion: _schemaVersion,
          ));
      when(() => syncService.uploadDump(
            channelId: any(named: 'channelId'),
            deviceId: any(named: 'deviceId'),
            schemaVersion: any(named: 'schemaVersion'),
            blob: any(named: 'blob'),
          )).thenAnswer((_) async {});

      Uint8List? restoredData;

      await orchestrator.sync(
        channelId: _channelId,
        deviceId: _myDeviceId,
        schemaVersion: _schemaVersion,
        syncKey: _testKey,
        dumpAll: () async => myDump,
        restoreAll: (data) async => restoredData = data,
        readBase: () async => baseDump, // base exists
        writeBase: (_) async {},
        allowedTables: {'babies'},
      );

      // 'c' was in base and I deleted it → deletion honored
      final restored =
          jsonDecode(utf8.decode(restoredData!)) as Map<String, dynamic>;
      final babies =
          (restored['tables'] as Map<String, dynamic>)['babies'] as List;
      final ids = babies.map((r) => (r as Map)['id']).toSet();
      expect(ids, equals({'a'}));
      expect(ids.contains('c'), isFalse);
    });

    test('filters out own device from device list', () async {
      when(() => syncService.listDevices(channelId: _channelId))
          .thenAnswer((_) async => [
                SyncDeviceInfo(
                  deviceId: _myDeviceId, // my own device in the list
                  schemaVersion: _schemaVersion,
                  uploadedAt: DateTime.utc(2026, 4, 16),
                  blobSizeBytes: 100,
                ),
              ]);
      when(() => syncService.uploadDump(
            channelId: any(named: 'channelId'),
            deviceId: any(named: 'deviceId'),
            schemaVersion: any(named: 'schemaVersion'),
            blob: any(named: 'blob'),
          )).thenAnswer((_) async {});

      final myDump = _makePayload({'babies': []});

      final result = await orchestrator.sync(
        channelId: _channelId,
        deviceId: _myDeviceId,
        schemaVersion: _schemaVersion,
        syncKey: _testKey,
        dumpAll: () async => myDump,
        restoreAll: (_) async {},
        readBase: () async => null,
        writeBase: (_) async {},
        allowedTables: {'babies'},
      );

      // Should not try to download our own blob
      verifyNever(() => syncService.downloadDump(
            channelId: _channelId,
            deviceId: _myDeviceId,
          ));
      expect(result.didMerge, isFalse);
    });
  });
}
