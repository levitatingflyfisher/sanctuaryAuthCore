import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:mocktail/mocktail.dart';
import 'package:sanctuary_auth_core/src/backup/ghost_backup.dart';
import 'package:sanctuary_auth_core/src/crypto/envelope_cipher.dart';
import 'package:sanctuary_auth_core/src/sync/sync_orchestrator.dart';
import 'package:sanctuary_auth_core/src/sync/sync_service.dart';
import 'package:sanctuary_auth_core/src/sync/three_way_merge.dart';

class MockSyncService extends Mock implements SyncService {}

final _testKey = Uint8List.fromList(List.generate(32, (i) => i));

const _channelId = 'abc123';
const _myDeviceId = 'device-mine';
const _peerDeviceId = 'device-peer';
const _schemaVersion = 5;

Uint8List _payload(Map<String, List<Map<String, dynamic>>> tables) {
  return Uint8List.fromList(utf8.encode(jsonEncode({
    'schemaVersion': _schemaVersion,
    'exportedAt': '2026-04-16T12:00:00.000Z',
    'tables': tables,
  })));
}

Future<Uint8List> _encryptSync(Uint8List plaintext) async {
  return GhostBackup.export(
    plaintext,
    _testKey,
    EnvelopeCipher(),
    context: syncBackupContext,
  );
}

Future<Uint8List> _encryptGhost(Uint8List plaintext) async {
  return GhostBackup.export(plaintext, _testKey, EnvelopeCipher());
}

void main() {
  late MockSyncService service;
  late SyncOrchestrator orchestrator;

  setUpAll(() {
    registerFallbackValue(Uint8List(0));
  });

  setUp(() {
    service = MockSyncService();
    orchestrator = SyncOrchestrator(
      syncService: service,
      cipher: EnvelopeCipher(),
    );

    when(() => service.uploadDump(
          channelId: any(named: 'channelId'),
          deviceId: any(named: 'deviceId'),
          schemaVersion: any(named: 'schemaVersion'),
          blob: any(named: 'blob'),
        )).thenAnswer((_) async {});
  });

  group('SyncOrchestrator hardening', () {
    test('rejects a peer blob that was encrypted with the ghost-backup '
        'AAD context (cross-context replay attempt)', () async {
      // Hostile peer re-uploads someone's ghost-tier OHBK as a sync dump.
      // AAD binding must make the orchestrator reject it cleanly rather
      // than merging its contents.
      final hostileBlob = await _encryptGhost(_payload({
        'babies': [
          {'id': 'injected', 'modifiedAt': 999, 'name': 'Mallory'},
        ],
      }));

      when(() => service.listDevices(channelId: _channelId))
          .thenAnswer((_) async => [
                SyncDeviceInfo(
                  deviceId: _peerDeviceId,
                  schemaVersion: _schemaVersion,
                  uploadedAt: DateTime.utc(2026, 4, 16),
                  blobSizeBytes: hostileBlob.length,
                ),
              ]);
      when(() => service.downloadDump(
            channelId: _channelId,
            deviceId: _peerDeviceId,
          )).thenAnswer((_) async => SyncBlob(
              data: hostileBlob, schemaVersion: _schemaVersion));

      Uint8List? restored;
      final result = await orchestrator.sync(
        channelId: _channelId,
        deviceId: _myDeviceId,
        schemaVersion: _schemaVersion,
        syncKey: _testKey,
        dumpAll: () async => _payload({'babies': []}),
        restoreAll: (data) async => restored = data,
        readBase: () async => null,
        writeBase: (_) async {},
        allowedTables: {'babies'},
      );

      expect(result.didMerge, isFalse);
      expect(result.hasErrors, isTrue);
      expect(result.deviceErrors.keys, contains(_peerDeviceId));
      expect(restored, isNull,
          reason: 'merge must not run when peer blob fails AEAD check');
    });

    test('allowedTables drops rows in unknown tables from peer dumps',
        () async {
      // Peer includes an unknown "secrets" table. App opted only into
      // "babies" — "secrets" must be silently discarded before merging.
      final peerBlob = await _encryptSync(_payload({
        'babies': [
          {'id': 'b', 'modifiedAt': 200, 'name': 'Bob'},
        ],
        'secrets': [
          {'id': 'x', 'modifiedAt': 200, 'value': 'evil'},
        ],
      }));

      when(() => service.listDevices(channelId: _channelId))
          .thenAnswer((_) async => [
                SyncDeviceInfo(
                  deviceId: _peerDeviceId,
                  schemaVersion: _schemaVersion,
                  uploadedAt: DateTime.utc(2026, 4, 16),
                  blobSizeBytes: peerBlob.length,
                ),
              ]);
      when(() => service.downloadDump(
            channelId: _channelId,
            deviceId: _peerDeviceId,
          )).thenAnswer((_) async => SyncBlob(
              data: peerBlob, schemaVersion: _schemaVersion));

      Uint8List? restored;
      await orchestrator.sync(
        channelId: _channelId,
        deviceId: _myDeviceId,
        schemaVersion: _schemaVersion,
        syncKey: _testKey,
        dumpAll: () async => _payload({'babies': []}),
        restoreAll: (data) async => restored = data,
        readBase: () async => null,
        writeBase: (_) async {},
        allowedTables: {'babies'},
      );

      final restoredJson =
          jsonDecode(utf8.decode(restored!)) as Map<String, dynamic>;
      final tables = restoredJson['tables'] as Map<String, dynamic>;
      expect(tables.containsKey('secrets'), isFalse,
          reason: 'allowedTables must drop tables the app did not opt into');
      expect((tables['babies'] as List).map((r) => (r as Map)['id']),
          contains('b'));
    });

    test('merge output is canonically ordered (sorted by id)', () async {
      // Two peers sending rows in different orders must still produce the
      // same merged bytes — otherwise the relay churns on every sync.
      final mergeA = threeWayMerge(
        base: {},
        mine: {
          'babies': [
            {'id': 'z', 'modifiedAt': 1},
            {'id': 'a', 'modifiedAt': 1},
            {'id': 'm', 'modifiedAt': 1},
          ],
        },
        theirs: {},
      );
      final mergeB = threeWayMerge(
        base: {},
        mine: {
          'babies': [
            {'id': 'm', 'modifiedAt': 1},
            {'id': 'a', 'modifiedAt': 1},
            {'id': 'z', 'modifiedAt': 1},
          ],
        },
        theirs: {},
      );
      final idsA =
          mergeA.merged['babies']!.map((r) => r['id'] as String).toList();
      final idsB =
          mergeB.merged['babies']!.map((r) => r['id'] as String).toList();
      expect(idsA, equals(['a', 'm', 'z']));
      expect(idsA, equals(idsB));
    });
  });

  group('threeWayMerge hardening', () {
    test('clamps far-future modifiedAt so a hostile peer cannot pin LWW',
        () {
      final now = DateTime.utc(2026, 4, 17, 12);
      final nowMs = now.millisecondsSinceEpoch;
      final futureMs = DateTime.utc(3000).millisecondsSinceEpoch;

      final result = threeWayMerge(
        base: {},
        mine: {
          'babies': [
            {'id': 'a', 'modifiedAt': nowMs, 'name': 'me'},
          ],
        },
        theirs: {
          'babies': [
            {'id': 'a', 'modifiedAt': futureMs, 'name': 'hostile'},
          ],
        },
        now: now,
      );

      final row = result.merged['babies']!.single;
      expect(row['name'], equals('me'),
          reason: 'future-stamped peer row must lose LWW after clamp');
      expect(result.stats['babies']!.clampedFutureTimestamps, equals(1));
    });

    test('allowedTables records rejected table names', () {
      final result = threeWayMerge(
        base: {},
        mine: {},
        theirs: {
          'babies': [
            {'id': 'a', 'modifiedAt': 1},
          ],
          'evil_injection': [
            {'id': 'x', 'modifiedAt': 1},
          ],
        },
        allowedTables: {'babies'},
      );
      expect(result.merged.containsKey('evil_injection'), isFalse);
      expect(result.rejectedTables, equals(['evil_injection']));
    });

    test('clock-skew within 24h is tolerated (not clamped)', () {
      final now = DateTime.utc(2026, 4, 17, 12);
      final nowMs = now.millisecondsSinceEpoch;
      final slightlyAhead =
          now.add(const Duration(hours: 2)).millisecondsSinceEpoch;

      final result = threeWayMerge(
        base: {},
        mine: {
          'babies': [
            {'id': 'a', 'modifiedAt': nowMs, 'name': 'me'},
          ],
        },
        theirs: {
          'babies': [
            {'id': 'a', 'modifiedAt': slightlyAhead, 'name': 'peer'},
          ],
        },
        now: now,
      );
      expect(result.merged['babies']!.single['name'], equals('peer'),
          reason: 'peer with mild clock skew should still win LWW');
      expect(result.stats['babies']!.clampedFutureTimestamps, equals(0));
    });
  });

  group('SyncResult', () {
    test('hasErrors / wasClean reflect deviceErrors and skippedDevices', () {
      expect(
        const SyncResult(deviceErrors: {'d': 'oops'}).hasErrors,
        isTrue,
      );
      expect(
        const SyncResult(skippedDevices: ['d']).wasClean,
        isFalse,
      );
      expect(
        const SyncResult(mergedDevices: ['d']).wasClean,
        isTrue,
      );
    });
  });
}
