import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:mocktail/mocktail.dart';
import 'package:sanctuary_auth_core/src/backup/ghost_backup.dart';
import 'package:sanctuary_auth_core/src/crypto/envelope_cipher.dart';
import 'package:sanctuary_auth_core/src/sync/sync_orchestrator.dart';
import 'package:sanctuary_auth_core/src/sync/sync_service.dart';

/// Tests the orchestrator's sequential multi-peer merge behaviour.
///
/// Two-peer scenarios are covered in `sync_orchestrator_test.dart` and
/// `sync_hardening_test.dart`. This file exercises 3+ peer topologies
/// (phone + tablet + laptop) — the sticky-base vs static-base question
/// only matters once there's more than one peer in a single cycle.

class MockSyncService extends Mock implements SyncService {}

final _testKey = Uint8List.fromList(List.generate(32, (i) => i));

const _channelId = 'abc123';
const _myDeviceId = 'device-mine';
const _schemaVersion = 5;

Uint8List _payload(Map<String, List<Map<String, dynamic>>> tables) {
  return Uint8List.fromList(utf8.encode(jsonEncode({
    'schemaVersion': _schemaVersion,
    'exportedAt': '2026-04-17T12:00:00.000Z',
    'tables': tables,
  })));
}

Future<Uint8List> _encrypt(Uint8List plaintext) {
  return GhostBackup.export(
    plaintext,
    _testKey,
    EnvelopeCipher(),
    context: syncBackupContext,
  );
}

/// Runs a sync with an arbitrary number of peer devices.
Future<Map<String, dynamic>> _runSync({
  required Map<String, List<Map<String, dynamic>>> mine,
  required Map<String, List<Map<String, dynamic>>>? base,
  required Map<String, Map<String, List<Map<String, dynamic>>>> peers,
}) async {
  final service = MockSyncService();
  final orchestrator = SyncOrchestrator(
    syncService: service,
    cipher: EnvelopeCipher(),
  );

  final encryptedPeers = <String, Uint8List>{};
  for (final entry in peers.entries) {
    encryptedPeers[entry.key] = await _encrypt(_payload(entry.value));
  }

  when(() => service.listDevices(channelId: _channelId)).thenAnswer(
    (_) async => peers.keys
        .map((id) => SyncDeviceInfo(
              deviceId: id,
              schemaVersion: _schemaVersion,
              uploadedAt: DateTime.utc(2026, 4, 17),
              blobSizeBytes: encryptedPeers[id]!.length,
            ))
        .toList(),
  );
  for (final id in peers.keys) {
    when(() => service.downloadDump(channelId: _channelId, deviceId: id))
        .thenAnswer((_) async => SyncBlob(
            data: encryptedPeers[id]!, schemaVersion: _schemaVersion));
  }
  when(() => service.uploadDump(
        channelId: any(named: 'channelId'),
        deviceId: any(named: 'deviceId'),
        schemaVersion: any(named: 'schemaVersion'),
        blob: any(named: 'blob'),
      )).thenAnswer((_) async {});

  Uint8List? restored;
  await orchestrator.sync(
    channelId: _channelId,
    deviceId: _myDeviceId,
    schemaVersion: _schemaVersion,
    syncKey: _testKey,
    dumpAll: () async => _payload(mine),
    restoreAll: (data) async => restored = data,
    readBase: () async => base == null ? null : _payload(base),
    writeBase: (_) async {},
    allowedTables: {'babies'},
  );

  return jsonDecode(utf8.decode(restored!)) as Map<String, dynamic>;
}

Set<String> _ids(Map<String, dynamic> payload, String table) {
  final list =
      (payload['tables'] as Map<String, dynamic>)[table] as List? ?? const [];
  return list.map((r) => (r as Map)['id'] as String).toSet();
}

Map<String, Map<String, dynamic>> _rowsById(
    Map<String, dynamic> payload, String table) {
  final list =
      (payload['tables'] as Map<String, dynamic>)[table] as List? ?? const [];
  return {
    for (final r in list) (r as Map)['id'] as String: r.cast<String, dynamic>(),
  };
}

void main() {
  setUpAll(() {
    registerFallbackValue(Uint8List(0));
  });

  group('multi-peer merge — additions', () {
    test('three peers each add a distinct row — all three survive', () async {
      final result = await _runSync(
        base: null,
        mine: {
          'babies': [
            {'id': 'a', 'modifiedAt': 100, 'name': 'Alice'},
          ],
        },
        peers: {
          'peer-b': {
            'babies': [
              {'id': 'b', 'modifiedAt': 100, 'name': 'Bob'},
            ],
          },
          'peer-c': {
            'babies': [
              {'id': 'c', 'modifiedAt': 100, 'name': 'Charlie'},
            ],
          },
        },
      );
      expect(_ids(result, 'babies'), equals({'a', 'b', 'c'}));
    });
  });

  group('multi-peer merge — updates', () {
    test(
        'three peers update the same row — latest modifiedAt wins '
        'regardless of peer order', () async {
      final scenarioA = await _runSync(
        base: {
          'babies': [
            {'id': 'x', 'modifiedAt': 100, 'name': 'base'},
          ],
        },
        mine: {
          'babies': [
            {'id': 'x', 'modifiedAt': 150, 'name': 'mine'},
          ],
        },
        peers: {
          'peer-b': {
            'babies': [
              {'id': 'x', 'modifiedAt': 200, 'name': 'b-wins'},
            ],
          },
          'peer-c': {
            'babies': [
              {'id': 'x', 'modifiedAt': 180, 'name': 'c-loses'},
            ],
          },
        },
      );
      expect(_rowsById(scenarioA, 'babies')['x']?['name'], equals('b-wins'));
    });
  });

  group('multi-peer merge — deletions', () {
    test(
        'my deletion survives against multiple peers that still hold the row',
        () async {
      // Regression: with the sticky-base pattern, the second peer would
      // resurrect a row the first peer had "agreed" to delete — the merge
      // with peer B zeroed out the rolling base, so peer C's row looked
      // brand-new rather than "was in base, I deleted". Using the original
      // base for every peer in the cycle preserves the deletion intent.
      final result = await _runSync(
        base: {
          'babies': [
            {'id': 'x', 'modifiedAt': 100, 'name': 'original'},
          ],
        },
        mine: {
          'babies': const <Map<String, dynamic>>[],
        },
        peers: {
          'peer-b': {
            'babies': [
              {'id': 'x', 'modifiedAt': 100, 'name': 'original'},
            ],
          },
          'peer-c': {
            'babies': [
              {'id': 'x', 'modifiedAt': 100, 'name': 'original'},
            ],
          },
        },
      );
      expect(_ids(result, 'babies'), isEmpty,
          reason:
              'a row I deliberately deleted must stay deleted even when '
              'multiple peers still hold their last-synced copy');
    });

    test('peer deletion survives against peers that still hold the row',
        () async {
      // Peer B deleted row x. Peer C still has it. My side still has it.
      // With original-base merge, the deletion should propagate.
      final result = await _runSync(
        base: {
          'babies': [
            {'id': 'x', 'modifiedAt': 100, 'name': 'original'},
            {'id': 'y', 'modifiedAt': 100, 'name': 'keeper'},
          ],
        },
        mine: {
          'babies': [
            {'id': 'x', 'modifiedAt': 100, 'name': 'original'},
            {'id': 'y', 'modifiedAt': 100, 'name': 'keeper'},
          ],
        },
        peers: {
          'peer-b': {
            'babies': [
              {'id': 'y', 'modifiedAt': 100, 'name': 'keeper'},
              // x deleted by B
            ],
          },
          'peer-c': {
            'babies': [
              {'id': 'x', 'modifiedAt': 100, 'name': 'original'},
              {'id': 'y', 'modifiedAt': 100, 'name': 'keeper'},
            ],
          },
        },
      );
      expect(_ids(result, 'babies'), equals({'y'}),
          reason:
              'B deleted x; C still had the pre-deletion copy — B\'s deletion '
              'must not be forgotten by the time we get to C');
    });
  });
}
