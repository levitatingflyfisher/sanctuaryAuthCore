import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:mocktail/mocktail.dart';
import 'package:sanctuary_auth_core/src/backup/ghost_backup.dart';
import 'package:sanctuary_auth_core/src/crypto/envelope_cipher.dart';
import 'package:sanctuary_auth_core/src/sync/sync_orchestrator.dart';
import 'package:sanctuary_auth_core/src/sync/sync_service.dart';

class MockSyncService extends Mock implements SyncService {}

final _key = Uint8List.fromList(List.generate(32, (i) => i));

Uint8List _payload(Map<String, List<Map<String, dynamic>>> t) =>
    Uint8List.fromList(utf8.encode(jsonEncode(
        {'schemaVersion': 1, 'exportedAt': 'x', 'tables': t})));

void main() {
  setUpAll(() => registerFallbackValue(Uint8List(0)));

  // KNOWN RED (sync defect D1). Cycle 1 writes the merged state as the
  // single shared base while B's blob is stale; cycle 2 then reads S as
  // "in base, in mine, not in theirs" = B deleted it, and drops it. Deletion
  // inferred from absence cannot tell "deleted" from "not seen yet". Not
  // fixed here: the fleet decided (sync decision 1) to replace this tier with
  // a hash-linked, signed op log in the Rust sync kernel (hearthSync), where
  // deletes are explicit ops. This scenario is to be ported there and must
  // pass; this tier's lib/src/sync/ is deleted when its first app moves.
  test('row created on A survives two syncs against a stale peer B',
      skip: 'Known red (D1: stale-peer delete-by-absence). To be fixed by '
          'design in the planned hearthSync Rust sync kernel, not in this '
          'tier; port the scenario there.',
      () async {
    final svc = MockSyncService();
    final orch = SyncOrchestrator(syncService: svc, cipher: EnvelopeCipher());
    final r0 = {'id': 'r0', 'modifiedAt': 1000};
    // B uploaded once, before A created S, and has not synced since.
    final bBlob = await GhostBackup.export(
        _payload({'items': [r0]}), _key, EnvelopeCipher(),
        context: syncBackupContext);
    when(() => svc.listDevices(channelId: 'c')).thenAnswer((_) async => [
          SyncDeviceInfo(
              deviceId: 'B',
              schemaVersion: 1,
              uploadedAt: DateTime.utc(2026),
              blobSizeBytes: bBlob.length)
        ]);
    when(() => svc.downloadDump(channelId: 'c', deviceId: 'B'))
        .thenAnswer((_) async => SyncBlob(data: bBlob, schemaVersion: 1));
    when(() => svc.uploadDump(
        channelId: any(named: 'channelId'),
        deviceId: any(named: 'deviceId'),
        schemaVersion: any(named: 'schemaVersion'),
        blob: any(named: 'blob'))).thenAnswer((_) async {});

    // A's local DB: r0 (shared) + S (new, never synced).
    var aLocal = _payload({'items': [r0, {'id': 'S', 'modifiedAt': 2000}]});
    Uint8List? aBase = _payload({'items': [r0]}); // last agreed state

    Future<void> cycle() => orch.sync(
          channelId: 'c',
          deviceId: 'A',
          schemaVersion: 1,
          syncKey: _key,
          dumpAll: () async => aLocal,
          restoreAll: (d) async => aLocal = d,
          readBase: () async => aBase,
          writeBase: (d) async => aBase = d,
          allowedTables: {'items'},
        );

    List ids() => ((jsonDecode(utf8.decode(aLocal))['tables']['items'])
            as List)
        .map((r) => r['id'])
        .toList();

    await cycle();
    expect(ids(), contains('S'), reason: 'after cycle 1');
    await cycle(); // B still hasn't re-uploaded
    expect(ids(), contains('S'), reason: 'after cycle 2 — S must not vanish');
  });
}
