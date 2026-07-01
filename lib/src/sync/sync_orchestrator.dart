import 'dart:convert';

import 'package:flutter/foundation.dart';

import '../backup/ghost_backup.dart';
import '../crypto/envelope_cipher.dart';
import '../exceptions.dart';
import 'sync_service.dart';
import 'three_way_merge.dart';

/// AAD context label bound into every sync-tier OHBK blob. Distinct from the
/// ghost-backup default so a ghost-tier backup file cannot be replayed as a
/// sync payload (the AEAD tag will not verify).
const syncBackupContext = 'sync-dump/v1';

/// Result of a full sync cycle.
@immutable
class SyncResult {
  /// Per-table merge statistics (empty if no merge was needed).
  final Map<String, TableMergeStats> stats;

  /// Devices whose schema version was too new to merge.
  /// The user should update the app to sync with these devices.
  final List<String> skippedDevices;

  /// Devices that were successfully merged.
  final List<String> mergedDevices;

  /// Errors encountered per device (non-fatal — other devices still sync).
  final Map<String, String> deviceErrors;

  const SyncResult({
    this.stats = const {},
    this.skippedDevices = const [],
    this.mergedDevices = const [],
    this.deviceErrors = const {},
  });

  /// True if at least one device was merged.
  bool get didMerge => mergedDevices.isNotEmpty;

  /// True if any peer failed with an error (corrupt/mismatched/injection).
  /// UIs should surface "sync completed with warnings" when this is true,
  /// regardless of [didMerge].
  bool get hasErrors => deviceErrors.isNotEmpty;

  /// True if the sync cycle completed cleanly: no per-peer errors and no
  /// peers skipped for schema reasons. [didMerge] may still be false if the
  /// user is the only device in the channel.
  bool get wasClean => !hasErrors && skippedDevices.isEmpty;
}

/// Orchestrates the full sync flow: download → decrypt → merge → write → encrypt → upload.
///
/// The orchestrator is app-agnostic — consuming apps provide callbacks for
/// serialization, deserialization, and base-state storage.
///
/// See `SYNC_TIER_SPEC.md` §"Sync Flow" for the 10-step sequence.
class SyncOrchestrator {
  final SyncService _syncService;
  final EnvelopeCipher _cipher;

  SyncOrchestrator({
    required SyncService syncService,
    required EnvelopeCipher cipher,
  })  : _syncService = syncService,
        _cipher = cipher;

  /// Runs a full sync cycle.
  ///
  /// [channelId] — hex-encoded sync channel ID.
  /// [deviceId] — this device's UUID.
  /// [schemaVersion] — this app's current Drift schema version.
  /// [syncKey] — 32-byte HKDF-derived sync key (distinct from the
  ///             master ghost-backup key). See [AuthState.syncKey].
  /// [dumpAll] — callback to serialize all local data to JSON bytes.
  /// [restoreAll] — callback to deserialize and write merged data to the local DB.
  /// [readBase] — callback to read the last-synced base state (null = first sync).
  /// [writeBase] — callback to persist the merged state as the new base.
  /// [allowedTables] — **required** allow-list of table names the app is
  ///                   willing to accept. Tables outside the list are
  ///                   silently dropped from every dump (mine, base, peers)
  ///                   before merging. Required so that an app that forgets
  ///                   to enumerate fails closed (merges nothing) instead of
  ///                   fails open (accepts arbitrary peer-supplied tables).
  ///                   Pass an empty set to merge no tables at all. If a
  ///                   consuming app genuinely wants wildcard behaviour
  ///                   (not recommended) it can precompute the full set
  ///                   from its own schema.
  Future<SyncResult> sync({
    required String channelId,
    required String deviceId,
    required int schemaVersion,
    required Uint8List syncKey,
    required Future<Uint8List> Function() dumpAll,
    required Future<void> Function(Uint8List data) restoreAll,
    required Future<Uint8List?> Function() readBase,
    required Future<void> Function(Uint8List data) writeBase,
    required Set<String> allowedTables,
  }) async {
    // 1. List other devices in the sync group
    final devices = await _syncService.listDevices(channelId: channelId);
    final otherDevices =
        devices.where((d) => d.deviceId != deviceId).toList();

    if (otherDevices.isEmpty) {
      // No peers — just upload our dump and return
      final myDump = await dumpAll();
      final blob = await GhostBackup.export(
        myDump,
        syncKey,
        _cipher,
        context: syncBackupContext,
      );
      await _syncService.uploadDump(
        channelId: channelId,
        deviceId: deviceId,
        schemaVersion: schemaVersion,
        blob: blob,
      );
      return const SyncResult();
    }

    // 2. Load local state
    final myDumpBytes = await dumpAll();
    final myPayload =
        jsonDecode(utf8.decode(myDumpBytes)) as Map<String, dynamic>;
    final myTables = _filterTables(_extractTables(myPayload), allowedTables);

    // 3. Load base state (null = first sync → empty base)
    final baseBytes = await readBase();
    Map<String, List<Map<String, dynamic>>> baseTables;
    if (baseBytes != null) {
      final basePayload =
          jsonDecode(utf8.decode(baseBytes)) as Map<String, dynamic>;
      baseTables = _filterTables(_extractTables(basePayload), allowedTables);
    } else {
      baseTables = {};
    }

    // 4. Merge each peer sequentially.
    //
    // The base passed to each round is the ORIGINAL last-synced base, not
    // the rolling merged state. A sticky rolling base corrupts the merge
    // for 3+ peers: rows that round-1 added (via peer B) look, from
    // round-2's perspective, like rows that "were in base" and that peer C
    // "no longer has" — which the 3-way merge treats as a deletion and
    // drops on the floor. Keeping the base static preserves the semantic
    // "inBase = existed at the last time everyone agreed", which is the
    // only ground truth the 3-way merge can trust.
    var currentMerged = myTables;
    final mergedDevices = <String>[];
    final skippedDevices = <String>[];
    final deviceErrors = <String, String>{};
    var aggregatedStats = <String, TableMergeStats>{};

    for (final device in otherDevices) {
      // Schema version check
      if (device.schemaVersion > schemaVersion) {
        skippedDevices.add(device.deviceId);
        continue;
      }

      try {
        // Download their blob
        final syncBlob = await _syncService.downloadDump(
          channelId: channelId,
          deviceId: device.deviceId,
        );
        if (syncBlob == null) continue;

        // Decrypt (AAD binding: sync-dump/v1 — rejects ghost-backup replays)
        final theirDumpBytes = await GhostBackup.import(
          syncBlob.data,
          syncKey,
          _cipher,
          context: syncBackupContext,
        );
        final theirPayload =
            jsonDecode(utf8.decode(theirDumpBytes)) as Map<String, dynamic>;
        final theirTables =
            _filterTables(_extractTables(theirPayload), allowedTables);

        // 3-way merge against the original base, not the rolling result.
        final result = threeWayMerge(
          base: baseTables,
          mine: currentMerged,
          theirs: theirTables,
          allowedTables: allowedTables,
        );

        currentMerged = result.merged;
        aggregatedStats = result.stats;
        mergedDevices.add(device.deviceId);
      } on SanctuaryAuthException catch (e) {
        deviceErrors[device.deviceId] = e.message;
      } on FormatException catch (e) {
        deviceErrors[device.deviceId] = 'Invalid data format: $e';
      } catch (e) {
        // Catch-all so one hostile or corrupt peer cannot crash the entire
        // sync cycle. Includes the runtime type so debugging reports are
        // actionable.
        deviceErrors[device.deviceId] =
            'Unexpected error (${e.runtimeType}): $e';
      }
    }

    if (mergedDevices.isEmpty) {
      // Nothing was merged — still upload our dump
      final blob = await GhostBackup.export(
        myDumpBytes,
        syncKey,
        _cipher,
        context: syncBackupContext,
      );
      await _syncService.uploadDump(
        channelId: channelId,
        deviceId: deviceId,
        schemaVersion: schemaVersion,
        blob: blob,
      );
      return SyncResult(
        skippedDevices: skippedDevices,
        deviceErrors: deviceErrors,
      );
    }

    // 5. Reconstruct the full payload with merged tables
    final mergedPayload = <String, dynamic>{
      'schemaVersion': schemaVersion,
      'exportedAt': DateTime.now().toUtc().toIso8601String(),
      'tables': currentMerged,
    };
    final mergedBytes =
        Uint8List.fromList(utf8.encode(jsonEncode(mergedPayload)));

    // 6. Write merged state to local DB
    await restoreAll(mergedBytes);

    // 7. Save merged state as the new base
    await writeBase(mergedBytes);

    // 8. Encrypt and upload merged state
    final blob = await GhostBackup.export(
      mergedBytes,
      syncKey,
      _cipher,
      context: syncBackupContext,
    );
    await _syncService.uploadDump(
      channelId: channelId,
      deviceId: deviceId,
      schemaVersion: schemaVersion,
      blob: blob,
    );

    return SyncResult(
      stats: aggregatedStats,
      mergedDevices: mergedDevices,
      skippedDevices: skippedDevices,
      deviceErrors: deviceErrors,
    );
  }

  /// Extracts the `tables` map from a backup payload.
  Map<String, List<Map<String, dynamic>>> _extractTables(
    Map<String, dynamic> payload,
  ) {
    final tables = payload['tables'] as Map<String, dynamic>?;
    if (tables == null) return {};
    return tables.map(
      (key, value) => MapEntry(
        key,
        (value as List<dynamic>).cast<Map<String, dynamic>>(),
      ),
    );
  }

  /// Drops any table whose name is not in [allowed].
  Map<String, List<Map<String, dynamic>>> _filterTables(
    Map<String, List<Map<String, dynamic>>> tables,
    Set<String> allowed,
  ) {
    return {
      for (final entry in tables.entries)
        if (allowed.contains(entry.key)) entry.key: entry.value,
    };
  }
}
