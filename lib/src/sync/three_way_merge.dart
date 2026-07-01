/// Pure 3-way merge for OpenHearth full-dump sync.
///
/// Operates on the JSON structure produced by BackupSerializer:
/// `{ tables: { tableName: [ {id, modifiedAt, ...}, ... ] } }`
///
/// See `SYNC_TIER_SPEC.md` §"3-Way Merge Algorithm" for the full spec.
library;

import 'package:flutter/foundation.dart';

/// How far into the future a peer's `modifiedAt` may be before the merge
/// clamps it back to "now". 24 hours covers legitimate clock skew on
/// consumer devices without letting a hostile peer pin their rows as the
/// LWW winner forever by sending year-3000 timestamps.
const _futureClockSkewTolerance = Duration(hours: 24);

/// Per-table merge statistics.
@immutable
class TableMergeStats {
  /// Rows added from the local device's dump (new on my side).
  final int addedFromMine;

  /// Rows added from the remote device's dump (new on their side).
  final int addedFromTheirs;

  /// Rows where the local version was newer (LWW → mine wins).
  final int updatedFromMine;

  /// Rows where the remote version was newer (LWW → theirs wins).
  final int updatedFromTheirs;

  /// Rows deleted (present in base, absent from both mine and theirs).
  final int deleted;

  /// Rows unchanged from base.
  final int unchanged;

  /// Rows whose `modifiedAt` was clamped because it claimed to be more than
  /// [_futureClockSkewTolerance] in the future. Tracked so the consuming app
  /// can surface a warning when a peer's clock looks hostile or badly
  /// misconfigured.
  final int clampedFutureTimestamps;

  const TableMergeStats({
    this.addedFromMine = 0,
    this.addedFromTheirs = 0,
    this.updatedFromMine = 0,
    this.updatedFromTheirs = 0,
    this.deleted = 0,
    this.unchanged = 0,
    this.clampedFutureTimestamps = 0,
  });

  int get totalMerged =>
      addedFromMine +
      addedFromTheirs +
      updatedFromMine +
      updatedFromTheirs +
      unchanged;
}

/// The result of a 3-way merge across all tables.
@immutable
class MergeResult {
  /// The merged table data: `{ tableName: [ row, row, ... ] }`.
  ///
  /// Rows within each table are sorted lexicographically by `id` so two
  /// devices merging the same inputs produce byte-identical outputs.
  final Map<String, List<Map<String, dynamic>>> merged;

  /// Per-table merge statistics.
  final Map<String, TableMergeStats> stats;

  /// Table names that were present in one of the inputs but outside the
  /// caller-supplied allow-list. Empty when no allow-list was configured
  /// or every table was recognized.
  final List<String> rejectedTables;

  const MergeResult({
    required this.merged,
    required this.stats,
    this.rejectedTables = const [],
  });
}

/// Performs a 3-way merge of table data from two devices.
///
/// [base] is the "last synced" state (empty map `{}` for first sync).
/// [mine] is the local device's current dump.
/// [theirs] is the remote device's dump.
///
/// Each value is a map of `tableName → List<row>` where each row is a
/// `Map<String, dynamic>` with at least `id` (String UUID) and
/// `modifiedAt` (int, millisecondsSinceEpoch) fields.
///
/// [allowedTables] — when non-null, tables outside this set are dropped
/// from every input and recorded in [MergeResult.rejectedTables]. Lets the
/// consuming app refuse peer injections into tables it does not own.
///
/// [now] — used to clamp peer `modifiedAt` values to the present (plus
/// [_futureClockSkewTolerance]). Overridable for deterministic tests.
///
/// **Merge rules (per the sync spec):**
/// - Both have it → LWW by `modifiedAt`. Tie → mine wins.
/// - Only mine has it, was in base → they deleted it → honor deletion.
/// - Only mine has it, not in base → new on my side → include.
/// - Only theirs has it, was in base → I deleted it → honor deletion.
/// - Only theirs has it, not in base → new on their side → include.
/// - Neither has it, was in base → both deleted → gone.
/// - Unknown tables in theirs (not in mine) → pass through entirely.
/// - Tables only in mine → keep entirely.
MergeResult threeWayMerge({
  required Map<String, List<Map<String, dynamic>>> base,
  required Map<String, List<Map<String, dynamic>>> mine,
  required Map<String, List<Map<String, dynamic>>> theirs,
  Set<String>? allowedTables,
  DateTime? now,
}) {
  final rejectedTables = <String>{};
  final filteredBase = _applyAllowList(base, allowedTables, rejectedTables);
  final filteredMine = _applyAllowList(mine, allowedTables, rejectedTables);
  final filteredTheirs = _applyAllowList(theirs, allowedTables, rejectedTables);

  final clampReference = now ?? DateTime.now();
  // `clampThreshold`: beyond this value, a timestamp is treated as hostile.
  // `clampFallback`: the value we substitute when we clamp. We clamp to the
  // real present, not to the threshold — clamping to the threshold would
  // still let the peer win LWW by 24 h, which is exactly the attack we're
  // preventing.
  final clampThreshold =
      clampReference.add(_futureClockSkewTolerance).millisecondsSinceEpoch;
  final clampFallback = clampReference.millisecondsSinceEpoch;

  final allTables = <String>{
    ...filteredBase.keys,
    ...filteredMine.keys,
    ...filteredTheirs.keys,
  };
  final merged = <String, List<Map<String, dynamic>>>{};
  final stats = <String, TableMergeStats>{};

  for (final table in allTables) {
    final baseRows = _indexById(filteredBase[table]);
    final myRows = _indexById(filteredMine[table]);
    final theirRows = _indexById(filteredTheirs[table]);

    final allIds = <String>{
      ...baseRows.keys,
      ...myRows.keys,
      ...theirRows.keys,
    };

    final mergedRows = <Map<String, dynamic>>[];
    var addedFromMine = 0;
    var addedFromTheirs = 0;
    var updatedFromMine = 0;
    var updatedFromTheirs = 0;
    var deleted = 0;
    var unchanged = 0;
    var clampedFutureTimestamps = 0;

    for (final id in allIds) {
      final inBase = baseRows.containsKey(id);
      final inMine = myRows.containsKey(id);
      final inTheirs = theirRows.containsKey(id);

      if (inMine && inTheirs) {
        final myRaw = _modifiedAt(myRows[id]!);
        final theirRaw = _modifiedAt(theirRows[id]!);
        if (theirRaw > clampThreshold) clampedFutureTimestamps++;
        final myMod =
            myRaw > clampThreshold ? clampFallback : myRaw;
        final theirMod =
            theirRaw > clampThreshold ? clampFallback : theirRaw;
        if (myMod >= theirMod) {
          mergedRows.add(myRows[id]!);
          if (inBase && myMod == _modifiedAt(baseRows[id]!)) {
            unchanged++;
          } else {
            updatedFromMine++;
          }
        } else {
          mergedRows.add(theirRows[id]!);
          updatedFromTheirs++;
        }
      } else if (inMine && !inTheirs) {
        if (inBase) {
          // Was in base, I still have it, they deleted it → honor deletion
          deleted++;
        } else {
          // New on my side → include
          mergedRows.add(myRows[id]!);
          addedFromMine++;
        }
      } else if (inTheirs && !inMine) {
        if (inBase) {
          // Was in base, they still have it, I deleted it → honor deletion
          deleted++;
        } else {
          // New on their side → include
          final theirRaw = _modifiedAt(theirRows[id]!);
          if (theirRaw > clampThreshold) clampedFutureTimestamps++;
          mergedRows.add(theirRows[id]!);
          addedFromTheirs++;
        }
      } else if (inBase && !inMine && !inTheirs) {
        // Both deleted it → gone
        deleted++;
      }
    }

    // Canonical ordering: sort by id so the merged byte payload is
    // deterministic regardless of input iteration order. Two devices given
    // the same inputs must produce the same bytes — otherwise the relay
    // upload would churn on every sync.
    mergedRows.sort((a, b) =>
        (a['id'] as String).compareTo(b['id'] as String));

    merged[table] = mergedRows;
    stats[table] = TableMergeStats(
      addedFromMine: addedFromMine,
      addedFromTheirs: addedFromTheirs,
      updatedFromMine: updatedFromMine,
      updatedFromTheirs: updatedFromTheirs,
      deleted: deleted,
      unchanged: unchanged,
      clampedFutureTimestamps: clampedFutureTimestamps,
    );
  }

  return MergeResult(
    merged: merged,
    stats: stats,
    rejectedTables: rejectedTables.toList()..sort(),
  );
}

Map<String, List<Map<String, dynamic>>> _applyAllowList(
  Map<String, List<Map<String, dynamic>>> tables,
  Set<String>? allowed,
  Set<String> rejected,
) {
  if (allowed == null) return tables;
  final out = <String, List<Map<String, dynamic>>>{};
  for (final entry in tables.entries) {
    if (allowed.contains(entry.key)) {
      out[entry.key] = entry.value;
    } else {
      rejected.add(entry.key);
    }
  }
  return out;
}

/// Indexes a list of rows by their `id` field for O(1) lookup.
Map<String, Map<String, dynamic>> _indexById(
  List<Map<String, dynamic>>? rows,
) {
  if (rows == null || rows.isEmpty) return const {};
  return {for (final row in rows) row['id'] as String: row};
}

/// Extracts the `modifiedAt` timestamp as an integer.
///
/// Handles both int (Drift's default serialization) and ISO string formats.
int _modifiedAt(Map<String, dynamic> row) {
  final value = row['modifiedAt'];
  if (value is int) return value;
  if (value is String) return DateTime.parse(value).millisecondsSinceEpoch;
  return 0;
}
