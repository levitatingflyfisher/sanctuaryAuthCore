import 'package:flutter_test/flutter_test.dart';
import 'package:sanctuary_auth_core/src/sync/three_way_merge.dart';

Map<String, dynamic> _row(String id, int modifiedAt,
    {String name = 'test'}) {
  return {'id': id, 'modifiedAt': modifiedAt, 'name': name};
}

void main() {
  group('threeWayMerge', () {
    // ── First sync (no base) ──────────────────────────────

    test('first sync: union of both dumps when base is empty', () {
      final mine = {
        'babies': [_row('a', 100, name: 'Alice')],
      };
      final theirs = {
        'babies': [_row('b', 200, name: 'Bob')],
      };

      final result = threeWayMerge(base: {}, mine: mine, theirs: theirs);
      final ids = result.merged['babies']!.map((r) => r['id']).toSet();

      expect(ids, equals({'a', 'b'}));
      expect(result.stats['babies']!.addedFromMine, equals(1));
      expect(result.stats['babies']!.addedFromTheirs, equals(1));
    });

    test('first sync: same row on both sides uses LWW', () {
      final mine = {
        'babies': [_row('a', 200, name: 'Alice-mine')],
      };
      final theirs = {
        'babies': [_row('a', 100, name: 'Alice-theirs')],
      };

      final result = threeWayMerge(base: {}, mine: mine, theirs: theirs);

      expect(result.merged['babies']!.single['name'], equals('Alice-mine'));
    });

    // ── LWW conflict resolution ───────────────────────────

    test('LWW: theirs wins when their modifiedAt is newer', () {
      final base = {
        'babies': [_row('a', 100, name: 'original')],
      };
      final mine = {
        'babies': [_row('a', 150, name: 'my-edit')],
      };
      final theirs = {
        'babies': [_row('a', 200, name: 'their-edit')],
      };

      final result = threeWayMerge(base: base, mine: mine, theirs: theirs);

      expect(result.merged['babies']!.single['name'], equals('their-edit'));
      expect(result.stats['babies']!.updatedFromTheirs, equals(1));
    });

    test('LWW: mine wins when my modifiedAt is newer', () {
      final base = {
        'babies': [_row('a', 100)],
      };
      final mine = {
        'babies': [_row('a', 200, name: 'my-edit')],
      };
      final theirs = {
        'babies': [_row('a', 150, name: 'their-edit')],
      };

      final result = threeWayMerge(base: base, mine: mine, theirs: theirs);

      expect(result.merged['babies']!.single['name'], equals('my-edit'));
      expect(result.stats['babies']!.updatedFromMine, equals(1));
    });

    test('LWW: tie goes to mine', () {
      final base = {
        'babies': [_row('a', 100)],
      };
      final mine = {
        'babies': [_row('a', 200, name: 'my-version')],
      };
      final theirs = {
        'babies': [_row('a', 200, name: 'their-version')],
      };

      final result = threeWayMerge(base: base, mine: mine, theirs: theirs);

      expect(result.merged['babies']!.single['name'], equals('my-version'));
    });

    // ── Deletion handling ─────────────────────────────────

    test('they deleted a row that was in base → honor deletion', () {
      final base = {
        'babies': [_row('a', 100), _row('b', 100)],
      };
      final mine = {
        'babies': [_row('a', 100), _row('b', 100)],
      };
      final theirs = {
        'babies': [_row('a', 100)],
        // b is absent = they deleted it
      };

      final result = threeWayMerge(base: base, mine: mine, theirs: theirs);

      final ids = result.merged['babies']!.map((r) => r['id']).toList();
      expect(ids, equals(['a']));
      expect(result.stats['babies']!.deleted, equals(1));
    });

    test('I deleted a row that was in base → honor deletion', () {
      final base = {
        'babies': [_row('a', 100), _row('b', 100)],
      };
      final mine = {
        'babies': [_row('a', 100)],
        // b is absent = I deleted it
      };
      final theirs = {
        'babies': [_row('a', 100), _row('b', 100)],
      };

      final result = threeWayMerge(base: base, mine: mine, theirs: theirs);

      final ids = result.merged['babies']!.map((r) => r['id']).toList();
      expect(ids, equals(['a']));
      expect(result.stats['babies']!.deleted, equals(1));
    });

    test('both deleted the same row → gone', () {
      final base = {
        'babies': [_row('a', 100), _row('b', 100)],
      };
      final mine = {
        'babies': [_row('a', 100)],
      };
      final theirs = {
        'babies': [_row('a', 100)],
      };

      final result = threeWayMerge(base: base, mine: mine, theirs: theirs);

      expect(result.merged['babies'], hasLength(1));
      expect(result.stats['babies']!.deleted, equals(1));
    });

    // ── New rows ──────────────────────────────────────────

    test('new row from mine (not in base) is included', () {
      final base = {
        'babies': [_row('a', 100)],
      };
      final mine = {
        'babies': [_row('a', 100), _row('new-mine', 200)],
      };
      final theirs = {
        'babies': [_row('a', 100)],
      };

      final result = threeWayMerge(base: base, mine: mine, theirs: theirs);

      final ids = result.merged['babies']!.map((r) => r['id']).toSet();
      expect(ids, contains('new-mine'));
      expect(result.stats['babies']!.addedFromMine, equals(1));
    });

    test('new row from theirs (not in base) is included', () {
      final base = {
        'babies': [_row('a', 100)],
      };
      final mine = {
        'babies': [_row('a', 100)],
      };
      final theirs = {
        'babies': [_row('a', 100), _row('new-theirs', 200)],
      };

      final result = threeWayMerge(base: base, mine: mine, theirs: theirs);

      final ids = result.merged['babies']!.map((r) => r['id']).toSet();
      expect(ids, contains('new-theirs'));
      expect(result.stats['babies']!.addedFromTheirs, equals(1));
    });

    // ── Cross-table behavior ──────────────────────────────

    test('unknown table from theirs is passed through', () {
      final base = <String, List<Map<String, dynamic>>>{};
      final mine = {
        'babies': [_row('a', 100)],
      };
      final theirs = {
        'babies': [_row('b', 100)],
        'vaccineRecords': [_row('v1', 100, name: 'MMR')],
      };

      final result = threeWayMerge(base: base, mine: mine, theirs: theirs);

      expect(result.merged.containsKey('vaccineRecords'), isTrue);
      expect(result.merged['vaccineRecords'], hasLength(1));
    });

    test('table only in mine is kept', () {
      final base = <String, List<Map<String, dynamic>>>{};
      final mine = {
        'babies': [_row('a', 100)],
        'medicineLogs': [_row('m1', 100)],
      };
      final theirs = {
        'babies': [_row('b', 100)],
      };

      final result = threeWayMerge(base: base, mine: mine, theirs: theirs);

      expect(result.merged.containsKey('medicineLogs'), isTrue);
      expect(result.merged['medicineLogs'], hasLength(1));
    });

    // ── Edge cases ────────────────────────────────────────

    test('all empty inputs produce empty output', () {
      final result = threeWayMerge(base: {}, mine: {}, theirs: {});

      expect(result.merged, isEmpty);
      expect(result.stats, isEmpty);
    });

    test('empty table produces empty merged table', () {
      final result = threeWayMerge(
        base: {'babies': []},
        mine: {'babies': []},
        theirs: {'babies': []},
      );

      expect(result.merged['babies'], isEmpty);
    });

    test('unchanged row is counted as unchanged', () {
      final row = _row('a', 100, name: 'same');
      final result = threeWayMerge(
        base: {'babies': [row]},
        mine: {'babies': [row]},
        theirs: {'babies': [row]},
      );

      expect(result.stats['babies']!.unchanged, equals(1));
      expect(result.merged['babies'], hasLength(1));
    });

    test('handles modifiedAt as ISO string', () {
      final mine = {
        'babies': [
          {
            'id': 'a',
            'modifiedAt': '2026-04-16T12:00:00.000Z',
            'name': 'mine',
          },
        ],
      };
      final theirs = {
        'babies': [
          {
            'id': 'a',
            'modifiedAt': '2026-04-16T13:00:00.000Z',
            'name': 'theirs',
          },
        ],
      };

      final result = threeWayMerge(base: {}, mine: mine, theirs: theirs);

      // theirs is 1 hour later → theirs wins
      expect(result.merged['babies']!.single['name'], equals('theirs'));
    });

    test('complex multi-table scenario', () {
      final base = {
        'babies': [_row('baby1', 100, name: 'Baby')],
        'feedingLogs': [
          _row('f1', 100),
          _row('f2', 100),
          _row('f3', 100),
        ],
      };
      final mine = {
        'babies': [_row('baby1', 200, name: 'Baby-renamed')],
        'feedingLogs': [
          _row('f1', 100), // unchanged
          // f2 deleted by me
          _row('f3', 150), // I edited
          _row('f4', 200), // new from me
        ],
      };
      final theirs = {
        'babies': [_row('baby1', 100, name: 'Baby')], // not edited
        'feedingLogs': [
          _row('f1', 100), // unchanged
          _row('f2', 100), // they still have f2
          _row('f3', 180), // they also edited, later than me
          _row('f5', 200), // new from them
        ],
      };

      final result = threeWayMerge(base: base, mine: mine, theirs: theirs);

      // Baby: mine wins (modifiedAt 200 > 100)
      expect(
        result.merged['babies']!.single['name'],
        equals('Baby-renamed'),
      );

      // Feedings:
      // f1: unchanged (both have it, same modifiedAt as base)
      // f2: I deleted, was in base → honor deletion
      // f3: both have it, theirs newer (180 > 150) → theirs wins
      // f4: new from me → included
      // f5: new from theirs → included
      final feedingIds =
          result.merged['feedingLogs']!.map((r) => r['id']).toSet();
      expect(feedingIds, equals({'f1', 'f3', 'f4', 'f5'}));
      expect(feedingIds.contains('f2'), isFalse);

      final feedStats = result.stats['feedingLogs']!;
      expect(feedStats.deleted, equals(1)); // f2
      expect(feedStats.addedFromMine, equals(1)); // f4
      expect(feedStats.addedFromTheirs, equals(1)); // f5
      expect(feedStats.updatedFromTheirs, equals(1)); // f3
    });
  });
}
