import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:sanctuary_auth_core/src/util/hex.dart';

void main() {
  group('HexEncoding', () {
    test('toHex encodes bytes as lowercase hex', () {
      final bytes = Uint8List.fromList([0xDE, 0xAD, 0xBE, 0xEF]);
      expect(bytes.toHex(), equals('deadbeef'));
    });

    test('toHex handles zero bytes', () {
      final bytes = Uint8List.fromList([0x00, 0x01, 0x0F]);
      expect(bytes.toHex(), equals('00010f'));
    });

    test('toHex of empty list is empty string', () {
      expect(Uint8List(0).toHex(), equals(''));
    });

    test('fromHex parses lowercase hex string', () {
      final bytes = HexEncoding.fromHex('deadbeef');
      expect(bytes, equals(Uint8List.fromList([0xDE, 0xAD, 0xBE, 0xEF])));
    });

    test('fromHex parses uppercase hex string', () {
      final bytes = HexEncoding.fromHex('DEADBEEF');
      expect(bytes, equals(Uint8List.fromList([0xDE, 0xAD, 0xBE, 0xEF])));
    });

    test('fromHex of empty string is empty list', () {
      expect(HexEncoding.fromHex(''), equals(Uint8List(0)));
    });

    test('fromHex throws on odd-length string', () {
      expect(
        () => HexEncoding.fromHex('abc'),
        throwsA(isA<FormatException>()),
      );
    });

    test('fromHex throws on invalid hex characters', () {
      expect(
        () => HexEncoding.fromHex('zzzz'),
        throwsA(isA<FormatException>()),
      );
    });

    test('round-trip: fromHex(toHex(bytes)) == bytes', () {
      final original = Uint8List.fromList(List.generate(32, (i) => i * 8));
      final roundTripped = HexEncoding.fromHex(original.toHex());
      expect(roundTripped, equals(original));
    });
  });
}
