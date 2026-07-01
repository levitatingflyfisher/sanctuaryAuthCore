import 'dart:typed_data';

/// Hex encoding/decoding for byte arrays.
extension HexEncoding on Uint8List {
  /// Returns the lowercase hex string representation of these bytes.
  ///
  /// Example: `Uint8List.fromList([0xDE, 0xAD])` → `"dead"`.
  String toHex() =>
      map((b) => b.toRadixString(16).padLeft(2, '0')).join();

  /// Parses a hex string into a [Uint8List].
  ///
  /// Throws [FormatException] if [hex] has an odd length or contains
  /// non-hex characters.
  static Uint8List fromHex(String hex) {
    if (hex.length.isOdd) {
      throw FormatException(
        'Hex string must have even length; got ${hex.length}',
        hex,
      );
    }
    final bytes = Uint8List(hex.length ~/ 2);
    for (var i = 0; i < bytes.length; i++) {
      final byteHex = hex.substring(i * 2, i * 2 + 2);
      final value = int.tryParse(byteHex, radix: 16);
      if (value == null) {
        throw FormatException(
          'Invalid hex byte: "$byteHex"',
          hex,
          i * 2,
        );
      }
      bytes[i] = value;
    }
    return bytes;
  }
}
