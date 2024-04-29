import 'dart:convert';

class CipherData {
  String mac;
  String value;

  CipherData({required this.mac, required this.value});

  factory CipherData.fromJson(json) {
    Map<String, dynamic> data = json is String ? jsonDecode(json) : json;
    return CipherData(
      mac: data['mac'].toString(),
      value: data['value'].toString(),
    );
  }

  Map<String, dynamic> toJson() {
    return {
      'mac': mac,
      'value': value,
    };
  }

  @override
  bool operator ==(Object other) =>
      identical(this, other) || (other is CipherData && other.mac == mac && other.value == value);

  @override
  String toString() => 'CipherData(mac: $mac, value: $value)';

  @override
  int get hashCode => Object.hash(mac, value);
}
