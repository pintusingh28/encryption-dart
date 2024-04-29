import 'dart:convert';
import 'dart:math' as math;

import 'package:crypto/crypto.dart';
import 'package:encrypt/encrypt.dart';
import 'package:encryption/src/aes/cipher_data.dart';

class AesEncryptionHelper {
  final IV _iv;
  late final Encrypter _encrypter;
  late final Hmac _hMac;

  AesEncryptionHelper.fromUtf8({required String key, required String iv}) : _iv = IV.fromUtf8(iv) {
    var encryptionKey = Key.fromUtf8(key);
    _encrypter = Encrypter(AES(encryptionKey, mode: AESMode.cbc));
    _hMac = Hmac(sha256, encryptionKey.bytes);
  }

  AesEncryptionHelper.fromBase64({required String key, required String iv}) : _iv = IV.fromBase64(iv) {
    var encryptionKey = Key.fromBase64(key);
    _encrypter = Encrypter(AES(encryptionKey, mode: AESMode.cbc));
    _hMac = Hmac(sha256, encryptionKey.bytes);
  }

  CipherData encrypt(String plainText) {
    var encryptedValue = _encrypter.encrypt(plainText, iv: _iv).base64.replaceAll("\n", "");
    var mac = _hMac.convert(utf8.encode(_iv.base64 + encryptedValue)).toString();
    var encData = CipherData(mac: mac.toString(), value: encryptedValue);
    return encData;
  }

  String decrypt(CipherData cipher) {
    var mac = _hMac.convert(utf8.encode(_iv.base64 + cipher.value));
    if (mac.toString() != cipher.mac) throw CipherValidationException();
    return _encrypter.decrypt64(cipher.value, iv: _iv);
  }

  static String generateKey([int keyLength = 32]) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890';
    final random = math.Random.secure();

    return List.generate(
      keyLength,
      (index) => chars[(random.nextDouble() * chars.length).floor()],
    ).join();
  }
}

class CipherValidationException implements Exception {
  const CipherValidationException();
}
