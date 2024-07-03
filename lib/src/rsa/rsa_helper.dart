import 'dart:math' as math;
import 'dart:typed_data';

import 'package:encrypt/encrypt.dart';
import 'package:pointycastle/export.dart';

class RsaEncryptionHelper {
  RsaEncryptionHelper({
    required RSAPublicKey publicKey,
    required RSAPrivateKey privateKey,
  }) {
    _encrypter = Encrypter(
      RSA(publicKey: publicKey, privateKey: privateKey, digest: RSADigest.SHA256, encoding: RSAEncoding.OAEP),
    );
  }

  late final Encrypter _encrypter;

  static AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey> generateRsaKeyPair({int bitLength = 256}) {
    final secureRandom = FortunaRandom();
    final random = math.Random.secure();
    final seeds = List.generate(32, (index) => random.nextInt(255));
    secureRandom.seed(KeyParameter(Uint8List.fromList(seeds)));

    final keyGenerator = RSAKeyGenerator();
    keyGenerator.init(ParametersWithRandom(
      RSAKeyGeneratorParameters(BigInt.parse('65537'), bitLength, 64),
      secureRandom,
    ));
    final pair = keyGenerator.generateKeyPair();
    return AsymmetricKeyPair(pair.publicKey as RSAPublicKey, pair.privateKey as RSAPrivateKey);
  }

  String encrypt(String plaintext) {
    var cipherText = _encrypter.encrypt(plaintext);
    return cipherText.base64;
  }

  String decrypt(String ciphertext) {
    var decrypted = _encrypter.decrypt64(ciphertext);
    return decrypted;
  }
}
