import 'dart:convert';
import 'dart:math' as math;
import 'dart:typed_data';

import 'package:pointycastle/export.dart';

class RsaEncryptionHelper {
  RsaEncryptionHelper({
    required this.publicKey,
    required this.privateKey,
  }) {
    _encryption.init(true, PublicKeyParameter<RSAPublicKey>(publicKey));
    _decryption.init(false, PrivateKeyParameter<RSAPrivateKey>(privateKey));
  }

  final RSAPrivateKey privateKey;
  final RSAPublicKey publicKey;

  final OAEPEncoding _encryption = OAEPEncoding(RSAEngine());
  final OAEPEncoding _decryption = OAEPEncoding(RSAEngine());

  static AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey> generateRsaKeyPair({int bitLength = 592}) {
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
    return AsymmetricKeyPair(
        pair.publicKey as RSAPublicKey, pair.privateKey as RSAPrivateKey);
  }

  String encrypt(String plaintext) {
    var cipherText =
        _encryption.process(Uint8List.fromList(plaintext.codeUnits));
    return base64Encode(cipherText);
  }

  String decrypt(String ciphertext) {
    final data = base64Decode(ciphertext);
    var decrypted = _decryption.process(data);
    return String.fromCharCodes(decrypted);
  }
}
