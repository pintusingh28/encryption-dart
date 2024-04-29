import 'package:encryption/encryption.dart';

void main() {
  final result = RsaEncryptionHelper.generateRsaKeyPair(bitLength: 1024);
  final encryption = RsaEncryptionHelper(
    privateKey: result.privateKey,
    publicKey: result.publicKey,
  );

  print("publicKey: ${RsaKeyHelper.encodePublicKey(result.publicKey)}");
  print("privateKey: ${RsaKeyHelper.encodePrivateKey(result.privateKey)}");

  const plainText = "LSKjQcTGeH89UMo5mWIheJrNErvtS0EQ";
  final cipherText = encryption.encrypt(plainText);
  final decryptedText = encryption.decrypt(cipherText);

  print("plainText: $plainText");
  print("cipherText: $cipherText");
  print("decryptedText: $decryptedText");
}
