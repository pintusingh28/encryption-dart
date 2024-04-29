import 'dart:convert';
import 'dart:typed_data';

import "package:asn1lib/asn1lib.dart";
import 'package:pointycastle/export.dart';

class RsaKeyHelper {
  static const _publicKeyBeginSequence = "-----BEGIN RSA PUBLIC KEY-----";
  static const _publicKeyEndSequence = "-----END RSA PUBLIC KEY-----";
  static const _privateKeyBeginSequence = "-----BEGIN RSA PRIVATE KEY-----";
  static const _privateKeyEndSequence = "-----END RSA PRIVATE KEY-----";
  static const _newLineSequence = "\r\n";

  static String encodePrivateKey(RSAPrivateKey privateKey) {
    final asn1Sequence = ASN1Sequence();

    asn1Sequence.add(ASN1Integer(BigInt.from(0)));
    asn1Sequence.add(ASN1Integer(privateKey.n!));
    asn1Sequence.add(ASN1Integer(privateKey.publicExponent!));
    asn1Sequence.add(ASN1Integer(privateKey.privateExponent!));
    asn1Sequence.add(ASN1Integer(privateKey.p!));
    asn1Sequence.add(ASN1Integer(privateKey.q!));
    asn1Sequence.add(ASN1Integer(privateKey.privateExponent! % (privateKey.p! - BigInt.from(1))));
    asn1Sequence.add(ASN1Integer(privateKey.privateExponent! % (privateKey.q! - BigInt.from(1))));
    asn1Sequence.add(ASN1Integer(privateKey.q!.modInverse(privateKey.p!)));

    var dataBase64 = base64.encode(asn1Sequence.encodedBytes);

    final stringBuffer = StringBuffer();
    stringBuffer.writeAll([_privateKeyBeginSequence, dataBase64, _privateKeyEndSequence], _newLineSequence);
    return stringBuffer.toString();
  }

  static String encodePublicKey(RSAPublicKey publicKey) {
    var asn1Sequence = ASN1Sequence();
    asn1Sequence.add(ASN1Integer(publicKey.modulus!));
    asn1Sequence.add(ASN1Integer(publicKey.exponent!));
    var dataBase64 = base64.encode(asn1Sequence.encodedBytes);

    final stringBuffer = StringBuffer();
    stringBuffer.writeAll([_publicKeyBeginSequence, dataBase64, _publicKeyEndSequence], _newLineSequence);
    return stringBuffer.toString();
  }

  static RSAPublicKey decodePublicKey(String keyContent) {
    var publicKeyDER = _decodeKey(keyContent);
    var asn1Parser = ASN1Parser(publicKeyDER as Uint8List);
    var topLevelSeq = asn1Parser.nextObject() as ASN1Sequence;

    ASN1Integer modulus, exponent;

    if (topLevelSeq.elements[0].runtimeType == ASN1Integer) {
      modulus = topLevelSeq.elements[0] as ASN1Integer;
      exponent = topLevelSeq.elements[1] as ASN1Integer;
    } else {
      var publicKeyBitString = topLevelSeq.elements[1];
      var publicKeyAsn = ASN1Parser(publicKeyBitString.contentBytes());
      ASN1Sequence publicKeySeq = publicKeyAsn.nextObject() as ASN1Sequence;
      modulus = publicKeySeq.elements[0] as ASN1Integer;
      exponent = publicKeySeq.elements[1] as ASN1Integer;
    }

    RSAPublicKey rsaPublicKey = RSAPublicKey(
      modulus.valueAsBigInteger,
      exponent.valueAsBigInteger,
    );
    return rsaPublicKey;
  }

  static RSAPrivateKey decodePrivateKey(String keyContent) {
    var privateKeyDER = _decodeKey(keyContent);
    var asn1Parser = ASN1Parser(privateKeyDER as Uint8List);
    var topLevelSeq = asn1Parser.nextObject() as ASN1Sequence;

    ASN1Integer modulus, privateExponent, p, q;
    if (topLevelSeq.elements.length == 3) {
      var privateKey = topLevelSeq.elements[2];

      asn1Parser = ASN1Parser(privateKey.contentBytes());
      var pkSeq = asn1Parser.nextObject() as ASN1Sequence;

      modulus = pkSeq.elements[1] as ASN1Integer;
      privateExponent = pkSeq.elements[3] as ASN1Integer;
      p = pkSeq.elements[4] as ASN1Integer;
      q = pkSeq.elements[5] as ASN1Integer;
    } else {
      modulus = topLevelSeq.elements[1] as ASN1Integer;
      privateExponent = topLevelSeq.elements[3] as ASN1Integer;
      p = topLevelSeq.elements[4] as ASN1Integer;
      q = topLevelSeq.elements[5] as ASN1Integer;
    }

    RSAPrivateKey rsaPrivateKey = RSAPrivateKey(
      modulus.valueAsBigInteger,
      privateExponent.valueAsBigInteger,
      p.valueAsBigInteger,
      q.valueAsBigInteger,
    );

    return rsaPrivateKey;
  }

  static List<int> _decodeKey(String keyContent) {
    var startsWith = [_privateKeyBeginSequence, _publicKeyBeginSequence];
    var endsWith = [_privateKeyEndSequence, _publicKeyEndSequence];

    keyContent = keyContent.replaceAll('\n', '').replaceAll('\r', '');

    for (var s in startsWith) {
      if (keyContent.startsWith(s)) {
        keyContent = keyContent.substring(s.length);
      }
    }

    for (var s in endsWith) {
      if (keyContent.endsWith(s)) {
        keyContent = keyContent.substring(0, keyContent.length - s.length);
      }
    }
    return base64.decode(keyContent);
  }
}
