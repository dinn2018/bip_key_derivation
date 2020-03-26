import 'dart:async';
import 'dart:typed_data';
import 'dart:convert';
import 'package:convert/convert.dart';
import 'package:flutter/services.dart';
import 'package:bip_key_derivation/keystore.dart';

class BipKeyDerivation {
  static const MethodChannel _channel =
      const MethodChannel('bip_key_derivation');

  static Future<String> generateRandomMnemonic(int strength) async {
    final String mnemonic =
        await _channel.invokeMethod('generateRandomMnemonic', [strength]);
    return mnemonic;
  }

  static Future<bool> isValidMnemonic(String mnemonic) async {
    final bool isValid =
        await _channel.invokeMethod('isValidMnemonic', [mnemonic]);
    return isValid;
  }

  static Future<Uint8List> decryptedByMnemonic(
      String mnemonic, String derivationPath) async {
    final dynamic result = await _channel
        .invokeMethod('decryptedByMnemonic', [mnemonic, derivationPath]);
    KeyError error = KeyError.withCode(result);
    if (error != null) {
      throw error;
    }
    return result;
  }

  static Future<Uint8List> decryptedByKeystore(
      KeyStore keystore, String password) async {
    final dynamic result = await _channel
        .invokeMethod('decryptedByKeystore', [keystore.encoded, password]);
    KeyError error = KeyError.withCode(result);
    if (error != null) {
      throw error;
    }
    return result;
  }

  static Future<KeyStore> encrypt(Uint8List privateKey, String password) async {
    final dynamic result = await _channel
        .invokeMethod('encrypt', [hex.encode(privateKey), password]);
    KeyError error = KeyError.withCode(result);
    if (error != null) {
      throw error;
    }
    Map<String, dynamic> parsedJSON = json.decode(result);
    String addr = parsedJSON["activeAccounts"][0]["address"];
    return KeyStore.fromJSON({
      "id": parsedJSON["id"],
      "address": addr.substring(2).toLowerCase(),
      "crypto": parsedJSON["crypto"],
      "version": parsedJSON["version"],
    });
  }

  static Future<Uint8List> privateToPublic(Uint8List privateKey) async {
    final dynamic result = await _channel
        .invokeMethod('privateToPublic', [hex.encode(privateKey)]);
    KeyError error = KeyError.withCode(result);
    if (error != null) {
      throw error;
    }
    return result;
  }

  static Future<Uint8List> publicToAddress(Uint8List publicKey) async {
    final dynamic result =
        await _channel.invokeMethod('publicToAddress', [hex.encode(publicKey)]);
    KeyError error = KeyError.withCode(result);
    if (error != null) {
      throw error;
    }
    return result;
  }
}

class KeyError extends Error {
  String message;
  int code;

  KeyError(this.message, this.code);

  factory KeyError.withCode(dynamic code) {
    switch (code) {
      case 0:
        return KeyError('invalid args', code);
      case 1:
        return KeyError('invalid mnemonic', code);
      case 2:
        return KeyError('invalid private key', code);
      case 3:
        return KeyError('invalid public key', code);
      case 4:
        return KeyError('invalid keystore', code);
      case 5:
        return KeyError('invalid password', code);
      case 6:
        return KeyError('invalid derivation path', code);
    }
    return null;
  }

  @override
  String toString() {
    return message;
  }
}
