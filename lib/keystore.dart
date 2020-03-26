import 'dart:core';

class KeyStore {
  String id;

  String address;

  KeystoreKeyHeader crypto;

  int version = 3;

  KeyStore({this.id, this.address, this.crypto, this.version}) {
    if (version != 3) {
      throw 'unsupported version';
    }
  }

  factory KeyStore.fromJSON(Map<String, dynamic> parsedJSON) {
    return KeyStore(
      id: parsedJSON['id'],
      address: parsedJSON['address'],
      crypto: KeystoreKeyHeader.fromJSON(parsedJSON['crypto']),
      version: parsedJSON['version'],
    );
  }

  Map<String, dynamic> get encoded {
    return {
      'id': id,
      'address': address,
      'crypto': crypto.encoded,
      'version': version,
    };
  }
}

class KeystoreKeyHeader {
  String cipherText;

  String cipher;

  CipherParams cipherParams;

  String kdf;

  ScryptParams kdfParams;

  String mac;

  KeystoreKeyHeader({
    this.cipherText,
    this.cipher,
    this.cipherParams,
    this.kdf,
    this.kdfParams,
    this.mac,
  });

  factory KeystoreKeyHeader.fromJSON(Map<String, dynamic> parsedJSON) {
    return KeystoreKeyHeader(
      cipherText: parsedJSON["ciphertext"],
      cipher: parsedJSON["cipher"],
      cipherParams: CipherParams.fromJSON(parsedJSON["cipherparams"]),
      kdf: parsedJSON["kdf"],
      kdfParams: ScryptParams.fromJSON(parsedJSON["kdfparams"]),
      mac: parsedJSON["mac"],
    );
  }

  Map<String, dynamic> get encoded {
    return {
      'ciphertext': cipherText,
      'cipher': cipher,
      'cipherparams': cipherParams.encoded,
      'kdf': kdf,
      'kdfparams': kdfParams.encoded,
      'mac': mac,
    };
  }
}

class CipherParams {
  String iv;

  CipherParams({this.iv});

  factory CipherParams.fromJSON(Map<String, dynamic> parsedJSON) {
    return CipherParams(
      iv: parsedJSON["iv"],
    );
  }

  Map<String, String> get encoded {
    return {
      'iv': iv,
    };
  }
}

class ScryptParams {
  final int N;
  final int r;
  final int p;
  final int desiredKeyLength;
  final String salt;

  ScryptParams(this.N, this.r, this.p, this.desiredKeyLength, this.salt);

  Map<String, dynamic> get encoded {
    return {
      "n": N,
      "r": r,
      "p": p,
      "dklen": desiredKeyLength,
      "salt": salt,
    };
  }

  factory ScryptParams.fromJSON(Map<String, dynamic> parsedJson) {
    return ScryptParams(
      parsedJson['n'],
      parsedJson['r'],
      parsedJson['p'],
      parsedJson['dklen'],
      parsedJson['salt'],
    );
  }
}
