package com.example.bip_key_derivation;

import com.google.common.base.Charsets;

import org.json.JSONObject;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Map;
import io.flutter.plugin.common.MethodCall;
import io.flutter.plugin.common.MethodChannel;
import io.flutter.plugin.common.MethodChannel.MethodCallHandler;
import io.flutter.plugin.common.MethodChannel.Result;
import io.flutter.plugin.common.PluginRegistry.Registrar;
import wallet.core.jni.CoinType;
import wallet.core.jni.HDWallet;
import wallet.core.jni.Hash;
import wallet.core.jni.PrivateKey;
import wallet.core.jni.StoredKey;

/** BipKeyDerivationPlugin */
public class BipKeyDerivationPlugin implements MethodCallHandler {


  /** Plugin registration. */
  public static void registerWith(Registrar registrar) {
    System.loadLibrary("TrustWalletCore");
    final MethodChannel channel = new MethodChannel(registrar.messenger(), "bip_key_derivation");
    channel.setMethodCallHandler(new BipKeyDerivationPlugin());
  }

  final int InvalidArgs = 0;
  final int InvalidMnemonic = 1;
  final int InvalidPrivateKey = 2;
  final int InvalidPublicKey = 3;
  final int InvalidKeystore = 4;
  final int InvalidPassword = 5;
  final int InvalidDerivationPath = 6;

  @Override
  public void onMethodCall(MethodCall call, Result result) {
    if (call.method.equals("generateRandomMnemonic")) {
      ArrayList<Integer> args = (ArrayList<Integer>)call.arguments;
      final Integer strength = args.get(0);
      generateRandomMnemonic(strength.intValue(),result);
    } else if (call.method.equals("isValidMnemonic")) {
      ArrayList<String> args = (ArrayList<String>)call.arguments;
      isValidMnemonic(args.get(0),result);
    } else if (call.method.equals("decryptedByMnemonic")) {
      ArrayList<String> args = (ArrayList<String>)call.arguments;
      decryptedByMnemonic(args.get(0),args.get(1),result);
    } else if (call.method.equals("decryptedByKeystore")) {
      ArrayList<Object> args = (ArrayList<Object>)call.arguments;
      final Map<String, Object> keystore = (Map<String, Object>)args.get(0);
      final String password = (String)args.get(1);
      decryptedByKeystore(keystore,password,result);
    } else if (call.method.equals("encrypt")) {
      ArrayList<String> args = (ArrayList<String>)call.arguments;
      encrypt(args.get(0),args.get(1),result);
    } else if (call.method.equals("privateToPublic")) {
      ArrayList<String> args = (ArrayList<String>)call.arguments;
      privateToPublic(args.get(0),result);
    } else if (call.method.equals("publicToAddress")) {
      ArrayList<String> args = (ArrayList<String>)call.arguments;
      publicToAddress(args.get(0),result);
    } else{
      result.notImplemented();
    }
  }

  private void generateRandomMnemonic(int strength,Result result) {
    try{
      HDWallet wallet = new HDWallet(strength, "");
      result.success(wallet.mnemonic());
    }catch (Exception e) {
      result.success(InvalidArgs);
    }
  }

  private void isValidMnemonic(String mnemonic,Result result) {
    try {
      boolean isValid = HDWallet.isValid(mnemonic);
      result.success(isValid);
    }catch (Exception e) {
      result.success(InvalidMnemonic);
    }
  }

  private void decryptedByMnemonic(String mnemonic, String derivationPath, Result result) {
    try{
      if(!HDWallet.isValid(mnemonic)) {
        result.success(InvalidMnemonic);
        return;
      }
    } catch (Exception e) {
      result.success(InvalidArgs);
      return;
    }
    try {
      HDWallet wallet = new HDWallet(mnemonic,"");
      PrivateKey key = wallet.getKey(derivationPath);
      result.success(key.data());
    }catch (Exception e) {
      result.success(InvalidDerivationPath);
    }

  }

  private void decryptedByKeystore(Map<String, Object> keystore, String password, Result result) {
    try {
      JSONObject jsonObject = new JSONObject(keystore);
      StoredKey storedKey = StoredKey.importJSON(jsonObject.toString().getBytes(Charsets.UTF_8));
      try {
        PrivateKey key = storedKey.privateKey(CoinType.VECHAIN,password);
        if(key == null) {
          result.success(InvalidPassword);
          return;
        }
        result.success(key.data());
      } catch (Exception e) {
        result.success(InvalidKeystore);
      }
    } catch (Exception e) {
      result.success(InvalidKeystore);
    }
  }

  private void encrypt(String privateKey, String password, Result result) {
    try{
      StoredKey storedKey = StoredKey.importPrivateKey(hexStringToByteArray(privateKey),"",password, CoinType.VECHAIN);
      String json = new String(storedKey.exportJSON(), StandardCharsets.UTF_8);
      result.success(json);
    }catch (Exception e) {
      result.success(InvalidPrivateKey);
    }

  }

  private void privateToPublic(String privateKey, Result result) {
    try{
      PrivateKey key = new PrivateKey(hexStringToByteArray(privateKey));
      result.success(key.getPublicKeySecp256k1(false).data());
    } catch (Exception e) {
      result.success(InvalidPrivateKey);
    }
  }

  private void publicToAddress(String publicKey, Result result) {
    try{
      byte[] data = hexStringToByteArray(publicKey);
      byte[] dataList = Arrays.copyOfRange(data,1,data.length);
      byte[] hash = Hash.keccak256(dataList);
      result.success(Arrays.copyOfRange(hash,hash.length-20,hash.length));
    } catch (Exception e) {
      result.success(InvalidPublicKey);
    }

  }

  private static byte[] hexStringToByteArray(String s) {
    int len = s.length();
    byte[] data = new byte[len / 2];
    for (int i = 0; i < len; i += 2) {
      data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
              + Character.digit(s.charAt(i+1), 16));
    }
    return data;
  }

}
