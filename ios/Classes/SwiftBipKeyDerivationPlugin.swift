import Flutter
import UIKit
import TrustWalletCore

public class SwiftBipKeyDerivationPlugin: NSObject, FlutterPlugin {
    public static func register(with registrar: FlutterPluginRegistrar) {
        let channel = FlutterMethodChannel(name: "bip_key_derivation", binaryMessenger: registrar.messenger())
        let instance = SwiftBipKeyDerivationPlugin()
        registrar.addMethodCallDelegate(instance, channel: channel)
    }
    
    let InvalidArgs = 0
    let InvalidMnemonic = 1
    let InvalidPrivateKey = 2
    let InvalidPublicKey = 3
    let InvalidKeystore = 4
    let InvalidPassword = 5
    let InvalidDerivationPath = 6
    
    public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        guard let args = call.arguments as? Array<Any> else {
            return result(InvalidArgs)
        }
        switch call.method {
        case "generateRandomMnemonic":
            guard let strength = args[0] as? Int32 else {
                return result(InvalidArgs)
            }
            return result(generateRandomMnemonic(strength: strength))
        case "isValidMnemonic":
            guard let mnemonic = args[0] as? String else {
                return result(InvalidArgs)
            }
            return result(isValidMnemonic(mnemonic: mnemonic))
        case "decryptedByMnemonic":
            guard let mnemonic = args[0] as? String else {
                return result(InvalidArgs)
            }
            guard let derivationPath = args[1] as? String else {
                return result(InvalidArgs)
            }
            return result(decryptedByMnemonic(mnemonic: mnemonic, derivationPath: derivationPath))
        case "decryptedByKeystore":
            guard let keystore = args[0] as? [String: Any] else {
                return  result(InvalidArgs)
            }
            guard let password = args[1] as? String else {
                return  result(InvalidArgs)
            }
            return result(decryptedByKeystore(keystore: keystore, password: password))
        case "encrypt":
            guard let privateKey = args[0] as? String else {
                return  result(InvalidArgs)
            }
            guard let password = args[1] as? String else {
                return  result(InvalidArgs)
            }
            return result(encrypt(privateKey: privateKey, password: password))
        case "privateToPublic":
            guard let privateKey = args[0] as? String else {
                return  result(InvalidArgs)
            }
            return result(privateToPublic(privateKey: privateKey))
        case "publicToAddress":
            guard let publicKey = args[0] as? String else {
                return  result(InvalidArgs)
            }
            return result(publicToAddress(publicKey: publicKey))
        default:
            return result(InvalidArgs);
        }
    }
    
    private func decryptedByMnemonic(mnemonic: String , derivationPath: String) -> Any{
        if(!isValidMnemonic(mnemonic: mnemonic)) {
            return InvalidArgs
        }
        let wallet = HDWallet(mnemonic: mnemonic, passphrase: "")
        guard let path = DerivationPath(derivationPath) else {
            return InvalidDerivationPath
        }
        let privateKey = wallet.getKey(at: path)
        return privateKey.data
    }
    
    private func decryptedByKeystore(keystore: [String: Any], password: String) -> Any {
        guard let data = try? JSONSerialization.data(withJSONObject: keystore, options: JSONSerialization.WritingOptions.prettyPrinted) else {
            return InvalidKeystore
        }
        guard let storedKey = StoredKey.importJSON(json: data) else {
            return InvalidKeystore
        }
        guard let privateKey = storedKey.decryptPrivateKey(password: password) else {
            return InvalidPassword
        }
        return privateKey
    }
    
    private func encrypt(privateKey: String, password: String) -> Any{
        guard let data = Data(hexString: privateKey) else {
            return InvalidPrivateKey
        }
        let storedKey = StoredKey.importPrivateKey(privateKey: data, name: "", password: password, coin: CoinType.veChain)
        guard let json = storedKey?.exportJSON() else {
            return InvalidArgs
        }
        return String(data: json, encoding: .utf8)!
    }
    
    private func privateToPublic(privateKey: String) -> Any {
        guard let data = Data(hexString: privateKey) else {
            return InvalidPrivateKey
        }
        guard let key = PrivateKey(data: data) else {
            return InvalidPrivateKey
        }
        return key.getPublicKeySecp256k1(compressed: false).data
    }
    
    private func publicToAddress(publicKey: String) -> Any {
        guard let data = Data(hexString: publicKey) else {
            return InvalidPublicKey
        }
        let formatData = data.dropFirst()
        return Hash.keccak256(data: formatData).suffix(20)
    }
    
    private func isValidMnemonic(mnemonic: String) -> Bool {
        return HDWallet.isValid(mnemonic: mnemonic)
    }
    
    private func generateRandomMnemonic(strength: Int32) -> String {
        let wallet = HDWallet(strength: strength, passphrase: "")
        return wallet.mnemonic
    }
    
}
