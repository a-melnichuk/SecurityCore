//
//  ViewController.swift
//  Examples
//
//  Created by Alex Melnichuk on 7/1/19.
//  Copyright © 2019 Baltic International Group OU. All rights reserved.
//

import UIKit
import SecurityCore
import LocalAuthentication

class ViewController: UIViewController {

    @IBOutlet weak var passwordTextField: UITextField!
    
    var context: SecurityContext {
        let laContext = LAContext()
        laContext.localizedReason = "_Localized reason"
        laContext.localizedCancelTitle = "_Cancel"
        laContext.localizedFallbackTitle = "_Fallback title"
        laContext.touchIDAuthenticationAllowableReuseDuration = 10
        return SecurityContext(useOperationPrompt: "_Prompt", laContext: laContext)
    }
    
    let privateKey = SecurityKey<SecPrivateKey>(namespace: "test", key: "private_key")
    let publicKey = SecurityKey<SecPublicKey>(namespace: "test", key: "public_key")
    let encryptedPassword = SecurityKey<Data>(namespace: "test", key: "password", accessControlFlags: [])
    let encryptedPasswordInfo = SecurityKey<Data>(namespace: "test", key: "password_signature", accessControlFlags: [])
    
    override func viewDidLoad() {
        super.viewDidLoad()
    }
    
    // MARK: Actions
    
    @IBAction func didTabEncrypt(_ sender: Any) {
        self.view.endEditing(true)
        let password = passwordTextField.text ?? ""
        guard !password.isEmpty else {
            self.view.endEditing(true)
            let alert = UIAlertController(title: "Enter password", message: nil, preferredStyle: .alert)
            alert.addAction(UIAlertAction(title: "OK", style: .default, handler: nil))
            present(alert, animated: true, completion: nil)
            return
        }
    
        var errorCode = 0
        do {
            let (privateKey, publicKey) = try retreiveKeyPair()
            errorCode = 1
            let encryptedPassword = try publicKey.encrypt(password)
            errorCode = 2
            try self.encryptedPassword.write(encryptedPassword, context: context)
            
            
            
            let alert = UIAlertController(title: "Password encrypted", message: nil, preferredStyle: .alert)
            alert.addAction(UIAlertAction(title: "OK", style: .default, handler: nil))
            present(alert, animated: true, completion: nil)
            
        }  catch SecureStorageError.canceled {
        }  catch SecureStorageError.passcodeDisabled {
            self.openPasscodeSettings()
        } catch {
            let alert = UIAlertController(title: "Error \(errorCode)", message: "\(error)", preferredStyle: .alert)
            alert.addAction(UIAlertAction(title: "OK", style: .default, handler: nil))
            present(alert, animated: true, completion: nil)
        }
    }
    
    @IBAction func didTapDecryptPassword(_ sender: Any) {
        self.view.endEditing(true)
        var errorCode = 0
        do {
            guard let encryptedPassword = try self.encryptedPassword.readIfPresent(context: context) else {
                let alert = UIAlertController(title: "Password not found", message: nil, preferredStyle: .alert)
                alert.addAction(UIAlertAction(title: "OK", style: .default, handler: nil))
                present(alert, animated: true, completion: nil)
                return
            }
            errorCode = 1
            let (privateKey, publicKey) = try retreiveKeyPair()
             errorCode = 2
            let password = try privateKey.decrypt(String.self, from: encryptedPassword)
            
            let alert = UIAlertController(title: "Decrypted", message: password, preferredStyle: .alert)
            alert.addAction(UIAlertAction(title: "OK", style: .default, handler: nil))
            present(alert, animated: true, completion: nil)
        } catch SecureStorageError.canceled {
        } catch SecureStorageError.passcodeDisabled {
           self.openPasscodeSettings()
        } catch {
            let alert = UIAlertController(title: "Error \(errorCode)", message: "\(error)", preferredStyle: .alert)
            alert.addAction(UIAlertAction(title: "OK", style: .default, handler: nil))
            present(alert, animated: true, completion: nil)
        }
    }
    
    @IBAction func didTapClear(_ sender: Any) {
        self.view.endEditing(true)
        clearKeychain()
    }
    
    @IBAction func didTabGeneratePrivateKey(_ sender: Any) {
        do {
            let privateKey = try retreivePrivateKey()
            let publicKey = try SecPublicKey(privateKey: privateKey)
            
            let alert = UIAlertController(title: "Keys created", message: nil, preferredStyle: .alert)
            alert.addAction(UIAlertAction(title: "OK", style: .default, handler: nil))
            present(alert, animated: true, completion: nil)
        } catch {
            let alert = UIAlertController(title: "Error", message: "\(error)", preferredStyle: .alert)
            alert.addAction(UIAlertAction(title: "OK", style: .default, handler: nil))
            present(alert, animated: true, completion: nil)
        }
    }
    
    @IBAction func didTabDelete(_ sender: Any) {
        self.view.endEditing(true)
        do {
            try encryptedPassword.delete()
        } catch {
            let alert = UIAlertController(title: "Error", message: "\(error)", preferredStyle: .alert)
            alert.addAction(UIAlertAction(title: "OK", style: .default, handler: nil))
            present(alert, animated: true, completion: nil)
        }
    }
    
    // MARK: Private functions
    
    private func openPasscodeSettings() {
        let alert = UIAlertController(title: "Enable passcode", message:  nil, preferredStyle: .alert)
        alert.addAction(UIAlertAction(title: "Settings", style: .default, handler: { _ in
            if let url = URL(string: "App-Prefs:root=TOUCHID_PASSCODE") {
                UIApplication.shared.open(url, completionHandler: .none)
            }
        }))
        alert.addAction(UIAlertAction(title: "Cancel", style: .cancel, handler: nil))
        present(alert, animated: true, completion: nil)
    }
    
    private func retreivePrivateKey() throws -> SecPrivateKey {
        if let currPrivateKey = try self.privateKey.readIfPresent(context: context) {
            return currPrivateKey
        } else {
            return try self.privateKey.generateKey(context: context)
        }
    }
    
    private func retreiveKeyPair() throws -> (privateKey: SecPrivateKey, publicKey: SecPublicKey) {
        var errorCode = 0
        do {
            let privateKey: SecPrivateKey
            let publicKey: SecPublicKey
            
            if let currPrivateKey = try self.privateKey.readIfPresent(context: context) {
                privateKey = currPrivateKey
                print("Private key found")
            } else {
                errorCode = 1
                privateKey = try self.privateKey.generateKey(context: context)
                print("Private key created")
            }
            
            errorCode = 2
            print("__READ_PUBLIC_KEY")
            if let currPublicKey = try self.publicKey.readIfPresent(context: context) {
                publicKey = currPublicKey
                print("Public key found")
            } else {
                errorCode = 3
                let newPublicKey = try SecPublicKey(privateKey: privateKey)
                errorCode = 4
                // TODO: Check if biometry is requested in this case
                print("__WRITE_PUBLIC_KEY")
                try self.publicKey.write(newPublicKey, context: context)
                errorCode = 5
                print("__READ_PUBLIC_KEY 2")
                publicKey = try self.publicKey.read(context: context)
                print("Public key created")
            }
            
            return (privateKey, publicKey)
        } catch SecureStorageError.passcodeDisabled {
            throw SecureStorageError.passcodeDisabled 
        } catch SecureStorageError.canceled {
            throw SecureStorageError.canceled
        } catch {
            throw KeyRetrievalError(code: errorCode, error: error)
        }
    }
    
    private func clearKeychain() {
        try? privateKey.delete()
        try? publicKey.delete()
        try? encryptedPassword.delete()
    }
}

struct KeyRetrievalError: Error, CustomDebugStringConvertible, CustomStringConvertible {
    let code: Int
    let error: Error
    
    var debugDescription: String {
        return localizedDescription
    }
    
    var description: String {
        return localizedDescription
    }
    
    var localizedDescription: String {
        return "\(code): \(error)"
    }
}

struct EncryptedPasswordInfo {
    let encryptedPassword: Data
    let encryptedPasswordSignature: Data
}
