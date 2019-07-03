//
//  Encryptor.swift
//  SecurityCore
//
//  Created by Alex Melnichuk on 7/2/19.
//  Copyright © 2019 Baltic International Group OU. All rights reserved.
//

import Foundation

public protocol SecurityCrypto {
    func encrypt(_ data: Data, publicKey: SecKey) throws -> Data
    func decrypt(_ data: Data, privateKey: SecKey) throws -> Data
    
    func sign(_ data: Data, privateKey: SecKey) throws -> Data
    func validateSignature(_ signature: Data, data: Data, publicKey: SecKey) throws
}

public extension SecurityCrypto {
    func encrypt(_ data: Data, publicKey: SecKey, algorithm: SecKeyAlgorithm) throws -> Data {
        guard SecKeyIsAlgorithmSupported(publicKey, .encrypt, algorithm) else {
            throw SecureStorageError.invalidAttributes("Encryption: Algorithm not supported - \(algorithm)")
        }
        var error: Unmanaged<CFError>?
        guard let cipherText = SecKeyCreateEncryptedData(
            publicKey,
            algorithm,
            data as CFData,
            &error) as Data? else {
                throw SecureStorageError.securityError(error!.takeRetainedValue() as Error)
        }
        return cipherText
    }
    
    func decrypt(_ data: Data, privateKey: SecKey, algorithm: SecKeyAlgorithm) throws -> Data {
        guard SecKeyIsAlgorithmSupported(privateKey, .decrypt, algorithm) else {
            throw SecureStorageError.invalidAttributes("Decryption: Algorithm not supported - \(algorithm)")
        }
        
        var error: Unmanaged<CFError>? = nil
        guard let clearText = SecKeyCreateDecryptedData(
            privateKey,
            algorithm,
            data as CFData,
            &error) as Data? else {
                throw SecureStorageError.securityError(error!.takeRetainedValue() as Error)
        }
        return clearText
    }
    
    func sign(_ data: Data, privateKey: SecKey, algorithm: SecKeyAlgorithm) throws -> Data {
        guard SecKeyIsAlgorithmSupported(privateKey, .sign, algorithm) else {
            throw SecureStorageError.invalidAttributes("Signature: Algorithm not supported - \(algorithm)")
        }
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            privateKey,
            algorithm,
            data as CFData,
            &error) as Data? else {
                throw SecureStorageError.signatureFailed(error!.takeRetainedValue() as Error)
        }
        return signature
    }
    func validateSignature(_ signature: Data, data: Data, publicKey: SecKey, algorithm: SecKeyAlgorithm) throws {
        var error: Unmanaged<CFError>?
        guard SecKeyVerifySignature(
            publicKey,
            algorithm,
            data as CFData,
            signature as CFData,
            &error) else {
                throw SecureStorageError.signatureInvalid(error!.takeRetainedValue() as Error)
        }
    }
}

public struct SymmetricKeychainCrypto: SecurityCrypto {
    
    public init() {}
    
    public func encrypt(_ data: Data, publicKey: SecKey) throws -> Data {
        return try encrypt(data, publicKey: publicKey, algorithm: .rsaEncryptionOAEPSHA512AESGCM)
    }
    
    public func decrypt(_ data: Data, privateKey: SecKey) throws -> Data {
        return try decrypt(data, privateKey: privateKey, algorithm: .rsaEncryptionOAEPSHA512AESGCM)
    }
    
    public func sign(_ data: Data, privateKey: SecKey) throws -> Data {
        return try sign(data, privateKey: privateKey, algorithm: .rsaEncryptionOAEPSHA512AESGCM)
    }
    
    public func validateSignature(_ signature: Data, data: Data, publicKey: SecKey) throws {
        try validateSignature(signature, data: data, publicKey: publicKey, algorithm: .rsaEncryptionOAEPSHA512AESGCM)
    }
}

public struct SymmetricSecureEnclaveCrypto: SecurityCrypto {
    public init() {}
    
    public func encrypt(_ data: Data, publicKey: SecKey) throws -> Data {
        return try encrypt(data, publicKey: publicKey, algorithm: .eciesEncryptionCofactorX963SHA256AESGCM)
    }
    
    public func decrypt(_ data: Data, privateKey: SecKey) throws -> Data {
        return try decrypt(data, privateKey: privateKey, algorithm: .eciesEncryptionCofactorX963SHA256AESGCM)
    }
    
    public func sign(_ data: Data, privateKey: SecKey) throws -> Data {
        return try sign(data, privateKey: privateKey, algorithm: .ecdhKeyExchangeCofactorX963SHA512)
    }
    
    public func validateSignature(_ signature: Data, data: Data, publicKey: SecKey) throws {
        try validateSignature(signature, data: data, publicKey: publicKey, algorithm: .ecdhKeyExchangeCofactorX963SHA512)
    }
}
