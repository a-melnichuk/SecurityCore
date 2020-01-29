//
//  SecPublicKey.swift
//  SecurityCore
//
//  Created by Alex Melnichuk on 7/1/19.
//  Copyright © 2019 Baltic International Group OU. All rights reserved.
//

import Foundation

public class SecPublicKey {
    public let secKey: SecKey
    private let crypto: SecurityCrypto
    
    public init(_ secKey: SecKey) {
        let biometryAvailable = SecurityUtils.biometryAvailable
        self.secKey = secKey
        self.crypto = biometryAvailable ? SymmetricSecureEnclaveCrypto() : SymmetricKeychainCrypto()
    }
    
    public convenience init(privateKey: SecPrivateKey) throws {
        guard let publicKey = SecKeyCopyPublicKey(privateKey.secKey) else {
            throw SecureStorageError.unableToCreateKey
        }
        self.init(publicKey)
    }
    
    public func encrypt(_ data: Data) throws -> Data {
        return try crypto.encrypt(data, publicKey: secKey)
    }
    
    public func encrypt(_ data: SecurityConvertible) throws -> Data {
        let data = try data.convertToSecureData()
        return try crypto.encrypt(data, publicKey: secKey)
    }
    
    public func validateSignature(_ signature: Data, data: Data) throws {
        try crypto.validateSignature(signature, data: data, publicKey: secKey)
    }
    
    public func validateSignature<T: SecurityConvertible>(_ signature: Data, for value: T) throws {
        let data = try value.convertToSecureData()
        try crypto.validateSignature(signature, data: data, publicKey: secKey)
    }
}
