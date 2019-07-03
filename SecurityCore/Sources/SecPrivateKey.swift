//
//  SecPrivateKey.swift
//  SecurityCore
//
//  Created by Alex Melnichuk on 7/1/19.
//  Copyright © 2019 Baltic International Group OU. All rights reserved.
//

import Foundation

public class SecPrivateKey {
    public let secKey: SecKey
    private let crypto: SecurityCrypto

    public init(_ secKey: SecKey) {
        let biometryAvailable = SecurityUtils.biometryAvailable
        self.secKey = secKey
        self.crypto = biometryAvailable ? SymmetricSecureEnclaveCrypto() : SymmetricKeychainCrypto()
    }
    
    public func decrypt(_ data: Data) throws -> Data {
        return try crypto.decrypt(data, privateKey: secKey)
    }
    
    public func decrypt<T: SecurityConvertible>(_: T.Type, from data: Data) throws -> T {
        let secureData = try crypto.decrypt(data, privateKey: secKey)
        return try T(secureData: secureData)
    }
    
    public func sign(_ data: Data) throws -> Data {
        return try crypto.sign(data, privateKey: secKey)
    }
    
    public func sign<T: SecurityConvertible>(_ value: T) throws -> Data {
        let data = try value.convertToSecureData()
        return try crypto.sign(data, privateKey: secKey)
    }
}
