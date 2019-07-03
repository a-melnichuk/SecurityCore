//
//  PublicKeySecurityProvider.swift
//  SecurityCore
//
//  Created by Alex Melnichuk on 7/1/19.
//  Copyright © 2019 Baltic International Group OU. All rights reserved.
//

import Foundation
import LocalAuthentication

public final class PublicKeySecurityProvider: SecurityProvider {
    public typealias T = SecPublicKey
    
    private let keyProvider = KeySecurityProvider()
    
    public init() {}
    
    public func write(_ value: T,
                      forTag tag: Data,
                      context: SecurityContext?,
                      secureStorageOptions: SecureStorageAccessOptions,
                      accessControlFlags: SecAccessControlCreateFlags) throws {
        return try keyProvider.write(value.secKey,
                                     forTag: tag,
                                     context: context,
                                     secureStorageOptions: secureStorageOptions,
                                     accessControlFlags: accessControlFlags)
    }
    
    public func read(tag: Data,
                     context: SecurityContext?,
                     secureStorageOptions: SecureStorageAccessOptions,
                     accessControlFlags: SecAccessControlCreateFlags) throws -> T {
        let key = try keyProvider.read(tag: tag,
                                       context: context,
                                       secureStorageOptions: secureStorageOptions,
                                       accessControlFlags: accessControlFlags)
        return SecPublicKey(key)
    }
    
    public func delete(tag: Data) throws {
        try keyProvider.delete(tag: tag)
    }
}
