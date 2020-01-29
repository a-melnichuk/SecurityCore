//
//  SecurityKey+Extension.swift
//  SecurityCore
//
//  Created by Alex Melnichuk on 7/1/19.
//  Copyright © 2019 Baltic International Group OU. All rights reserved.
//

import Foundation

// MARK: - SecurityKey+SecurityConvertible

public extension SecurityKey where T: SecurityConvertible  {
    convenience init(namespace: String,
                     key: String,
                     secureStorageOptions: SecureStorageAccessOptions = .defaultOptions,
                     accessControlFlags: SecAccessControlCreateFlags = []) {
        self.init(provider: DataSecurityProvider<T>(),
                  namespace: namespace,
                  key: key,
                  secureStorageOptions: secureStorageOptions,
                  accessControlFlags: accessControlFlags)
    }
    
    convenience init<S: SecuritySuiteParams>(
        _ suite: S,
        key: S.Keys,
        secureStorageOptions: SecureStorageAccessOptions = .defaultOptions,
        accessControlFlags: SecAccessControlCreateFlags = []) {
        self.init(namespace: suite.kind.rawValue,
                  key: key.rawValue,
                  secureStorageOptions: secureStorageOptions,
                  accessControlFlags: accessControlFlags)
    }
}

// MARK: - SecurityKey+SecPrivateKey

public extension SecurityKey where T == SecPrivateKey {
    convenience init(namespace: String,
                     key: String,
                     generateKeyIfNotFound: Bool = false,
                     secureStorageOptions: SecureStorageAccessOptions = .defaultOptions,
                     accessControlFlags: SecAccessControlCreateFlags = .privateKeyFlags) {
        let tag = SecurityUtils.makeTag(namespace: namespace, key: key)
        let provider = PrivateKeySecurityProvider(tag: tag,
                                                  secureStorageOptions: secureStorageOptions,
                                                  accessControlFlags: accessControlFlags,
                                                  generateKeyIfNotFound: generateKeyIfNotFound)
        self.init(provider: provider,
                  namespace: namespace,
                  key: key,
                  secureStorageOptions: secureStorageOptions,
                  accessControlFlags: accessControlFlags)
    }
    
    convenience init<S: SecuritySuiteParams>(
        _ suite: S,
        key: S.Keys,
        generateKeyIfNotFound: Bool = false,
        secureStorageOptions: SecureStorageAccessOptions = .defaultOptions,
        accessControlFlags: SecAccessControlCreateFlags = .privateKeyFlags) {
        self.init(namespace: suite.kind.rawValue,
                  key: key.rawValue,
                  generateKeyIfNotFound: generateKeyIfNotFound,
                  secureStorageOptions: secureStorageOptions,
                  accessControlFlags: accessControlFlags)
    }

    func generateKey(context: SecurityContext? = nil) throws -> T {
        return try self.generateKey()
    }
}

// MARK: - SecurityKey+SecPublicKey

public extension SecurityKey where T == SecPublicKey {
    convenience init(namespace: String,
                     key: String,
                     secureStorageOptions: SecureStorageAccessOptions = .defaultOptions,
                     accessControlFlags: SecAccessControlCreateFlags = .passcodeOrBiometry) {
        self.init(provider: PublicKeySecurityProvider(),
                  namespace: namespace,
                  key: key,
                  secureStorageOptions: secureStorageOptions,
                  accessControlFlags: accessControlFlags)
        
    }
    
    convenience init<S: SecuritySuiteParams>(
        _ suite: S,
        key: S.Keys,
        secureStorageOptions: SecureStorageAccessOptions = .defaultOptions,
        accessControlFlags: SecAccessControlCreateFlags = .passcodeOrBiometry) {
        self.init(namespace: suite.kind.rawValue,
                  key: key.rawValue,
                  secureStorageOptions: secureStorageOptions,
                  accessControlFlags: accessControlFlags)
    }
}
