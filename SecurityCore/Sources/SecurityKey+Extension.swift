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
    
    convenience init<S: SecuritySuite>(
        _ suite: S,
        key: S.Keys,
        secureStorageOptions: SecureStorageAccessOptions = .defaultOptions,
        accessControlFlags: SecAccessControlCreateFlags = []) {
        guard SecurityUtils.uniqueSecuritySuiteKeys.insert(suite.kind.rawValue + key.rawValue).inserted else {
            fatalError("Duplicate item inserted in suite \(S.self) \(suite.kind) for key \(key)")
        }
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
        let tag = makeTag(namespace: namespace, key: key)
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
    
    convenience init<S: SecuritySuite>(
        _ suite: S,
        key: S.Keys,
        generateKeyIfNotFound: Bool = false,
        secureStorageOptions: SecureStorageAccessOptions = .defaultOptions,
        accessControlFlags: SecAccessControlCreateFlags = .privateKeyFlags) {
        guard SecurityUtils.uniqueSecuritySuiteKeys.insert(suite.kind.rawValue + key.rawValue).inserted else {
            fatalError("Duplicate item inserted in suite \(S.self) \(suite.kind) for key \(key)")
        }
        self.init(namespace: suite.kind.rawValue,
                  key: key.rawValue,
                  generateKeyIfNotFound: generateKeyIfNotFound,
                  secureStorageOptions: secureStorageOptions,
                  accessControlFlags: accessControlFlags)
    }

    func generateKey(context: SecurityContext? = nil) throws -> T {
        do {
            return try self.read(context: context)
        } catch SecureStorageError.notFound {
            lock.lock()
            defer { lock.unlock() }
            let provider = PrivateKeySecurityProvider(tag: tag,
                                                      secureStorageOptions: secureStorageOptions,
                                                      accessControlFlags: accessControlFlags,
                                                      generateKeyIfNotFound: false)
            return SecPrivateKey(try provider.generateKey())
        }
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
    
    convenience init<S: SecuritySuite>(
        _ suite: S,
        key: S.Keys,
        secureStorageOptions: SecureStorageAccessOptions = .defaultOptions,
        accessControlFlags: SecAccessControlCreateFlags = .passcodeOrBiometry) {
        guard SecurityUtils.uniqueSecuritySuiteKeys.insert(suite.kind.rawValue + key.rawValue).inserted else {
            fatalError("Duplicate item inserted in suite \(S.self) \(suite.kind) for key \(key)")
        }
        self.init(namespace: suite.kind.rawValue,
                  key: key.rawValue,
                  secureStorageOptions: secureStorageOptions,
                  accessControlFlags: accessControlFlags)
    }
}
