//
//  SecurityKey+Extension.swift
//  SecurityCore
//
//  Created by Alex Melnichuk on 7/1/19.
//  Copyright © 2019 Baltic International Group OU. All rights reserved.
//

import Foundation

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
    
    convenience init<N: RawRepresentable>(
        namespace: N,
        key: String,
        secureStorageOptions: SecureStorageAccessOptions = .defaultOptions,
        accessControlFlags: SecAccessControlCreateFlags = []) where N.RawValue == String {
        self.init(namespace: namespace.rawValue,
                  key: key,
                  secureStorageOptions: secureStorageOptions,
                  accessControlFlags: accessControlFlags)
    }
}

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
    
    convenience init<N: RawRepresentable>(
        namespace: N,
        key: String,
        secureStorageOptions: SecureStorageAccessOptions = .defaultOptions,
        accessControlFlags: SecAccessControlCreateFlags = .privateKeyFlags) where N.RawValue == String {
        self.init(namespace: namespace.rawValue,
                  key: key,
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
    
    convenience init<N: RawRepresentable>(
        namespace: N,
        key: String,
        secureStorageOptions: SecureStorageAccessOptions = .defaultOptions,
        accessControlFlags: SecAccessControlCreateFlags = .passcodeOrBiometry) where N.RawValue == String {
        self.init(namespace: namespace.rawValue,
                  key: key,
                  secureStorageOptions: secureStorageOptions,
                  accessControlFlags: accessControlFlags)
    }
}
