//
//  PrivateKeySecurityProvider.swift
//  SecurityCore
//
//  Created by Alex Melnichuk on 7/1/19.
//  Copyright © 2019 Baltic International Group OU. All rights reserved.
//

import Foundation
import LocalAuthentication

public final class PrivateKeySecurityProvider: SecurityProvider {
    public typealias T = SecPrivateKey
    
    public let tag: Data
    public let generateKeyIfNotFound: Bool
    public let secureStorageOptions: SecureStorageAccessOptions
    public let accessControlFlags: SecAccessControlCreateFlags
    
    private let secureEnclaveIsAvailable = SecurityUtils.biometryAvailable
    private let keyProvider = KeySecurityProvider()
    
    public init(tag: Data,
                secureStorageOptions: SecureStorageAccessOptions,
                accessControlFlags: SecAccessControlCreateFlags,
                generateKeyIfNotFound: Bool) {
        self.tag = tag
        self.secureStorageOptions = secureStorageOptions
        self.accessControlFlags = accessControlFlags
        self.generateKeyIfNotFound = generateKeyIfNotFound
    }
    
    public func write(_ value: T,
                      forTag tag: Data,
                      context: SecurityContext?,
                      secureStorageOptions: SecureStorageAccessOptions,
                      accessControlFlags: SecAccessControlCreateFlags) throws {
        if secureEnclaveIsAvailable {
            throw SecureStorageError.cannotWriteToSecureEnclave
        }
        try keyProvider.write(value.secKey,
                              forTag: tag,
                              context: context,
                              secureStorageOptions: secureStorageOptions,
                              accessControlFlags: accessControlFlags)
    }
    
    public func read(tag: Data,
                     context: SecurityContext?,
                     secureStorageOptions: SecureStorageAccessOptions,
                     accessControlFlags: SecAccessControlCreateFlags) throws -> T {
        do {
            let query: [String: Any?] = [
                kSecClass as String: kSecClassKey,
                kSecMatchLimit as String: kSecMatchLimitOne,
                kSecAttrApplicationTag as String: tag,
                kSecReturnRef as String: true,
                kSecUseOperationPrompt as String: context?.useOperationPrompt,
                kSecUseAuthenticationContext as String: context?.laContext
            ]
            var item: CFTypeRef?
            let status = SecItemCopyMatching(query.cfDictionary, &item)
            guard status == errSecSuccess else {
                throw SecureStorageError(status: status)
            }
            return SecPrivateKey(item as! SecKey)
        } catch SecureStorageError.notFound where generateKeyIfNotFound {
            return SecPrivateKey(try generateKey())
        }
    }
    
    public func generateKey() throws -> SecKey {
        let access = SecAccessControlCreateWithFlags(
            nil,
            secureStorageOptions.rawValue,
            accessControlFlags,
            nil)!
        var attributes: [String: Any] = [
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String:      true,
                kSecAttrApplicationTag as String:   tag,
                kSecAttrAccessControl as String:    access,
            ]
        ]
        if secureEnclaveIsAvailable {
            // Secure enclave stores only 256-bit elliptic curve private keys.
            attributes[kSecAttrKeyType as String] = kSecAttrKeyTypeEC
            attributes[kSecAttrKeySizeInBits as String] = 256
            attributes[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave
        } else {
            attributes[kSecAttrKeyType as String] = kSecAttrKeyTypeRSA
            attributes[kSecAttrKeySizeInBits as String] = 2048
        }
        var error: Unmanaged<CFError>? = nil
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            let cfError = error!.takeRetainedValue()
            #if DEBUG
            print("key generation cfError: \(cfError)")
            #endif
            throw SecureStorageError.securityError(cfError as Error)
        }
        return privateKey
    }
    
    public func delete(tag: Data) throws {
        try keyProvider.delete(tag: tag)
    }
}
