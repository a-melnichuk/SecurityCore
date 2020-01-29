//
//  KeySecurityProvider.swift
//  SecurityCore
//
//  Created by Alex Melnichuk on 7/2/19.
//  Copyright © 2019 Baltic International Group OU. All rights reserved.
//

import Foundation

public final class KeySecurityProvider: SecurityProvider {
    
    public typealias T = SecKey
    
    public init() {
    }
    
    public func write(_ value: T,
                      forTag tag: Data,
                      context: SecurityContext?,
                      secureStorageOptions: SecureStorageAccessOptions,
                      accessControlFlags: SecAccessControlCreateFlags) throws {
        let access = SecAccessControlCreateWithFlags(nil,
                                                     secureStorageOptions.rawValue,
                                                     accessControlFlags,
                                                     nil)!
        let attributes: [String: Any?] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrAccessControl as String: access as Any,
            kSecValueRef as String: value,
            kSecUseAuthenticationContext as String: context?.laContext
        ]
        var status = SecItemAdd(attributes.cfDictionary, nil)
        if status == errSecDuplicateItem {
            let attributes: [String: Any] = [
                kSecValueRef as String: value
            ]
            let query: [String: Any?] = [
                kSecClass as String: kSecClassKey,
                kSecAttrApplicationTag as String: tag,
                kSecUseOperationPrompt as String: context?.useOperationPrompt,
                kSecUseAuthenticationContext as String: context?.laContext
            ]
            status = SecItemUpdate(query.cfDictionary, attributes as CFDictionary)
        }
        guard status == errSecSuccess else {
            throw SecureStorageError(status: status)
        }
    }
    
    public func read(tag: Data,
                     context: SecurityContext?,
                     secureStorageOptions: SecureStorageAccessOptions,
                     accessControlFlags: SecAccessControlCreateFlags) throws -> T {
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
        return item as! SecKey
    }
    
    public func generateKey() throws -> SecKey {
        throw SecureStorageError.unableToCreateKey
    }
    
    public func delete(tag: Data) throws {
        let attributes: [String: Any?] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag
        ]
        let status = SecItemDelete(attributes.cfDictionary as CFDictionary)
        #if DEBUG
        print("deletion status - \(status) for tag: \(String(data: tag, encoding: .utf8)!)")
        #endif
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw SecureStorageError.invalidStatus(status)
        }
    }
}
