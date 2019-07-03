//
//  DataSecurityProvider.swift
//  SecurityCore
//
//  Created by Alex Melnichuk on 7/1/19.
//  Copyright © 2019 Baltic International Group OU. All rights reserved.
//

import Foundation
import LocalAuthentication

public final class DataSecurityProvider<T: SecurityConvertible>: SecurityProvider {

    public init() {}
    
    public func write(_ value: T,
                      forTag tag: Data,
                      context: SecurityContext?,
                      secureStorageOptions: SecureStorageAccessOptions,
                      accessControlFlags: SecAccessControlCreateFlags) throws {
        let data = try value.convertToSecureData()
        let access = SecAccessControlCreateWithFlags(nil,
                                                     secureStorageOptions.rawValue,
                                                     accessControlFlags,
                                                     nil)!
        let attributes: [String: Any?] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: tag,
            kSecAttrAccessControl as String: access,
            kSecValueData as String: data,
            kSecUseAuthenticationContext as String: context?.laContext
        ]
        var status = SecItemAdd(attributes.cfDictionary, nil)
        if status == errSecDuplicateItem {
            let attributes: [String: Any] = [
                kSecValueData as String: data
            ]
            let query: [String: Any?] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrAccount as String: tag,
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
            kSecClass as String: kSecClassGenericPassword,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecAttrAccount as String: tag,
            kSecReturnData as String: true,
            kSecUseOperationPrompt as String: context?.useOperationPrompt,
            kSecUseAuthenticationContext as String: context?.laContext
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query.cfDictionary, &item)
        guard let data = item as? Data, status == errSecSuccess else {
            throw SecureStorageError(status: status)
        }
        return try T(secureData: data)
    }
    
    public func delete(tag: Data) throws {
        let attributes: [String: Any?] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: tag
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
