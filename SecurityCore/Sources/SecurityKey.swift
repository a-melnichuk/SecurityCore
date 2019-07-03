//
//  SecurityKey.swift
//  SecurityCore
//
//  Created by Alex Melnichuk on 7/1/19.
//  Copyright © 2019 Baltic International Group OU. All rights reserved.
//

import Foundation
import LocalAuthentication

public final class SecurityKey<T> {
    public let tag: Data
    public let lock = NSRecursiveLock()
    public let secureStorageOptions: SecureStorageAccessOptions
    public let accessControlFlags: SecAccessControlCreateFlags
    
    private let reader: ((SecurityContext?, SecureStorageAccessOptions, SecAccessControlCreateFlags) throws -> T)
    private let writer: ((T, SecurityContext?, SecureStorageAccessOptions, SecAccessControlCreateFlags) throws -> Void)
    private let deleter: (() throws -> Void)
    
    deinit {
        #if DEBUG
        print("🗑 deinit \(self)<\(T.self)>, tag: \(String(data: tag, encoding: .utf8)!)")
        #endif
    }
    
    public init<P: SecurityProvider>(provider: P,
                                     namespace: String,
                                     key: String,
                                     secureStorageOptions: SecureStorageAccessOptions = .defaultOptions,
                                     accessControlFlags: SecAccessControlCreateFlags) where P.T == T {
        let tag = makeTag(namespace: namespace, key: key)
        self.reader = {
            try provider.read(tag: tag, context: $0, secureStorageOptions: $1, accessControlFlags: $2)
        }
        self.writer = {
            try provider.write($0, forTag: tag, context: $1, secureStorageOptions: $2, accessControlFlags: $3)
        }
        self.deleter = {
            try provider.delete(tag: tag)
        }
        self.tag = tag
        self.secureStorageOptions = secureStorageOptions
        self.accessControlFlags = accessControlFlags
    }
    
    public convenience init<N: RawRepresentable, P: SecurityProvider>(
        provider: P,
        namespace: N,
        key: String,
        secureStorageOptions: SecureStorageAccessOptions = .defaultOptions,
        accessControlFlags: SecAccessControlCreateFlags) where P.T == T, N.RawValue == String {
        self.init(provider: provider,
                  namespace: namespace.rawValue,
                  key: key,
                  secureStorageOptions: secureStorageOptions,
                  accessControlFlags: accessControlFlags)
    }
    
    public func write(_ value: T, context: SecurityContext? = nil) throws {
        lock.lock()
        defer { lock.unlock() }
        try writer(value, context, secureStorageOptions, accessControlFlags)
    }
    
    public func read(context: SecurityContext? = nil) throws -> T {
        lock.lock()
        defer { lock.unlock() }
        return try reader(context, secureStorageOptions, accessControlFlags)
    }
    
    public func readIfPresent(context: SecurityContext? = nil) throws -> T? {
        do {
            return try read(context: context)
        } catch SecureStorageError.notFound {
            return nil
        }
    }
    
    public func delete() throws {
        lock.lock()
        defer { lock.unlock() }
        try deleter()
    }
}

func makeTag(namespace: String, key: String) -> Data {
    var bundle = ""
    if let bundleId = Bundle.main.bundleIdentifier {
        bundle += "\(bundleId)."
    }
    return Data("\(bundle)\(namespace).\(key)".utf8)
}
