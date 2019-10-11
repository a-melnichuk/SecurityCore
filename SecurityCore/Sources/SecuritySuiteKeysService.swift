//
//  SecuritySuiteKeysService.swift
//  SecurityCore
//
//  Created by Alex Melnichuk on 10/11/19.
//  Copyright © 2019 Baltic International Group OU. All rights reserved.
//

import Foundation

struct SecuritySuiteKeysService {
    private static let securitySuiteKeysLock = NSRecursiveLock()
    private static var uniqueSecuritySuiteKeys = Set<String>()
    
    static func addKey(tagged tag: Data) {
        securitySuiteKeysLock.lock()
        defer { securitySuiteKeysLock.unlock() }
        guard let key = String(data: tag, encoding: .utf8) else {
            return
        }
        guard uniqueSecuritySuiteKeys.insert(key).inserted else {
            fatalError("Duplicate item inserted in suite: \(key)")
        }
    }
    
    static func removeKey(tagged tag: Data) {
        securitySuiteKeysLock.lock()
        defer { securitySuiteKeysLock.unlock() }
        guard let key = String(data: tag, encoding: .utf8) else {
            return
        }
        uniqueSecuritySuiteKeys.remove(key)
    }
}
