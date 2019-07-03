//
//  SecurityProvider.swift
//  SecurityTest
//
//  Created by Vitalii Havryliuk on 5/31/19.
//  Copyright © 2019 Alex Melnichuk. All rights reserved.
//

import Foundation
import LocalAuthentication

public protocol SecurityProvider {
    associatedtype T
    func write(_ value: T,
               forTag tag: Data,
               context: SecurityContext?,
               secureStorageOptions: SecureStorageAccessOptions,
               accessControlFlags: SecAccessControlCreateFlags) throws
    func read(tag: Data,
              context: SecurityContext?,
              secureStorageOptions: SecureStorageAccessOptions,
              accessControlFlags: SecAccessControlCreateFlags) throws -> T
    func delete(tag: Data) throws 
}
