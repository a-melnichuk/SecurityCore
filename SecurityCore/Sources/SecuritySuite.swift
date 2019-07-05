//
//  SecuritySuite.swift
//  SecurityCore
//
//  Created by Alex Melnichuk on 7/3/19.
//  Copyright © 2019 Baltic International Group OU. All rights reserved.
//

import Foundation

public protocol SecuritySuiteParams where SuiteKind.RawValue == String,
                                          Keys.RawValue == String,
                                          Keys: CaseIterable {
    associatedtype SuiteKind: RawRepresentable
    associatedtype Keys: RawRepresentable
    
    var kind: SuiteKind { get }
    init()
}


public protocol SecuritySuite {
    associatedtype SuiteParams: SecuritySuiteParams
    func clear()
}

public extension SecuritySuite {
    func clear() {
        let dataProvider = DataSecurityProvider<Data>()
        let keyProvider = KeySecurityProvider()
        let suite = SuiteParams()
        SuiteParams.Keys.allCases.forEach {
            let tag = SecurityUtils.makeTag(namespace: suite.kind.rawValue, key: $0.rawValue)
            try? dataProvider.delete(tag: tag)
            try? keyProvider.delete(tag: tag)
        }
    }
}
