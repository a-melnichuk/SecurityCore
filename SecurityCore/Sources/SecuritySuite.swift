//
//  SecuritySuite.swift
//  SecurityCore
//
//  Created by Alex Melnichuk on 7/3/19.
//  Copyright © 2019 Baltic International Group OU. All rights reserved.
//

import Foundation

public protocol SecuritySuite where Suite.RawValue == String, Keys.RawValue == String {
    associatedtype Suite: RawRepresentable
    associatedtype Keys: RawRepresentable
    
    var kind: Suite { get }
}
