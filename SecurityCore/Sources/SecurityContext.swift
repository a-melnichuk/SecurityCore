//
//  SecurityContext.swift
//  SecurityCore
//
//  Created by Alex Melnichuk on 7/2/19.
//  Copyright © 2019 Baltic International Group OU. All rights reserved.
//

import Foundation
import LocalAuthentication

public struct SecurityContext {
    public let useOperationPrompt: String?
    public let laContext: LAContext?
    
    public init(useOperationPrompt: String?, laContext: LAContext?) {
        self.useOperationPrompt = useOperationPrompt
        self.laContext = laContext
    }
}
