//
//  Dictionary+Extension.swift
//  SecurityCore
//
//  Created by Alex Melnichuk on 7/3/19.
//  Copyright © 2019 Baltic International Group OU. All rights reserved.
//

import Foundation

extension Dictionary where Key == String, Value == Any? {
    var cfDictionary: CFDictionary {
        return self.compactMapValues { $0 } as CFDictionary
    }
}
