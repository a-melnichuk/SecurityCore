//
//  ExamplesTests.swift
//  ExamplesTests
//
//  Created by Alex Melnichuk on 7/1/19.
//  Copyright © 2019 Baltic International Group OU. All rights reserved.
//

import XCTest
import SecurityCore
@testable import Examples

class ExamplesTests: XCTestCase {

    func testExample() {
        let privateKey = SecurityKey<SecPrivateKey>(namespace: "unit_test", key: "private_key", generateKeyIfNotFound: false)
        XCTAssertNoThrow(try privateKey.delete())
        XCTAssertNoThrow(try privateKey.generateKey())
        XCTAssertNoThrow(try privateKey.read())
    }
}
