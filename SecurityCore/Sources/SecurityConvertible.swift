//
//  SecurityConvertible.swift
//  SecurityTest
//
//  Created by Vitalii Havryliuk on 6/28/19.
//  Copyright © 2019 Alex Melnichuk. All rights reserved.
//

import Foundation

public protocol SecurityConvertible {
    init(secureData: Data) throws
    func convertToSecureData() throws -> Data
}

extension SecurityConvertible where Self: Codable {
    public init(secureData: Data) throws {
        self = try JSONDecoder().decode(Self.self, from: secureData)
    }
    
    public func convertToSecureData() throws -> Data {
        return try JSONEncoder().encode(self)
    }
}

extension String: SecurityConvertible {
    public init(secureData: Data) throws {
        guard let string = String(data: secureData, encoding: .utf8) else {
            throw NSError(domain: "Encoding failed", code: -1, userInfo: [:])
        }
        self = string
    }
    
    public func convertToSecureData() throws -> Data {
        return Data(self.utf8)
    }
}

extension Bool: SecurityConvertible {
    public init(secureData: Data) throws {
        self = secureData.first == 1
    }
    
    public func convertToSecureData() throws -> Data {
        return Data(repeating: self ? 1 : 0, count: 1)
    }
}

extension Data: SecurityConvertible {
    public init(secureData: Data) throws {
        self = secureData
    }
    
    public func convertToSecureData() throws -> Data {
        return self
    }
}
