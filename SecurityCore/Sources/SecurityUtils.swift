//
//  SecurityUtils.swift
//  SecurityCore
//
//  Created by Alex Melnichuk on 7/3/19.
//  Copyright © 2019 Baltic International Group OU. All rights reserved.
//

import Foundation
import LocalAuthentication

public struct SecurityUtils {
    
    static var uniqueSecuritySuiteKeys = Set<String>()
    
    public static var biometryAvailable: Bool = {
        let authContext = LAContext()
        let biometryAvailable = authContext.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
        if #available(iOS 11.0, *) {
            switch authContext.biometryType {
            case .none:
                return false
            case .touchID, .faceID:
                return true
            @unknown default:
                return false
            }
        } else {
            return biometryAvailable
        }
    }()
    
    public static var passcodeEnabled: Bool = {
        //checks to see if devices (not apps) passcode has been set
        return LAContext().canEvaluatePolicy(.deviceOwnerAuthentication, error: nil)
    }()
    
    public static func makeTag(namespace: String, key: String) -> Data {
        var bundle = ""
        if let bundleId = Bundle.main.bundleIdentifier {
            bundle += "\(bundleId)."
        }
        return Data("\(bundle)\(namespace).\(key)".utf8)
    }
    
    private init() {}
}
