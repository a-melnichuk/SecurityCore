//
//  SecureStorageService.swift
//  SecurityTest
//
//  Created by Alex Melnichuk on 4/30/19.
//  Copyright © 2019 Alex Melnichuk. All rights reserved.
//

import Foundation
import LocalAuthentication

public extension SecAccessControlCreateFlags {
    
    static var privateKeyFlags: SecAccessControlCreateFlags {
        if SecurityUtils.biometryAvailable {
            return .privateKeyUsage
        } else {
            return []
        }
    }
    
    static var passcodeOrBiometry: SecAccessControlCreateFlags {
        if #available(iOS 11.3, *) {
            return .userPresence
        }
        if SecurityUtils.biometryAvailable {
            return [.devicePasscode, .or, .touchIDAny]
        }
        return .devicePasscode
    }
}

public enum SecureStorageError: Error {
    case securityError(Error)
    case invalidStatus(OSStatus)
    case unableToCreatePublicKey
    case invalidAttributes(String)
    case notFound
    case encoding
    case cannotWriteToSecureEnclave
    case canceled
    case duplicateItem
    case passcodeDisabled
    case signatureFailed(Error)
    case signatureInvalid(Error)
    
    public var localizedDescription: String {
        if #available(iOS 11.3, *) {
            switch self {
            case .invalidStatus(let status):
                return SecCopyErrorMessageString(status, nil) as String? ?? "Unknown error."
            default:
                break
            }
        }
        return "\(self)"
    }
    
    public init(status: OSStatus) {
        switch status {
        case errSecDuplicateItem:
            self = .duplicateItem
        case errSecUserCanceled:
            self = .canceled
        case errSecItemNotFound:
            self = .notFound
        case errSecAuthFailed where !SecurityUtils.passcodeEnabled:
            self = .passcodeDisabled
        default:
            self = .invalidStatus(status)
        }
    }
}

public enum SecureStorageClass: RawRepresentable {
    public typealias RawValue = CFString
    
    case genericPassword
    case internetPassword
    case certificate
    case key
    case identity
    
    public var rawValue: CFString {
        switch self {
        case .genericPassword:
            return kSecClassGenericPassword
        case .internetPassword:
            return kSecClassInternetPassword
        case .certificate:
            return kSecClassCertificate
        case .key:
            return kSecClassKey
        case .identity:
            return kSecClassIdentity
        }
    }
    
    public init?(rawValue: CFString) {
        switch rawValue {
        case kSecClassGenericPassword:
            self = .genericPassword
        case kSecClassInternetPassword:
            self = .internetPassword
        case kSecClassCertificate:
            self = .certificate
        case kSecClassKey:
            self = .key
        case kSecClassIdentity:
            self = .identity
        default:
            return nil
        }
    }
}

public enum SecureStorageAccessOptions: RawRepresentable {
    public typealias RawValue = CFString
    
    public static var defaultOptions: SecureStorageAccessOptions {
        return unlockedDeviceOnly
    }
    
    case unlockedDeviceOnly
    case unlocked
    case passcodeSetDeviceOnly
    case afterFirstUnlockDeviceOnly
    case afterFirstUnlock
    case alwaysDeviceOnly
    case always
    
    public var rawValue: CFString {
        switch self {
        case .unlockedDeviceOnly:
            return kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        case .unlocked:
            return kSecAttrAccessibleWhenUnlocked
        case .passcodeSetDeviceOnly:
            return kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
        case .afterFirstUnlockDeviceOnly:
            return kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        case .afterFirstUnlock:
            return kSecAttrAccessibleAfterFirstUnlock
        case .alwaysDeviceOnly:
            return kSecAttrAccessibleAlwaysThisDeviceOnly
        case .always:
            return kSecAttrAccessibleAlways
        }
    }
    
    public init?(rawValue: CFString) {
        switch rawValue {
        case kSecAttrAccessibleWhenUnlockedThisDeviceOnly:
            self = .unlockedDeviceOnly
        case kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly:
            self = .passcodeSetDeviceOnly
        case kSecAttrAccessibleWhenUnlocked:
            self = .unlocked
        case kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly:
            self = .afterFirstUnlockDeviceOnly
        case kSecAttrAccessibleAfterFirstUnlock:
            self = .afterFirstUnlock
        case kSecAttrAccessibleAlwaysThisDeviceOnly:
            self = .alwaysDeviceOnly
        case kSecAttrAccessibleAlways:
            self = .always
        default:
            return nil
        }
    }
}


