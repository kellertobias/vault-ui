import Foundation
import Security
import LocalAuthentication

let serviceName = "com.vaultui.biometric.test"
let accountId = "test_account_123"

func storeKeys() {
    var error: Unmanaged<CFError>?
    guard let access = SecAccessControlCreateWithFlags(
        nil,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        .biometryCurrentSet,
        &error
    ) else {
        print("Access control failed")
        return
    }

    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: serviceName,
        kSecAttrAccount as String: accountId,
        kSecValueData as String: "test_data".data(using: .utf8)!,
        kSecAttrAccessControl as String: access,
        //kSecUseDataProtectionKeychain as String: true
    ]

    SecItemDelete(query as CFDictionary)
    let status = SecItemAdd(query as CFDictionary, nil)
    print("Store status: \(status)")
}

func hasStoredKeys() -> Int32 {
    let context = LAContext()
    context.interactionNotAllowed = true
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: serviceName,
        kSecAttrAccount as String: accountId,
        kSecUseAuthenticationContext as String: context,
        //kSecUseDataProtectionKeychain as String: true
    ]
    let status = SecItemCopyMatching(query as CFDictionary, nil)
    return status
}

storeKeys()
print("hasStoredKeys status: \(hasStoredKeys())")
