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
    ) else { return }

    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: serviceName,
        kSecAttrAccount as String: accountId,
        kSecValueData as String: "test_data".data(using: .utf8)!,
        kSecAttrAccessControl as String: access,
    ]
    SecItemDelete(query as CFDictionary)
    let status = SecItemAdd(query as CFDictionary, nil)
    print("Store: \(status)")
}

func checkExistence() {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: serviceName,
        kSecAttrAccount as String: accountId,
        kSecReturnAttributes as String: true
    ]
    var item: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &item)
    print("Check: \(status)")
}

storeKeys()
checkExistence()
