import SafariServices
import os.log
import VaultModels
import VaultServices

class SafariWebExtensionHandler: NSObject, NSExtensionRequestHandling {

    private var context: NSExtensionContext?

    func beginRequest(with context: NSExtensionContext) {
        let item = context.inputItems[0] as! NSExtensionItem
        let message = item.userInfo?[SFExtensionMessageKey] as? [String: Any]
        
        self.context = context
        
        os_log(.default, "Received message from browser.runtime.sendNativeMessage: %{public}@", String(describing: message))
        
        guard let action = message?["action"] as? String else {
            Self.sendResponse(["error": "No action specified"], context: context)
            return
        }
        
        if action == "checkSubdomains" {
            guard let urlString = message?["url"] as? String else {
                Self.sendResponse(["error": "No URL provided"], context: context)
                return
            }
            Self.checkSubdomains(for: urlString, context: context)
        } else if action == "showNativePicker" {
            guard let urlString = message?["url"] as? String else {
                Self.sendResponse(["error": "No URL provided"], context: context)
                return
            }
            Self.triggerNativePicker(for: urlString, context: context)
        } else {
            Self.sendResponse(["error": "Unknown action"], context: context)
        }
    }
    
    private static func extractBaseDomain(from urlString: String) -> String {
        let clean = urlString.lowercased().replacingOccurrences(of: "https://", with: "").replacingOccurrences(of: "http://", with: "")
        let host = clean.components(separatedBy: "/").first ?? clean
        // Simple eTLD+1 approximation: get last two parts if not IP
        let parts = host.components(separatedBy: ".")
        if parts.count > 2 {
            // Check if it's an IP
            if Int(parts.last!) != nil { return host }
            // For simple domains like tokenet.de, return last two
            return parts.suffix(2).joined(separator: ".")
        }
        return host
    }
    
    private static func extractFullDomain(from urlString: String) -> String {
        let clean = urlString.lowercased().replacingOccurrences(of: "https://", with: "").replacingOccurrences(of: "http://", with: "")
        return clean.components(separatedBy: "/").first ?? clean
    }
    
    private static func checkSubdomains(for urlString: String, context: NSExtensionContext) {
        let baseDomain = extractBaseDomain(from: urlString)
        let sharedStore = SharedCredentialStore()
        let credentials = sharedStore.fetchCredentials()
        
        var uniqueSubdomains = Set<String>()
        var matchCount = 0
        
        for entry in credentials {
            var matchedBase = false
            for uri in entry.uris {
                let cleanUri = extractFullDomain(from: uri)
                if cleanUri.hasSuffix(baseDomain) {
                    uniqueSubdomains.insert(cleanUri)
                    matchedBase = true
                }
            }
            if matchedBase {
                matchCount += 1
            }
        }
        
        let hasMultiple = uniqueSubdomains.count > 1
        sendResponse(["hasMultipleSubdomains": hasMultiple, "totalMatches": matchCount], context: context)
    }

    private static func triggerNativePicker(for urlString: String, context: NSExtensionContext) {
        let requestId = UUID().uuidString
        let sharedDefaults = UserDefaults(suiteName: "group.de.tobisk.apps.vaultui")
        
        // Write the request to shared defaults
        sharedDefaults?.set(["id": requestId, "url": urlString], forKey: "VaultUIPickerRequest")
        
        // Post notification to wake up the main app
        DistributedNotificationCenter.default().postNotificationName(NSNotification.Name("de.tobisk.apps.vaultui.ShowPicker"), object: nil, userInfo: nil, deliverImmediately: true)
        
        // Poll for the response
        DispatchQueue.global().async {
            var timeout = 600 // 60 seconds (600 * 100ms)
            while timeout > 0 {
                if let response = sharedDefaults?.dictionary(forKey: "VaultUIPickerResponse-\(requestId)") {
                    // We found the response!
                    sharedDefaults?.removeObject(forKey: "VaultUIPickerResponse-\(requestId)")
                    
                    let sharedStore = SharedCredentialStore()
                    if let entryId = response["id"] as? String,
                       let name = response["name"] as? String {
                        
                        var dict: [String: Any] = [
                            "id": entryId,
                            "name": name,
                            "username": response["username"] as? String ?? ""
                        ]
                        
                        if let password = sharedStore.fetchPassword(id: entryId) {
                            dict["password"] = password
                        }
                        if let totp = sharedStore.fetchTotp(id: entryId) {
                            dict["totp"] = totp
                        }
                        
                        sendResponse(["credentials": [dict]], context: context)
                        return
                    }
                }
                
                if let cancel = sharedDefaults?.string(forKey: "VaultUIPickerCancel-\(requestId)") {
                    sharedDefaults?.removeObject(forKey: "VaultUIPickerCancel-\(requestId)")
                    sendResponse(["error": "User cancelled"], context: context)
                    return
                }
                
                Thread.sleep(forTimeInterval: 0.1)
                timeout -= 1
            }
            
            // Timeout
            sendResponse(["error": "Request timed out"], context: context)
        }
    }

    private static func sendResponse(_ response: [String: Any], context: NSExtensionContext) {
        let responseItem = NSExtensionItem()
        responseItem.userInfo = [ SFExtensionMessageKey: response ]
        context.completeRequest(returningItems: [responseItem], completionHandler: nil)
    }

}
