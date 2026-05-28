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
        } else if action == "updateAutoFillFormContext" {
            guard let urlString = message?["url"] as? String,
                  let name = message?["name"] as? String else {
                Self.sendResponse(["success": false, "error": "Missing form context data"], context: context)
                return
            }

            SharedCredentialStore.shared.storeAutoFillFormContext(
                AutoFillFormContext(
                    url: urlString,
                    name: name,
                    username: message?["username"] as? String,
                    password: message?["password"] as? String
                )
            )
            Self.sendResponse(["success": true], context: context)
        } else if action == "queueTemporaryCredentialDraft" {
            guard let urlString = message?["url"] as? String,
                  let username = message?["username"] as? String,
                  let name = message?["name"] as? String else {
                Self.sendResponse(["success": false, "error": "Missing temporary draft data"], context: context)
                return
            }

            SharedCredentialStore.shared.queueTemporaryCredentialDraft(
                TemporaryCredentialDraft(
                    name: name,
                    username: username,
                    url: urlString
                )
            )
            Self.sendResponse(["success": true], context: context)
        } else if action == "promoteTemporaryCredential" {
            guard let urlString = message?["url"] as? String,
                  let username = message?["username"] as? String,
                  let password = message?["password"] as? String else {
                Self.sendResponse(["success": false, "error": "Missing promotion data"], context: context)
                return
            }

            guard Self.hasTemporaryCredential(url: urlString, username: username) else {
                Self.sendResponse(["success": false, "error": "No matching temporary credential"], context: context)
                return
            }

            let name = (message?["name"] as? String)
                ?? URL(string: urlString)?.host
                ?? Self.extractBaseDomain(from: urlString)

            SharedCredentialStore.shared.queuePendingCredential(PendingCredential(
                name: name,
                username: username,
                password: password,
                url: urlString
            ))
            SharedCredentialStore.shared.removeTemporaryCredentialDraft(url: urlString, username: username)
            Self.sendResponse(["success": true], context: context)
        } else if action == "saveCredential" {
            guard let urlString = message?["url"] as? String,
                  let username = message?["username"] as? String,
                  let password = message?["password"] as? String else {
                Self.sendResponse(["success": false, "error": "Missing credential data"], context: context)
                return
            }

            let name = (message?["name"] as? String)
                ?? URL(string: urlString)?.host
                ?? Self.extractBaseDomain(from: urlString)

            SharedCredentialStore.shared.queuePendingCredential(PendingCredential(
                name: name,
                username: username,
                password: password,
                url: urlString
            ))
            SharedCredentialStore.shared.removeTemporaryCredentialDraft(url: urlString, username: username)
            Self.sendResponse(["success": true], context: context)
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

    private static func hasTemporaryCredential(url urlString: String, username: String) -> Bool {
        let fullDomain = extractFullDomain(from: urlString)
        return SharedCredentialStore.shared.fetchCredentials().contains { entry in
            guard entry.isTemporaryCredential, entry.username == username else { return false }
            return entry.uris.contains { extractFullDomain(from: $0) == fullDomain }
        }
    }
    
    private static func checkSubdomains(for urlString: String, context: NSExtensionContext) {
        let baseDomain = extractBaseDomain(from: urlString)
        let fullDomain = extractFullDomain(from: urlString)
        let sharedStore = SharedCredentialStore()
        let credentials = sharedStore.fetchCredentials()
        
        var uniqueSubdomains = Set<String>()
        var matchCount = 0
        var exactMatches: [SharedCredentialEntry] = []
        
        for entry in credentials {
            var matchedBase = false
            var matchedExact = false
            for uri in entry.uris {
                let cleanUri = extractFullDomain(from: uri)
                if cleanUri.hasSuffix(baseDomain) {
                    uniqueSubdomains.insert(cleanUri)
                    matchedBase = true
                }
                if cleanUri == fullDomain {
                    matchedExact = true
                }
            }
            if matchedBase {
                matchCount += 1
            }
            if matchedExact {
                exactMatches.append(entry)
            }
        }
        
        let hasMultiple = uniqueSubdomains.count > 1
        var response: [String: Any] = [
            "hasMultipleSubdomains": hasMultiple, 
            "totalMatches": matchCount,
            "exactMatchCount": exactMatches.count
        ]
        
        if exactMatches.count == 1, let username = exactMatches.first?.username {
            response["singleUsername"] = username
        }
        
        sendResponse(response, context: context)
    }

    private static func sendResponse(_ response: [String: Any], context: NSExtensionContext) {
        let responseItem = NSExtensionItem()
        responseItem.userInfo = [ SFExtensionMessageKey: response ]
        context.completeRequest(returningItems: [responseItem], completionHandler: nil)
    }

}
