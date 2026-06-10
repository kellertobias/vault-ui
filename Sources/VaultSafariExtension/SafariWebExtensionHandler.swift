import SafariServices
import os.log
import LocalAuthentication
import VaultModels
import VaultServices
import VaultCrypto

class SafariWebExtensionHandler: NSObject, NSExtensionRequestHandling {

    private var context: NSExtensionContext?

    func beginRequest(with context: NSExtensionContext) {
        let item = context.inputItems[0] as! NSExtensionItem
        let message = item.userInfo?[SFExtensionMessageKey] as? [String: Any]
        
        self.context = context
        
        guard let action = message?["action"] as? String else {
            Self.sendResponse(["error": "No action specified"], context: context)
            return
        }

        os_log("Received Safari extension action: %{public}@", log: .default, type: .debug, action)
        
        if action == "checkSubdomains" {
            guard let urlString = message?["url"] as? String else {
                Self.sendResponse(["error": "No URL provided"], context: context)
                return
            }
            Self.checkSubdomains(for: urlString, context: context)
        } else if action == "getCertificateFill" {
            guard let urlString = message?["url"] as? String else {
                Self.sendResponse(["success": false, "error": "No URL provided"], context: context)
                return
            }
            Self.getCertificateFill(for: urlString, context: context)
        } else if action == "getPendingCredentialFill" {
            guard let urlString = message?["url"] as? String else {
                Self.sendResponse(["success": false, "error": "No URL provided"], context: context)
                return
            }
            Self.getPendingCredentialFill(for: urlString, context: context)
        } else if action == "clearPendingCredentialFill" {
            SharedCredentialStore.shared.clearAutoFillCredentialFillRequest()
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
    
    private static func hasTemporaryCredential(url urlString: String, username: String) -> Bool {
        return SharedCredentialStore.shared.fetchCredentials().contains { entry in
            guard entry.isTemporaryCredential, entry.username == username else { return false }
            return entry.uris.contains { CredentialMatcher.matches(storedURI: $0, siteIdentifier: urlString) }
        }
    }

    private static func getPendingCredentialFill(for urlString: String, context: NSExtensionContext) {
        guard let request = SharedCredentialStore.shared.fetchRecentAutoFillCredentialFillRequest() else {
            sendResponse(["success": true, "hasCredential": false], context: context)
            return
        }

        guard CredentialMatcher.matches(storedURI: request.url, siteIdentifier: urlString) else {
            sendResponse(["success": true, "hasCredential": false], context: context)
            return
        }

        sendResponse([
            "success": true,
            "hasCredential": true,
            "username": request.username,
            "password": request.password,
            "name": request.name,
            "url": request.url
        ], context: context)
    }

    private static func getCertificateFill(for urlString: String, context: NSExtensionContext) {
        let sharedStore = SharedCredentialStore.shared

        guard let entry = sharedStore.fetchCredentials().first(where: { entry in
            guard entry.supportsCertificateFill else { return false }
            return entry.uris.contains { CredentialMatcher.matches(storedURI: $0, siteIdentifier: urlString) }
        }) else {
            sendResponse(["success": true, "hasCertificate": false], context: context)
            return
        }

        // The certificate (P12 bytes + password) is encrypted at rest. Decrypt it only
        // after the user authenticates; the vault key is released by the Secure Enclave
        // userPresence gate, so nothing leaks without an explicit Touch ID / passcode.
        let laContext = LAContext()
        laContext.touchIDAuthenticationAllowableReuseDuration = 10
        var policyError: NSError?
        guard laContext.canEvaluatePolicy(.deviceOwnerAuthentication, error: &policyError) else {
            sendResponse(["success": true, "hasCertificate": false], context: context)
            return
        }

        laContext.evaluatePolicy(
            .deviceOwnerAuthentication,
            localizedReason: "Authenticate to fill the certificate for \(entry.name)"
        ) { success, _ in
            guard success,
                  let vaultKey = sharedStore.retrieveAutoFillVaultKey(context: laContext),
                  let certificate = sharedStore.fetchCertificate(id: entry.id, key: vaultKey) else {
                sendResponse(["success": true, "hasCertificate": false], context: context)
                return
            }

            var response: [String: Any] = [
                "success": true,
                "hasCertificate": true,
                "id": entry.id,
                "name": entry.name,
                "fileName": certificate.fileName,
                "dataBase64": certificate.dataBase64,
                "password": certificate.password
            ]
            if let expiresAt = certificate.expiresAt {
                response["expiresAt"] = CertificateMetadata.string(from: expiresAt)
            }

            sendResponse(response, context: context)
        }
    }
    
    private static func checkSubdomains(for urlString: String, context: NSExtensionContext) {
        let siteHost = CredentialMatcher.deconstruct(urlString).host
        let sharedStore = SharedCredentialStore()
        let credentials = sharedStore.fetchCredentials()

        var uniqueSubdomains = Set<String>()
        var matchCount = 0
        var matchingEntries: [SharedCredentialEntry] = []
        var exactMatches: [SharedCredentialEntry] = []

        for entry in credentials {
            var matchedBase = false
            var matchedExact = false
            for uri in entry.uris {
                // Boundary-aware match (domain/subdomain + protocol + path),
                // replacing the previous unbounded `hasSuffix` compare.
                if CredentialMatcher.matches(storedURI: uri, siteIdentifier: urlString) {
                    uniqueSubdomains.insert(CredentialMatcher.deconstruct(uri).host)
                    matchedBase = true
                }
                if !siteHost.isEmpty, CredentialMatcher.deconstruct(uri).host == siteHost {
                    matchedExact = true
                }
            }
            if matchedBase {
                matchCount += 1
                matchingEntries.append(entry)
            }
            if matchedExact {
                exactMatches.append(entry)
            }
        }

        let hasMultiple = uniqueSubdomains.count > 1
        let matchingUsernames = Array(Set(matchingEntries.compactMap { $0.username })).sorted()
        let exactUsernames = Array(Set(exactMatches.compactMap { $0.username })).sorted()
        var response: [String: Any] = [
            "hasMultipleSubdomains": hasMultiple, 
            "totalMatches": matchCount,
            "matchingUsernames": matchingUsernames,
            "exactMatchCount": exactMatches.count,
            "exactUsernames": exactUsernames
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
