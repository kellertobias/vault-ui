import AuthenticationServices
import Cocoa
import SwiftUI
import LocalAuthentication
import VaultModels
import VaultServices
import VaultAPI
import VaultCrypto
import OSLog

private let logger = Logger(subsystem: "com.vaultui", category: "AutoFillExtension")

// MARK: - SwiftUI Credential Picker

/// Observable model for the credential list UI.
@MainActor
final class CredentialListModel: ObservableObject {
    @Published var credentials: [SharedCredentialEntry] = []
    @Published var searchText: String = ""

    var filtered: [SharedCredentialEntry] {
        if searchText.isEmpty { return credentials }
        let query = searchText.lowercased()
        return credentials.filter {
            $0.name.lowercased().contains(query)
            || ($0.username?.lowercased().contains(query) ?? false)
            || $0.uris.contains(where: { $0.lowercased().contains(query) })
        }
    }
    
    @Published var isPasskeyRegistration: Bool = false
    @Published var relyingPartyId: String? = nil
    @Published var newCipherName: String = ""
}

/// SwiftUI view shown inside the extension overlay.
struct CredentialListView: View {
    @ObservedObject var model: CredentialListModel
    var onSelect: (SharedCredentialEntry) -> Void
    var onCreateNew: ((String?) -> Void)?
    var onCancel: () -> Void

    var body: some View {
        VStack(spacing: 0) {
            // Header
            HStack {
                Button("Cancel") { onCancel() }
                    .keyboardShortcut(.cancelAction)
                Spacer()
                Text("Vault UI — AutoFill")
                    .font(.headline)
                Spacer()
                // Balance the layout
                Button("Cancel") { onCancel() }
                    .hidden()
            }
            .padding()

            // Search
            TextField("Search credentials…", text: $model.searchText)
                .textFieldStyle(.roundedBorder)
                .padding(.horizontal)
                .padding(.bottom, 8)
                
            if model.isPasskeyRegistration, let rpId = model.relyingPartyId {
                Text("Register Passkey for \(rpId)")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .padding(.horizontal)
                    .padding(.bottom, 4)
            }

            Divider()

            // Credential list
            if model.filtered.isEmpty {
                Spacer()
                if model.credentials.isEmpty {
                    VStack(spacing: 8) {
                        Image(systemName: "key.slash")
                            .font(.largeTitle)
                            .foregroundStyle(.secondary)
                        Text("No credentials available")
                            .font(.title3)
                            .foregroundStyle(.secondary)
                        Text("Open Vault UI and sync your vault first.")
                            .font(.caption)
                            .foregroundStyle(.tertiary)
                    }
                } else {
                    Text("No matching credentials")
                        .foregroundStyle(.secondary)
                }
                Spacer()
            } else {
                List {
                    if model.isPasskeyRegistration {
                        VStack(alignment: .leading, spacing: 8) {
                            Text("Create New Item")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                            
                            HStack {
                                TextField("Item Name", text: $model.newCipherName)
                                    .textFieldStyle(.roundedBorder)
                                    .onAppear {
                                        if model.newCipherName.isEmpty, let rp = model.relyingPartyId {
                                            model.newCipherName = rp
                                        }
                                    }
                                
                                Button(action: { onCreateNew?(model.newCipherName) }) {
                                    HStack {
                                        Image(systemName: "plus.circle.fill")
                                        Text("Create")
                                    }
                                    .foregroundStyle(.white)
                                    .padding(.horizontal, 12)
                                    .padding(.vertical, 4)
                                    .background(model.newCipherName.isEmpty ? Color.gray : Color.blue)
                                    .clipShape(Capsule())
                                }
                                .buttonStyle(.plain)
                                .disabled(model.newCipherName.isEmpty)
                            }
                        }
                        .padding(.vertical, 8)
                        .padding(.horizontal, 4)
                        
                        Text("Or assign to existing item:")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .padding(.top, 8)
                            .padding(.bottom, 4)
                    }

                    ForEach(model.filtered, id: \.id) { entry in
                        Button(action: { onSelect(entry) }) {
                            HStack {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(entry.name)
                                        .font(.body)
                                        .fontWeight(.medium)
                                    if let username = entry.username, !username.isEmpty {
                                        Text(username)
                                            .font(.caption)
                                            .foregroundStyle(.secondary)
                                    }
                                    if let uri = entry.uris.first {
                                        Text(uri)
                                            .font(.caption2)
                                            .foregroundStyle(.tertiary)
                                            .lineLimit(1)
                                    }
                                }
                                Spacer()
                                Image(systemName: "arrow.right.circle.fill")
                                    .foregroundStyle(.blue)
                            }
                            .contentShape(Rectangle())
                            .padding(.vertical, 2)
                        }
                        .buttonStyle(.plain)
                    }
                }
            }
        }
        .frame(minWidth: 320, idealWidth: 400, minHeight: 300, idealHeight: 450)
    }
}

// MARK: - Credential Provider View Controller

/// Credential Provider Extension view controller.
///
/// macOS invokes this when the user triggers AutoFill from a login field.
/// The extension reads credential metadata from the shared Keychain
/// (populated by the main app after each sync) and provides matching
/// credentials to the system.
@objc(VaultCredentialProviderViewController)
class VaultCredentialProviderViewController: ASCredentialProviderViewController {
 
    private let credentialStore = SharedCredentialStore.shared
    private let model = CredentialListModel()
 
    private enum AutoFillRequestMode: CustomStringConvertible {
        case passwordsAndPasskeys
        case oneTimeCodes
        case passkeyRegistration
        case passkeys

        var description: String {
            switch self {
            case .passwordsAndPasskeys: return "passwordsAndPasskeys"
            case .oneTimeCodes: return "oneTimeCodes"
            case .passkeyRegistration: return "passkeyRegistration"
            case .passkeys: return "passkeys"
            }
        }
    }
 
    private var requestMode: AutoFillRequestMode = .passwordsAndPasskeys
 
    // MARK: - Extension Configuration
 
    /// Called when the user enables this credential provider in System Settings.
    /// Since we don't need additional configuration, complete immediately.
    override func prepareInterfaceForExtensionConfiguration() {
        logger.info("prepareInterfaceForExtensionConfiguration called — completing immediately")
        self.extensionContext.completeExtensionConfigurationRequest()
    }
 
    // MARK: - Credential List
 
    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        logger.info("prepareCredentialList called with \(serviceIdentifiers.count) service identifiers")
        self.requestMode = .passwordsAndPasskeys
 
        let allCredentials = credentialStore.fetchCredentials()
 
        if allCredentials.isEmpty {
            logger.warning("No credentials in shared store — vault may not have synced")
        }
 
        // Filter credentials that match the requested service identifiers
        let matching: [SharedCredentialEntry]
        if serviceIdentifiers.isEmpty {
            matching = allCredentials
        } else {
            matching = allCredentials.filter { entry in
                serviceIdentifiers.contains(where: { serviceId in
                    matchesService(entry: entry, serviceIdentifier: serviceId)
                })
            }
        }
 
        logger.info("Found \(matching.count) matching credentials out of \(allCredentials.count) total")
 
        // If we have matches, show only those; otherwise show all so the user can browse
        model.credentials = matching.isEmpty ? allCredentials : matching
 
        // Present the SwiftUI credential picker
        showCredentialPicker()
    }
 
    // MARK: - One-Time Code List
 
    override func prepareOneTimeCodeCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        logger.info("prepareOneTimeCodeCredentialList called with \(serviceIdentifiers.count) service identifiers")
        self.requestMode = .oneTimeCodes
 
        let allCredentials = credentialStore.fetchCredentials()
        let totpCredentials = allCredentials.filter { $0.supportsTotp }
 
        if totpCredentials.isEmpty {
            logger.warning("No credentials with TOTP in shared store")
        }
 
        // Filter credentials that match the requested service identifiers
        let matching: [SharedCredentialEntry]
        if serviceIdentifiers.isEmpty {
            matching = totpCredentials
        } else {
            matching = totpCredentials.filter { entry in
                serviceIdentifiers.contains(where: { serviceId in
                    matchesService(entry: entry, serviceIdentifier: serviceId)
                })
            }
        }
 
        logger.info("Found \(matching.count) matching TOTP credentials out of \(totpCredentials.count) total")
 
        // If we have matches, show only those; otherwise show all TOTP credentials so the user can browse
        model.credentials = matching.isEmpty ? totpCredentials : matching
 
        // Present the SwiftUI credential picker
        showCredentialPicker()
    }
    
    private func completeAssertion(for entry: SharedCredentialEntry, relyingParty: String, clientDataHash: Data) {
        let allPasskeys = credentialStore.fetchPasskeys(id: entry.id)
        guard let passkey = allPasskeys.first(where: { $0.relyingPartyId == relyingParty }) ?? allPasskeys.first else {
            logger.error("Passkey data not available for selected credential \(entry.id)")
            cancelWithError(.failed)
            return
        }
        
        guard let assertion = WebAuthnGenerator.generateAssertion(
            privateKeyBase64: passkey.privateKey,
            relyingPartyId: relyingParty,
            clientDataHash: clientDataHash
        ) else {
            logger.error("Failed to generate assertion")
            cancelWithError(.failed)
            return
        }
        
        guard let credentialID = Data(base64Encoded: passkey.credentialId),
              let userHandle = Data(base64Encoded: passkey.userHandle) else {
            logger.error("Invalid passkey data encoding")
            cancelWithError(.failed)
            return
        }
        
        let credential = ASPasskeyAssertionCredential(
            userHandle: userHandle,
            relyingParty: relyingParty,
            signature: assertion.signature,
            clientDataHash: clientDataHash,
            authenticatorData: assertion.authenticatorData,
            credentialID: credentialID
        )
        
        self.extensionContext.completeAssertionRequest(using: credential, completionHandler: nil)
        logger.info("Completed passkey assertion request")
    }

    // MARK: - Passkey & Additional Extensions support
 
    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier], requestParameters: ASPasskeyCredentialRequestParameters) {
        logger.info("prepareCredentialList(for:requestParameters:) called")
        self.requestMode = .passkeys
        self.currentPasskeyAssertionParameters = requestParameters
        
        let allCredentials = credentialStore.fetchCredentials()
        let passkeyCredentials = allCredentials.filter { $0.supportsPasskey }
        
        let matching: [SharedCredentialEntry]
        if serviceIdentifiers.isEmpty {
            matching = passkeyCredentials
        } else {
            matching = passkeyCredentials.filter { entry in
                serviceIdentifiers.contains(where: { serviceId in
                    matchesService(entry: entry, serviceIdentifier: serviceId)
                })
            }
        }
        
        model.credentials = matching.isEmpty ? passkeyCredentials : matching
        showCredentialPicker()
    }
 
    private var currentPasskeyRegistrationRequest: ASPasskeyCredentialRequest?
    private var currentPasskeyAssertionRequest: ASPasskeyCredentialRequest?
    private var currentPasskeyAssertionParameters: ASPasskeyCredentialRequestParameters?
    private var rawRegistrationRequest: ASCredentialRequest?

    override func prepareInterface(forPasskeyRegistration registrationRequest: ASCredentialRequest) {
        logger.info("prepareInterface(forPasskeyRegistration:) called")
        self.requestMode = .passkeyRegistration
        
        if let sharedDefaults = UserDefaults(suiteName: "group.de.tobisk.apps.vaultui") {
            sharedDefaults.set(String(describing: type(of: registrationRequest)), forKey: "debug_raw_request_type")
            sharedDefaults.set(String(describing: type(of: registrationRequest.credentialIdentity)), forKey: "debug_raw_identity_type")
        }

        self.rawRegistrationRequest = registrationRequest
        self.currentPasskeyRegistrationRequest = registrationRequest as? ASPasskeyCredentialRequest
        
        var allCredentials = credentialStore.fetchCredentials()
        model.credentials = allCredentials
        model.isPasskeyRegistration = true
        
        if let relyingParty = (registrationRequest.credentialIdentity as? ASPasskeyCredentialIdentity)?.relyingPartyIdentifier {
            model.relyingPartyId = relyingParty
        }
        
        showCredentialPicker()
    }
 
    // MARK: - Provide Credential Without UI
 
    override func provideCredentialWithoutUserInteraction(for credentialIdentity: ASPasswordCredentialIdentity) {
        logger.info("provideCredentialWithoutUserInteraction for: \(credentialIdentity.user)")
 
        guard let recordId = credentialIdentity.recordIdentifier else {
            logger.error("No record identifier in credential identity")
            let error = NSError(
                domain: ASExtensionErrorDomain,
                code: ASExtensionError.credentialIdentityNotFound.rawValue
            )
            self.extensionContext.cancelRequest(withError: error)
            return
        }
 
        // We always require user interaction for Touch ID / Device Password authentication
        logger.info("Authentication required for AutoFill, requesting user interaction")
        let error = NSError(
            domain: ASExtensionErrorDomain,
            code: ASExtensionError.userInteractionRequired.rawValue
        )
        self.extensionContext.cancelRequest(withError: error)
    }

    @available(macOS 14.0, *)
    override func provideCredentialWithoutUserInteraction(for credentialRequest: ASCredentialRequest) {
        logger.info("provideCredentialWithoutUserInteraction for credentialRequest")
        // We always require user interaction
        let error = NSError(
            domain: ASExtensionErrorDomain,
            code: ASExtensionError.userInteractionRequired.rawValue
        )
        self.extensionContext.cancelRequest(withError: error)
    }
 
    // MARK: - Provide Credential With UI
 
    override func prepareInterfaceToProvideCredential(for credentialIdentity: ASPasswordCredentialIdentity) {
        logger.info("prepareInterfaceToProvideCredential for: \(credentialIdentity.user)")
 
        guard let recordId = credentialIdentity.recordIdentifier else {
            cancelWithError(.credentialIdentityNotFound)
            return
        }
 
        // Try the shared keychain first
        if let password = credentialStore.fetchPassword(id: recordId) {
            authenticateUser { [weak self] success, _ in
                guard let self = self else { return }
                DispatchQueue.main.async {
                    if success {
                        let credential = ASPasswordCredential(
                            user: credentialIdentity.user,
                            password: password
                        )
                        self.extensionContext.completeRequest(
                            withSelectedCredential: credential,
                            completionHandler: nil
                        )
                    } else {
                        self.cancelWithError(.userCanceled)
                    }
                }
            }
            return
        }
 
        // If password isn't available, show an error
        logger.error("Could not retrieve password for credential \(recordId)")
        cancelWithError(.failed)
    }

    @available(macOS 14.0, *)
    override func prepareInterfaceToProvideCredential(for credentialRequest: ASCredentialRequest) {
        logger.info("prepareInterfaceToProvideCredential for credentialRequest")

        if let passwordRequest = credentialRequest as? ASPasswordCredentialRequest,
           let identity = passwordRequest.credentialIdentity as? ASPasswordCredentialIdentity {
            self.prepareInterfaceToProvideCredential(for: identity)
        } else if let otpRequest = credentialRequest as? ASOneTimeCodeCredentialRequest {
            self.requestMode = .oneTimeCodes
            let identity = otpRequest.credentialIdentity
            
            guard let recordId = identity.recordIdentifier else {
                cancelWithError(.credentialIdentityNotFound)
                return
            }

            // Immediately provide the OTP if we can authenticate
            authenticateUser { [weak self] success, _ in
                guard let self = self else { return }
                DispatchQueue.main.async {
                    if success {
                        if let entry = self.credentialStore.fetchCredentials().first(where: { $0.id == recordId }) {
                            self.provideSelectedCredential(entry)
                        } else {
                            self.cancelWithError(.failed)
                        }
                    } else {
                        self.cancelWithError(.userCanceled)
                    }
                }
            }
        } else if let assertionRequest = credentialRequest as? ASPasskeyCredentialRequest {
            logger.info("prepareInterfaceToProvideCredential for ASPasskeyCredentialRequest")
            self.requestMode = .passkeys
            self.currentPasskeyAssertionRequest = assertionRequest
            let identity = assertionRequest.credentialIdentity
            
            guard let recordId = identity.recordIdentifier else {
                cancelWithError(.credentialIdentityNotFound)
                return
            }
            
            authenticateUser { [weak self] success, _ in
                guard let self = self else { return }
                DispatchQueue.main.async {
                    if success {
                        if let entry = self.credentialStore.fetchCredentials().first(where: { $0.id == recordId }) {
                            self.provideSelectedCredential(entry)
                        } else {
                            self.cancelWithError(.failed)
                        }
                    } else {
                        self.cancelWithError(.userCanceled)
                    }
                }
            }
        } else {
            cancelWithError(.failed)
        }
    }
 
    // MARK: - UI Setup
 
    private func showCredentialPicker() {
        let pickerView = CredentialListView(
            model: model,
            onSelect: { [weak self] entry in
                self?.selectCredential(entry)
            },
            onCreateNew: { [weak self] name in
                self?.createNewPasskeyItem(name: name)
            },
            onCancel: { [weak self] in
                self?.cancelWithError(.userCanceled)
            }
        )
 
        let hostingView = NSHostingView(rootView: pickerView)
        hostingView.translatesAutoresizingMaskIntoConstraints = false
 
        // Replace any existing content
        view.subviews.forEach { $0.removeFromSuperview() }
        view.addSubview(hostingView)
 
        NSLayoutConstraint.activate([
            hostingView.topAnchor.constraint(equalTo: view.topAnchor),
            hostingView.bottomAnchor.constraint(equalTo: view.bottomAnchor),
            hostingView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            hostingView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
        ])
    }
 
    private func selectCredential(_ entry: SharedCredentialEntry) {
        logger.info("User selected credential: \(entry.name) for request mode: \(self.requestMode)")
 
        authenticateUser { [weak self] success, _ in
            guard let self = self else { return }
            DispatchQueue.main.async {
                if success {
                    if self.requestMode == .passkeyRegistration {
                        self.processPasskeyRegistration(targetCipherId: entry.id, username: entry.username)
                    } else {
                        self.provideSelectedCredential(entry)
                    }
                } else {
                    self.cancelWithError(.userCanceled)
                }
            }
        }
    }
    
    private func createNewPasskeyItem(name: String?) {
        logger.info("User selected to create a new passkey item with name: \(name ?? "nil")")
        authenticateUser { [weak self] success, _ in
            guard let self = self else { return }
            DispatchQueue.main.async {
                if success {
                    self.processPasskeyRegistration(targetCipherId: nil, targetCipherName: name, username: nil)
                } else {
                    self.cancelWithError(.userCanceled)
                }
            }
        }
    }

    private func provideSelectedCredential(_ entry: SharedCredentialEntry) {
        switch requestMode {
        case .passwordsAndPasskeys, .passkeys:
            if let assertionRequest = currentPasskeyAssertionRequest {
                guard let passkeyIdentity = assertionRequest.credentialIdentity as? ASPasskeyCredentialIdentity else {
                    logger.error("Credential identity is not ASPasskeyCredentialIdentity")
                    cancelWithError(.credentialIdentityNotFound)
                    return
                }
                
                let relyingParty = passkeyIdentity.relyingPartyIdentifier
                let clientDataHash = assertionRequest.clientDataHash
                
                completeAssertion(for: entry, relyingParty: relyingParty, clientDataHash: clientDataHash)
                
            } else if let params = currentPasskeyAssertionParameters {
                let relyingParty = params.relyingPartyIdentifier
                let clientDataHash = params.clientDataHash
                
                completeAssertion(for: entry, relyingParty: relyingParty, clientDataHash: clientDataHash)
                
            } else {
                if let password = credentialStore.fetchPassword(id: entry.id) {
                    let credential = ASPasswordCredential(
                        user: entry.username ?? entry.name,
                        password: password
                    )
                    self.extensionContext.completeRequest(
                        withSelectedCredential: credential,
                        completionHandler: nil
                    )
                } else {
                    logger.error("Password not available for selected credential \(entry.id)")
                    cancelWithError(.failed)
                }
            }
 
        case .oneTimeCodes:
            guard let totpSecret = credentialStore.fetchTotp(id: entry.id) else {
                logger.error("TOTP secret not found in shared store for credential \(entry.id)")
                cancelWithError(.failed)
                return
            }
 
            guard let totpCode = TOTPService.generateCode(from: totpSecret) else {
                logger.error("Failed to generate TOTP code from secret")
                cancelWithError(.failed)
                return
            }
 
            let credential = ASOneTimeCodeCredential(code: totpCode.code)
            self.extensionContext.completeOneTimeCodeRequest(using: credential, completionHandler: nil)
 
        case .passkeyRegistration:
            logger.error("Passkey registration should be handled by processPasskeyRegistration")
            cancelWithError(.failed)
        }
    }
    
    private func processPasskeyRegistration(targetCipherId: String?, targetCipherName: String? = nil, username: String?) {
        guard let currentPasskeyRegistrationRequest = currentPasskeyRegistrationRequest else {
            logger.error("No active passkey registration request")
            cancelWithError(.failed)
            return
        }
        
        let relyingParty = (currentPasskeyRegistrationRequest.credentialIdentity as? ASPasskeyCredentialIdentity)?.relyingPartyIdentifier ?? model.relyingPartyId ?? "example.com"
        
        let finalClientDataHash = currentPasskeyRegistrationRequest.clientDataHash
        
        let userHandle = (currentPasskeyRegistrationRequest.credentialIdentity as? ASPasskeyCredentialIdentity)?.userHandle ?? Data()
        
        guard let generated = WebAuthnGenerator.generatePasskey(relyingPartyId: relyingParty) else {
            logger.error("Failed to generate passkey")
            cancelWithError(.failed)
            return
        }
        
        let pending = PendingPasskey(
            targetCipherId: targetCipherId,
            targetCipherName: targetCipherName,
            relyingPartyId: relyingParty,
            userHandle: userHandle,
            userName: username,
            credentialId: generated.credentialID,
            privateKeyBase64: generated.privateKey
        )
        
        credentialStore.queuePendingPasskey(pending)
        
        let credential = ASPasskeyRegistrationCredential(
            relyingParty: relyingParty,
            clientDataHash: finalClientDataHash,
            credentialID: generated.credentialID,
            attestationObject: generated.attestationObject
        )
        self.extensionContext.completeRegistrationRequest(using: credential, completionHandler: nil)
        logger.info("Completed passkey registration and queued PendingPasskey to SharedCredentialStore")
    }

    // MARK: - Authentication

    private func authenticateUser(completion: @escaping (Bool, Error?) -> Void) {
        let context = LAContext()
        var error: NSError?
        
        if context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) {
            context.evaluatePolicy(
                .deviceOwnerAuthentication,
                localizedReason: "Authenticate to AutoFill with Vault UI"
            ) { success, evalError in
                completion(success, evalError)
            }
        } else {
            // Fallback if no device authentication is configured
            logger.warning("Device authentication not available: \(error?.localizedDescription ?? "unknown")")
            completion(false, error)
        }
    }

    // MARK: - Helpers

    private func cancelWithError(_ code: ASExtensionError.Code) {
        let error = NSError(domain: ASExtensionErrorDomain, code: code.rawValue)
        self.extensionContext.cancelRequest(withError: error)
    }

    /// Check if a credential entry matches a service identifier.
    private func matchesService(entry: SharedCredentialEntry, serviceIdentifier: ASCredentialServiceIdentifier) -> Bool {
        let targetDomain = extractDomain(from: serviceIdentifier.identifier).lowercased()

        // Check against all URIs
        for uri in entry.uris {
            let entryDomain = extractDomain(from: uri).lowercased()

            // Exact match
            if entryDomain == targetDomain {
                return true
            }

            // Subdomain match (e.g., "login.example.com" matches "example.com")
            if entryDomain.hasSuffix(".\(targetDomain)") || targetDomain.hasSuffix(".\(entryDomain)") {
                return true
            }
        }

        // Also check the entry name as a fallback
        if entry.name.lowercased().contains(targetDomain) {
            return true
        }

        return false
    }

    /// Extract the domain from a URL string or service identifier.
    private func extractDomain(from input: String) -> String {
        // Try parsing as URL first
        if let url = URL(string: input), let host = url.host {
            return host
        }

        // Try adding scheme
        if !input.contains("://"),
           let url = URL(string: "https://\(input)"),
           let host = url.host {
            return host
        }

        // Return as-is if not a URL
        return input
    }
}
