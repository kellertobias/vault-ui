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
    @Published var matchedCredentials: [SharedCredentialEntry] = []
    @Published var allCredentials: [SharedCredentialEntry] = []
    @Published var showMoreSecrets: Bool = false
    @Published var searchText: String = ""

    var filtered: [SharedCredentialEntry] {
        let source = (showMoreSecrets || !searchText.isEmpty) ? allCredentials : matchedCredentials
        if searchText.isEmpty { return source }
        let query = searchText.lowercased()
        return source.filter {
            $0.name.lowercased().contains(query)
            || ($0.username?.lowercased().contains(query) ?? false)
            || $0.uris.contains(where: { $0.lowercased().contains(query) })
        }
    }
    
    @Published var isPasskeyRegistration: Bool = false
    @Published var relyingPartyId: String? = nil
    @Published var newCipherName: String = ""

    @Published var lastSyncWithApp: Date?
    @Published var lastSyncWithServer: Date?

    init() {
        if let dates = SharedCredentialStore.shared.fetchSyncDates() {
            lastSyncWithApp = dates.lastSyncWithApp
            lastSyncWithServer = dates.lastSyncWithServer
        }
    }

    var formattedLastSyncWithApp: String {
        guard let date = lastSyncWithApp else { return "Never" }
        let formatter = DateFormatter()
        formatter.dateStyle = .short
        formatter.timeStyle = .short
        return formatter.string(from: date)
    }

    var formattedLastSyncWithServer: String {
        guard let date = lastSyncWithServer else { return "Never" }
        let formatter = DateFormatter()
        formatter.dateStyle = .short
        formatter.timeStyle = .short
        return formatter.string(from: date)
    }
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
                if model.allCredentials.isEmpty {
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
                    VStack(spacing: 12) {
                        Text("No matching credentials")
                            .foregroundStyle(.secondary)
                        if !model.showMoreSecrets && model.searchText.isEmpty {
                            Button("Show more secrets") { model.showMoreSecrets = true }
                                .buttonStyle(.bordered)
                        }
                    }
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
                    if !model.showMoreSecrets && model.searchText.isEmpty && model.allCredentials.count > model.matchedCredentials.count {
                        Button(action: { model.showMoreSecrets = true }) {
                            HStack {
                                Spacer()
                                Text("Show more secrets")
                                    .font(.subheadline)
                                    .foregroundColor(.blue)
                                Spacer()
                            }
                            .padding(.vertical, 8)
                        }
                        .buttonStyle(.plain)
                    }

                    VStack(alignment: .center, spacing: 4) {
                        Text("Last synced with Vault UI: \(model.formattedLastSyncWithApp)")
                            .font(.caption2)
                            .foregroundColor(.secondary)
                        Text("Last synced with server: \(model.formattedLastSyncWithServer)")
                            .font(.caption2)
                            .foregroundColor(.secondary)
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.top, 4)
                    .padding(.bottom, 8)
                    .listRowSeparator(.hidden)
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
 
        let matching = filterAndSortCredentials(allCredentials, for: serviceIdentifiers)
 
        logger.info("Found \(matching.count) matching credentials out of \(allCredentials.count) total")
 
        model.allCredentials = allCredentials
        model.matchedCredentials = matching
        model.showMoreSecrets = false
 
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
 
        let matching = filterAndSortCredentials(totpCredentials, for: serviceIdentifiers)
 
        logger.info("Found \(matching.count) matching TOTP credentials out of \(totpCredentials.count) total")
 
        model.allCredentials = totpCredentials
        model.matchedCredentials = matching
        model.showMoreSecrets = false
 
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
        
        let matching = filterAndSortCredentials(allCredentials, for: serviceIdentifiers)
        
        model.allCredentials = allCredentials
        model.matchedCredentials = matching
        model.showMoreSecrets = false
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
        model.allCredentials = allCredentials
        model.matchedCredentials = filterAndSortCredentials(allCredentials, for: []) // No service identifier for passkey registration initially unless we parse relying party
        if let relyingParty = (registrationRequest.credentialIdentity as? ASPasskeyCredentialIdentity)?.relyingPartyIdentifier {
            model.matchedCredentials = filterAndSortCredentials(allCredentials, for: [ASCredentialServiceIdentifier(identifier: relyingParty, type: .domain)])
        }
        model.showMoreSecrets = false
        model.isPasskeyRegistration = true
        
        if let relyingParty = (registrationRequest.credentialIdentity as? ASPasskeyCredentialIdentity)?.relyingPartyIdentifier {
            model.relyingPartyId = relyingParty
        }
        
        showCredentialPicker()
    }
 
    // MARK: - Provide Credential Without UI
 
    override func provideCredentialWithoutUserInteraction(for credentialIdentity: ASPasswordCredentialIdentity) {
        logger.info("provideCredentialWithoutUserInteraction for: \(credentialIdentity.user)")
 
        guard let fullRecordId = credentialIdentity.recordIdentifier else {
            logger.error("No record identifier in credential identity")
            let error = NSError(
                domain: ASExtensionErrorDomain,
                code: ASExtensionError.credentialIdentityNotFound.rawValue
            )
            self.extensionContext.cancelRequest(withError: error)
            return
        }
        let recordId = fullRecordId.components(separatedBy: "|").first ?? fullRecordId
 
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
 
        guard let fullRecordId = credentialIdentity.recordIdentifier else {
            cancelWithError(.credentialIdentityNotFound)
            return
        }
        let recordId = fullRecordId.components(separatedBy: "|").first ?? fullRecordId
 
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
            
            guard let fullRecordId = identity.recordIdentifier else {
                cancelWithError(.credentialIdentityNotFound)
                return
            }
            let recordId = fullRecordId.components(separatedBy: "|").first ?? fullRecordId

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
            
            guard let fullRecordId = identity.recordIdentifier else {
                cancelWithError(.credentialIdentityNotFound)
                return
            }
            let recordId = fullRecordId.components(separatedBy: "|").first ?? fullRecordId
            
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
                
                if entry.supportsPasskey {
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

    private enum MatchQuality: Int, Comparable {
        case none = 0
        case fqdnMatch = 1
        case prefixMatch = 2
        case exactMatch = 3
        
        static func < (lhs: MatchQuality, rhs: MatchQuality) -> Bool {
            return lhs.rawValue < rhs.rawValue
        }
    }

    private func filterAndSortCredentials(_ allCredentials: [SharedCredentialEntry], for serviceIdentifiers: [ASCredentialServiceIdentifier]) -> [SharedCredentialEntry] {
        let matchingWithQuality: [(SharedCredentialEntry, MatchQuality)]
        if serviceIdentifiers.isEmpty {
            matchingWithQuality = allCredentials.map { ($0, .none) }
        } else {
            matchingWithQuality = allCredentials.compactMap { entry in
                let bestQuality = serviceIdentifiers.map { evaluateMatchQuality(entry: entry, serviceIdentifier: $0) }.max() ?? .none
                return bestQuality > .none ? (entry, bestQuality) : nil
            }
        }
        
        return matchingWithQuality.sorted { a, b in
            if a.1 != b.1 {
                return a.1 > b.1 // Higher quality first
            }
            let orderA = a.0.order ?? Int.max
            let orderB = b.0.order ?? Int.max
            if orderA != orderB {
                return orderA < orderB
            }
            return a.0.name.localizedStandardCompare(b.0.name) == .orderedAscending
        }.map { $0.0 }
    }

    private func evaluateMatchQuality(entry: SharedCredentialEntry, serviceIdentifier: ASCredentialServiceIdentifier) -> MatchQuality {
        let browserStr = serviceIdentifier.identifier.lowercased()
        
        var bestQuality: MatchQuality = .none
        
        for uri in entry.uris {
            let secretStr = uri.lowercased()
            let cleanSecret = secretStr.replacingOccurrences(of: "https://", with: "").replacingOccurrences(of: "http://", with: "")
            
            if cleanSecret.isEmpty || cleanSecret == "/" {
                continue
            }
            
            if browserStr == secretStr {
                bestQuality = max(bestQuality, .exactMatch)
                continue
            }
            
            if browserStr.hasPrefix(secretStr) {
                bestQuality = max(bestQuality, .prefixMatch)
                continue
            }
            
            let browserHost = extractDomain(from: browserStr)
            let secretHost = extractDomain(from: secretStr)
            
            if browserHost == secretHost {
                bestQuality = max(bestQuality, .fqdnMatch)
                continue
            }
            
            if secretHost.contains("*") {
                var regexPattern = NSRegularExpression.escapedPattern(for: secretHost)
                if regexPattern.hasPrefix("\\*\\.") {
                    let rest = String(regexPattern.dropFirst(4))
                    regexPattern = "(?:.*\\.)?" + rest
                } else {
                    regexPattern = regexPattern.replacingOccurrences(of: "\\*", with: ".*")
                }
                let pattern = "^" + regexPattern + "$"
                if let regex = try? NSRegularExpression(pattern: pattern, options: .caseInsensitive) {
                    let range = NSRange(location: 0, length: browserHost.utf16.count)
                    if regex.firstMatch(in: browserHost, options: [], range: range) != nil {
                        bestQuality = max(bestQuality, .fqdnMatch)
                    }
                }
            }
        }
        
        return bestQuality
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
