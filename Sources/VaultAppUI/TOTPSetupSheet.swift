// MARK: - VaultAppUI/TOTPSetupSheet.swift

import SwiftUI
import VaultModels
import VaultServices
import VaultCrypto
import VaultAPI

public struct TOTPSetupData: Equatable, Identifiable {
    public let id = UUID()
    public let secret: String
    public let issuer: String?
    public let accountName: String?
    public let domain: String?
    
    public init(secret: String, issuer: String?, accountName: String?, domain: String? = nil) {
        self.secret = secret
        self.issuer = issuer
        self.accountName = accountName
        self.domain = domain
    }
}

struct CipherDisplayData: Identifiable {
    let id: String
    let cipher: Cipher
    let name: String
    let username: String
    let uris: [String]
}

private enum TOTPSetupScreen {
    case matches
    case allLogins
    case createNew
}

public struct TOTPSetupSheet: View {
    let setupData: TOTPSetupData
    @Environment(\.dismiss) private var dismiss
    @EnvironmentObject var session: SessionManager
    
    @State private var screen: TOTPSetupScreen = .matches
    @State private var searchText = ""
    @State private var ciphers: [CipherDisplayData] = []
    @State private var matchedCiphers: [CipherDisplayData] = []
    @State private var isLoading = true
    @State private var isSaving = false
    @State private var errorMessage: String?
    @State private var addDomainToLogin = true
    @State private var newCipherName = ""
    @State private var newCipherUsername = ""
    @State private var newCipherHost = ""
    
    public init(setupData: TOTPSetupData) {
        self.setupData = setupData
    }
    
    private var filteredCiphers: [CipherDisplayData] {
        let source = screen == .allLogins ? ciphers : matchedCiphers
        guard screen == .allLogins else {
            return source
        }
        if searchText.isEmpty {
            return source
        }
        let query = searchText.lowercased()
        return source.filter { display in
            if display.name.lowercased().contains(query) { return true }
            if display.username.lowercased().contains(query) { return true }
            if display.uris.contains(where: { $0.lowercased().contains(query) }) { return true }
            return false
        }
    }

    private var targetHost: String? {
        normalizedHost(from: setupData.domain)
    }

    private var targetLogin: String? {
        let trimmed = setupData.accountName?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        return trimmed.isEmpty ? nil : trimmed
    }

    private var contextLabel: String {
        targetLogin ?? targetHost ?? setupData.domain ?? ""
    }

    private var canCreateNewCipher: Bool {
        !newCipherName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }
    
    public var body: some View {
        VStack(spacing: 0) {
            headerView
            
            if let error = errorMessage {
                Text(error)
                    .foregroundStyle(.red)
                    .font(.caption)
                    .padding(.horizontal)
            }
            
            Divider()
            
            if screen == .allLogins {
                HStack(spacing: 8) {
                    Button {
                        searchText = ""
                        screen = .matches
                    } label: {
                        Image(systemName: "chevron.left")
                    }
                    .buttonStyle(.borderless)
                    
                    TextField("Search logins...", text: $searchText)
                        .textFieldStyle(.roundedBorder)
                }
                .padding()
                
                Divider()
            }
            
            if screen == .createNew {
                createNewView
            } else {
                loginListView
            }
            
            if screen != .allLogins {
                Divider()
                footerView
            }
        }
        .frame(width: 400, height: 500)
        .task {
            await loadCiphers()
        }
        .onAppear {
            prepareNewCipherDefaults()
        }
        .disabled(isSaving)
        .overlay {
            if isSaving {
                Color.black.opacity(0.2)
                ProgressView()
            }
        }
    }

    private var headerView: some View {
        VStack(spacing: 8) {
            HStack {
                Button("Cancel") {
                    dismiss()
                }
                .keyboardShortcut(.cancelAction)
                
                Spacer()
                
                Text(screen == .createNew ? "New Verification Login" : "Set Up Verification Code")
                    .font(.headline)
                
                Spacer()
                
                Text(contextLabel.isEmpty ? "no login" : contextLabel)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .frame(width: 92, alignment: .trailing)
                    .lineLimit(1)
            }
            
            Text(screen == .createNew ? "Create a new login and save this TOTP code to it." : "Choose a login to save the TOTP code for:")
                .font(.subheadline)
                .foregroundStyle(.secondary)
            
            if let issuer = setupData.issuer {
                Text(issuer)
                    .font(.body.bold())
            }
            if let accountName = setupData.accountName {
                Text(accountName)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            
            if screen != .createNew, let domain = setupData.domain {
                Toggle("Add \(domain) to URLs", isOn: $addDomainToLogin)
                    .font(.caption)
                    .toggleStyle(.checkbox)
            }
        }
        .padding()
    }

    private var loginListView: some View {
        Group {
            if isLoading {
                Spacer()
                ProgressView()
                Spacer()
            } else if filteredCiphers.isEmpty {
                Spacer()
                Text(screen == .allLogins ? "No logins found." : "No matching logins found.")
                    .foregroundStyle(.secondary)
                Spacer()
            } else {
                List {
                    ForEach(filteredCiphers, id: \.id) { display in
                        Button {
                            saveTOTP(to: display.cipher)
                        } label: {
                            HStack {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(display.name)
                                        .font(.body.bold())
                                    if !display.username.isEmpty {
                                        Text(display.username)
                                            .font(.caption)
                                            .foregroundStyle(.secondary)
                                    }
                                    if !display.uris.isEmpty {
                                        Text(display.uris[0])
                                            .font(.caption2)
                                            .foregroundStyle(.tertiary)
                                            .lineLimit(1)
                                    }
                                }
                                Spacer()
                                Image(systemName: "plus.circle")
                                    .foregroundStyle(.blue)
                            }
                            .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                        .padding(.vertical, 4)
                    }
                }
            }
        }
    }

    private var createNewView: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Host")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    TextField("Host", text: $newCipherHost)
                        .textFieldStyle(.roundedBorder)
                }
                
                VStack(alignment: .leading, spacing: 4) {
                    Text("Title")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    TextField("Title", text: $newCipherName)
                        .textFieldStyle(.roundedBorder)
                }
                
                VStack(alignment: .leading, spacing: 4) {
                    Text("Username / email")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    TextField("Username / email", text: $newCipherUsername)
                        .textFieldStyle(.roundedBorder)
                }
            }
            .padding()
        }
    }

    private var footerView: some View {
        HStack {
            switch screen {
            case .matches:
                Button("Show All") {
                    searchText = ""
                    screen = .allLogins
                }
                
                Spacer()
                
                Button("Create New") {
                    prepareNewCipherDefaults()
                    screen = .createNew
                }
                .keyboardShortcut(.defaultAction)
            case .allLogins:
                EmptyView()
                Spacer()
            case .createNew:
                Button("Back") {
                    screen = .matches
                }
                
                Spacer()
                
                Button("Save") {
                    createNewCipher(name: newCipherName, username: newCipherUsername, host: newCipherHost)
                }
                .keyboardShortcut(.defaultAction)
                .disabled(!canCreateNewCipher)
            }
        }
        .padding()
    }
    
    private func loadCiphers() async {
        isLoading = true
        defer { isLoading = false }
        
        guard let engine = try? session.getSyncEngine() else { return }
        if let vaultKey = try? session.getVaultKey() {
            await TemporaryCredentialManager.cleanupExpiredTemporaryCredentials(syncEngine: engine)
            await TemporaryCredentialManager.processTemporaryCredentialDrafts(syncEngine: engine, vaultKey: vaultKey)
        }
        guard let allCiphers = try? engine.fetchCiphers(includeDeleted: false) else { return }
        
        // Only show login ciphers
        let logins = allCiphers.compactMap { try? $0.toCipher() }.filter { $0.type == .login }
        
        var displayData: [CipherDisplayData] = []
        for cipher in logins {
            let name = session.decrypt(cipher.name, for: cipher) ?? "Unnamed"
            let username = session.decrypt(cipher.login?.username, for: cipher) ?? ""
            
            var uris: [String] = []
            if let loginUris = cipher.login?.uris {
                for uriObj in loginUris {
                    if let uriStr = session.decrypt(uriObj.uri, for: cipher) {
                        uris.append(uriStr)
                    }
                }
            }
            displayData.append(CipherDisplayData(
                id: cipher.id ?? UUID().uuidString,
                cipher: cipher,
                name: name,
                username: username,
                uris: uris
            ))
        }
        
        await MainActor.run {
            let sorted = displayData.sorted { left, right in
                let leftScore = matchScore(for: left)
                let rightScore = matchScore(for: right)
                if leftScore != rightScore {
                    return leftScore > rightScore
                }
                return left.name.localizedCaseInsensitiveCompare(right.name) == .orderedAscending
            }

            self.ciphers = sorted
            self.matchedCiphers = sorted.filter { matchScore(for: $0) > 0 }
            self.searchText = ""
        }
    }
    
    private func saveTOTP(to cipher: Cipher) {
        isSaving = true
        errorMessage = nil
        
        Task {
            do {
                var updatedCipher = cipher
                let itemKey = try session.getItemKey(for: cipher)
                
                // Set the new TOTP secret
                var login = updatedCipher.login ?? VaultModels.LoginData()
                login.totp = try session.encrypt(setupData.secret, using: itemKey)
                
                if addDomainToLogin, let domain = setupData.domain {
                    var uris = login.uris ?? []
                    let domainExists = uris.contains { uriObj in
                        if let decrypted = session.decrypt(uriObj.uri, for: cipher) {
                            return decrypted.contains(domain)
                        }
                        return false
                    }
                    if !domainExists {
                        let newUri = LoginUri(uri: try session.encrypt(domain, using: itemKey), match: nil)
                        uris.append(newUri)
                        login.uris = uris
                    }
                }
                
                updatedCipher.login = login
                
                let engine = try session.getSyncEngine()
                try engine.saveCipherLocally(updatedCipher, operation: .update)
                Task {
                    try? await engine.fullSync()
                }
                
                await MainActor.run {
                    dismiss()
                }
            } catch {
                await MainActor.run {
                    errorMessage = error.localizedDescription
                    isSaving = false
                }
            }
        }
    }
    
    private func createNewCipher(name: String, username: String, host: String) {
        isSaving = true
        errorMessage = nil
        let trimmedName = name.trimmingCharacters(in: .whitespacesAndNewlines)
        let trimmedUsername = username.trimmingCharacters(in: .whitespacesAndNewlines)
        let trimmedHost = host.trimmingCharacters(in: .whitespacesAndNewlines)
        
        Task {
            do {
                let engine = try session.getSyncEngine()
                let (itemKey, encryptedKey) = try session.generateItemKey()
                
                var newCipher = Cipher(type: .login)
                newCipher.id = UUID().uuidString
                newCipher.name = try session.encrypt(trimmedName, using: itemKey)
                newCipher.key = encryptedKey
                
                var login = VaultModels.LoginData()
                login.totp = try session.encrypt(setupData.secret, using: itemKey)
                
                if !trimmedHost.isEmpty {
                    let newUri = LoginUri(uri: try session.encrypt(trimmedHost, using: itemKey), match: nil)
                    login.uris = [newUri]
                }
                
                if !trimmedUsername.isEmpty {
                    login.username = try session.encrypt(trimmedUsername, using: itemKey)
                }
                
                newCipher.login = login
                
                try engine.saveCipherLocally(newCipher, operation: .create)
                Task {
                    try? await engine.fullSync()
                }
                
                await MainActor.run {
                    dismiss()
                }
            } catch {
                await MainActor.run {
                    errorMessage = error.localizedDescription
                    isSaving = false
                }
            }
        }
    }

    private func prepareNewCipherDefaults() {
        if newCipherName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            newCipherName = setupData.issuer
                ?? targetHost
                ?? setupData.domain
                ?? "New Login"
        }
        if newCipherUsername.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            newCipherUsername = setupData.accountName ?? ""
        }
        if newCipherHost.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            newCipherHost = targetHost ?? setupData.domain ?? ""
        }
    }

    private func matchScore(for display: CipherDisplayData) -> Int {
        if let login = targetLogin {
            return loginMatchScore(for: display, login: login)
        }

        guard let host = targetHost else {
            return fallbackMatchScore(for: display)
        }

        var score = 0
        for uri in display.uris {
            guard let uriHost = normalizedHost(from: uri) else { continue }
            if uriHost == host {
                score = max(score, 100)
            } else if uriHost.hasSuffix(".\(host)") || host.hasSuffix(".\(uriHost)") {
                score = max(score, 80)
            } else if baseDomain(uriHost) == baseDomain(host) {
                score = max(score, 60)
            }
        }

        let hostName = host.components(separatedBy: ".").first ?? host
        if display.name.localizedCaseInsensitiveContains(host) {
            score = max(score, 40)
        } else if display.name.localizedCaseInsensitiveContains(hostName) {
            score = max(score, 25)
        }

        return score
    }

    private func loginMatchScore(for display: CipherDisplayData, login: String) -> Int {
        let normalizedLogin = normalizedLoginValue(login)
        let normalizedUsername = normalizedLoginValue(display.username)

        if normalizedUsername == normalizedLogin {
            return 200
        }
        if !normalizedUsername.isEmpty,
           (normalizedUsername.contains(normalizedLogin) || normalizedLogin.contains(normalizedUsername)) {
            return 160
        }
        if normalizedLoginValue(display.name).contains(normalizedLogin) {
            return 120
        }
        if display.uris.contains(where: { normalizedLoginValue($0).contains(normalizedLogin) }) {
            return 80
        }

        return 0
    }

    private func fallbackMatchScore(for display: CipherDisplayData) -> Int {
        var score = 0
        if let issuer = setupData.issuer, display.name.localizedCaseInsensitiveContains(issuer) {
            score = max(score, 20)
        }
        if let accountName = setupData.accountName, display.username.localizedCaseInsensitiveContains(accountName) {
            score = max(score, 10)
        }
        return score
    }

    private func normalizedHost(from value: String?) -> String? {
        guard let value else { return nil }
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }

        if let url = URL(string: trimmed), let host = url.host {
            return host.lowercased()
        }
        if let url = URL(string: "https://\(trimmed)"), let host = url.host {
            return host.lowercased()
        }

        return trimmed
            .components(separatedBy: "/").first?
            .components(separatedBy: ":").first?
            .lowercased()
    }

    private func normalizedLoginValue(_ value: String) -> String {
        value
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .removingPercentEncoding?
            .lowercased()
        ?? value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    }

    private func baseDomain(_ host: String) -> String {
        let parts = host.components(separatedBy: ".").filter { !$0.isEmpty }
        guard parts.count > 2, Int(parts.last ?? "") == nil else {
            return host
        }
        return parts.suffix(2).joined(separator: ".")
    }
}
