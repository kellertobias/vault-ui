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

public struct TOTPSetupSheet: View {
    let setupData: TOTPSetupData
    @Environment(\.dismiss) private var dismiss
    @EnvironmentObject var session: SessionManager
    
    @State private var searchText = ""
    @State private var ciphers: [CipherDisplayData] = []
    @State private var isLoading = true
    @State private var isSaving = false
    @State private var errorMessage: String?
    @State private var addDomainToLogin = true
    @State private var newCipherName = ""
    
    public init(setupData: TOTPSetupData) {
        self.setupData = setupData
    }
    
    private var filteredCiphers: [CipherDisplayData] {
        if searchText.isEmpty {
            return ciphers
        }
        let query = searchText.lowercased()
        return ciphers.filter { display in
            if display.name.lowercased().contains(query) { return true }
            if display.username.lowercased().contains(query) { return true }
            if display.uris.contains(where: { $0.lowercased().contains(query) }) { return true }
            return false
        }
    }
    
    public var body: some View {
        VStack(spacing: 0) {
            // Header
            VStack(spacing: 8) {
                Text("Set Up Verification Code")
                    .font(.headline)
                
                Text("Choose a login to save the TOTP code for:")
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
            }
            .padding()
            
            if let error = errorMessage {
                Text(error)
                    .foregroundStyle(.red)
                    .font(.caption)
                    .padding(.horizontal)
            }
            
            Divider()
            
            // Search
            HStack {
                TextField("Search logins...", text: $searchText)
                    .textFieldStyle(.roundedBorder)
                
                if !searchText.isEmpty {
                    Button("Show All Logins") {
                        searchText = ""
                    }
                }
            }
            .padding()
            
            // List
            if isLoading {
                Spacer()
                ProgressView()
                Spacer()
            } else if filteredCiphers.isEmpty {
                Spacer()
                Text("No matching logins found.")
                    .foregroundStyle(.secondary)
                Spacer()
            } else {
                List {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Create New Item")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        
                        HStack {
                            TextField("Item Name", text: $newCipherName)
                                .textFieldStyle(.roundedBorder)
                                .onAppear {
                                    if newCipherName.isEmpty, let issuer = setupData.issuer {
                                        newCipherName = issuer
                                    }
                                }
                            
                            Button(action: { createNewCipher(name: newCipherName) }) {
                                HStack {
                                    Image(systemName: "plus.circle.fill")
                                    Text("Create")
                                }
                                .foregroundStyle(.white)
                                .padding(.horizontal, 12)
                                .padding(.vertical, 4)
                                .background(newCipherName.isEmpty ? Color.gray : Color.blue)
                                .clipShape(Capsule())
                            }
                            .buttonStyle(.plain)
                            .disabled(newCipherName.isEmpty)
                        }
                    }
                    .padding(.vertical, 8)
                    .padding(.horizontal, 4)
                    
                    Text("Or assign to existing item:")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .padding(.top, 8)
                        .padding(.bottom, 4)
                    
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
            
            Divider()
            
            // Footer
            HStack {
                Button("Cancel") {
                    dismiss()
                }
                .keyboardShortcut(.cancelAction)
                
                Spacer()
                
                if let domain = setupData.domain {
                    Toggle("Add \(domain) to URLs", isOn: $addDomainToLogin)
                }
            }
            .padding()
        }
        .frame(width: 400, height: 500)
        .task {
            await loadCiphers()
        }
        .disabled(isSaving)
        .overlay {
            if isSaving {
                Color.black.opacity(0.2)
                ProgressView()
            }
        }
    }
    
    private func loadCiphers() async {
        isLoading = true
        defer { isLoading = false }
        
        guard let engine = try? session.getSyncEngine() else { return }
        guard let allCiphers = try? engine.fetchCiphers(includeDeleted: false) else { return }
        
        // Only show login ciphers
        let logins = allCiphers.compactMap { try? $0.toCipher() }.filter { $0.type == .login }
        
        var displayData: [CipherDisplayData] = []
        for cipher in logins {
            let name = session.decrypt(cipher.name, itemKey: cipher.key) ?? "Unnamed"
            let username = session.decrypt(cipher.login?.username, itemKey: cipher.key) ?? ""
            
            var uris: [String] = []
            if let loginUris = cipher.login?.uris {
                for uriObj in loginUris {
                    if let uriStr = session.decrypt(uriObj.uri, itemKey: cipher.key) {
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
            self.ciphers = displayData.sorted { c1, c2 in
                return c1.name.lowercased() < c2.name.lowercased()
            }
            
            // Auto-populate search text
            if let issuer = setupData.issuer {
                self.searchText = issuer
            }
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
                        if let decrypted = session.decrypt(uriObj.uri) {
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
                try await engine.fullSync()
                
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
    
    private func createNewCipher(name: String) {
        isSaving = true
        errorMessage = nil
        
        Task {
            do {
                let engine = try session.getSyncEngine()
                let (itemKey, encryptedKey) = try session.generateItemKey()
                
                var newCipher = Cipher(type: .login)
                newCipher.id = UUID().uuidString
                newCipher.name = try session.encrypt(name, using: itemKey)
                newCipher.key = encryptedKey
                
                var login = VaultModels.LoginData()
                login.totp = try session.encrypt(setupData.secret, using: itemKey)
                
                if addDomainToLogin, let domain = setupData.domain {
                    let newUri = LoginUri(uri: try session.encrypt(domain, using: itemKey), match: nil)
                    login.uris = [newUri]
                }
                
                if let accountName = setupData.accountName {
                    login.username = try session.encrypt(accountName, using: itemKey)
                }
                
                newCipher.login = login
                
                try engine.saveCipherLocally(newCipher, operation: .create)
                try await engine.fullSync()
                
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
}
