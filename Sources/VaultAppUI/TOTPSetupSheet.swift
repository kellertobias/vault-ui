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

public struct TOTPSetupSheet: View {
    let setupData: TOTPSetupData
    @Environment(\.dismiss) private var dismiss
    @EnvironmentObject var session: SessionManager
    
    @State private var searchText = ""
    @State private var ciphers: [Cipher] = []
    @State private var isLoading = true
    @State private var isSaving = false
    @State private var errorMessage: String?
    @State private var addDomainToLogin = true
    
    public init(setupData: TOTPSetupData) {
        self.setupData = setupData
    }
    
    private var filteredCiphers: [Cipher] {
        if searchText.isEmpty {
            return ciphers
        }
        let query = searchText.lowercased()
        return ciphers.filter { cipher in
            let name = session.decrypt(cipher.name)?.lowercased() ?? ""
            let username = session.decrypt(cipher.login?.username)?.lowercased() ?? ""
            return name.contains(query) || username.contains(query)
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
                List(filteredCiphers, id: \.id) { cipher in
                    Button {
                        saveTOTP(to: cipher)
                    } label: {
                        HStack {
                            VStack(alignment: .leading) {
                                Text(session.decrypt(cipher.name) ?? "Unnamed")
                                    .font(.body.bold())
                                if let username = session.decrypt(cipher.login?.username), !username.isEmpty {
                                    Text(username)
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
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
        
        await MainActor.run {
            self.ciphers = logins.sorted { c1, c2 in
                let n1 = session.decrypt(c1.name)?.lowercased() ?? ""
                let n2 = session.decrypt(c2.name)?.lowercased() ?? ""
                return n1 < n2
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
}
