// MARK: - VaultAppUI/MultiSelectMergeView.swift
// Detail view for merging multiple selected ciphers

import SwiftUI
import VaultModels
import VaultServices
import VaultSync
import VaultCrypto

struct MultiSelectMergeView: View {
    let cipherIds: Set<String>
    let onMergeComplete: () -> Void
    
    @EnvironmentObject var session: SessionManager
    
    @State private var ciphers: [Cipher] = []
    @State private var persistedCiphers: [PersistedCipher] = []
    @State private var isLoading = true
    @State private var mergeError: String?
    
    var body: some View {
        VStack(spacing: 0) {
            if isLoading {
                ProgressView()
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                VStack(spacing: 24) {
                    Image(systemName: "arrow.triangle.merge")
                        .font(.system(size: 64))
                        .foregroundStyle(.blue)
                        .padding(.top, 40)
                    
                    Text("\(cipherIds.count) Items Selected")
                        .font(.title)
                        .bold()
                    
                    if let error = mergeError {
                        VStack(spacing: 8) {
                            Image(systemName: "exclamationmark.triangle.fill")
                                .foregroundStyle(.red)
                            Text(error)
                                .font(.subheadline)
                                .foregroundStyle(.secondary)
                                .multilineTextAlignment(.center)
                        }
                        .padding()
                        .background(Color.red.opacity(0.1))
                        .cornerRadius(8)
                        
                        Text("Please select only Login items with the same username and password to merge them.")
                            .font(.caption)
                            .foregroundStyle(.tertiary)
                            .multilineTextAlignment(.center)
                            .padding(.horizontal, 40)
                    } else {
                        VStack(alignment: .leading, spacing: 16) {
                            Text("The following items will be merged:")
                                .font(.headline)
                                .foregroundStyle(.secondary)
                            
                            ScrollView {
                                VStack(alignment: .leading, spacing: 12) {
                                    ForEach(ciphers) { cipher in
                                        HStack {
                                            Image(systemName: cipher.type.iconName)
                                                .foregroundStyle(.blue)
                                            Text(session.decrypt(cipher.name) ?? "Unnamed")
                                                .font(.body)
                                            Spacer()
                                            if let uris = cipher.login?.uris, !uris.isEmpty {
                                                Text("\(uris.count) URIs")
                                                    .font(.caption)
                                                    .foregroundStyle(.tertiary)
                                            }
                                        }
                                        .padding(12)
                                        .background(Color(nsColor: .controlBackgroundColor))
                                        .cornerRadius(8)
                                    }
                                }
                            }
                            .frame(maxHeight: 200)
                            
                            VStack(alignment: .leading, spacing: 8) {
                                Text("Merge Actions:")
                                    .font(.subheadline.bold())
                                Text("• URIs and Custom Fields will be combined.")
                                    .font(.subheadline)
                                    .foregroundStyle(.secondary)
                                Text("• The older duplicate items will be moved to the Trash.")
                                    .font(.subheadline)
                                    .foregroundStyle(.secondary)
                            }
                            .padding(.top, 16)
                            
                            Button {
                                performMerge()
                            } label: {
                                Text("Merge Entries")
                                    .frame(maxWidth: .infinity)
                                    .padding(.vertical, 8)
                            }
                            .buttonStyle(.borderedProminent)
                            .controlSize(.large)
                            .padding(.top, 24)
                        }
                        .padding(.horizontal, 40)
                    }
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
            }
        }
        .task(id: cipherIds) {
            await loadCiphers()
        }
    }
    
    private func loadCiphers() async {
        isLoading = true
        defer { isLoading = false }
        
        mergeError = nil
        
        guard let engine = try? session.getSyncEngine() else { return }
        guard let allCiphers = try? engine.fetchCiphers(includeDeleted: false) else { return }
        
        let selected = allCiphers.filter { cipherIds.contains($0.id) }
        self.persistedCiphers = selected
        
        self.ciphers = selected.compactMap { try? $0.toCipher() }
        
        validateSelection()
    }
    
    private func validateSelection() {
        guard ciphers.count == cipherIds.count else {
            mergeError = "Some items could not be loaded."
            return
        }
        
        guard let first = ciphers.first else { return }
        
        let baseType = first.type
        let baseUsername = session.decrypt(first.login?.username)
        let basePassword = session.decrypt(first.login?.password)
        
        for cipher in ciphers.dropFirst() {
            if cipher.type != baseType {
                mergeError = "Cannot merge items of different types."
                return
            }
            if cipher.type != .login {
                mergeError = "Currently, only Login items can be merged."
                return
            }
            if session.decrypt(cipher.login?.username) != baseUsername {
                mergeError = "Items must have the exact same Username."
                return
            }
            if session.decrypt(cipher.login?.password) != basePassword {
                mergeError = "Items must have the exact same Password."
                return
            }
        }
    }
    
    private func performMerge() {
        guard ciphers.count > 1, mergeError == nil else { return }
        
        var baseCipher = ciphers[0]
        let _ = persistedCiphers[0]
        let duplicates = Array(ciphers.dropFirst())
        let duplicatePersisted = Array(persistedCiphers.dropFirst())
        
        // 1. Combine URIs
        var allUris = baseCipher.login?.uris ?? []
        var seenUrls = Set<String>()
        
        for uri in allUris {
            if let decrypted = session.decrypt(uri.uri) {
                seenUrls.insert(decrypted.lowercased())
            }
        }
        
        for dup in duplicates {
            if let dupUris = dup.login?.uris {
                for uri in dupUris {
                    if let decrypted = session.decrypt(uri.uri) {
                        let lower = decrypted.lowercased()
                        if !seenUrls.contains(lower) {
                            seenUrls.insert(lower)
                            allUris.append(uri)
                        }
                    }
                }
            }
        }
        
        baseCipher.login?.uris = allUris
        
        // 2. Combine Custom Fields
        var allFields = baseCipher.fields ?? []
        var seenFieldNames = Set<String>()
        
        for field in allFields {
            if let decrypted = session.decrypt(field.name) {
                seenFieldNames.insert(decrypted.lowercased())
            }
        }
        
        for dup in duplicates {
            if let dupFields = dup.fields {
                for field in dupFields {
                    if let decrypted = session.decrypt(field.name) {
                        let lower = decrypted.lowercased()
                        if !seenFieldNames.contains(lower) {
                            seenFieldNames.insert(lower)
                            allFields.append(field)
                        }
                    }
                }
            }
        }
        
        baseCipher.fields = allFields.isEmpty ? nil : allFields
        
        // Save base cipher as update
        guard let engine = try? session.getSyncEngine() else { return }
        
        do {
            try engine.saveCipherLocally(baseCipher, operation: .update)
            
            // Soft delete the duplicates
            for dup in duplicatePersisted {
                guard let cipher = try? dup.toCipher() else { continue }
                try engine.saveCipherLocally(cipher, operation: .softDelete)
            }
            
            // Finish
            onMergeComplete()
        } catch {
            mergeError = "Failed to merge: \(error.localizedDescription)"
        }
    }
}
