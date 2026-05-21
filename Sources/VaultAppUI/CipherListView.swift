// MARK: - VaultAppUI/CipherListView.swift
// Middle column: filterable list of vault items

import SwiftUI
import VaultModels
import VaultCrypto
import VaultServices
import VaultSync

/// A decrypted cipher for display in the list.
struct CipherListItem: Identifiable, Equatable {
    let id: String
    let type: CipherType
    let name: String
    let subtitle: String?
    let iconURL: URL?
    let isFavorite: Bool
    let isDeleted: Bool

    static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.id == rhs.id && lhs.isFavorite == rhs.isFavorite
    }
}

/// List of vault items filtered by sidebar selection and search.
struct CipherListView: View {
    let filter: SidebarFilter
    @Binding var searchText: String
    @Binding var selectedCipherIds: Set<String>
    var refreshToken: Int = 0
    @EnvironmentObject var session: SessionManager

    @State private var items: [CipherListItem] = []
    @State private var isLoading = true

    var body: some View {
        Group {
            if isLoading {
                ProgressView()
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if filteredItems.isEmpty {
                VStack(spacing: 12) {
                    Image(systemName: "magnifyingglass")
                        .font(.system(size: 32))
                        .foregroundStyle(.quaternary)
                    Text(searchText.isEmpty ? "No items" : "No results")
                        .font(.headline)
                        .foregroundStyle(.secondary)
                    if !searchText.isEmpty {
                        Text("Try a different search term.")
                            .font(.caption)
                            .foregroundStyle(.tertiary)
                    }
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                List(filteredItems, selection: $selectedCipherIds) { item in
                    CipherRowView(item: item)
                        .tag(item.id)
                        .draggable(item.id)
                }
                .listStyle(.inset(alternatesRowBackgrounds: true))
            }
        }
        .navigationTitle(filter.title)
        .task(id: "\(filter.hashValue)-\(refreshToken)") {
            await loadItems()
        }
    }

    private var filteredItems: [CipherListItem] {
        guard !searchText.isEmpty else { return items }
        let query = searchText.lowercased()
        return items.filter {
            $0.name.lowercased().contains(query) ||
            ($0.subtitle?.lowercased().contains(query) ?? false)
        }
    }

    private func loadItems() async {
        isLoading = true
        defer { isLoading = false }

        guard let engine = try? session.getSyncEngine() else { return }

        let includeDeleted = filter == .trash
        guard let ciphers = try? engine.fetchCiphers(includeDeleted: includeDeleted) else { return }

        var matchingFolderIds: Set<String>? = nil
        
        if case .folder(let folderId) = filter, let id = folderId {
            matchingFolderIds = [id]
            if let folders = try? engine.fetchFolders() {
                if let selectedFolder = folders.first(where: { $0.id == id }),
                   let selectedEnc = try? VaultCrypto.EncString(serialized: selectedFolder.encryptedName),
                   let selectedName = session.decrypt(selectedEnc) {
                   
                   let prefix = selectedName + "/"
                   for f in folders {
                       if let fEnc = try? VaultCrypto.EncString(serialized: f.encryptedName),
                          let fName = session.decrypt(fEnc),
                          fName.hasPrefix(prefix) {
                           matchingFolderIds?.insert(f.id)
                       }
                   }
                }
            }
        }

        items = ciphers.compactMap { persisted -> CipherListItem? in
            guard let cipher = try? persisted.toCipher() else { return nil }

            // Apply filter
            switch filter {
            case .allItems:
                guard !persisted.isDeleted else { return nil }
            case .favorites:
                guard persisted.isFavorite && !persisted.isDeleted else { return nil }
            case .trash:
                guard persisted.isDeleted else { return nil }
            case .totp:
                guard !persisted.isDeleted,
                      cipher.type == .login,
                      let login = cipher.login,
                      let totpEnc = login.totp,
                      let totpString = session.decrypt(totpEnc, itemKey: cipher.key),
                      !totpString.isEmpty else { return nil }
            case .type(let type):
                guard cipher.type == type && !persisted.isDeleted else { return nil }
            case .folder(let folderId):
                if folderId != nil {
                    guard let matching = matchingFolderIds,
                          let cipherFolderId = cipher.folderId,
                          matching.contains(cipherFolderId),
                          !persisted.isDeleted else { return nil }
                } else {
                    guard cipher.folderId == nil && !persisted.isDeleted else { return nil }
                }
            case .send:
                return nil // Sends are handled separately
            }

            let name = session.decrypt(cipher.name, itemKey: cipher.key) ?? "Unnamed"
            let subtitle = subtitleFor(cipher)
            
            var iconURL: URL?
            if cipher.type == .login,
               let uris = cipher.login?.uris,
               let firstUri = uris.first(where: { session.decrypt($0.uri, itemKey: cipher.key)?.isEmpty == false }),
               let uriString = session.decrypt(firstUri.uri, itemKey: cipher.key),
               let serverBase = session.activeAccount?.serverURL {
                
                let host: String?
                if let url = URL(string: uriString), let h = url.host {
                    host = h
                } else if !uriString.contains("://"), let url = URL(string: "https://\(uriString)"), let h = url.host {
                    host = h
                } else {
                    host = nil
                }
                
                if let host = host {
                    iconURL = serverBase.appendingPathComponent("icons/\(host)/icon.png")
                }
            }

            return CipherListItem(
                id: persisted.id,
                type: cipher.type,
                name: name,
                subtitle: subtitle,
                iconURL: iconURL,
                isFavorite: cipher.favorite,
                isDeleted: persisted.isDeleted
            )
        }
        .sorted { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
    }

    private func subtitleFor(_ cipher: Cipher) -> String? {
        switch cipher.type {
        case .login:
            return session.decrypt(cipher.login?.username, itemKey: cipher.key)
        case .card:
            if let brand = session.decrypt(cipher.card?.brand, itemKey: cipher.key),
               let number = session.decrypt(cipher.card?.number, itemKey: cipher.key) {
                let last4 = String(number.suffix(4))
                return "\(brand) •••• \(last4)"
            }
            return nil
        case .identity:
            let first = session.decrypt(cipher.identity?.firstName, itemKey: cipher.key) ?? ""
            let last = session.decrypt(cipher.identity?.lastName, itemKey: cipher.key) ?? ""
            return [first, last].filter { !$0.isEmpty }.joined(separator: " ")
        case .sshKey:
            return session.decrypt(cipher.sshKey?.keyFingerprint, itemKey: cipher.key)
        case .secureNote:
            return nil
        }
    }
}

/// A single row in the cipher list.
struct CipherRowView: View {
    let item: CipherListItem

    var body: some View {
        HStack(spacing: 12) {
            // Type icon
            if let iconURL = item.iconURL {
                CachedAsyncImage(url: iconURL) {
                    Image(systemName: "globe")
                        .font(.system(size: 16))
                        .foregroundStyle(iconColor)
                }
                .frame(width: 28, height: 28)
                .background(iconColor.opacity(0.12))
                .clipShape(RoundedRectangle(cornerRadius: 6))
            } else {
                Image(systemName: item.type.iconName)
                    .font(.system(size: 16))
                    .foregroundStyle(iconColor)
                    .frame(width: 28, height: 28)
                    .background(iconColor.opacity(0.12))
                    .clipShape(RoundedRectangle(cornerRadius: 6))
            }

            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 4) {
                    Text(item.name)
                        .font(.system(.body, design: .default))
                        .lineLimit(1)

                    if item.isFavorite {
                        Image(systemName: "star.fill")
                            .font(.system(size: 9))
                            .foregroundStyle(.yellow)
                    }
                }

                if let subtitle = item.subtitle, !subtitle.isEmpty {
                    Text(subtitle)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
            }

            Spacer()
        }
        .padding(.vertical, 2)
    }

    private var iconColor: Color {
        switch item.type {
        case .login: return .blue
        case .secureNote: return .green
        case .card: return .orange
        case .identity: return .purple
        case .sshKey: return .teal
        }
    }
}

// MARK: - Filter Title Extension

extension SidebarFilter {
    var title: String {
        switch self {
        case .allItems: return "All Items"
        case .favorites: return "Favorites"
        case .trash: return "Trash"
        case .totp: return "TOTP Codes"
        case .type(let t): return t.displayName
        case .folder(nil): return "No Folder"
        case .folder: return "Folder"
        case .send: return "Send"
        }
    }
}
