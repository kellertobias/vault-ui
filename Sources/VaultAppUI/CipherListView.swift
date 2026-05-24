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
    let username: String?
    let firstURL: String?
    let urlCount: Int
    let iconURL: URL?
    let isFavorite: Bool
    let isDeleted: Bool
    let hasPasskey: Bool

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
    var onAddCipher: ((CipherType) -> Void)? = nil
    var onGeneratePassword: (() -> Void)? = nil
    @EnvironmentObject var session: SessionManager

    @State private var items: [CipherListItem] = []
    @State private var isLoading = true
    @State private var showImport = false

    var body: some View {
        VStack(spacing: 0) {
            // Sticky Header with Search and Plus
            HStack {
                HStack {
                    Image(systemName: "magnifyingglass")
                        .foregroundStyle(.secondary)
                    TextField("Search vault…", text: $searchText)
                        .textFieldStyle(.plain)
                }
                .padding(6)
                .background(Color(nsColor: .controlBackgroundColor))
                .clipShape(RoundedRectangle(cornerRadius: 6))
                .overlay(RoundedRectangle(cornerRadius: 6).stroke(Color.secondary.opacity(0.2), lineWidth: 1))
                
                Menu {
                    Button("Add Login") { onAddCipher?(.login) }
                    Button("Add Secure Note") { onAddCipher?(.secureNote) }
                    Button("Add Card") { onAddCipher?(.card) }
                    Button("Add Identity") { onAddCipher?(.identity) }
                    Button("Add SSH Key") { onAddCipher?(.sshKey) }
                    Divider()
                    Button("Generate Password") { onGeneratePassword?() }
                    Button("Import Data…") { showImport = true }
                } label: {
                    Image(systemName: "plus")
                        .padding(6)
                        .background(Color(nsColor: .controlBackgroundColor))
                        .clipShape(RoundedRectangle(cornerRadius: 6))
                        .overlay(RoundedRectangle(cornerRadius: 6).stroke(Color.secondary.opacity(0.2), lineWidth: 1))
                }
                .menuStyle(.borderlessButton)
                .menuIndicator(.hidden)
                .fixedSize()
                .disabled(session.isOffline)
            }
            .padding()
            .background(.ultraThinMaterial)
            .zIndex(1)

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
                    List(selection: $selectedCipherIds) {
                        ForEach(groupedItems, id: \.0) { letter, letterItems in
                            Section(header: Text(letter).font(.headline)) {
                                ForEach(letterItems) { item in
                                    CipherRowView(item: item)
                                        .tag(item.id)
                                        .draggable(item.id)
                                }
                            }
                        }
                    }
                    .listStyle(.inset(alternatesRowBackgrounds: true))
                }
            }
        }
        .task(id: "\(filter.hashValue)-\(refreshToken)-\(session.dataUpdateToken)") {
            await loadItems()
        }
        .sheet(isPresented: $showImport) {
            ImportView()
        }
    }

    private var filteredItems: [CipherListItem] {
        guard !searchText.isEmpty else { return items }
        let query = searchText.lowercased()
        return items.filter {
            $0.name.lowercased().contains(query) ||
            ($0.username?.lowercased().contains(query) ?? false) ||
            ($0.firstURL?.lowercased().contains(query) ?? false)
        }
    }

    private var groupedItems: [(String, [CipherListItem])] {
        let itemsToGroup = filteredItems
        let grouped = Dictionary(grouping: itemsToGroup) { item in
            let firstChar = item.name.first?.uppercased() ?? "#"
            return firstChar.rangeOfCharacter(from: .letters) != nil ? firstChar : "#"
        }
        return grouped.sorted { $0.key < $1.key }
    }

    private func loadItems() async {
        if items.isEmpty {
            isLoading = true
        }
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

        var newItems: [CipherListItem] = []
        newItems.reserveCapacity(ciphers.count)

        for (index, persisted) in ciphers.enumerated() {
            if index > 0 && index % 100 == 0 {
                await Task.yield()
            }
            guard let cipher = try? persisted.toCipher() else { continue }

            // Apply filter
            switch filter {
            case .allItems:
                guard !persisted.isDeleted else { continue }
            case .favorites:
                guard persisted.isFavorite && !persisted.isDeleted else { continue }
            case .trash:
                guard persisted.isDeleted else { continue }
            case .totp:
                guard !persisted.isDeleted,
                      cipher.type == .login,
                      let login = cipher.login,
                      let totpEnc = login.totp,
                      let totpString = session.decrypt(totpEnc, itemKey: cipher.key),
                      !totpString.isEmpty else { continue }
            case .type(let type):
                guard cipher.type == type && !persisted.isDeleted else { continue }
            case .folder(let folderId):
                if folderId != nil {
                    guard let matching = matchingFolderIds,
                          let cipherFolderId = cipher.folderId,
                          matching.contains(cipherFolderId),
                          !persisted.isDeleted else { continue }
                } else {
                    guard cipher.folderId == nil && !persisted.isDeleted else { continue }
                }
            case .send:
                continue // Sends are handled separately
            }

            let name = session.decrypt(cipher.name, itemKey: cipher.key) ?? "Unnamed"
            let username = subtitleFor(cipher)
            
            var firstURL: String? = nil
            var urlCount = 0
            var iconURL: URL? = nil
            
            if cipher.type == .login, let uris = cipher.login?.uris {
                urlCount = uris.count
                if let firstUri = uris.first(where: { session.decrypt($0.uri, itemKey: cipher.key)?.isEmpty == false }),
                   let uriString = session.decrypt(firstUri.uri, itemKey: cipher.key) {
                    firstURL = uriString
                    
                    if let serverBase = session.activeAccount?.serverURL {
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
                }
            }

            newItems.append(CipherListItem(
                id: persisted.id,
                type: cipher.type,
                name: name,
                username: username,
                firstURL: firstURL,
                urlCount: urlCount,
                iconURL: iconURL,
                isFavorite: cipher.favorite,
                isDeleted: persisted.isDeleted,
                hasPasskey: (cipher.login?.fido2Credentials?.isEmpty == false)
            ))
        }
        
        items = newItems.sorted { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
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
                // Line 1: Title
                HStack(spacing: 4) {
                    Text(item.name)
                        .font(.system(.body, design: .default))
                        .lineLimit(1)
                        .frame(maxWidth: .infinity, alignment: .leading)

                    if item.isFavorite {
                        Image(systemName: "star.fill")
                            .font(.system(size: 9))
                            .foregroundStyle(.yellow)
                    }
                    
                    if item.hasPasskey {
                        Image(systemName: "person.badge.key.fill")
                            .font(.system(size: 10))
                            .foregroundStyle(.blue)
                    }
                }
                .frame(height: 18)

                // Line 2: URL
                HStack {
                    if let url = item.firstURL, !url.isEmpty {
                        Text(url)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                        if item.urlCount > 1 {
                            Text("+\(item.urlCount - 1)")
                                .font(.caption2)
                                .padding(.horizontal, 4)
                                .background(Color.secondary.opacity(0.2))
                                .clipShape(Capsule())
                        }
                    } else {
                        Text("No URL assigned")
                            .font(.caption)
                            .foregroundStyle(.secondary.opacity(0.5))
                            .lineLimit(1)
                    }
                }
                .frame(height: 14, alignment: .leading)

                // Line 3: Username
                HStack {
                    if let user = item.username, !user.isEmpty {
                        Text(user)
                            .font(.caption)
                            .foregroundStyle(.tertiary)
                            .lineLimit(1)
                    } else {
                        Text("No Username")
                            .font(.caption)
                            .foregroundStyle(.tertiary.opacity(0.5))
                            .lineLimit(1)
                    }
                }
                .frame(height: 14, alignment: .leading)
            }
            .padding(.vertical, 4)

            Spacer(minLength: 0)
        }
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
