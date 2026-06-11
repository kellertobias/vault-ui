// MARK: - VaultAppUI/SidebarView.swift
// Left sidebar with folder tree, type filters, and account

import SwiftUI
import UniformTypeIdentifiers
import VaultModels
import VaultCrypto
import VaultServices
import VaultSync
import VaultAPI

/// Sidebar filter options.
enum SidebarFilter: Hashable {
    case allItems
    case favorites
    case trash
    case temporaryCredentials
    case totp
    case wifi
    case passkeys
    case type(CipherType)
    case folder(String?)  // nil = unfiled
    case send
}

struct FolderNode: Identifiable, Hashable {
    let id: String // full path
    let name: String
    let actualId: String? // nil if virtual
    var children: [FolderNode]?
    
    var tagId: String {
        actualId ?? "virtual_\(id)"
    }
}

/// Sidebar with folder tree, vault type filters, and management sections.
struct SidebarView: View {
    @Binding var selectedFilter: SidebarFilter
    var onItemsMoved: (() -> Void)? = nil
    var onCreateSend: (() -> Void)? = nil
    @EnvironmentObject var session: SessionManager

    @State private var showNewFolderAlert = false
    @State private var newFolderName = ""
    @State private var folderError: String?
    @State private var folders: [(id: String, name: String)] = []
    @State private var dropTargetFolderId: String? = nil

    // Rename state
    @State private var showRenameAlert = false
    @State private var renamingFolderId: String?
    @State private var renameFolderName = ""

    // Delete state
    @State private var showDeleteConfirmation = false
    @State private var deletingFolderId: String?
    @State private var deletingFolderName = ""

    // User Menu state
    @State private var showSettings = false
    @State private var showLogoutConfirmation = false
    @State private var isManualSyncing = false
    @State private var syncSuccess = false
    @State private var showUserMenu = false
    @State private var temporaryCredentialCount = 0
    @State private var itemTypeCounts: [String: Int] = [:]
    @State private var folderCounts: [String: Int] = [:]
    @State private var sendCount = 0

    // Sidebar Edit state
    @AppStorage("hiddenSidebarItems") private var hiddenSidebarItemsRaw: String = ""
    @State private var isEditingSidebar = false
    @State private var tempHiddenSidebarItems: Set<String> = []

    private var hiddenSidebarItems: Set<String> {
        guard !hiddenSidebarItemsRaw.isEmpty else { return [] }
        return Set(hiddenSidebarItemsRaw.split(separator: ",").map(String.init))
    }

    private var trashHidden: Bool {
        isEditingSidebar ? tempHiddenSidebarItems.contains("trash") : hiddenSidebarItems.contains("trash")
    }

    private var folderTree: [FolderNode] {
        class Builder {
            let id: String
            let name: String
            var actualId: String?
            var children: [String: Builder] = [:]
            
            init(id: String, name: String, actualId: String?) {
                self.id = id
                self.name = name
                self.actualId = actualId
            }
            
            func toNode() -> FolderNode {
                let sortedChildren = children.values.sorted { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
                let childrenNodes = sortedChildren.map { $0.toNode() }
                return FolderNode(
                    id: id,
                    name: name,
                    actualId: actualId,
                    children: childrenNodes.isEmpty ? nil : childrenNodes
                )
            }
        }
        
        let root = Builder(id: "", name: "", actualId: nil)
        
        for folder in folders {
            let parts = folder.name.split(separator: "/").map(String.init)
            var current = root
            var currentPath = ""
            
            for (index, part) in parts.enumerated() {
                currentPath = currentPath.isEmpty ? part : "\(currentPath)/\(part)"
                let isLast = index == parts.count - 1
                
                if let existing = current.children[part] {
                    if isLast {
                        existing.actualId = folder.id
                    }
                    current = existing
                } else {
                    let newBuilder = Builder(
                        id: currentPath,
                        name: part,
                        actualId: isLast ? folder.id : nil
                    )
                    current.children[part] = newBuilder
                    current = newBuilder
                }
            }
        }
        
        return root.toNode().children ?? []
    }

    var body: some View {
        List(selection: $selectedFilter) {
            HStack(spacing: 12) {
                Image(nsImage: NSApplication.shared.applicationIconImage)
                    .resizable()
                    .scaledToFit()
                    .frame(width: 56, height: 56)
                    .shadow(color: .black.opacity(0.1), radius: 1, y: 1)
                
                Text("Vault UI")
                    .font(.title2.bold())
            }
            .frame(maxWidth: .infinity, alignment: .center)
            .padding(.leading, -16)
            .padding(.bottom, 4)
            .listRowInsets(EdgeInsets())
            .listRowBackground(Color.clear)

            // Item Types section
            Section("Item Types") {
                sidebarRow("All Items", systemImage: "tray.fill", count: itemTypeCounts["allItems"] ?? 0)
                    .tag(SidebarFilter.allItems)

                sidebarRow("Favorites", systemImage: "star.fill", count: itemTypeCounts["favorites"] ?? 0)
                    .tag(SidebarFilter.favorites)

                filterRow("Trash", systemImage: "trash", filter: .trash, id: "trash")

                if isEditingSidebar || temporaryCredentialCount > 0 {
                    filterRow("Temporary Credentials", systemImage: "clock.badge.exclamationmark", filter: .temporaryCredentials, id: "temporaryCredentials")
                }

                filterRow("Login Credentials", systemImage: "key.fill", filter: .type(.login), id: "login")
                filterRow("TOTP Codes", systemImage: "clock.arrow.circlepath", filter: .totp, id: "totp")
                filterRow("Wifi Networks", systemImage: "wifi", filter: .wifi, id: "wifi")
                filterRow("Secure Notes", systemImage: "note.text", filter: .type(.secureNote), id: "secureNote")
                filterRow("Cards", systemImage: "creditcard.fill", filter: .type(.card), id: "card")
                filterRow("Identities", systemImage: "person.text.rectangle.fill", filter: .type(.identity), id: "identity")
                filterRow("SSH Keys", systemImage: "terminal.fill", filter: .type(.sshKey), id: "sshKey")
                filterRow("Passkeys", systemImage: "person.badge.key.fill", filter: .passkeys, id: "passkeys")
            }

            // Folders section
            let foldersHidden = isEditingSidebar ? tempHiddenSidebarItems.contains("folders") : hiddenSidebarItems.contains("folders")
            if isEditingSidebar || !foldersHidden {
                Section {
                    sidebarRow("Uncategorized", systemImage: "folder", count: folderCounts["__none__"] ?? 0)
                        .tag(SidebarFilter.folder(nil))
                        .dropDestination(for: String.self) { droppedItems, _ in
                            moveCiphersToFolder(cipherIds: droppedItems, folderId: nil)
                            return true
                        } isTargeted: { targeted in
                            if targeted { dropTargetFolderId = "__none__" } else if dropTargetFolderId == "__none__" { dropTargetFolderId = nil }
                        }
                        .listRowBackground(
                            dropTargetFolderId == "__none__"
                                ? RoundedRectangle(cornerRadius: 6).fill(Color.accentColor.opacity(0.18))
                                : nil
                        )

                    ForEach(folderTree) { node in
                        FolderTreeView(
                            node: node,
                            selectedFilter: $selectedFilter,
                            dropTargetFolderId: $dropTargetFolderId,
                            renamingFolderId: $renamingFolderId,
                            renameFolderName: $renameFolderName,
                            folderError: $folderError,
                            showRenameAlert: $showRenameAlert,
                            deletingFolderId: $deletingFolderId,
                            deletingFolderName: $deletingFolderName,
                            showDeleteConfirmation: $showDeleteConfirmation,
                            folderCounts: folderCounts,
                            handleDrop: handleDrop
                        )
                    }
                } header: {
                    HStack {
                        if isEditingSidebar {
                            Image(systemName: !foldersHidden ? "checkmark.square" : "square")
                                .foregroundStyle(Color.accentColor)
                                .onTapGesture {
                                    if foldersHidden {
                                        tempHiddenSidebarItems.remove("folders")
                                    } else {
                                        tempHiddenSidebarItems.insert("folders")
                                    }
                                }
                        }
                        Text("Folders")
                        Spacer()
                        if !isEditingSidebar {
                            Button {
                                newFolderName = ""
                                folderError = nil
                                showNewFolderAlert = true
                            } label: {
                                HStack(spacing: 4) {
                                    Image(systemName: "plus")
                                    Text("Add Folder")
                                }
                                .font(.system(size: 10, weight: .medium))
                                .foregroundStyle(Color.accentColor)
                                .padding(.trailing, 8)
                            }
                            .buttonStyle(.plain)
                            .help("New Folder")
                        }
                    }
                }
            }

            // Send section
            let sendHidden = isEditingSidebar ? tempHiddenSidebarItems.contains("send") : hiddenSidebarItems.contains("send")
            if isEditingSidebar || !sendHidden {
                Section {
                    sidebarRow("All Sends", systemImage: "paperplane.fill", count: sendCount)
                        .tag(SidebarFilter.send)
                } header: {
                    HStack {
                        if isEditingSidebar {
                            Image(systemName: !sendHidden ? "checkmark.square" : "square")
                                .foregroundStyle(Color.accentColor)
                                .onTapGesture {
                                    if sendHidden {
                                        tempHiddenSidebarItems.remove("send")
                                    } else {
                                        tempHiddenSidebarItems.insert("send")
                                    }
                                }
                        }
                        Text("Send")
                        Spacer()
                        if !isEditingSidebar {
                            Button {
                                onCreateSend?()
                            } label: {
                                HStack(spacing: 4) {
                                    Image(systemName: "plus")
                                    Text("New Send")
                                }
                                .font(.system(size: 10, weight: .medium))
                                .foregroundStyle(Color.accentColor)
                                .padding(.trailing, 8)
                            }
                            .buttonStyle(.plain)
                            .help("New Send")
                        }
                    }
                }
            }
        }
        .listStyle(.sidebar)
        .scrollContentBackground(.hidden)
        .background(.ultraThinMaterial)
        .safeAreaInset(edge: .bottom) {
            userMenu
        }
        .frame(minWidth: 200)
        .task(id: session.dataUpdateToken) {
            loadFolders()
        }
        // New Folder alert
        .alert("New Folder", isPresented: $showNewFolderAlert) {
            TextField("Folder name", text: $newFolderName)
            Button("Cancel", role: .cancel) {}
            Button("Create") {
                createFolder()
            }
        } message: {
            if let error = folderError {
                Text(error)
            } else {
                Text("Enter a name for the new folder.")
            }
        }
        // Rename Folder alert
        .alert("Rename Folder", isPresented: $showRenameAlert) {
            TextField("Folder name", text: $renameFolderName)
            Button("Cancel", role: .cancel) {}
            Button("Rename") {
                renameFolder()
            }
        } message: {
            if let error = folderError {
                Text(error)
            } else {
                Text("Enter a new name for this folder.")
            }
        }
        // Delete Folder confirmation
        .alert("Delete Folder?", isPresented: $showDeleteConfirmation) {
            Button("Cancel", role: .cancel) {}
            Button("Delete", role: .destructive) {
                deleteFolder()
            }
        } message: {
            Text("Delete \"\(deletingFolderName)\"? Items in this folder will become unfiled, not deleted.")
        }
        .sheet(isPresented: $showSettings) {
            SettingsView()
                .frame(minWidth: 500, minHeight: 420)
        }
        .alert("Log Out?", isPresented: $showLogoutConfirmation) {
            Button("Cancel", role: .cancel) {}
            Button("Log Out", role: .destructive) {
                session.logout()
            }
        } message: {
            Text("This will delete all local vault data, saved credentials, and device registration. Your server data will not be affected. You will need to log in again and re-verify your device.")
        }
    }

    @ViewBuilder
    private func filterRow(_ title: String, systemImage: String, filter: SidebarFilter, id: String) -> some View {
        let isHidden = isEditingSidebar ? tempHiddenSidebarItems.contains(id) : hiddenSidebarItems.contains(id)
        
        if isEditingSidebar {
            HStack {
                Image(systemName: !isHidden ? "checkmark.square" : "square")
                    .foregroundStyle(Color.accentColor)
                    .onTapGesture {
                        if tempHiddenSidebarItems.contains(id) {
                            tempHiddenSidebarItems.remove(id)
                        } else {
                            tempHiddenSidebarItems.insert(id)
                        }
                    }
                Label(title, systemImage: systemImage)
            }
            .tag(filter)
        } else if !isHidden {
            sidebarRow(title, systemImage: systemImage, count: itemTypeCounts[id] ?? 0)
                .tag(filter)
        }
    }

    private func sidebarRow(_ title: String, systemImage: String, count: Int) -> some View {
        HStack {
            Label(title, systemImage: systemImage)
            Spacer(minLength: 8)
            Text(count, format: .number)
                .font(.caption.weight(.medium))
                .monospacedDigit()
                .foregroundStyle(.secondary)
                .padding(.horizontal, 6)
                .padding(.vertical, 1)
                .background(Color.secondary.opacity(0.12))
                .clipShape(Capsule())
                .accessibilityLabel("\(count) items")
        }
    }

    @ViewBuilder
    private var userMenu: some View {
        if let account = session.activeAccount {
            if isEditingSidebar {
                HStack {
                    Button("Cancel") {
                        isEditingSidebar = false
                    }
                    .buttonStyle(.plain)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 6)
                    .background(Color.secondary.opacity(0.2))
                    .clipShape(RoundedRectangle(cornerRadius: 6))
                    
                    Spacer()
                    
                    Button("Save") {
                        hiddenSidebarItemsRaw = tempHiddenSidebarItems.joined(separator: ",")
                        isEditingSidebar = false
                    }
                    .buttonStyle(.plain)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 6)
                    .background(Color.accentColor)
                    .foregroundStyle(.white)
                    .clipShape(RoundedRectangle(cornerRadius: 6))
                }
                .padding(12)
                .background(.ultraThinMaterial)
            } else {
                Button {
                    showUserMenu.toggle()
                } label: {
                    HStack(spacing: 8) {
                        if isManualSyncing || session.isSyncing {
                            ProgressView()
                                .controlSize(.small)
                                .frame(width: 32, height: 32)
                        } else if syncSuccess {
                            Image(systemName: "checkmark")
                                .foregroundStyle(.green)
                                .frame(width: 32, height: 32)
                        } else {
                            AccountAvatarView(email: account.email, size: 32)
                        }
                        
                        VStack(alignment: .leading, spacing: 2) {
                            Text(account.displayName)
                                .font(.system(size: 13, weight: .bold))
                                .lineLimit(1)
                            HStack(spacing: 4) {
                                Text(account.serverURL.host ?? account.serverURL.absoluteString)
                                    .font(.system(size: 10))
                                    .foregroundStyle(.secondary)
                                    .lineLimit(1)
                                if session.isOffline {
                                    Image(systemName: "wifi.slash")
                                        .font(.system(size: 8, weight: .bold))
                                        .foregroundStyle(.orange)
                                        .help("Vault is offline")
                                }
                            }
                        }
                        Spacer(minLength: 0)
                    }
                    .padding(8)
                    .background(.ultraThinMaterial)
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .popover(isPresented: $showUserMenu, arrowEdge: .bottom) {
                    VStack(alignment: .leading, spacing: 4) {
                        Group {
                            PopoverButton(title: "Lock Vault") { showUserMenu = false; session.lock(requirePassword: true) }
                            
                            Divider()
                            
                            PopoverButton(title: "Sync Now", trailingText: lastSyncText) { showUserMenu = false; syncNow() }
                            if trashHidden {
                                PopoverButton(title: "Show Trashed Items") { showUserMenu = false; selectedFilter = .trash }
                            }
                            PopoverButton(title: "Edit Sidebar") {
                                showUserMenu = false
                                tempHiddenSidebarItems = hiddenSidebarItems
                                withAnimation {
                                    isEditingSidebar = true
                                }
                            }
                            PopoverButton(title: "Settings…") { showUserMenu = false; showSettings = true }
                            
                            Divider()
                            
                            PopoverButton(title: "Switch Account…") { showUserMenu = false; session.lock(requirePassword: true) }
                            PopoverButton(title: "Log Out…", isDestructive: true) { showUserMenu = false; showLogoutConfirmation = true }
                        }
                    }
                    .padding(8)
                    .frame(width: 220)
                }
            }
        }
    }
    
    private var lastSyncText: String? {
        guard let engine = try? session.getSyncEngine(), let date = engine.lastSyncDate else { return nil }
        let formatter = RelativeDateTimeFormatter()
        formatter.dateTimeStyle = .named
        return formatter.localizedString(for: date, relativeTo: Date())
    }

    @MainActor
    private func syncNow() {
        guard !isManualSyncing && !session.isSyncing else { return }
        guard let engine = try? session.getSyncEngine() else { return }
        
        isManualSyncing = true
        syncSuccess = false
        
        Task.detached {
            defer {
                Task { @MainActor in
                    self.isManualSyncing = false
                }
            }
            do {
                try await engine.fullSync()
                Task { @MainActor in
                    self.syncSuccess = true
                }
                try? await Task.sleep(nanoseconds: 2_000_000_000)
                Task { @MainActor in
                    self.syncSuccess = false
                }
            } catch {
                // Ignore error
            }
        }
    }

    // MARK: - Data Loading

    private func loadFolders() {
        guard let engine = try? session.getSyncEngine() else { return }
        if let persistedFolders = try? engine.fetchFolders() {
            folders = persistedFolders.compactMap { folder in
                let name = session.decrypt(try? VaultCrypto.EncString(serialized: folder.encryptedName)) ?? "Unnamed"
                return (id: folder.id, name: name)
            }
        }

        if let ciphers = try? engine.fetchCiphers(includeDeleted: true) {
            updateCounts(ciphers: ciphers)
        }

        if let sends = try? engine.fetchSends() {
            sendCount = sends.count
        }
    }

    private func updateCounts(ciphers: [PersistedCipher]) {
        var counts: [String: Int] = [
            "allItems": 0,
            "favorites": 0,
            "trash": 0,
            "temporaryCredentials": 0,
            "login": 0,
            "totp": 0,
            "wifi": 0,
            "secureNote": 0,
            "card": 0,
            "identity": 0,
            "sshKey": 0,
            "passkeys": 0
        ]
        var directFolderCounts: [String: Int] = ["__none__": 0]

        for persisted in ciphers {
            if persisted.isDeleted {
                counts["trash", default: 0] += 1
                continue
            }

            counts["allItems", default: 0] += 1
            if persisted.isFavorite {
                counts["favorites", default: 0] += 1
            }
            if persisted.syncStatus == .temporaryDraft {
                counts["temporaryCredentials", default: 0] += 1
            }

            if let folderId = persisted.folderId {
                directFolderCounts[folderId, default: 0] += 1
            } else {
                directFolderCounts["__none__", default: 0] += 1
            }

            guard let cipher = try? persisted.toCipher() else { continue }

            switch cipher.type {
            case .login:
                counts["login", default: 0] += 1
            case .secureNote:
                counts["secureNote", default: 0] += 1
            case .card:
                counts["card", default: 0] += 1
            case .identity:
                counts["identity", default: 0] += 1
            case .sshKey:
                counts["sshKey", default: 0] += 1
            }

            if cipher.type == .login,
               let totpEnc = cipher.login?.totp,
               let totpString = session.decrypt(totpEnc, itemKey: cipher.key),
               !totpString.isEmpty {
                counts["totp", default: 0] += 1
            }

            if cipher.isWifiCredential(decrypt: { session.decrypt($0, itemKey: cipher.key) }) {
                counts["wifi", default: 0] += 1
            }

            if cipher.type == .login, cipher.login?.fido2Credentials?.isEmpty == false {
                counts["passkeys", default: 0] += 1
            }
        }

        temporaryCredentialCount = counts["temporaryCredentials"] ?? 0
        itemTypeCounts = counts
        folderCounts = countsByFolderPath(directFolderCounts: directFolderCounts)
    }

    private func countsByFolderPath(directFolderCounts: [String: Int]) -> [String: Int] {
        var counts: [String: Int] = ["__none__": directFolderCounts["__none__"] ?? 0]
        let folderNamesById = Dictionary(uniqueKeysWithValues: folders.map { ($0.id, $0.name) })

        for (folderId, directCount) in directFolderCounts where folderId != "__none__" {
            guard let folderPath = folderNamesById[folderId] else { continue }
            let parts = folderPath.split(separator: "/").map(String.init)
            guard !parts.isEmpty else { continue }

            var currentPath = ""
            for part in parts {
                currentPath = currentPath.isEmpty ? part : "\(currentPath)/\(part)"
                counts[currentPath, default: 0] += directCount
            }
        }

        return counts
    }

    // MARK: - Folder CRUD

    private func createFolder() {
        let trimmed = newFolderName.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty else { return }

        Task {
            do {
                let encName = try session.encrypt(trimmed)
                let folder = Folder(id: UUID().uuidString, name: encName)
                
                if let engine = try? session.getSyncEngine() {
                    try engine.saveFolderLocally(folder, operation: .create)
                    loadFolders()
                    
                    Task {
                        try? await engine.fullSync()
                    }
                }
            } catch {
                folderError = error.localizedDescription
                // Re-show the alert with the error
                showNewFolderAlert = true
            }
        }
    }

    private func renameFolder() {
        guard let folderId = renamingFolderId else { return }
        let trimmed = renameFolderName.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty else { return }

        Task {
            do {
                let encName = try session.encrypt(trimmed)
                let folder = Folder(id: folderId, name: encName)

                if let engine = try? session.getSyncEngine() {
                    try engine.saveFolderLocally(folder, operation: .update)
                    loadFolders()
                    
                    Task {
                        try? await engine.fullSync()
                    }
                }
            } catch {
                folderError = error.localizedDescription
                showRenameAlert = true
            }
        }
    }

    private func deleteFolder() {
        guard let folderId = deletingFolderId else { return }

        Task {
            do {
                if let engine = try? session.getSyncEngine() {
                    let folder = Folder(id: folderId, name: nil)
                    try engine.saveFolderLocally(folder, operation: .delete)

                    // If we were viewing the deleted folder, go back to all items
                    if selectedFilter == .folder(folderId) {
                        selectedFilter = .allItems
                    }
                    loadFolders()

                    Task {
                        try? await engine.fullSync()
                    }
                }
            } catch {
                folderError = error.localizedDescription
            }
        }
    }

    // MARK: - Drag & Drop

    /// Handle items dropped onto a folder — could be cipher IDs or folder IDs.
    private func handleDrop(items: [String], ontoFolderId: String?, ontoFolderName: String) {
        var cipherIds: [String] = []
        var folderIds: [String] = []

        for item in items {
            if item.hasPrefix("folder:") {
                let folderId = String(item.dropFirst("folder:".count))
                if folderId != ontoFolderId { // Don't drop a folder onto itself
                    folderIds.append(folderId)
                }
            } else if item.hasPrefix("virtualfolder:") {
                // Cannot drop virtual folders
                continue
            } else {
                cipherIds.append(item)
            }
        }

        if !cipherIds.isEmpty {
            if let actualId = ontoFolderId {
                moveCiphersToFolder(cipherIds: cipherIds, folderId: actualId)
            }
        }

        for folderId in folderIds {
            moveFolderIntoFolder(folderId: folderId, parentFolderName: ontoFolderName)
        }
    }

    /// Move one or more ciphers to a folder (or to unfiled if folderId is nil).
    private func moveCiphersToFolder(cipherIds: [String], folderId: String?) {
        Task {
            do {
                guard let engine = try? session.getSyncEngine() else { return }
                let allCiphers = try engine.fetchCiphers(includeDeleted: false)
                
                for id in cipherIds {
                    if let persisted = allCiphers.first(where: { $0.id == id }),
                       var cipher = try? persisted.toCipher() {
                        cipher.folderId = folderId
                        try engine.saveCipherLocally(cipher, operation: .update)
                    }
                }

                loadFolders()
                onItemsMoved?()
                Task {
                    try? await engine.fullSync()
                }
            } catch {
                folderError = error.localizedDescription
            }
        }
    }

    /// Nest a folder inside another by prefixing its name with the parent's path.
    private func moveFolderIntoFolder(folderId: String, parentFolderName: String) {
        guard let sourceFolder = folders.first(where: { $0.id == folderId }) else { return }

        // Determine the leaf name — if it's already nested, just use the last component
        let leafName = sourceFolder.name.split(separator: "/").last.map(String.init) ?? sourceFolder.name
        let newName = "\(parentFolderName)/\(leafName)"

        // Don't nest if already nested under this parent
        guard sourceFolder.name != newName else { return }

        Task {
            do {
                let encName = try session.encrypt(newName)
                let folder = Folder(id: folderId, name: encName)

                if let engine = try? session.getSyncEngine() {
                    try engine.saveFolderLocally(folder, operation: .update)
                    loadFolders()
                    onItemsMoved?()

                    Task {
                        try? await engine.fullSync()
                    }
                }
            } catch {
                folderError = error.localizedDescription
            }
        }
    }
}

/// A recursive view that manually creates DisclosureGroups for folder trees.
/// This allows us to apply the .dropDestination and .springLoadingBehavior
/// to the entire group so that hovering auto-expands the folder natively.
struct FolderTreeView: View {
    let node: FolderNode
    @Binding var selectedFilter: SidebarFilter
    @Binding var dropTargetFolderId: String?
    
    // Bindings for context menu actions
    @Binding var renamingFolderId: String?
    @Binding var renameFolderName: String
    @Binding var folderError: String?
    @Binding var showRenameAlert: Bool
    @Binding var deletingFolderId: String?
    @Binding var deletingFolderName: String
    @Binding var showDeleteConfirmation: Bool
    let folderCounts: [String: Int]
    
    let handleDrop: ([String], String?, String) -> Void
    
    @State private var isExpanded: Bool = false
    @State private var isTargeted: Bool = false

    var body: some View {
        if let children = node.children {
            DisclosureGroup(isExpanded: $isExpanded) {
                ForEach(children) { childNode in
                    FolderTreeView(
                        node: childNode,
                        selectedFilter: $selectedFilter,
                        dropTargetFolderId: $dropTargetFolderId,
                        renamingFolderId: $renamingFolderId,
                        renameFolderName: $renameFolderName,
                        folderError: $folderError,
                        showRenameAlert: $showRenameAlert,
                        deletingFolderId: $deletingFolderId,
                        deletingFolderName: $deletingFolderName,
                        showDeleteConfirmation: $showDeleteConfirmation,
                        folderCounts: folderCounts,
                        handleDrop: handleDrop
                    )
                }
            } label: {
                folderLabel
                    .dropDestination(for: String.self) { droppedItems, _ in
                        handleDrop(droppedItems, node.actualId, node.id)
                        return true
                    } isTargeted: { targeted in
                        isTargeted = targeted
                        if targeted { dropTargetFolderId = node.id } else if dropTargetFolderId == node.id { dropTargetFolderId = nil }
                        if targeted {
                            // Manually expand when hovered
                            DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {
                                if isTargeted {
                                    withAnimation {
                                        isExpanded = true
                                    }
                                }
                            }
                        }
                    }
            }
        } else {
            folderLabel
                .dropDestination(for: String.self) { droppedItems, _ in
                    handleDrop(droppedItems, node.actualId, node.id)
                    return true
                } isTargeted: { targeted in
                    if targeted { dropTargetFolderId = node.id } else if dropTargetFolderId == node.id { dropTargetFolderId = nil }
                }
        }
    }
    
    private var folderLabel: some View {
        HStack {
            Label(node.name, systemImage: node.actualId != nil ? "folder.fill" : "folder")
            Spacer(minLength: 8)
            Text(folderCounts[node.id] ?? 0, format: .number)
                .font(.caption.weight(.medium))
                .monospacedDigit()
                .foregroundStyle(.secondary)
                .padding(.horizontal, 6)
                .padding(.vertical, 1)
                .background(Color.secondary.opacity(0.12))
                .clipShape(Capsule())
                .accessibilityLabel("\(folderCounts[node.id] ?? 0) items")
        }
            .tag(SidebarFilter.folder(node.tagId))
            .draggable(node.actualId != nil ? "folder:\(node.actualId!)" : "virtualfolder:\(node.id)")
            .listRowBackground(
                dropTargetFolderId == node.id
                    ? RoundedRectangle(cornerRadius: 6).fill(Color.accentColor.opacity(0.18))
                    : nil
            )
            .contextMenu {
                if let actualId = node.actualId {
                    Button {
                        renamingFolderId = actualId
                        renameFolderName = node.id
                        folderError = nil
                        showRenameAlert = true
                    } label: {
                        Label("Rename", systemImage: "pencil")
                    }

                    Divider()

                    Button(role: .destructive) {
                        deletingFolderId = actualId
                        deletingFolderName = node.name
                        showDeleteConfirmation = true
                    } label: {
                        Label("Delete", systemImage: "trash")
                    }
                }
            }
    }
}
struct PopoverButton: View {
    let title: String
    var trailingText: String? = nil
    var isDestructive: Bool = false
    let action: () -> Void
    
    @State private var isHovered = false
    
    var body: some View {
        Button(action: action) {
            HStack {
                Text(title)
                Spacer()
                if let trailingText {
                    Text(trailingText)
                        .font(.caption)
                        .foregroundStyle(isHovered ? .white.opacity(0.8) : .secondary)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.vertical, 4)
            .padding(.horizontal, 8)
            .foregroundStyle(isHovered ? .white : (isDestructive ? .red : .primary))
            .background(isHovered ? (isDestructive ? Color.red : Color.accentColor) : Color.clear)
            .clipShape(RoundedRectangle(cornerRadius: 4))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .onHover { hover in
            isHovered = hover
        }
    }
}
