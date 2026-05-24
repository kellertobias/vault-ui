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
    case totp
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
            // Vault section
            Section("Vault") {
                Label("All Items", systemImage: "tray.fill")
                    .tag(SidebarFilter.allItems)

                Label("Favorites", systemImage: "star.fill")
                    .tag(SidebarFilter.favorites)

                Label("Trash", systemImage: "trash")
                    .tag(SidebarFilter.trash)
            }

            // Types section
            Section("Types") {
                Label("TOTP Codes", systemImage: "clock.arrow.circlepath")
                    .tag(SidebarFilter.totp)

                ForEach(CipherType.allCases, id: \.rawValue) { type in
                    Label(type.displayName, systemImage: type.iconName)
                        .tag(SidebarFilter.type(type))
                }
            }

            // Folders section
            Section {
                Label("Uncategorized", systemImage: "folder")
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
                        handleDrop: handleDrop
                    )
                }
            } header: {
                HStack(spacing: 4) {
                    Text("Folders")
                    Button {
                        newFolderName = ""
                        folderError = nil
                        showNewFolderAlert = true
                    } label: {
                        Image(systemName: "plus")
                            .font(.system(size: 12, weight: .medium))
                            .foregroundStyle(.secondary)
                    }
                    .buttonStyle(.plain)
                    .help("New Folder")
                }
            }

            // Send section
            Section("Send") {
                Label("All Sends", systemImage: "paperplane.fill")
                    .tag(SidebarFilter.send)
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
    private var userMenu: some View {
        if let account = session.activeAccount {
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
                        
                        PopoverButton(title: "Sync Now") { showUserMenu = false; syncNow() }
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
        guard let persistedFolders = try? engine.fetchFolders() else { return }

        folders = persistedFolders.compactMap { folder in
            let name = session.decrypt(try? VaultCrypto.EncString(serialized: folder.encryptedName)) ?? "Unnamed"
            return (id: folder.id, name: name)
        }
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
                        handleDrop: handleDrop
                    )
                }
            } label: {
                folderLabel
            }
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
        Label(node.name, systemImage: node.actualId != nil ? "folder.fill" : "folder")
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
    var isDestructive: Bool = false
    let action: () -> Void
    
    @State private var isHovered = false
    
    var body: some View {
        Button(action: action) {
            Text(title)
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
