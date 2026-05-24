// MARK: - VaultAppUI/MainVaultView.swift
// Main three-column vault layout

import SwiftUI
import VaultModels
import VaultServices
import VaultSync

/// Wrapper to make a cipher ID work with sheet(item:).
struct EditSheetItem: Identifiable {
    let id: String
}

/// Wrapper to make a cipher type work with sheet(item:).
struct CreateSheetItem: Identifiable {
    let id = UUID()
    let type: CipherType
}

/// The main vault view with a three-column layout:
/// - Sidebar: folders, types, account switcher
/// - Content: cipher list
/// - Detail: selected cipher details
struct MainVaultView: View {
    @EnvironmentObject var session: SessionManager
    @State private var selectedFilter: SidebarFilter = .allItems
    @State private var selectedCipherIds: Set<String> = []
    @State private var searchText = ""
    @State private var columnVisibility = NavigationSplitViewVisibility.all
    @State private var showPasswordGenerator = false
    @State private var createSheetItem: CreateSheetItem?
    @State private var editSheetItem: EditSheetItem?
    @State private var showSettings = false
    @State private var showImport = false
    @State private var refreshToken = 0
    @State private var isManualSyncing = false
    @State private var syncSuccess = false

    @State private var showLogoutConfirmation = false

    var body: some View {
        NavigationSplitView(columnVisibility: $columnVisibility) {
            SidebarView(selectedFilter: $selectedFilter, onItemsMoved: {
                refreshToken += 1
            })
        } content: {
            if selectedFilter == .send {
                SendListView()
                    .navigationSplitViewColumnWidth(min: 300, ideal: 340, max: 500)
            } else {
                CipherListView(
                    filter: selectedFilter,
                    searchText: $searchText,
                    selectedCipherIds: $selectedCipherIds,
                    refreshToken: refreshToken
                )
                .navigationSplitViewColumnWidth(min: 300, ideal: 340, max: 500)
            }
        } detail: {
            if selectedCipherIds.count == 1, let cipherId = selectedCipherIds.first {
                CipherDetailView(
                    cipherId: cipherId,
                    refreshToken: refreshToken,
                    onEdit: { id in editCipher(id: id) },
                    onDelete: {
                        selectedCipherIds.remove(cipherId)
                        refreshToken += 1
                    },
                    onFavoriteToggled: {
                        refreshToken += 1
                    }
                )
            } else if selectedCipherIds.count > 1 {
                MultiSelectMergeView(cipherIds: selectedCipherIds) {
                    selectedCipherIds.removeAll()
                    refreshToken += 1
                    // Push the local merge changes to the server
                    Task {
                        if let engine = try? session.getSyncEngine() {
                            try? await engine.fullSync()
                        }
                    }
                }
            } else {
                EmptyDetailView()
            }
        }
        .searchable(text: $searchText, prompt: "Search vault…")
        .toolbar {
            ToolbarItemGroup(placement: .primaryAction) {
                Button {
                    showPasswordGenerator = true
                } label: {
                    Image(systemName: "key.fill")
                }
                .help("Password Generator")

                Button {
                    syncNow()
                } label: {
                    if isManualSyncing || session.isSyncing {
                        ProgressView()
                            .controlSize(.small)
                    } else if syncSuccess {
                        Image(systemName: "checkmark")
                            .foregroundStyle(.green)
                    } else {
                        Image(systemName: "arrow.triangle.2.circlepath")
                    }
                }
                .help("Sync Now")
                .disabled(session.isOffline || isManualSyncing || session.isSyncing)

                Menu {
                    Button("Add Login") { addCipher(.login) }
                    Button("Add Secure Note") { addCipher(.secureNote) }
                    Button("Add Card") { addCipher(.card) }
                    Button("Add Identity") { addCipher(.identity) }
                    Button("Add SSH Key") { addCipher(.sshKey) }
                } label: {
                    Image(systemName: "plus")
                }
                .help("Add Item")
                .disabled(session.isOffline)
            }

            ToolbarItem(placement: .navigation) {
                if session.isOffline {
                    Image(systemName: "wifi.slash")
                        .font(.system(size: 11, weight: .bold))
                        .frame(width: 24, height: 24)
                        .background(.orange.opacity(0.2))
                        .foregroundStyle(.orange)
                        .clipShape(Circle())
                        .padding(.leading, 6) // small left padding inside the offline button
                        .padding(.trailing, 2)
                        .help("Vault is currently offline. You are in read-only mode.")
                }
            }

            ToolbarItem(placement: .navigation) {
                // Account indicator
                if let account = session.activeAccount {
                    Menu {
                        Section(account.email) {
                            Button("Switch Account…") { session.lock(requirePassword: true) }
                            Divider()
                            Button("Import Data…") { showImport = true }
                            Button("Settings…") { showSettings = true }
                            Divider()
                            if session.forceOffline {
                                Button("Go Online (Test)") { session.forceOffline = false }
                            } else {
                                Button("Go Offline (Test)") { session.forceOffline = true }
                            }
                            Divider()
                            Button("Lock Vault") { session.lock(requirePassword: true) }
                            Button("Log Out…", role: .destructive) {
                                showLogoutConfirmation = true
                            }
                        }
                    } label: {
                        let parts = account.email.split(separator: "@").first ?? ""
                        let first = parts.prefix(1).uppercased()
                        let letter = first.isEmpty ? "?" : String(first)
                        // Inject physical spaces to force the macOS menu button to widen
                        let paddedText = session.isOffline ? " \(letter)    " : "   \(letter)   "
                        Text(paddedText)
                            .font(.system(size: 14, weight: .semibold, design: .rounded))
                    }
                    .menuStyle(.borderlessButton)
                    .menuIndicator(.hidden)
                }
            }
        }
        .alert("Log Out?", isPresented: $showLogoutConfirmation) {
            Button("Cancel", role: .cancel) {}
            Button("Log Out", role: .destructive) {
                session.logout()
            }
        } message: {
            Text("This will delete all local vault data, saved credentials, and device registration. Your server data will not be affected. You will need to log in again and re-verify your device.")
        }
        .sheet(isPresented: $showPasswordGenerator) {
            PasswordGeneratorView()
                .frame(minWidth: 400, minHeight: 500)
        }
        .sheet(item: $createSheetItem, onDismiss: { refreshToken += 1 }) { item in
            CipherEditView(mode: .create(item.type))
                .environmentObject(session)
                .frame(minWidth: 500, minHeight: 600)
        }
        .sheet(item: $editSheetItem, onDismiss: { refreshToken += 1 }) { item in
            CipherEditView(mode: .edit(item.id))
                .environmentObject(session)
                .frame(minWidth: 500, minHeight: 600)
        }
        .sheet(isPresented: $showSettings) {
            SettingsView()
                .frame(minWidth: 500, minHeight: 420)
        }
        .sheet(isPresented: $showImport) {
            ImportView()
        }
        .onChange(of: selectedCipherIds) { _, _ in session.resetLockTimer() }
        .onChange(of: searchText) { _, _ in session.resetLockTimer() }
    }

    private func addCipher(_ type: CipherType) {
        createSheetItem = CreateSheetItem(type: type)
    }

    func editCipher(id: String) {
        editSheetItem = EditSheetItem(id: id)
    }

    @MainActor
    private func syncNow() {
        guard !isManualSyncing && !session.isSyncing else { return }
        isManualSyncing = true
        syncSuccess = false
        Task {
            defer { isManualSyncing = false }
            guard let engine = try? session.getSyncEngine() else { return }
            do {
                try await engine.fullSync()
                syncSuccess = true
                Task { @MainActor in
                    try? await Task.sleep(nanoseconds: 2_000_000_000)
                    syncSuccess = false
                }
            } catch {
                // Ignore error, maybe log it
            }
        }
    }
}

/// Empty detail placeholder.
struct EmptyDetailView: View {
    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: "shield.lefthalf.filled")
                .font(.system(size: 64))
                .foregroundStyle(.quaternary)
            Text("Select an item")
                .font(.title3)
                .foregroundStyle(.secondary)
            Text("Choose an item from the list to view its details.")
                .font(.caption)
                .foregroundStyle(.tertiary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

/// Small avatar circle with initials.
struct AccountAvatarView: View {
    let email: String
    let size: CGFloat

    var body: some View {
        ZStack {
            Circle()
                .fill(
                    .linearGradient(
                        colors: [.blue, .purple],
                        startPoint: .topLeading,
                        endPoint: .bottomTrailing
                    )
                )
            Text(initials)
                .font(.system(size: size * 0.4, weight: .semibold, design: .rounded))
                .foregroundStyle(.white)
        }
        .frame(width: size, height: size)
    }

    private var initials: String {
        let parts = email.split(separator: "@").first ?? ""
        let first = parts.prefix(1).uppercased()
        return first.isEmpty ? "?" : first
    }
}
