// MARK: - VaultAppUI/OrganizationOwnershipView.swift
// Choosing who owns an item: this account, or one of its organizations.

import SwiftUI
import VaultModels
import VaultServices

/// Picks an owner (personal vault or an organization) and, for an organization,
/// the collections the item goes into.
///
/// An organization-owned item must sit in at least one collection or nobody can
/// see it, so the first writable collection is selected automatically. While an
/// organization is selected, the view warns that the move cannot be undone.
struct OrganizationOwnershipView: View {
    @EnvironmentObject var session: SessionManager

    /// nil = personal vault.
    @Binding var organizationId: String?
    @Binding var collectionIds: Set<String>

    /// Whether the owner itself can still be changed (false once an item is shared).
    var allowsOwnerChange: Bool = true

    private var organizations: [(id: String, name: String)] {
        session.organizationsAvailableForNewItems
    }

    private var collections: [(id: String, name: String)] {
        guard let organizationId else { return [] }
        return session.writableCollections(inOrganization: organizationId)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            if allowsOwnerChange {
                Picker("Owner", selection: $organizationId) {
                    Text("My Vault").tag(String?.none)
                    ForEach(organizations, id: \.id) { organization in
                        Text(organization.name).tag(String?.some(organization.id))
                    }
                }
                .pickerStyle(.menu)
                .onChange(of: organizationId) { _, _ in
                    selectDefaultCollection()
                }
            }

            if organizationId != nil {
                if collections.isEmpty {
                    Label(
                        "This organization has no collection you can write to.",
                        systemImage: "exclamationmark.triangle"
                    )
                    .font(.caption)
                    .foregroundStyle(.orange)
                } else {
                    Text("Collections")
                        .font(.caption)
                        .foregroundStyle(.secondary)

                    ForEach(collections, id: \.id) { collection in
                        Toggle(collection.name, isOn: binding(for: collection.id))
                            .toggleStyle(.checkbox)
                    }

                    if collectionIds.isEmpty {
                        Text("Pick at least one collection.")
                            .font(.caption2)
                            .foregroundStyle(.red)
                    }
                }

                // Shown for as long as an organization is selected, not just at
                // save time: sharing cannot be undone.
                Label {
                    Text("Everyone with access to the selected collections can read this item. It cannot be moved back to your personal vault afterwards.")
                        .fixedSize(horizontal: false, vertical: true)
                } icon: {
                    Image(systemName: "exclamationmark.triangle.fill")
                }
                .font(.caption)
                .foregroundStyle(.orange)
            }
        }
        .onAppear { selectDefaultCollection() }
    }

    private func binding(for collectionId: String) -> Binding<Bool> {
        Binding(
            get: { collectionIds.contains(collectionId) },
            set: { isOn in
                if isOn {
                    collectionIds.insert(collectionId)
                } else {
                    collectionIds.remove(collectionId)
                }
            }
        )
    }

    /// Keep the selection valid when the owner changes: drop collections that
    /// belong to another organization, and preselect one so the common case is a
    /// single click.
    private func selectDefaultCollection() {
        guard organizationId != nil else {
            collectionIds = []
            return
        }
        let available = Set(collections.map(\.id))
        collectionIds.formIntersection(available)
        if collectionIds.isEmpty, let first = collections.first {
            collectionIds = [first.id]
        }
    }
}

/// Sheet for moving an existing personal item into an organization.
///
/// The move is one-way (Bitwarden has no "unshare"), so the sheet shows that
/// warning and the confirm button reads "Share Permanently".
struct ShareToOrganizationSheet: View {
    @EnvironmentObject var session: SessionManager

    let cipher: Cipher
    let itemName: String
    var onShared: (Cipher) -> Void

    @Environment(\.dismiss) private var dismiss

    @State private var organizationId: String?
    @State private var collectionIds: Set<String> = []
    @State private var isSharing = false
    @State private var errorMessage: String?

    private var canShare: Bool {
        organizationId != nil && !collectionIds.isEmpty && !isSharing && !session.isOffline
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Share “\(itemName)”")
                .font(.title3.bold())

            OrganizationOwnershipView(
                organizationId: $organizationId,
                collectionIds: $collectionIds
            )

            if cipher.attachments?.isEmpty == false {
                Label(
                    "Attachments move with the item.",
                    systemImage: "paperclip"
                )
                .font(.caption2)
                .foregroundStyle(.secondary)
            }

            if let errorMessage {
                Text(errorMessage)
                    .font(.caption)
                    .foregroundStyle(.red)
                    .fixedSize(horizontal: false, vertical: true)
                    .textSelection(.enabled)
            }

            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button {
                    share()
                } label: {
                    if isSharing {
                        ProgressView().controlSize(.small)
                    } else {
                        Text("Share Permanently")
                    }
                }
                .buttonStyle(.borderedProminent)
                .keyboardShortcut(.defaultAction)
                .disabled(!canShare)
            }
        }
        .padding(20)
        .frame(width: 420)
        .onAppear {
            if organizationId == nil {
                organizationId = session.organizationsAvailableForNewItems.first?.id
            }
        }
    }

    private func share() {
        guard let organizationId else { return }
        isSharing = true
        errorMessage = nil

        Task {
            do {
                let shared = try await session.shareCipher(
                    cipher,
                    withOrganization: organizationId,
                    collectionIds: Array(collectionIds)
                )
                isSharing = false
                onShared(shared)
                dismiss()
            } catch {
                isSharing = false
                errorMessage = error.localizedDescription
            }
        }
    }
}
