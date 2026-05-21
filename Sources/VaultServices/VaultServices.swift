// MARK: - VaultServices/SessionManager.swift
// Manages the authenticated session and vault unlock state

import Foundation
import VaultCrypto
import VaultModels
import VaultAPI
import VaultSync
import SwiftData
import LocalAuthentication
import OSLog

private let logger = Logger(subsystem: "com.vaultui", category: "SessionManager")

/// Manages the full application session: login, unlock, lock, and vault key state.
///
/// This is the central coordinator that the UI interacts with for auth state.
@MainActor
public final class SessionManager: ObservableObject {

    /// Current authentication state
    @Published public var authState: AuthState = .locked
    @Published public var authStatusMessage: String = ""
    @Published public var activeAccount: Account?
    @Published public var accounts: [Account] = []

    /// The decrypted vault key — only in memory, never persisted
    private var vaultKey: SymmetricCryptoKey?

    /// The decrypted private key for org operations
    private var privateKeyData: Data?

    private var apiClient: APIClient?
    private var syncEngine: SyncEngine?
    private var syncScheduler: SyncScheduler?
    private var modelContainer: ModelContainer?
    private var lockTimer: Timer?

    private let tokenStorage = TokenStorage()
    private let biometricKeyStorage = BiometricKeyStorage()

    public enum AuthState: Equatable {
        case noAccount
        case locked
        case unlocking
        case unlocked
        case loginRequired
        case twoFactorRequired(providers: [Int])
        case error(String)
    }

    public init() {}

    /// Whether biometric unlock is available for the current account.
    public var canUnlockWithBiometrics: Bool {
        guard let account = activeAccount else { return false }
        return biometricKeyStorage.hasStoredKeys(for: account.id)
    }

    // MARK: - Setup

    /// Initialize with a model container.
    public func setup(modelContainer: ModelContainer) async {
        self.modelContainer = modelContainer
        await loadAccounts()
    }

    /// Load persisted accounts from SwiftData.
    private func loadAccounts() async {
        guard let container = modelContainer else { return }
        let context = container.mainContext

        let descriptor = FetchDescriptor<PersistedAccount>()
        guard let persistedAccounts = try? context.fetch(descriptor) else { return }

        accounts = persistedAccounts.compactMap { $0.toAccount() }

        if let active = persistedAccounts.first(where: { $0.isActive }),
           let account = active.toAccount() {
            activeAccount = account
            // Try to restore session from stored tokens
            if let tokens = try? tokenStorage.loadTokens(for: account.id) {
                let client = APIClient(account: account, tokens: tokens)
                self.apiClient = client
                authState = .locked  // Require unlock (Touch ID or password)
            } else {
                authState = .loginRequired
            }
        } else if accounts.isEmpty {
            authState = .noAccount
        } else {
            authState = .loginRequired
        }
    }

    // MARK: - Login

    /// Perform full login flow.
    public func login(
        email: String,
        password: String,
        serverURL: URL,
        twoFactorProvider: TwoFactorProviderType? = nil,
        twoFactorToken: String? = nil
    ) async throws {
        authStatusMessage = "Connecting to server..."

        do {
            // Create temporary account for prelogin
            var account = Account(email: email, serverURL: serverURL)
            let tempClient = APIClient(account: account)
            let authService = AuthService(client: tempClient)

            // Step 1: Prelogin — get KDF config
            let kdfConfig = try await authService.prelogin(email: email)
            account = Account(
                id: account.id,
                email: email,
                serverURL: serverURL,
                kdfConfig: kdfConfig
            )

            authStatusMessage = "Deriving master key..."
            // Step 2: Derive master key
            let masterKey = try MasterKey.derive(
                password: password,
                email: email,
                kdfConfig: kdfConfig
            )

            authStatusMessage = "Logging in..."
            // Step 3: Compute auth hash
            let passwordHash = try MasterPasswordHash.compute(
                masterKey: masterKey,
                password: password
            )

            // Step 4: Login to server
            let client = APIClient(account: account)
            let loginService = AuthService(client: client)

            let loginResult: AuthService.LoginResult
            do {
                loginResult = try await loginService.login(
                    AuthService.LoginRequest(
                        email: email,
                        masterPasswordHash: passwordHash,
                        twoFactorProvider: twoFactorProvider,
                        twoFactorToken: twoFactorToken
                    )
                )
            } catch let error as APIError {
                if case .twoFactorRequired(let providers) = error {
                    self.apiClient = client
                    self.activeAccount = account
                    authState = .twoFactorRequired(providers: providers)
                    authStatusMessage = ""
                    // Store master key temporarily for after 2FA
                    return
                }
                throw error
            }

            authStatusMessage = "Decrypting vault..."
            // Step 5: Decrypt the vault key
            let stretchedKey = try masterKey.stretch()
            guard let encKeyString = loginResult.tokens.encryptedKey else {
                throw APIError.serverMessage("Server did not return encrypted key")
            }
            let protectedKey = try EncString(serialized: encKeyString)
            let vaultKey = try CipherEncryption.decryptProtectedSymmetricKey(
                protectedKey,
                stretchedMasterKey: stretchedKey
            )

            // Step 6: Decrypt private key if available
            var privKeyData: Data?
            if let encPrivKey = loginResult.tokens.encryptedPrivateKey {
                let privKeyEnc = try EncString(serialized: encPrivKey)
                privKeyData = try CipherEncryption.decryptData(privKeyEnc, key: vaultKey)
            }

            authStatusMessage = "Syncing vault data..."
            // Step 7: Save state
            self.apiClient = client
            self.activeAccount = account
            self.vaultKey = vaultKey
            self.privateKeyData = privKeyData

            // Persist account and tokens
            try tokenStorage.saveTokens(loginResult.tokens, for: account.id)
            try persistAccount(account, isActive: true)

            // Step 8: Perform initial sync
            if let container = modelContainer {
                let engine = SyncEngine(
                    apiClient: client,
                    modelContainer: container,
                    accountId: account.id
                )
                self.syncEngine = engine
                try await engine.fullSync()

                // Export decrypted credential metadata for AutoFill extension
                SharedCredentialStore.shared.exportCredentials(from: engine, session: self)
            }

            // Step 9: Store keys for future biometric unlock
            try? biometricKeyStorage.storeKeys(
                vaultKey: vaultKey,
                privateKey: privKeyData,
                for: account.id
            )

            authStatusMessage = ""
            authState = .unlocked
            startBackgroundServices()
            logger.info("Login successful for \(email)")

        } catch {
            authStatusMessage = ""
            throw error
        }
    }

    // MARK: - Unlock (Touch ID / Password)

    /// Unlock the vault using Touch ID.
    ///
    /// Retrieves the vault key from the Keychain using a biometric-protected item.
    /// The key was stored there during the last successful password-based login.
    public func unlockWithBiometrics() async throws {
        guard let account = activeAccount else {
            throw BiometricError.noStoredKeys
        }

        let context = LAContext()
        var error: NSError?

        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            throw BiometricError.biometricNotAvailable
        }

        // Check if we have stored keys before prompting Touch ID
        guard biometricKeyStorage.hasStoredKeys(for: account.id) else {
            // No stored keys — must sign in with password first
            authState = .loginRequired
            return
        }

        authState = .unlocking

        // Authenticate with Touch ID
        let success = try await context.evaluatePolicy(
            .deviceOwnerAuthenticationWithBiometrics,
            localizedReason: "Unlock Vault UI"
        )

        guard success else {
            authState = .locked
            throw BiometricError.biometricFailed
        }

        // Retrieve vault key using the authenticated context (no second prompt)
        let (vaultKey, privateKey) = try biometricKeyStorage.retrieveKeys(
            for: account.id,
            context: context
        )

        self.vaultKey = vaultKey
        self.privateKeyData = privateKey

        // Restore API client from stored tokens
        let loadedTokens = try? tokenStorage.loadTokens(for: account.id)
        guard let tokens = loadedTokens.flatMap({ $0 }) else {
            // Tokens expired or missing — must re-authenticate with password
            self.vaultKey = nil
            self.privateKeyData = nil
            authState = .loginRequired
            logger.warning("Biometric unlock succeeded but tokens are missing — requiring password login")
            return
        }

        let client = APIClient(account: account, tokens: tokens)
        self.apiClient = client

        // Restore sync engine
        if let container = modelContainer {
            let engine = SyncEngine(
                apiClient: client,
                modelContainer: container,
                accountId: account.id
            )
            self.syncEngine = engine

            // Background sync to pick up any changes while locked
            Task { [weak self] in
                try? await engine.fullSync()
                // Export decrypted credential metadata for AutoFill extension
                if let self = self {
                    SharedCredentialStore.shared.exportCredentials(from: engine, session: self)
                }
            }
        }

        authState = .unlocked
        startBackgroundServices()
        logger.info("Vault unlocked via Touch ID for \(account.email)")
    }

    // MARK: - Lock

    /// Lock the vault — zero key material from memory, then release references.
    public func lock() {
        // Zero key material before releasing (defense against memory forensics)
        if vaultKey != nil {
            vaultKey!.zeroize()
        }
        vaultKey = nil

        if privateKeyData != nil {
            privateKeyData!.resetBytes(in: privateKeyData!.startIndex ..< privateKeyData!.endIndex)
        }
        privateKeyData = nil

        stopBackgroundServices()
        syncEngine = nil
        authState = .locked
        logger.info("Vault locked")
    }

    // MARK: - Background Services

    /// Start background sync scheduler and lock timeout timer.
    private func startBackgroundServices() {
        // Sync scheduler
        if let engine = syncEngine {
            let scheduler = SyncScheduler(syncEngine: engine)
            let savedInterval = UserDefaults.standard.integer(forKey: "syncInterval")
            if savedInterval > 0 {
                scheduler.interval = TimeInterval(savedInterval * 60)  // stored in minutes
            }
            scheduler.start()
            self.syncScheduler = scheduler
        }

        // Lock timeout
        resetLockTimer()
    }

    /// Stop background services.
    private func stopBackgroundServices() {
        syncScheduler?.stop()
        syncScheduler = nil
        lockTimer?.invalidate()
        lockTimer = nil
    }

    /// Reset the lock timeout timer (call on user activity).
    public func resetLockTimer() {
        lockTimer?.invalidate()
        let timeout = UserDefaults.standard.integer(forKey: "lockTimeout")
        guard timeout > 0 else {
            lockTimer = nil
            return
        }

        lockTimer = Timer.scheduledTimer(withTimeInterval: TimeInterval(timeout * 60), repeats: false) { [weak self] _ in
            Task { @MainActor [weak self] in
                self?.lock()
                logger.info("Auto-locked after \(timeout) minute timeout")
            }
        }
    }

    // MARK: - Vault Key Access

    /// Get the vault key for decryption (only available when unlocked).
    public func getVaultKey() throws -> SymmetricCryptoKey {
        guard let key = vaultKey else {
            throw CryptoError.missingKey("Vault is locked")
        }
        return key
    }

    /// Get the API client.
    public func getAPIClient() throws -> APIClient {
        guard let client = apiClient else {
            throw APIError.noAccessToken
        }
        return client
    }

    /// Get the sync engine.
    public func getSyncEngine() throws -> SyncEngine {
        guard let engine = syncEngine else {
            throw SyncError.databaseError("Sync engine not initialized")
        }
        return engine
    }

    // MARK: - Decrypt Helpers

    /// Decrypt an EncString using the item key (if provided) or the vault key.
    public func decrypt(_ encString: EncString?, itemKey: EncString? = nil) -> String? {
        guard let encString = encString, let vKey = vaultKey else { return nil }
        
        let decryptionKey: SymmetricCryptoKey
        if let itemKey = itemKey,
           let keyData = try? CipherEncryption.decryptData(itemKey, key: vKey),
           let derivedKey = try? SymmetricCryptoKey(keyData: keyData) {
            decryptionKey = derivedKey
        } else {
            decryptionKey = vKey
        }
        
        return try? CipherEncryption.decryptString(encString, key: decryptionKey)
    }

    /// Encrypt a string using the vault key.
    public func encrypt(_ string: String) throws -> EncString {
        guard let key = vaultKey else {
            throw CryptoError.missingKey("Vault is locked")
        }
        return try CipherEncryption.encrypt(string: string, key: key)
    }

    /// Generate a new 512-bit item key and return its encrypted format using the vault key.
    public func generateItemKey() throws -> (SymmetricCryptoKey, EncString) {
        guard let vKey = vaultKey else {
            throw CryptoError.missingKey("Vault is locked")
        }
        let itemKey = try SymmetricCryptoKey.generate()
        let encryptedItemKey = try CipherEncryption.encrypt(data: itemKey.keyData, key: vKey)
        return (itemKey, encryptedItemKey)
    }

    /// Encrypt a string using a specific item key.
    public func encrypt(_ string: String, using key: SymmetricCryptoKey) throws -> EncString {
        return try CipherEncryption.encrypt(string: string, key: key)
    }

    /// Extract the symmetric key for a cipher (falls back to vaultKey if cipher.key is nil)
    public func getItemKey(for cipher: Cipher) throws -> SymmetricCryptoKey {
        guard let vKey = vaultKey else {
            throw CryptoError.missingKey("Vault is locked")
        }
        if let keyEnc = cipher.key,
           let keyData = try? CipherEncryption.decryptData(keyEnc, key: vKey) {
            return try SymmetricCryptoKey(keyData: keyData)
        }
        return vKey
    }

    // MARK: - Account Management

    private func persistAccount(_ account: Account, isActive: Bool) throws {
        guard let container = modelContainer else { return }
        let context = container.mainContext

        // Deactivate all other accounts
        if isActive {
            let allAccounts = FetchDescriptor<PersistedAccount>()
            if let existing = try? context.fetch(allAccounts) {
                for acc in existing { acc.isActive = false }
            }
        }

        // Upsert this account
        let accountId = account.id
        let descriptor = FetchDescriptor<PersistedAccount>(
            predicate: #Predicate { $0.id == accountId }
        )
        if let existing = try? context.fetch(descriptor).first {
            existing.email = account.email
            existing.serverURLString = account.serverURL.absoluteString
            existing.kdfTypeRawValue = account.kdfConfig.type.rawValue
            existing.kdfIterations = Int(account.kdfConfig.iterations)
            existing.isActive = isActive
        } else {
            let persisted = PersistedAccount.from(account: account)
            persisted.isActive = isActive
            context.insert(persisted)
        }

        try context.save()

        if !accounts.contains(where: { $0.id == account.id }) {
            accounts.append(account)
        }
    }
}
