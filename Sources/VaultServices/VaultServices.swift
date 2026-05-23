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
import Network

private let logger = Logger(subsystem: "com.vaultui", category: "SessionManager")

/// Manages the full application session: login, unlock, lock, and vault key state.
///
/// This is the central coordinator that the UI interacts with for auth state.
@MainActor
public final class SessionManager: ObservableObject {

    /// Current authentication state
    @Published public var authState: AuthState = .locked
    @Published public var authStatusMessage: String = ""
    @Published public var biometricAttempted: Bool = false
    @Published public var activeAccount: Account?
    @Published public var accounts: [Account] = []

    @Published public var isOffline: Bool = false
    @Published public var forceOffline: Bool = false {
        didSet { updateOfflineState() }
    }
    private var networkOffline: Bool = false {
        didSet { updateOfflineState() }
    }
    private let pathMonitor = NWPathMonitor()

    private func updateOfflineState() {
        isOffline = forceOffline || networkOffline
    }

    /// When true, the unlock screen requires the master password (set by manual lock).
    /// Resets to false on app launch and after a successful password-based login.
    @Published public var requiresPasswordUnlock: Bool = false

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

    public init() {
        pathMonitor.pathUpdateHandler = { [weak self] path in
            Task { @MainActor [weak self] in
                self?.networkOffline = path.status != .satisfied
            }
        }
        pathMonitor.pathUpdateHandler?(pathMonitor.currentPath)
        pathMonitor.start(queue: DispatchQueue.global(qos: .background))
    }

    /// Whether biometric unlock is available for the current account.
    public var canUnlockWithBiometrics: Bool {
        guard !requiresPasswordUnlock else {
            logger.debug("canUnlockWithBiometrics: false — requiresPasswordUnlock is set")
            return false
        }
        guard let account = activeAccount else {
            logger.debug("canUnlockWithBiometrics: false — no active account")
            return false
        }
        let hasKeys = biometricKeyStorage.hasStoredKeys(for: account.id)
        if !hasKeys {
            logger.debug("canUnlockWithBiometrics: false — no stored keys for \(account.email)")
        }
        return hasKeys
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
                setupAPIClient(client)
                syncEngine = nil // Clear engine
        
        biometricAttempted = false
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
            // Create temporary account for prelogin.
            // If we already have an active account for this email+server, reuse its ID
            // so that the persisted device identifier is found (keyed by account ID).
            let matchedAccount = accounts.first { $0.email.lowercased() == email.lowercased() && $0.serverURL == serverURL }
            let existingId = activeAccount?.id ?? matchedAccount?.id
            var account = Account(id: existingId ?? UUID().uuidString, email: email, serverURL: serverURL)
            let tempClient = APIClient(account: account)
            let authService = AuthService(client: tempClient)

            // Step 1: Prelogin — get KDF config
            let kdfConfig: KDFConfig
            if isOffline {
                guard let storedKdf = matchedAccount?.kdfConfig else {
                    throw APIError.serverMessage("Cannot login offline for the first time.")
                }
                kdfConfig = storedKdf
            } else {
                kdfConfig = try await authService.prelogin(email: email)
            }
            
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

            if isOffline {
                authStatusMessage = "Authenticating offline..."
                guard let tokens = try? tokenStorage.loadTokens(for: account.id),
                      let encKeyString = tokens.encryptedKey else {
                    throw APIError.serverMessage("Cannot login offline: no cached vault data available.")
                }
                
                // Decrypt the vault key
                let stretchedKey = try masterKey.stretch()
                let protectedKey = try EncString(serialized: encKeyString)
                let vaultKey = try CipherEncryption.decryptProtectedSymmetricKey(
                    protectedKey,
                    stretchedMasterKey: stretchedKey
                )
                
                // Decrypt private key if available
                var privKeyData: Data?
                if let encPrivKey = tokens.encryptedPrivateKey {
                    let privKeyEnc = try EncString(serialized: encPrivKey)
                    privKeyData = try CipherEncryption.decryptData(privKeyEnc, key: vaultKey)
                }
                
                // Setup client without network call
                let client = APIClient(account: account, tokens: tokens)
                setupAPIClient(client)
                self.apiClient = client
                self.activeAccount = account
                self.vaultKey = vaultKey
                self.privateKeyData = privKeyData
                
                // Restore sync engine
                if let container = modelContainer {
                    let engine = SyncEngine(
                        apiClient: client,
                        modelContainer: container,
                        accountId: account.id
                    )
                    self.syncEngine = engine
                    // Export decrypted credential metadata for AutoFill extension
                    SharedCredentialStore.shared.exportCredentials(from: engine, session: self)
                }
                
                requiresPasswordUnlock = false
                authStatusMessage = ""
                authState = .unlocked
                startBackgroundServices()
                logger.info("Offline login successful for \(email)")
                return
            }

            // Step 4: Login to server
            let client = APIClient(account: account)
            setupAPIClient(client)
            let loginService = AuthService(client: client)

            let loginResult: AuthService.LoginResult
            let persistedDeviceId = APIClient.getOrCreateDeviceId(for: account)
            do {
                loginResult = try await loginService.login(
                    AuthService.LoginRequest(
                        email: email,
                        masterPasswordHash: passwordHash,
                        deviceId: persistedDeviceId,
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
            do {
                try biometricKeyStorage.storeKeys(
                    vaultKey: vaultKey,
                    privateKey: privKeyData,
                    for: account.id
                )
            } catch {
                logger.error("Failed to store biometric keys: \(error.localizedDescription)")
            }

            // Clear the manual-lock flag after a successful password login
            requiresPasswordUnlock = false

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
            logger.error("unlockWithBiometrics: no active account")
            throw BiometricError.noStoredKeys
        }

        let context = LAContext()
        var error: NSError?

        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            logger.error("unlockWithBiometrics: biometrics not available — \(error?.localizedDescription ?? "unknown")")
            throw BiometricError.biometricNotAvailable
        }

        // Check if we have stored keys before prompting Touch ID
        guard biometricKeyStorage.hasStoredKeys(for: account.id) else {
            // No stored keys — must sign in with password first
            logger.warning("unlockWithBiometrics: no stored biometric keys for \(account.email)")
            authState = .loginRequired
            return
        }

        logger.info("unlockWithBiometrics: starting Touch ID prompt for \(account.email)")

        biometricAttempted = true
        authState = .unlocking

        do {
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
            setupAPIClient(client)
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
        } catch {
            authState = .locked
            throw error
        }
    }

    // MARK: - Lock

    /// Lock the vault — zero key material from memory, then release references.
    ///
    /// - Parameter requirePassword: If `true`, the next unlock must use the master
    ///   password (Touch ID is suppressed). This flag is in-memory only, so a fresh
    ///   app launch always allows Touch ID.
    public func lock(requirePassword: Bool = false) {
        if requirePassword {
            requiresPasswordUnlock = true
            logger.info("Manual lock — master password required for next unlock")
        }

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

    // MARK: - API Client Setup

    private func setupAPIClient(_ client: APIClient) {
        Task {
            await client.setTokensUpdatedCallback { [weak self] tokens in
                guard let self = self else { return }
                Task { @MainActor in
                    if let account = self.activeAccount {
                        try? self.tokenStorage.saveTokens(tokens, for: account.id)
                    }
                }
            }
            await client.setSessionExpiredCallback { [weak self] in
                Task { @MainActor in
                    self?.handleSessionExpired()
                }
            }
        }
    }

    public func handleSessionExpired() {
        guard let account = activeAccount else { return }
        logger.warning("Session expired - logging out")
        try? tokenStorage.deleteTokens(for: account.id)
        self.lock(requirePassword: true)
        self.authState = .loginRequired
        self.authStatusMessage = "Session expired. Please log in again."
    }
}
