// MARK: - VaultServices/CipherKeyRewrap.swift
// Re-encrypting a cipher's fields from one key to another.

import Foundation
import VaultModels
import VaultCrypto

/// Moves a cipher's encrypted fields from one symmetric key to another.
///
/// Needed when a personal item joins an organization. Two cases:
///
/// - The cipher has its own **item key**: only that key's wrapper changes (vault
///   key → org key). Every field, and every attachment key, stays exactly as it
///   is, because they are all encrypted under the item key, which is unchanged.
///   This is the safe path and the one modern items take.
/// - The cipher has **no item key** (pre-2023 items encrypt fields directly under
///   the vault key): every field has to be decrypted and re-encrypted under a
///   fresh item key. That is what `rewrapFields` does.
///
/// Every field is moved via raw *data*, not strings, so non-UTF-8 payloads (an
/// attachment key, for example) survive unchanged.
enum CipherKeyRewrap {

    enum RewrapError: Error, LocalizedError {
        case attachmentWithoutKey(String)

        var errorDescription: String? {
            switch self {
            case .attachmentWithoutKey(let fileName):
                return """
                    Attachment \"\(fileName)\" predates per-attachment keys and would have to be \
                    re-uploaded to be shared. Remove it, or share this item from an official \
                    Bitwarden client.
                    """
            }
        }
    }

    /// Re-encrypt every encrypted field of a cipher from `oldKey` to `newKey`.
    ///
    /// Only for ciphers with no item key of their own. Attachments are re-keyed
    /// too; an attachment with no key at all cannot be re-keyed without
    /// re-uploading its ciphertext, so that is refused rather than silently
    /// leaving it unreadable.
    static func rewrapFields(
        _ cipher: Cipher,
        from oldKey: SymmetricCryptoKey,
        to newKey: SymmetricCryptoKey
    ) throws -> Cipher {
        var result = cipher

        let move: (EncString?) throws -> EncString? = { encString in
            guard let encString else { return nil }
            let plaintext = try CipherEncryption.decryptData(encString, key: oldKey)
            return try CipherEncryption.encrypt(data: plaintext, key: newKey)
        }

        result.name = try move(cipher.name)
        result.notes = try move(cipher.notes)

        if var login = cipher.login {
            login.username = try move(login.username)
            login.password = try move(login.password)
            login.totp = try move(login.totp)

            if let uris = login.uris {
                login.uris = try uris.map { uri in
                    guard let encryptedUri = uri.uri else { return uri }
                    // Re-encrypt the URI and recompute its checksum under the new
                    // key. The item gains an item key here, which is exactly when
                    // official clients start requiring the checksum.
                    let plaintext = try CipherEncryption.decryptString(encryptedUri, key: oldKey)
                    return try LoginUri.encrypted(plaintext, match: uri.match, key: newKey)
                }
            }

            if let credentials = login.fido2Credentials {
                login.fido2Credentials = try credentials.map { credential in
                    var moved = credential
                    moved.credentialId = try move(credential.credentialId)
                    moved.keyType = try move(credential.keyType)
                    moved.keyAlgorithm = try move(credential.keyAlgorithm)
                    moved.keyCurve = try move(credential.keyCurve)
                    moved.keyValue = try move(credential.keyValue)
                    moved.rpId = try move(credential.rpId)
                    moved.rpName = try move(credential.rpName)
                    moved.userHandle = try move(credential.userHandle)
                    moved.userName = try move(credential.userName)
                    moved.userDisplayName = try move(credential.userDisplayName)
                    moved.discoverable = try move(credential.discoverable)
                    moved.counter = try move(credential.counter)
                    return moved
                }
            }
            result.login = login
        }

        if var card = cipher.card {
            card.cardholderName = try move(card.cardholderName)
            card.brand = try move(card.brand)
            card.number = try move(card.number)
            card.expMonth = try move(card.expMonth)
            card.expYear = try move(card.expYear)
            card.code = try move(card.code)
            result.card = card
        }

        if var identity = cipher.identity {
            identity.title = try move(identity.title)
            identity.firstName = try move(identity.firstName)
            identity.middleName = try move(identity.middleName)
            identity.lastName = try move(identity.lastName)
            identity.address1 = try move(identity.address1)
            identity.address2 = try move(identity.address2)
            identity.address3 = try move(identity.address3)
            identity.city = try move(identity.city)
            identity.state = try move(identity.state)
            identity.postalCode = try move(identity.postalCode)
            identity.country = try move(identity.country)
            identity.company = try move(identity.company)
            identity.email = try move(identity.email)
            identity.phone = try move(identity.phone)
            identity.ssn = try move(identity.ssn)
            identity.username = try move(identity.username)
            identity.passportNumber = try move(identity.passportNumber)
            identity.licenseNumber = try move(identity.licenseNumber)
            result.identity = identity
        }

        if var sshKey = cipher.sshKey {
            sshKey.privateKey = try move(sshKey.privateKey)
            sshKey.publicKey = try move(sshKey.publicKey)
            sshKey.keyFingerprint = try move(sshKey.keyFingerprint)
            result.sshKey = sshKey
        }

        if let fields = cipher.fields {
            result.fields = try fields.map { field in
                var moved = field
                moved.name = try move(field.name)
                moved.value = try move(field.value)
                return moved
            }
        }

        if let history = cipher.passwordHistory {
            result.passwordHistory = try history.map { entry in
                var moved = entry
                moved.password = try move(entry.password)
                return moved
            }
        }

        if let attachments = cipher.attachments {
            result.attachments = try attachments.map { attachment in
                var moved = attachment
                moved.fileName = try move(attachment.fileName)
                // The attachment's own key is wrapped under the cipher's base key,
                // so it moves with everything else. Without one, the file's
                // ciphertext is tied to the old key and can only be re-uploaded.
                guard attachment.key != nil else {
                    let name = attachment.fileName
                        .flatMap { try? CipherEncryption.decryptString($0, key: oldKey) }
                        ?? attachment.id
                        ?? "unnamed"
                    throw RewrapError.attachmentWithoutKey(name)
                }
                moved.key = try move(attachment.key)
                return moved
            }
        }

        return result
    }
}
