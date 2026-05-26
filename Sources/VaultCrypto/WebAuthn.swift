// MARK: - VaultCrypto/WebAuthn.swift
// FIDO2 / WebAuthn passkey generation

import Foundation
import CryptoKit
import os

private let logger = Logger(subsystem: "de.tobisk.apps.vaultui", category: "WebAuthnGenerator")

/// Utility to generate FIDO2 / WebAuthn passkeys without heavy external CBOR dependencies.
public enum WebAuthnGenerator {
    
    /// Generates a new ECDSA P-256 passkey and constructs a valid "none" attestation object.
    ///
    /// - Parameter relyingPartyId: The relying party ID (e.g. "example.com").
    /// - Returns: A tuple containing the `attestationObject`, `credentialID`, and the base64-encoded private key.
    public static func generatePasskey(relyingPartyId: String) -> (attestationObject: Data, credentialID: Data, privateKey: String)? {
        let privateKey = P256.Signing.PrivateKey()
        let publicKey = privateKey.publicKey
        
        // Export the private key as raw bytes and base64 encode it for storage
        let privateKeyData = privateKey.rawRepresentation
        let privateKeyString = privateKeyData.base64EncodedString()
        
        let x = publicKey.rawRepresentation.prefix(32)
        let y = publicKey.rawRepresentation.suffix(32)
        
        // COSE_Key for P-256 (CBOR Map of 5 items)
        var coseKey = Data()
        coseKey.append(0xA5)
        coseKey.append(contentsOf: [0x01, 0x02]) // kty: EC2
        coseKey.append(contentsOf: [0x03, 0x26]) // alg: ES256
        coseKey.append(contentsOf: [0x20, 0x01]) // crv: P-256
        coseKey.append(contentsOf: [0x21, 0x58, 0x20]) // x: 32 bytes
        coseKey.append(x)
        coseKey.append(contentsOf: [0x22, 0x58, 0x20]) // y: 32 bytes
        coseKey.append(y)
        
        // RP ID Hash (SHA-256)
        let rpIdData = Data(relyingPartyId.utf8)
        let rpIdHash = Data(SHA256.hash(data: rpIdData))
        
        // Flags: UP (User Present), UV (User Verified), BE (Backup Eligible), BS (Backed Up), AT (Attested Credential Data)
        let flags: UInt8 = 0x5D // 0x01 | 0x04 | 0x08 | 0x10 | 0x40
        let signCount: UInt32 = 0
        
        // AAGUID (all zeros is valid for self-attested/none)
        let aaguid = Data(repeating: 0, count: 16)
        
        // Generate a random 32-byte credential ID
        var randomBytes = [UInt8](repeating: 0, count: 32)
        let result = SecRandomCopyBytes(kSecRandomDefault, randomBytes.count, &randomBytes)
        guard result == errSecSuccess else { return nil }
        let credentialID = Data(randomBytes)
        
        var authData = Data()
        authData.append(rpIdHash)
        authData.append(flags)
        
        var countBytes = signCount.bigEndian
        authData.append(Data(bytes: &countBytes, count: MemoryLayout<UInt32>.size))
        
        authData.append(aaguid)
        
        let credIdLen = UInt16(credentialID.count).bigEndian
        var lenBytes = credIdLen
        authData.append(Data(bytes: &lenBytes, count: MemoryLayout<UInt16>.size))
        
        authData.append(credentialID)
        authData.append(coseKey)
        
        // attestationObject (CBOR Map of 3 items)
        var attObj = Data()
        attObj.append(0xA3)
        
        // "fmt": "none"
        attObj.append(contentsOf: [0x63, 0x66, 0x6D, 0x74])
        attObj.append(contentsOf: [0x64, 0x6E, 0x6F, 0x6E, 0x65])
        
        // "attStmt": {}
        attObj.append(contentsOf: [0x67, 0x61, 0x74, 0x74, 0x53, 0x74, 0x6D, 0x74])
        attObj.append(0xA0)
        
        // "authData": bytes
        attObj.append(contentsOf: [0x68, 0x61, 0x75, 0x74, 0x68, 0x44, 0x61, 0x74, 0x61])
        
        if authData.count <= 255 {
            attObj.append(0x58)
            attObj.append(UInt8(authData.count))
        } else {
            attObj.append(0x59)
            var adLen = UInt16(authData.count).bigEndian
            attObj.append(Data(bytes: &adLen, count: MemoryLayout<UInt16>.size))
        }
        attObj.append(authData)
        
        return (attObj, credentialID, privateKeyString)
    }
    
    /// Generate a WebAuthn assertion signature for login.
    ///
    /// - Parameters:
    ///   - privateKeyBase64: The base64-encoded raw private key.
    ///   - relyingPartyId: The relying party ID.
    ///   - clientDataHash: The client data hash to sign.
    /// - Returns: A tuple of (signature, authenticatorData) if successful.
    public static func generateAssertion(
        privateKeyBase64: String,
        relyingPartyId: String,
        clientDataHash: Data
    ) -> (signature: Data, authenticatorData: Data)? {
        
        var privateKeyData: Data? = nil
        
        logger.info("Attempting to decode private key starting with: \(privateKeyBase64.prefix(10))")
        
        if privateKeyBase64.hasPrefix("{") {
            logger.info("Detected JWK JSON format.")
            if let data = privateKeyBase64.data(using: .utf8) {
                do {
                    let json = try JSONSerialization.jsonObject(with: data) as? [String: Any]
                    logger.info("Successfully parsed JSON.")
                    
                    if let dBase64Url = json?["d"] as? String {
                        logger.info("Found 'd' parameter.")
                        var base64 = dBase64Url
                            .replacingOccurrences(of: "-", with: "+")
                            .replacingOccurrences(of: "_", with: "/")
                        let remainder = base64.count % 4
                        if remainder > 0 {
                            base64 += String(repeating: "=", count: 4 - remainder)
                        }
                        privateKeyData = Data(base64Encoded: base64, options: .ignoreUnknownCharacters)
                        if privateKeyData == nil {
                            logger.error("Failed to base64 decode 'd' parameter: \(base64)")
                        } else {
                            logger.info("Successfully decoded 'd' parameter.")
                        }
                    } else {
                        logger.error("Missing 'd' parameter in JWK.")
                    }
                } catch {
                    logger.error("Failed to parse JWK JSON: \(error.localizedDescription)")
                }
            } else {
                logger.error("Failed to convert privateKeyBase64 to utf8 data.")
            }
        } else {
            logger.info("Detected raw base64 string format.")
            var base64 = privateKeyBase64
                .replacingOccurrences(of: "-", with: "+")
                .replacingOccurrences(of: "_", with: "/")
            let remainder = base64.count % 4
            if remainder > 0 {
                base64 += String(repeating: "=", count: 4 - remainder)
            }
            privateKeyData = Data(base64Encoded: base64, options: .ignoreUnknownCharacters)
            if privateKeyData == nil {
                logger.error("Failed to base64 decode raw string.")
            }
        }
        
        guard let validKeyData = privateKeyData else {
            logger.error("validKeyData is nil, returning nil early.")
            return nil
        }
        
        do {
            logger.info("Attempting to initialize P256 PrivateKey with \(validKeyData.count) bytes.")
            let privateKey: P256.Signing.PrivateKey
            
            do {
                // Try raw representation first (32 bytes)
                privateKey = try P256.Signing.PrivateKey(rawRepresentation: validKeyData)
                logger.info("Successfully initialized private key using rawRepresentation.")
            } catch {
                logger.info("rawRepresentation failed, trying derRepresentation... (\(error.localizedDescription))")
                do {
                    // Try DER representation (e.g. PKCS#8 which Bitwarden often uses)
                    privateKey = try P256.Signing.PrivateKey(derRepresentation: validKeyData)
                    logger.info("Successfully initialized private key using derRepresentation.")
                } catch {
                    logger.info("derRepresentation failed, trying x963Representation... (\(error.localizedDescription))")
                    // Try x963 representation as a last resort
                    privateKey = try P256.Signing.PrivateKey(x963Representation: validKeyData)
                    logger.info("Successfully initialized private key using x963Representation.")
                }
            }
            
            // Generate authenticatorData for assertion
            let rpIdHash = Data(SHA256.hash(data: Data(relyingPartyId.utf8)))
            let flags: UInt8 = 0x1D // UP (0x01) | UV (0x04) | BE (0x08) | BS (0x10) = 0x1D
            let signCount: [UInt8] = [0, 0, 0, 0] // Signature counter (0 is often accepted)
            
            var authData = Data()
            authData.append(rpIdHash)
            authData.append(flags)
            authData.append(contentsOf: signCount)
            
            // Data to sign: authData || clientDataHash
            var dataToSign = Data()
            dataToSign.append(authData)
            dataToSign.append(clientDataHash)
            
            let signature = try privateKey.signature(for: dataToSign)
            logger.info("Successfully generated assertion signature.")
            return (signature: signature.derRepresentation, authenticatorData: authData)
        } catch {
            logger.error("Failed to generate assertion signature: \(error)")
            return nil
        }
    }
}
