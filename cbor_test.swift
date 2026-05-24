import Foundation
import CryptoKit

func generatePasskey() -> (attestationObject: Data, credentialID: Data, privateKey: P256.Signing.PrivateKey)? {
    let privateKey = P256.Signing.PrivateKey()
    let publicKey = privateKey.publicKey
    
    let x = publicKey.rawRepresentation.prefix(32)
    let y = publicKey.rawRepresentation.suffix(32)
    
    // COSE_Key for P-256
    var coseKey = Data()
    coseKey.append(0xA5) // Map of 5 items
    coseKey.append(contentsOf: [0x01, 0x02]) // kty: EC2
    coseKey.append(contentsOf: [0x03, 0x26]) // alg: ES256
    coseKey.append(contentsOf: [0x20, 0x01]) // crv: P-256
    coseKey.append(contentsOf: [0x21, 0x58, 0x20]) // x: 32 bytes
    coseKey.append(x)
    coseKey.append(contentsOf: [0x22, 0x58, 0x20]) // y: 32 bytes
    coseKey.append(y)
    
    // authData
    let rpIdHash = Data(repeating: 0, count: 32) // We'll compute SHA256 of RP ID
    let flags: UInt8 = 0x41 // UP and AT
    let signCount: UInt32 = 0
    let aaguid = Data(repeating: 0, count: 16)
    
    let credentialID = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
    
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
    
    // attestationObject
    var attObj = Data()
    attObj.append(0xA3) // Map of 3 items
    
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
    
    return (attObj, credentialID, privateKey)
}

if let passkey = generatePasskey() {
    print("attestationObject: \(passkey.attestationObject.base64EncodedString())")
    print("credentialID: \(passkey.credentialID.base64EncodedString())")
}
