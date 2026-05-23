import AuthenticationServices

let req = ASPasskeyRegistrationCredential(relyingParty: "test", clientDataHash: Data(), credentialID: Data(), attestationObject: Data())
print(req)
