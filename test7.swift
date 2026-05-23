import AuthenticationServices

func test(req: ASCredentialRequest) {
    let id = req.credentialIdentity as? ASPasskeyCredentialIdentity
    print(id?.relyingPartyIdentifier ?? "")
}
