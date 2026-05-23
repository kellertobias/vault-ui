import AuthenticationServices

func test(req: ASCredentialRequest) {
    if let passkeyReq = req as? ASPasskeyCredentialRequest {
        print(passkeyReq.clientDataHash)
    }
}
