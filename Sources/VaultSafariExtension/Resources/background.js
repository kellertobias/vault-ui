// Actions whose result depends on *which origin* is asking — credential and
// certificate lookups, and credential saves. For these we must use an origin
// the browser vouches for, never one the page/content-script reported.
const ORIGIN_SENSITIVE_ACTIONS = new Set([
    "checkSubdomains",
    "getCertificateFill",
    "getPendingCredentialFill",
    "promoteTemporaryCredential",
    "saveCredential",
]);

browser.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (!request || !request.action) {
        return;
    }

    // Security: do not trust a page- or content-script-supplied `url` to decide
    // which origin's secrets to release. The browser populates `sender.url` with
    // the real document URL of the frame that sent the message; a web page
    // cannot forge it. Force the outgoing `url` to that attested origin so the
    // native handler always matches credentials against the true caller.
    const trustedUrl = sender && typeof sender.url === "string" ? sender.url : null;

    if (ORIGIN_SENSITIVE_ACTIONS.has(request.action) && !trustedUrl) {
        // No verified origin (e.g. message not from a content script) — refuse
        // rather than fall back to a spoofable, page-supplied value.
        return Promise.resolve({ success: false, error: "No verified sender origin" });
    }

    const outgoing = Object.assign({}, request);
    if (trustedUrl) {
        outgoing.url = trustedUrl;
    }

    const nativeAppId = browser.runtime.id || "com.example.vaultui.SafariExtension";
    return browser.runtime.sendNativeMessage(nativeAppId, outgoing)
        .then((response) => {
            if (response?.error) {
                console.error("Native message error:", response.error);
            }
            return response;
        })
        .catch((error) => {
            console.error("Native message error:", error);
            return { error: error.toString() };
        });
});
