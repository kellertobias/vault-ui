browser.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action) {
        // Return promise directly for MV3 compatibility
        const nativeAppId = browser.runtime.id || "com.example.vaultui.SafariExtension"
        return browser.runtime.sendNativeMessage(nativeAppId, request)
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
    }
});
