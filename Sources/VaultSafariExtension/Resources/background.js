browser.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action) {
        // Return promise directly for MV3 compatibility
        return browser.runtime.sendNativeMessage("de.tobisk.apps.vaultui.SafariExtension", request)
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
