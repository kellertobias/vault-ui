browser.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "getCredentials") {
        // Send native message to the Swift handler
        browser.runtime.sendNativeMessage("de.tobisk.apps.vaultui.SafariExtension", {
            action: "getCredentials",
            url: request.url
        }).then((response) => {
            console.log("Received native response:", response);
            sendResponse(response);
        }).catch((error) => {
            console.error("Native message error:", error);
            sendResponse({ error: error.toString() });
        });
        return true; // Indicates an asynchronous response
    }
});

browser.action.onClicked.addListener(async (tab) => {
    try {
        await browser.runtime.sendNativeMessage("de.tobisk.apps.vaultui.SafariExtension", {
            action: "showNativePicker",
            url: tab.url
        });
    } catch (e) {
        console.error("Native message error:", e);
    }
});
