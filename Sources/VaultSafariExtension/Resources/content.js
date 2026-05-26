if (typeof window.VaultUIAutoFill === 'undefined') {
window.VaultUIAutoFill = class VaultUIAutoFill {
    constructor() {
        this.processedInputs = new WeakSet();
        this.overlays = new Map();
        this.hasMultipleSubdomains = false;
        this.isChecking = false;
        
        this.init();
    }

    async init() {
        // Check with background if we need to suppress native autofill
        try {
            console.log("Vault UI: Initializing Autofill script...");
            this.isChecking = true;
            const response = await browser.runtime.sendMessage({
                action: "checkSubdomains",
                url: window.location.href
            });
            console.log("Vault UI: Background response:", response);
            
            if (response) {
                this.singleUsername = response.singleUsername;
            }
            this.isChecking = false;
            
            // Setup MutationObserver to handle SPAs and dynamic inputs
            const observer = new MutationObserver(() => this.scanForInputs());
            observer.observe(document.body, { childList: true, subtree: true });
            
            // Scan immediately
            console.log("Vault UI: Scanning for password fields...");
            this.scanForInputs();
            
            // Reposition overlays on resize/scroll
            window.addEventListener('resize', () => this.repositionOverlays());
            window.addEventListener('scroll', () => this.repositionOverlays(), true);
        } catch (e) {
            console.error("Vault UI: Error checking subdomains", e);
            this.isChecking = false;
        }
    }

    scanForInputs() {
        const passwordFields = document.querySelectorAll('input[type="password"]');
        for (const passInput of passwordFields) {
            if (!this.processedInputs.has(passInput)) {
                this.processedInputs.add(passInput);
                
                // Try to find corresponding username field
                const form = passInput.closest('form');
                if (form) {
                    const textInputs = form.querySelectorAll('input[type="text"], input[type="email"]');
                    for (const textInput of textInputs) {
                        // Usually the username is the closest one before the password, but we'll grab the first
                        if (!this.processedInputs.has(textInput)) {
                            this.processedInputs.add(textInput);
                            
                            if (this.singleUsername) {
                                this.autofillUsername(textInput, this.singleUsername);
                            }
                            
                            break; 
                        }
                    }
                }
            }
        }
    }

    autofillUsername(input, username) {
        if (!input.value) {
            input.value = username;
            input.dispatchEvent(new Event('input', { bubbles: true }));
            input.dispatchEvent(new Event('change', { bubbles: true }));
        }
    }
}

// Initialize
new window.VaultUIAutoFill();
}
