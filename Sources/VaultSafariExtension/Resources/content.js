class VaultUIAutoFill {
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
            this.isChecking = true;
            const response = await browser.runtime.sendMessage({
                action: "checkSubdomains",
                url: window.location.href
            });
            
            this.hasMultipleSubdomains = response.hasMultipleSubdomains === true;
            this.isChecking = false;
            
            if (this.hasMultipleSubdomains) {
                console.log("Vault UI: Multiple subdomains detected. Suppressing native AutoFill.");
                // Setup MutationObserver to handle SPAs and dynamic inputs
                const observer = new MutationObserver(() => this.scanForInputs());
                observer.observe(document.body, { childList: true, subtree: true });
                
                // Scan immediately
                this.scanForInputs();
                
                // Reposition overlays on resize/scroll
                window.addEventListener('resize', () => this.repositionOverlays());
                window.addEventListener('scroll', () => this.repositionOverlays(), true);
            } else {
                console.log("Vault UI: Single subdomain. Letting native Apple AutoFill handle it.");
            }
        } catch (e) {
            console.error("Vault UI: Error checking subdomains", e);
            this.isChecking = false;
        }
    }

    scanForInputs() {
        if (!this.hasMultipleSubdomains) return;
        
        const passwordFields = document.querySelectorAll('input[type="password"]');
        for (const passInput of passwordFields) {
            if (!this.processedInputs.has(passInput)) {
                this.processedInputs.add(passInput);
                this.injectOverlay(passInput, 'password');
                
                // Try to find corresponding username field
                const form = passInput.closest('form');
                if (form) {
                    const textInputs = form.querySelectorAll('input[type="text"], input[type="email"]');
                    for (const textInput of textInputs) {
                        // Usually the username is the closest one before the password, but we'll grab the first
                        if (!this.processedInputs.has(textInput)) {
                            this.processedInputs.add(textInput);
                            this.injectOverlay(textInput, 'username', passInput);
                            break; 
                        }
                    }
                }
            }
        }
    }

    injectOverlay(input, type, associatedPasswordInput = null) {
        // Don't inject if input is too small or hidden
        if (input.offsetWidth < 10 || input.offsetHeight < 10) return;

        const overlay = document.createElement('div');
        overlay.style.position = 'absolute';
        overlay.style.zIndex = '2147483647'; // Max z-index
        overlay.style.cursor = 'text';
        overlay.style.backgroundColor = 'transparent';
        
        overlay.addEventListener('click', (e) => {
            e.preventDefault();
            e.stopPropagation();
            this.handleOverlayClick(input, type, associatedPasswordInput, overlay);
        });

        document.body.appendChild(overlay);
        this.overlays.set(input, overlay);
        
        this.updateOverlayPosition(input, overlay);
        
        // Also observe input size/visibility changes
        const resizeObserver = new ResizeObserver(() => this.updateOverlayPosition(input, overlay));
        resizeObserver.observe(input);
    }

    updateOverlayPosition(input, overlay) {
        const rect = input.getBoundingClientRect();
        if (rect.width === 0 || rect.height === 0 || input.style.visibility === 'hidden' || input.style.display === 'none') {
            overlay.style.display = 'none';
            return;
        }
        
        overlay.style.display = 'block';
        overlay.style.top = `${rect.top + window.scrollY}px`;
        overlay.style.left = `${rect.left + window.scrollX}px`;
        overlay.style.width = `${rect.width}px`;
        overlay.style.height = `${rect.height}px`;
    }

    repositionOverlays() {
        for (const [input, overlay] of this.overlays.entries()) {
            this.updateOverlayPosition(input, overlay);
        }
    }

    async handleOverlayClick(input, type, associatedPasswordInput, overlay) {
        // Temporarily change cursor to progress while waiting for native modal
        overlay.style.cursor = 'wait';
        
        try {
            const response = await browser.runtime.sendMessage({
                action: "showNativePicker",
                url: window.location.href
            });
            
            overlay.style.cursor = 'text';
            
            if (response.credentials && response.credentials.length > 0) {
                // Remove overlays so user can interact natively again
                for (const ov of this.overlays.values()) {
                    ov.style.display = 'none';
                }
                
                this.fillCredentials(response.credentials[0], input, type, associatedPasswordInput);
                
                // Focus the actual input
                input.focus();
            }
        } catch (e) {
            console.error("Vault UI: Error showing native picker", e);
            overlay.style.cursor = 'text';
        }
    }

    fillCredentials(cred, input, type, associatedPasswordInput) {
        const setVal = (el, val) => {
            if (!el || !val) return;
            el.value = val;
            el.dispatchEvent(new Event('input', { bubbles: true }));
            el.dispatchEvent(new Event('change', { bubbles: true }));
        };

        if (type === 'password') {
            setVal(input, cred.password);
            const form = input.closest('form');
            if (form) {
                const textInputs = form.querySelectorAll('input[type="text"], input[type="email"]');
                for (const textInput of textInputs) {
                    if (cred.username) {
                        setVal(textInput, cred.username);
                        break;
                    }
                }
            }
        } else {
            setVal(input, cred.username);
            if (associatedPasswordInput) {
                setVal(associatedPasswordInput, cred.password);
            }
        }
    }
}

// Initialize
new VaultUIAutoFill();
