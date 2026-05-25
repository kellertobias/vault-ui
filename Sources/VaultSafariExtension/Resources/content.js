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
            
            this.singleUsername = response.singleUsername;
            this.isChecking = false;
            
            // Setup MutationObserver to handle SPAs and dynamic inputs
            const observer = new MutationObserver(() => this.scanForInputs());
            observer.observe(document.body, { childList: true, subtree: true });
            
            // Scan immediately
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

    injectOverlay(input, type, associatedPasswordInput = null) {
        // Don't inject if input is too small or hidden
        if (input.offsetWidth < 30 || input.offsetHeight < 10) return;

        const iconContainer = document.createElement('div');
        iconContainer.style.position = 'absolute';
        iconContainer.style.zIndex = '2147483647'; // Max z-index
        iconContainer.style.cursor = 'pointer';
        iconContainer.style.display = 'flex';
        iconContainer.style.alignItems = 'center';
        iconContainer.style.justifyContent = 'center';
        iconContainer.style.width = '24px';
        iconContainer.style.height = '24px';
        iconContainer.style.backgroundColor = 'white';
        iconContainer.style.borderRadius = '4px';
        iconContainer.style.boxShadow = '0 1px 3px rgba(0,0,0,0.2)';
        iconContainer.style.transition = 'transform 0.1s ease';
        
        // Use the actual App Icon
        const iconUrl = browser.runtime.getURL("icons/32.png");
        iconContainer.innerHTML = `<img src="${iconUrl}" style="width: 16px; height: 16px; border-radius: 3px;" draggable="false" />`;
        
        iconContainer.addEventListener('mouseenter', () => {
            iconContainer.style.transform = 'scale(1.1)';
        });
        iconContainer.addEventListener('mouseleave', () => {
            iconContainer.style.transform = 'scale(1)';
        });

        iconContainer.addEventListener('click', (e) => {
            e.preventDefault();
            e.stopPropagation();
            this.handleOverlayClick(input, type, associatedPasswordInput, iconContainer);
        });

        // Intercept mousedown so we don't blur the input if it's already focused
        iconContainer.addEventListener('mousedown', (e) => {
            e.preventDefault();
        });

        document.body.appendChild(iconContainer);
        this.overlays.set(input, iconContainer);
        
        this.updateOverlayPosition(input, iconContainer);
        
        // Also observe input size/visibility changes
        const resizeObserver = new ResizeObserver(() => this.updateOverlayPosition(input, iconContainer));
        resizeObserver.observe(input);
    }

    updateOverlayPosition(input, iconContainer) {
        const rect = input.getBoundingClientRect();
        const style = window.getComputedStyle(input);
        if (rect.width === 0 || rect.height === 0 || style.visibility === 'hidden' || style.display === 'none') {
            iconContainer.style.display = 'none';
            return;
        }
        
        iconContainer.style.display = 'flex';
        // Position on the right side of the input, vertically centered
        const iconSize = 24;
        let paddingRight = 6;
        
        // Respect existing padding so we don't overlap native icons (like 'clear' or 'eye')
        const computedPaddingRight = parseFloat(style.paddingRight);
        if (!isNaN(computedPaddingRight) && computedPaddingRight > 10) {
            paddingRight = computedPaddingRight + 2;
        }
        
        iconContainer.style.top = `${rect.top + window.scrollY + (rect.height - iconSize) / 2}px`;
        iconContainer.style.left = `${rect.left + window.scrollX + rect.width - iconSize - paddingRight}px`;
    }

    repositionOverlays() {
        for (const [input, overlay] of this.overlays.entries()) {
            this.updateOverlayPosition(input, overlay);
        }
    }

    async handleOverlayClick(input, type, associatedPasswordInput, iconContainer) {
        // Temporarily change cursor to progress while waiting for native modal
        iconContainer.style.cursor = 'wait';
        
        try {
            const response = await browser.runtime.sendMessage({
                action: "showNativePicker",
                url: window.location.href
            });
            
            iconContainer.style.cursor = 'pointer';
            
            if (response.credentials && response.credentials.length > 0) {
                // We keep the icon visible in case the user wants to pick a different credential later
                this.fillCredentials(response.credentials[0], input, type, associatedPasswordInput);
                
                // Focus the actual input
                input.focus();
            }
        } catch (e) {
            console.error("Vault UI: Error showing native picker", e);
            iconContainer.style.cursor = 'pointer';
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
