if (typeof window.VaultUIAutoFill === 'undefined') {
window.VaultUIAutoFill = class VaultUIAutoFill {
    constructor() {
        this.processedInputs = new WeakSet();
        this.processedForms = new WeakSet();
        this.submittingForms = new WeakSet();
        this.savedCredentialKeys = new Set();
        this.pendingPromotion = null;
        this.contextTimer = null;
        this.autofillCount = 0;
        this.isChecking = false;
        this.singleUsername = null;
        this.observer = null;

        this.init();
    }

    async init() {
        console.log("Vault UI: Initializing Autofill script...");
        try {
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

        } catch (e) {
            console.error("Vault UI: Error checking subdomains", e);
            this.isChecking = false;
        } finally {
            this.startScanning();
        }
    }

    startScanning() {
        if (this.observer || !document.body) { return; }

        this.observer = new MutationObserver(() => {
            if (this.autofillCount < 10) {
                this.scanForInputs();
            } else {
                console.log("Vault UI: Reached maximum autofill attempts (10). Stopping observer.");
                this.observer.disconnect();
            }
        });
        this.observer.observe(document.body, { childList: true, subtree: true });

        this.scanForInputs();
    }

    scanForInputs() {
        const passwordFields = document.querySelectorAll('input[type="password"]');
        for (const passInput of passwordFields) {
            if (!this.processedInputs.has(passInput)) {
                this.processedInputs.add(passInput);
                this.preparePasswordField(passInput);
            }

            const form = passInput.closest('form');
            if (form && !this.processedForms.has(form)) {
                this.processedForms.add(form);
                form.addEventListener('submit', event => this.handleFormSubmit(event, form), true);
            }
        }
    }

    preparePasswordField(passInput) {
        const form = passInput.closest('form');
        const usernameInput = this.findUsernameInput(form, passInput);

        if (usernameInput && this.singleUsername && !this.isRegistrationForm(form, passInput)) {
            this.autofillUsername(usernameInput, this.singleUsername);
        }

        this.attachFormContextListeners(form, passInput, usernameInput);
        this.queueFormContextUpdate(form, passInput);
    }

    findUsernameInput(form, passInput) {
        const scope = form || document;
        const candidates = Array.from(scope.querySelectorAll([
            'input[type="email"]',
            'input[type="text"]',
            'input[type="tel"]',
            'input:not([type])'
        ].join(','))).filter(input => {
            if (input.disabled || input.readOnly || input.offsetParent === null) { return false; }
            const autocomplete = (input.autocomplete || '').toLowerCase();
            const name = `${input.name || ''} ${input.id || ''} ${input.placeholder || ''}`.toLowerCase();
            return autocomplete.includes('username')
                || autocomplete.includes('email')
                || /user|email|login|account/.test(name)
                || Boolean(input.compareDocumentPosition(passInput) & Node.DOCUMENT_POSITION_FOLLOWING);
        });

        return candidates.find(input => input.compareDocumentPosition(passInput) & Node.DOCUMENT_POSITION_FOLLOWING)
            || candidates[0]
            || null;
    }

    isRegistrationForm(form, passInput) {
        if (!passInput) { return false; }

        const scope = form || document;
        const passwordFields = Array.from(scope.querySelectorAll('input[type="password"]'))
            .filter(input => !input.disabled && input.offsetParent !== null);
        const autocomplete = (passInput.autocomplete || '').toLowerCase();
        const text = [
            form?.getAttribute('aria-label') || '',
            form?.id || '',
            form?.name || '',
            passInput.name || '',
            passInput.id || '',
            passInput.placeholder || '',
            document.title || ''
        ].join(' ').toLowerCase();

        return autocomplete === 'new-password'
            || passwordFields.length >= 2
            || /sign.?up|signup|register|registration|create.?account|new.?account|join/.test(text);
    }

    async handleFormSubmit(event, form) {
        if (this.submittingForms.has(form)) {
            this.submittingForms.delete(form);
            return;
        }

        if (!this.isRegistrationForm(form, form.querySelector('input[type="password"]'))) { return; }

        const passwordFields = Array.from(form.querySelectorAll('input[type="password"]'));
        const password = passwordFields.find(input => input.value)?.value || '';
        const username = this.findUsernameInput(form, passwordFields[0])?.value?.trim() || '';

        if (!username || !password) { return; }

        this.pendingPromotion = {
            form,
            url: window.location.href,
            name: window.location.hostname,
            username,
            password,
            sent: false
        };

        window.setTimeout(() => this.promoteAfterSuccessfulSubmit(), 1500);
    }

    attachFormContextListeners(form, passInput, usernameInput) {
        const fields = [passInput, usernameInput].filter(Boolean);
        for (const field of fields) {
            field.addEventListener('focus', () => this.queueFormContextUpdate(form, passInput), true);
            field.addEventListener('input', () => this.queueFormContextUpdate(form, passInput), true);
        }
    }

    queueFormContextUpdate(form, passInput) {
        window.clearTimeout(this.contextTimer);
        this.contextTimer = window.setTimeout(() => this.updateFormContext(form, passInput), 150);
    }

    async updateFormContext(form, passInput) {
        const password = passInput?.value || '';
        const username = this.findUsernameInput(form, passInput)?.value?.trim() || '';

        try {
            await browser.runtime.sendMessage({
                action: "updateAutoFillFormContext",
                url: window.location.href,
                name: window.location.hostname,
                username,
                password
            });
        } catch (e) {
            console.error("Vault UI: Failed to update form context", e);
        }
    }

    promoteAfterSuccessfulSubmit(force = false) {
        const pending = this.pendingPromotion;
        if (!pending || pending.sent) { return; }

        const formRemoved = !document.contains(pending.form);
        const hasInvalidField = Boolean(pending.form.querySelector(':invalid'));
        if (!force && !formRemoved && hasInvalidField) { return; }

        pending.sent = true;
        this.promoteTemporaryCredential(pending);
    }

    async promoteTemporaryCredential(pending) {
        const key = `${window.location.origin}|${pending.username}|${pending.password}`;
        if (this.savedCredentialKeys.has(key)) { return; }

        try {
            const response = await browser.runtime.sendMessage({
                action: "promoteTemporaryCredential",
                url: pending.url,
                name: pending.name,
                username: pending.username,
                password: pending.password
            });

            if (response?.success) {
                this.savedCredentialKeys.add(key);
            } else if (response?.error) {
                console.error("Vault UI: Failed to promote temporary credential", response.error);
            }
        } catch (e) {
            console.error("Vault UI: Failed to promote temporary credential", e);
        }
    }

    autofillUsername(input, username) {
        if (!input.value) {
            this.autofillCount++;
            this.setInputValue(input, username);
        }
    }

    setInputValue(input, value) {
        const nativeInputValueSetter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value")?.set;
        if (nativeInputValueSetter) {
            nativeInputValueSetter.call(input, value);
        } else {
            input.value = value;
        }

        input.dispatchEvent(new Event('input', { bubbles: true }));
        input.dispatchEvent(new Event('change', { bubbles: true }));
    }
}

window.vaultUIAutoFillInstance = new window.VaultUIAutoFill();
window.addEventListener('pagehide', () => window.vaultUIAutoFillInstance?.promoteAfterSuccessfulSubmit(true));
}
