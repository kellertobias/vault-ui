if (typeof window.VaultUIAutoFill === 'undefined') {
window.VaultUIAutoFill = class VaultUIAutoFill {
    constructor() {
        this.processedInputs = new WeakSet();
        this.processedForms = new WeakSet();
        this.processedTemporaryDraftForms = new WeakSet();
        this.submittingForms = new WeakSet();
        this.savedCredentialKeys = new Set();
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

        if (this.isRegistrationForm(form, passInput) && !this.processedTemporaryDraftForms.has(form)) {
            const username = usernameInput?.value?.trim() || this.findUsernameInput(form, passInput)?.value?.trim() || '';
            if (username) {
                this.processedTemporaryDraftForms.add(form);
                this.queueTemporaryCredentialDraft(username);
            }
        }
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

        event.preventDefault();
        event.stopImmediatePropagation();

        await this.confirmAndSaveCredential(username, password);
        this.submittingForms.add(form);

        if (typeof form.requestSubmit === 'function') {
            form.requestSubmit();
        } else {
            form.submit();
        }
    }

    async confirmAndSaveCredential(username, password) {
        const key = `${window.location.origin}|${username}|${password}`;
        if (this.savedCredentialKeys.has(key)) { return; }

        const shouldSave = window.confirm(`Save credentials for ${username} in Vault UI?`);
        if (!shouldSave) { return false; }

        try {
            const response = await browser.runtime.sendMessage({
                action: "saveCredential",
                url: window.location.href,
                name: window.location.hostname,
                username,
                password
            });

            if (response?.success) {
                this.savedCredentialKeys.add(key);
                return true;
            } else if (response?.error) {
                console.error("Vault UI: Failed to queue credential save", response.error);
            }
        } catch (e) {
            console.error("Vault UI: Failed to queue credential save", e);
        }
        return false;
    }

    async queueTemporaryCredentialDraft(username) {
        try {
            await browser.runtime.sendMessage({
                action: "queueTemporaryCredentialDraft",
                url: window.location.href,
                name: window.location.hostname,
                username
            });
        } catch (e) {
            console.error("Vault UI: Failed to queue temporary credential draft", e);
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

new window.VaultUIAutoFill();
}
