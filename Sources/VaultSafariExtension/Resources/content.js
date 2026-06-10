if (typeof window.VaultUIAutoFill === 'undefined') {
window.VaultUIAutoFill = class VaultUIAutoFill {
    constructor() {
        this.processedInputs = new WeakSet();
        this.processedFileInputs = new WeakSet();
        this.processedForms = new WeakSet();
        this.submittingForms = new WeakSet();
        this.savedCredentialKeys = new Set();
        this.dismissedCredentialKeys = new Set();
        this.saveBanner = null;
        this.pendingFillTimer = null;
        this.pendingFillPolls = 0;
        this.pendingFillInFlight = false;
        this.certificateFillInFlight = false;
        this.pendingFillWakeupsInstalled = false;
        this.submitClickCaptureInstalled = false;
        this.scanRetriesInstalled = false;
        this.autofillCount = 0;
        this.isChecking = false;
        this.singleUsername = null;
        this.credentialLookupSucceeded = false;
        this.matchingCredentialCount = 0;
        this.exactCredentialCount = 0;
        this.knownUsernames = new Set();
        this.exactUsernames = new Set();
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

            if (response && !response.error) {
                this.singleUsername = response.singleUsername;
                this.credentialLookupSucceeded = true;
                this.matchingCredentialCount = Number(response.totalMatches || 0);
                this.exactCredentialCount = Number(response.exactMatchCount || 0);
                this.knownUsernames = new Set((response.matchingUsernames || response.exactUsernames || [])
                    .map(username => this.normalizeUsername(username))
                    .filter(Boolean));
                this.exactUsernames = new Set((response.exactUsernames || [])
                    .map(username => this.normalizeUsername(username))
                    .filter(Boolean));
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
        this.installScanRetries();
        this.installSubmitClickCapture();
        this.installPendingFillWakeups();
        this.startPendingFillPolling();
    }

    installScanRetries() {
        if (this.scanRetriesInstalled) { return; }
        this.scanRetriesInstalled = true;

        for (const delay of [100, 300, 700, 1500, 3000]) {
            window.setTimeout(() => this.scanForInputs(), delay);
        }
    }

    scanForInputs() {
        const passwordFields = document.querySelectorAll('input[type="password"]');
        for (const passInput of passwordFields) {
            if (!this.processedInputs.has(passInput)) {
                this.processedInputs.add(passInput);
                this.preparePasswordField(passInput);
            } else {
                this.tryAutofillPasswordField(passInput);
            }

            const form = passInput.closest('form');
            if (form && !this.processedForms.has(form)) {
                this.processedForms.add(form);
                form.addEventListener('submit', event => this.handleFormSubmit(event, form), true);
            }
        }
        const fileInputs = document.querySelectorAll('input[type="file"]');
        for (const fileInput of fileInputs) {
            if (!this.processedFileInputs.has(fileInput)) {
                this.processedFileInputs.add(fileInput);
                this.tryCertificateFileFill(fileInput);
            }
        }
        this.prepareStandaloneFormContext();
        this.checkPendingCredentialFill();
    }

    async tryCertificateFileFill(fileInput) {
        if (!(fileInput instanceof HTMLInputElement)) { return false; }
        if (fileInput.disabled || fileInput.offsetParent === null) { return false; }
        if (!this.isLikelyCertificateFileInput(fileInput)) { return false; }
        if (this.certificateFillInFlight) { return false; }

        this.certificateFillInFlight = true;
        try {
            const response = await browser.runtime.sendMessage({
                action: "getCertificateFill",
                url: window.location.href
            });

            if (!response?.hasCertificate || !response.dataBase64 || !response.fileName) {
                return false;
            }

            const fileFilled = this.setFileInputValue(fileInput, response.fileName, response.dataBase64);
            const passwordField = this.findCertificatePasswordInput(fileInput);
            if (passwordField && response.password) {
                this.setInputValue(passwordField, response.password);
            }
            return fileFilled;
        } catch (e) {
            console.error("Vault UI: Failed to fill certificate file", e);
            return false;
        } finally {
            this.certificateFillInFlight = false;
        }
    }

    isLikelyCertificateFileInput(input) {
        const accept = (input.getAttribute('accept') || '').toLowerCase();
        if (accept.includes('.pfx') || accept.includes('.p12') || accept.includes('pkcs12')) { return true; }

        const text = [
            input.name || '',
            input.id || '',
            input.getAttribute('aria-label') || '',
            input.closest('form')?.textContent || '',
            document.title || ''
        ].join(' ').toLowerCase();

        return /pfx|p12|pkcs.?12|zertifikat|certificate|elster/.test(text);
    }

    findCertificatePasswordInput(fileInput) {
        const form = fileInput.closest('form');
        const scope = form || document;
        const passwordFields = Array.from(scope.querySelectorAll('input[type="password"]'))
            .filter(input => this.isUsablePasswordInput(input));
        if (passwordFields.length === 0) { return null; }

        const labelled = passwordFields.find(input => {
            const text = [
                input.name || '',
                input.id || '',
                input.placeholder || '',
                input.getAttribute('aria-label') || ''
            ].join(' ').toLowerCase();
            return /pin|passwort|password|kennwort|zertifikat|certificate/.test(text);
        });
        return labelled || passwordFields[0];
    }

    setFileInputValue(input, fileName, dataBase64) {
        try {
            const binary = atob(dataBase64);
            const bytes = new Uint8Array(binary.length);
            for (let i = 0; i < binary.length; i++) {
                bytes[i] = binary.charCodeAt(i);
            }

            const file = new File([bytes], fileName, { type: "application/x-pkcs12" });
            const transfer = new DataTransfer();
            transfer.items.add(file);
            input.files = transfer.files;
            input.dispatchEvent(new Event('input', { bubbles: true, composed: true }));
            input.dispatchEvent(new Event('change', { bubbles: true, composed: true }));
            return input.files?.length === 1;
        } catch (e) {
            console.error("Vault UI: Browser refused certificate file assignment", e);
            return false;
        }
    }

    preparePasswordField(passInput) {
        this.tryAutofillPasswordField(passInput);
    }

    tryAutofillPasswordField(passInput) {
        const form = passInput.closest('form');
        const usernameInput = this.findUsernameInput(form, passInput);

        if (usernameInput && this.singleUsername && !this.isRegistrationForm(form, passInput, null)) {
            this.autofillUsername(usernameInput, this.singleUsername);
        }

        return usernameInput;
    }

    prepareStandaloneFormContext() {
        const usernameInput = this.findUsernameInput(null, null);
        if (!usernameInput) { return; }
        const form = usernameInput.closest('form');
        const passwordScope = form || document;
        if (passwordScope.querySelector('input[type="password"]')) { return; }

        if (this.singleUsername && this.isLikelyUsernameFirstLogin(usernameInput)) {
            this.autofillUsername(usernameInput, this.singleUsername);
        }
    }

    findUsernameInput(form, passInput) {
        const scope = form || document;
        const keys = ['username', 'user', 'login', 'email', 'mail', 'name'];

        for (const key of keys) {
            const input = this.findInputByAttribute(scope, 'autocomplete', key);
            if (input) { return input; }
        }

        for (const key of keys) {
            const input = this.findInputByAttribute(scope, 'name', key);
            if (input) { return input; }
        }

        for (const key of keys) {
            const input = this.findInputById(scope, key);
            if (input) { return input; }
        }

        return null;
    }

    findInputByAttribute(scope, attribute, value) {
        return Array.from(scope.querySelectorAll(`[${attribute}]`))
            .map(node => this.resolveInputNode(node))
            .find(input => {
                if (!this.isUsableTextInput(input)) { return false; }
                return (input.getAttribute(attribute) || '').toLowerCase() === value;
            }) || null;
    }

    findInputById(scope, value) {
        return Array.from(scope.querySelectorAll(`[id]`))
            .filter(node => (node.id || '').toLowerCase() === value)
            .map(node => this.resolveInputNode(node))
            .find(input => this.isUsableTextInput(input)) || null;
    }

    resolveInputNode(node) {
        if (node instanceof HTMLInputElement) { return node; }
        const children = Array.from(node.children || []);
        if (children.length !== 1 || !(children[0] instanceof HTMLInputElement)) { return null; }
        return children[0];
    }

    isUsableTextInput(input) {
        if (!(input instanceof HTMLInputElement)) { return false; }
        if (input.disabled || input.readOnly || input.offsetParent === null) { return false; }
        const type = (input.getAttribute('type') || 'text').toLowerCase();
        return ['email', 'text', 'tel', ''].includes(type);
    }

    isRegistrationForm(form, passInput, trigger) {
        if (!passInput) { return false; }

        const scope = form || document;
        const passwordFields = Array.from(scope.querySelectorAll('input[type="password"]'))
            .filter(input => !input.disabled && input.offsetParent !== null);
        const autocomplete = (passInput.autocomplete || '').toLowerCase();
        const formLabel = form instanceof Element ? form.getAttribute('aria-label') || '' : '';
        const formId = form instanceof Element ? form.id || '' : '';
        const formName = form instanceof HTMLFormElement ? form.name || '' : '';
        const triggerText = trigger ? [
            trigger.textContent || '',
            trigger.value || '',
            trigger.getAttribute?.('aria-label') || '',
            trigger.name || '',
            trigger.id || ''
        ].join(' ') : '';
        const text = [
            formLabel,
            formId,
            formName,
            this.formActionText(form),
            passInput.name || '',
            passInput.id || '',
            passInput.placeholder || '',
            triggerText,
            document.title || ''
        ].join(' ').toLowerCase();

        return autocomplete === 'new-password'
            || passwordFields.length >= 2
            || /sign.?up|signup|register|registration|create.?account|new.?account|join/.test(text);
    }

    isLikelyUsernameFirstLogin(input) {
        const autocomplete = (input.getAttribute('autocomplete') || '').toLowerCase();
        if (['username', 'email'].includes(autocomplete)) { return true; }

        const text = [
            input.name || '',
            input.id || '',
            input.placeholder || '',
            input.getAttribute('aria-label') || '',
            input.getAttribute('data-test') || '',
            input.closest('form')?.getAttribute('aria-label') || '',
            this.formActionText(input.closest('form')),
            document.title || ''
        ].join(' ').toLowerCase();

        return /(user.?name|benutzername|email|e.?mail|login|sign.?in|anmelden)/.test(text)
            && !/(sign.?up|signup|register|registration|create.?account|new.?account|join)/.test(text);
    }

    formActionText(form) {
        if (!form) { return ''; }
        return Array.from(form.querySelectorAll('button, input[type="submit"], input[type="button"], [role="button"]'))
            .map(control => [
                control.textContent || '',
                control.value || '',
                control.getAttribute?.('aria-label') || '',
                control.name || '',
                control.id || ''
            ].join(' '))
            .join(' ');
    }

    async handleFormSubmit(event, form) {
        if (this.submittingForms.has(form)) {
            this.submittingForms.delete(form);
            return;
        }

        const trigger = event.submitter || document.activeElement;
        const passwordField = this.firstPasswordField(form);
        if (!passwordField) { return; }

        const isRegistration = this.isRegistrationForm(form, passwordField, trigger);
        this.captureSubmittedCredential(form, { isRegistration });
    }

    installSubmitClickCapture() {
        if (this.submitClickCaptureInstalled) { return; }
        this.submitClickCaptureInstalled = true;

        document.addEventListener('click', event => this.handlePossibleSubmitClick(event), true);
    }

    handlePossibleSubmitClick(event) {
        if (!(event.target instanceof Element)) { return; }

        const trigger = event.target.closest('button, input[type="submit"], input[type="button"], [role="button"]');
        if (!trigger) { return; }
        if (!this.isSubmitLikeTrigger(trigger)) { return; }

        const form = this.findPasswordScopeForTrigger(trigger);
        if (!form) { return; }

        const passwordField = this.firstPasswordField(form);
        if (!passwordField) { return; }

        const isRegistration = this.isRegistrationForm(form, passwordField, trigger);
        this.captureSubmittedCredential(form, { isRegistration });
    }

    isSubmitLikeTrigger(trigger) {
        const label = [
            trigger.textContent || '',
            trigger.value || '',
            trigger.getAttribute?.('aria-label') || '',
            trigger.name || '',
            trigger.id || ''
        ].join(' ').toLowerCase();
        const looksLikeRegistrationAction = /sign.?up|signup|register|registration|create.?account|new.?account|join/.test(label);

        if (trigger instanceof HTMLButtonElement) {
            return trigger.type === 'submit' || looksLikeRegistrationAction;
        }

        if (trigger instanceof HTMLInputElement) {
            const type = (trigger.getAttribute('type') || '').toLowerCase();
            return type === 'submit' || looksLikeRegistrationAction;
        }

        return looksLikeRegistrationAction;
    }

    findPasswordScopeForTrigger(trigger) {
        const enclosingForm = trigger.closest('form');
        if (enclosingForm) { return enclosingForm; }

        let ancestor = trigger.parentElement;
        while (ancestor && ancestor !== document.body) {
            if (ancestor.querySelector('input[type="password"]')) {
                return ancestor;
            }
            ancestor = ancestor.parentElement;
        }

        const forms = Array.from(document.querySelectorAll('form'))
            .filter(form => form.querySelector('input[type="password"]'));

        if (forms.length === 1) { return forms[0]; }

        const nearestForm = forms
            .map(form => ({ form, distance: this.nodeDistance(trigger, form) }))
            .filter(entry => Number.isFinite(entry.distance))
            .sort((left, right) => left.distance - right.distance)[0]?.form || null;
        if (nearestForm) { return nearestForm; }

        return document.querySelector('input[type="password"]') ? document : null;
    }

    nodeDistance(leftNode, rightNode) {
        const leftRect = leftNode.getBoundingClientRect?.();
        const rightRect = rightNode.getBoundingClientRect?.();
        if (!leftRect || !rightRect) { return Infinity; }

        const leftX = leftRect.left + leftRect.width / 2;
        const leftY = leftRect.top + leftRect.height / 2;
        const rightX = rightRect.left + rightRect.width / 2;
        const rightY = rightRect.top + rightRect.height / 2;
        return Math.hypot(leftX - rightX, leftY - rightY);
    }

    captureSubmittedCredential(form, options = {}) {
        const passwordFields = Array.from(form.querySelectorAll('input[type="password"]'))
            .filter(input => this.isUsablePasswordInput(input));
        const password = passwordFields.find(input => input.value)?.value || '';
        const username = this.findUsernameInput(form, passwordFields[0])?.value?.trim() || '';

        if (!username || !password) { return false; }
        // Don't offer to save when the browser already considers the form invalid
        // (e.g. a failed client-side validation on submit).
        if (form.querySelector?.(':invalid')) { return false; }
        if (!options.isRegistration && !this.credentialLookupSucceeded) { return false; }
        if (!options.isRegistration && this.hasStoredCredentialForUsername(username)) { return false; }

        this.offerToSaveCredential({
            url: window.location.href,
            name: window.location.hostname,
            username,
            password,
            preferTemporaryPromotion: Boolean(options.isRegistration)
        });
        return true;
    }

    // Credentials are never persisted by the extension on their own. We surface an
    // in-page prompt and only forward them to the app when the user explicitly
    // confirms, so nothing sensitive is written to the shared keychain unasked.
    offerToSaveCredential(pending) {
        const key = `${window.location.origin}|${pending.username}|${pending.password}`;
        if (this.savedCredentialKeys.has(key) || this.dismissedCredentialKeys.has(key)) { return; }
        pending.key = key;
        this.showSaveBanner(pending);
    }

    firstPasswordField(form) {
        return Array.from(form.querySelectorAll('input[type="password"]'))
            .find(input => this.isUsablePasswordInput(input)) || null;
    }

    normalizeUsername(username) {
        return String(username || '').trim().toLowerCase();
    }

    hasStoredCredentialForUsername(username) {
        const normalized = this.normalizeUsername(username);
        if (!normalized) { return this.matchingCredentialCount > 0 || this.exactCredentialCount > 0; }
        if (this.knownUsernames.has(normalized)) { return true; }
        if (this.exactUsernames.has(normalized)) { return true; }
        if (this.singleUsername && this.normalizeUsername(this.singleUsername) === normalized) { return true; }

        return (this.matchingCredentialCount > 0 || this.exactCredentialCount > 0)
            && this.knownUsernames.size === 0
            && this.exactUsernames.size === 0;
    }

    startPendingFillPolling() {
        if (this.pendingFillTimer) { return; }
        this.pendingFillPolls = 0;
        this.checkPendingCredentialFill();
        this.pendingFillTimer = window.setInterval(() => {
            this.pendingFillPolls++;
            if (this.pendingFillPolls > 120) {
                window.clearInterval(this.pendingFillTimer);
                this.pendingFillTimer = null;
                return;
            }
            this.checkPendingCredentialFill();
        }, 500);
    }

    installPendingFillWakeups() {
        if (this.pendingFillWakeupsInstalled) { return; }
        this.pendingFillWakeupsInstalled = true;

        const wakePendingFill = () => {
            this.checkPendingCredentialFill();
            this.startPendingFillPolling();
        };

        window.addEventListener('focus', wakePendingFill, true);
        window.addEventListener('pageshow', wakePendingFill, true);
        document.addEventListener('visibilitychange', () => {
            if (!document.hidden) {
                wakePendingFill();
            }
        }, true);
    }

    async checkPendingCredentialFill() {
        if (this.pendingFillInFlight) { return; }
        this.pendingFillInFlight = true;

        try {
            const response = await browser.runtime.sendMessage({
                action: "getPendingCredentialFill",
                url: window.location.href
            });

            if (response?.hasCredential && response.password) {
                const filled = this.fillCredentialIntoPage(response.username || '', response.password);
                if (filled) {
                    await browser.runtime.sendMessage({ action: "clearPendingCredentialFill" });
                    if (this.pendingFillTimer) {
                        window.clearInterval(this.pendingFillTimer);
                        this.pendingFillTimer = null;
                    }
                }
            }
        } catch (e) {
            console.error("Vault UI: Failed to fill pending credential", e);
        } finally {
            this.pendingFillInFlight = false;
        }
    }

    fillCredentialIntoPage(username, password) {
        const passwordFields = Array.from(document.querySelectorAll('input[type="password"]'))
            .filter(input => this.isUsablePasswordInput(input));
        if (passwordFields.length === 0) { return false; }

        for (const passwordField of passwordFields) {
            const form = passwordField.closest('form');
            const usernameInput = this.findUsernameInput(form, passwordField);
            if (usernameInput && username) {
                this.setInputValue(usernameInput, username);
            }
            this.setInputValue(passwordField, password);
        }
        return true;
    }

    isUsablePasswordInput(input) {
        if (!(input instanceof HTMLInputElement)) { return false; }
        if (input.disabled || input.readOnly || input.offsetParent === null) { return false; }
        return (input.getAttribute('type') || '').toLowerCase() === 'password';
    }

    showSaveBanner(pending) {
        // Only one banner at a time; a newer login offer replaces the previous one.
        this.removeSaveBanner();

        const host = document.createElement('div');
        host.style.cssText = 'all: initial; position: fixed; z-index: 2147483647;';
        const shadow = host.attachShadow({ mode: 'closed' });

        let iconURL = '';
        try { iconURL = browser.runtime.getURL('icons/32.png'); } catch (e) { iconURL = ''; }

        const title = pending.preferTemporaryPromotion ? 'New Account Detected' : 'New Login Detected';
        const subtitle = pending.username
            ? `Save ${this.escapeHTML(pending.username)} for ${this.escapeHTML(pending.name)}?`
            : `Save these credentials for ${this.escapeHTML(pending.name)}?`;

        shadow.innerHTML = `
            <style>
                :host { all: initial; }
                .vaultui-banner {
                    position: fixed; bottom: 20px; right: 20px;
                    width: 320px; box-sizing: border-box; padding: 16px;
                    background: #1e1e1e; color: #f5f5f7;
                    border: 1px solid rgba(255,255,255,0.12); border-radius: 12px;
                    box-shadow: 0 10px 30px rgba(0,0,0,0.45);
                    font-family: -apple-system, BlinkMacSystemFont, "SF Pro Text", system-ui, sans-serif;
                    font-size: 13px; line-height: 1.4;
                    animation: vaultui-in 0.18s ease-out;
                }
                @keyframes vaultui-in {
                    from { opacity: 0; transform: translateY(8px); }
                    to { opacity: 1; transform: translateY(0); }
                }
                .vaultui-head { display: flex; align-items: center; gap: 10px; margin-bottom: 6px; }
                .vaultui-head img { width: 22px; height: 22px; border-radius: 5px; }
                .vaultui-title { font-weight: 600; font-size: 14px; }
                .vaultui-sub { color: #b9b9be; margin-bottom: 14px; word-break: break-word; }
                .vaultui-actions { display: flex; gap: 8px; justify-content: flex-end; }
                button {
                    font: inherit; cursor: pointer; border-radius: 7px;
                    padding: 7px 14px; border: 1px solid transparent;
                }
                .vaultui-save { background: #34c759; color: #04270f; font-weight: 600; }
                .vaultui-save:hover { background: #2fb350; }
                .vaultui-dismiss { background: transparent; color: #c9c9ce; border-color: rgba(255,255,255,0.18); }
                .vaultui-dismiss:hover { background: rgba(255,255,255,0.08); }
                .vaultui-status { color: #34c759; font-weight: 600; }
            </style>
            <div class="vaultui-banner" role="dialog" aria-live="polite">
                <div class="vaultui-head">
                    ${iconURL ? `<img src="${iconURL}" alt="">` : ''}
                    <span class="vaultui-title">${this.escapeHTML(title)}</span>
                </div>
                <div class="vaultui-sub">${subtitle}</div>
                <div class="vaultui-actions">
                    <button class="vaultui-dismiss" type="button">Not Now</button>
                    <button class="vaultui-save" type="button">Save</button>
                </div>
            </div>
        `;

        const banner = shadow.querySelector('.vaultui-banner');
        const saveButton = shadow.querySelector('.vaultui-save');
        const dismissButton = shadow.querySelector('.vaultui-dismiss');

        dismissButton.addEventListener('click', () => {
            this.dismissedCredentialKeys.add(pending.key);
            this.removeSaveBanner();
        });

        saveButton.addEventListener('click', async () => {
            saveButton.disabled = true;
            dismissButton.disabled = true;
            const saved = await this.saveSubmittedCredential(pending);
            if (saved) {
                const sub = shadow.querySelector('.vaultui-sub');
                if (sub) { sub.innerHTML = '<span class="vaultui-status">Saved to Vault UI</span>'; }
                shadow.querySelector('.vaultui-actions')?.remove();
                window.setTimeout(() => this.removeSaveBanner(), 1800);
            } else {
                this.removeSaveBanner();
            }
        });

        (document.body || document.documentElement).appendChild(host);
        this.saveBanner = host;

        // Auto-dismiss the offer if the user ignores it.
        this.saveBannerTimer = window.setTimeout(() => this.removeSaveBanner(), 25000);
    }

    removeSaveBanner() {
        window.clearTimeout(this.saveBannerTimer);
        this.saveBannerTimer = null;
        if (this.saveBanner) {
            this.saveBanner.remove();
            this.saveBanner = null;
        }
    }

    escapeHTML(value) {
        return String(value || '').replace(/[&<>"']/g, char => ({
            '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
        }[char]));
    }

    async saveSubmittedCredential(pending) {
        const key = pending.key || `${window.location.origin}|${pending.username}|${pending.password}`;
        if (this.savedCredentialKeys.has(key)) { return true; }

        if (pending.preferTemporaryPromotion) {
            const promoted = await this.sendCredentialSaveMessage("promoteTemporaryCredential", pending);
            if (promoted) {
                this.savedCredentialKeys.add(key);
                return true;
            }
        }

        const saved = await this.sendCredentialSaveMessage("saveCredential", pending);
        if (saved) {
            this.savedCredentialKeys.add(key);
        }
        return saved;
    }

    async sendCredentialSaveMessage(action, pending) {
        try {
            const response = await browser.runtime.sendMessage({
                action,
                url: pending.url,
                name: pending.name,
                username: pending.username,
                password: pending.password
            });

            if (response?.success) {
                return true;
            } else if (response?.error) {
                console.error(`Vault UI: Failed to ${action}`, response.error);
            }
        } catch (e) {
            console.error(`Vault UI: Failed to ${action}`, e);
        }
        return false;
    }

    autofillUsername(input, username) {
        if (!input.value) {
            this.autofillCount++;
            console.log("Vault UI: Autofilling username field", {
                id: input.id || null,
                autocomplete: input.getAttribute('autocomplete') || null,
                ariaLabel: input.getAttribute('aria-label') || null,
                dataTest: input.getAttribute('data-test') || null
            });
            this.setInputValue(input, username);
        }
    }

    setInputValue(input, value) {
        const applyValue = () => {
            const nativeInputValueSetter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value")?.set;
            if (nativeInputValueSetter) {
                nativeInputValueSetter.call(input, value);
            } else {
                input.value = value;
            }
            input.setAttribute('value', value);
        };

        applyValue();

        const inputEvent = typeof InputEvent === 'function'
            ? new InputEvent('input', {
                bubbles: true,
                composed: true,
                data: value,
                inputType: 'insertReplacementText'
            })
            : new Event('input', { bubbles: true, composed: true });
        input.dispatchEvent(inputEvent);
        input.dispatchEvent(new Event('change', { bubbles: true, composed: true }));

        window.setTimeout(() => {
            if (input.value === value) { return; }
            applyValue();
            input.dispatchEvent(new Event('input', { bubbles: true, composed: true }));
            input.dispatchEvent(new Event('change', { bubbles: true, composed: true }));
        }, 100);
    }
}

window.vaultUIAutoFillInstance = new window.VaultUIAutoFill();
}
