// Drives the web vault that Vaultwarden serves, for the Swift integration tests.
//
//   node webvault.mjs read-item --url <server> --email <e> --password <p> --item <name>
//
// Logs in through the real UI, opens the named item and prints what the official
// web client decrypted, as JSON on the last stdout line:
//   {"name": "...", "username": "...", "password": "..."}
//
// Trust: the test server's certificate comes from a throwaway CA. Chrome can't be
// handed a CA file, so instead it is told to accept exactly the server's public
// key (--ignore-certificate-errors-spki-list), read from the certificate next to
// $NODE_EXTRA_CA_CERTS. Every other certificate error still fails.
//
// On failure a screenshot is written to $WEBVAULT_ARTIFACTS (default: tmpdir) and
// its path is printed.

import { chromium } from 'playwright';
import { createHash, X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';

const STEP_TIMEOUT = 30_000;

function parseArguments(argv) {
    const [command, ...rest] = argv;
    const options = {};
    for (let i = 0; i < rest.length; i += 2) {
        const key = rest[i];
        if (!key?.startsWith('--') || rest[i + 1] === undefined) {
            throw new Error(`bad argument near "${key}"`);
        }
        options[key.slice(2)] = rest[i + 1];
    }
    return { command, options };
}

function requireOption(options, name) {
    if (!options[name]) throw new Error(`missing --${name}`);
    return options[name];
}

/** Base64 SHA-256 of the server certificate's public key, for Chrome's pin flag. */
function serverKeyPin() {
    const ca = process.env.NODE_EXTRA_CA_CERTS;
    if (!ca) return null;
    const pem = readFileSync(join(dirname(ca), 'cert.pem'));
    const spki = new X509Certificate(pem).publicKey.export({ type: 'spki', format: 'der' });
    return createHash('sha256').update(spki).digest('base64');
}

async function launchBrowser() {
    const pin = serverKeyPin();
    const args = pin ? [`--ignore-certificate-errors-spki-list=${pin}`] : [];
    try {
        // Prefer the installed Chrome, so no browser download is needed.
        return await chromium.launch({ channel: 'chrome', headless: true, args });
    } catch {
        return await chromium.launch({ headless: true, args });
    }
}

/**
 * Log in and get past the first-login interstitials to the vault list.
 *
 * New accounts are routed through "install the extension" and a welcome tour;
 * both are skipped the way a user would.
 */
async function logIn(page, { url, email, password }) {
    await page.goto(new URL('/#/login', url).toString(), { waitUntil: 'domcontentloaded' });
    await page.getByTestId('login-email-input').fill(email);
    await page.getByTestId('login-continue-button').click();
    await page.getByTestId('login-master-password-input').fill(password);
    await page.getByTestId('login-submit-button').click();

    await page.waitForURL(/#\/(vault|setup-extension)/, { timeout: STEP_TIMEOUT });

    if (page.url().includes('setup-extension')) {
        await page.getByRole('button', { name: 'Add it later' }).click();
        await page.getByText('Skip to web app').click();
        await page.waitForURL(/#\/vault/, { timeout: STEP_TIMEOUT });
    }

    // The welcome tour appears once, a moment after the vault loads.
    const skipTour = page.getByRole('button', { name: 'Skip', exact: true });
    await skipTour.waitFor({ timeout: 5_000 }).then(() => skipTour.click()).catch(() => {});
}

async function readItem(page, options) {
    const itemName = requireOption(options, 'item');
    await logIn(page, {
        url: requireOption(options, 'url'),
        email: requireOption(options, 'email'),
        password: requireOption(options, 'password'),
    });

    // The list shows the decrypted name; opening the row shows the details.
    const row = page.getByRole('button', { name: itemName, exact: true });
    await row.waitFor({ timeout: STEP_TIMEOUT });
    await row.click();

    const dialog = page.getByRole('dialog').filter({ has: page.getByTestId('login-password') });
    await dialog.waitFor({ timeout: STEP_TIMEOUT });

    // Reveal the password as a user would, then read both fields.
    await dialog.getByTestId('toggle-password').click();
    const passwordInput = dialog.getByTestId('login-password');
    await passwordInput.evaluate(
        (input, timeout) => new Promise((resolve, reject) => {
            if (input.type === 'text') return resolve();
            const observer = new MutationObserver(() => {
                if (input.type === 'text') { observer.disconnect(); resolve(); }
            });
            observer.observe(input, { attributes: true, attributeFilter: ['type'] });
            setTimeout(() => { observer.disconnect(); reject(new Error('password was not revealed')); }, timeout);
        }),
        STEP_TIMEOUT,
    );

    return {
        name: itemName,
        username: await dialog.getByTestId('login-username').inputValue(),
        password: await passwordInput.inputValue(),
    };
}

const { command, options } = parseArguments(process.argv.slice(2));
const commands = { 'read-item': readItem };
if (!commands[command]) {
    console.error(`unknown command "${command}"; expected one of: ${Object.keys(commands).join(', ')}`);
    process.exit(2);
}

const browser = await launchBrowser();
const context = await browser.newContext({ locale: 'en-US' });
const page = await context.newPage();
page.setDefaultTimeout(STEP_TIMEOUT);

try {
    const result = await commands[command](page, options);
    console.log(JSON.stringify(result));
} catch (error) {
    const screenshot = join(process.env.WEBVAULT_ARTIFACTS ?? tmpdir(), `webvault-failure-${Date.now()}.png`);
    await page.screenshot({ path: screenshot, fullPage: true }).catch(() => {});
    console.error(`web vault step failed at ${page.url()}: ${error.message}\nscreenshot: ${screenshot}`);
    process.exitCode = 1;
} finally {
    await browser.close();
}
