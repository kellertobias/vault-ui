import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

function loadContentPrototype({ protocol = 'https:' } = {}) {
  const listeners = [];
  const storage = new Map();
  const context = {
    console,
    performance: {
      now: () => 0
    },
    URLSearchParams,
    browser: {
      runtime: {
        sendMessage: async () => ({ success: true })
      }
    },
    window: {
      location: {
        protocol,
        search: '',
        host: 'vault.example',
        pathname: '/login',
        href: `${protocol}//vault.example/login`
      },
      localStorage: {
        getItem: key => storage.get(key) ?? null
      },
      sessionStorage: {
        getItem: key => storage.get(key) ?? null
      },
      setTimeout,
      clearTimeout,
      setInterval,
      clearInterval
    },
    document: {
      readyState: 'complete',
      hidden: false,
      title: 'Vault UI test',
      body: {},
      addEventListener(type, listener, options) {
        listeners.push({ type, listener, options });
      },
      querySelectorAll() {
        return [];
      },
      getElementById() {
        return null;
      }
    },
    HTMLInputElement: class HTMLInputElement {},
    HTMLFormElement: class HTMLFormElement {},
    Element: class Element {},
    InputEvent: class InputEvent {},
    Event: class Event {}
  };
  context.window.VaultUIAutoFill = undefined;
  context.window.console = console;
  context.window.performance = context.performance;

  const source = fs
    .readFileSync('Sources/VaultSafariExtension/Resources/content.js', 'utf8')
    .replace('window.vaultUIAutoFillInstance = new window.VaultUIAutoFill();', '');

  vm.runInNewContext(source, context, { filename: 'content.js' });
  assert.equal(typeof context.window.VaultUIAutoFill, 'function');
  return {
    prototype: context.window.VaultUIAutoFill.prototype,
    context,
    listeners
  };
}

function makeInstance(prototype) {
  return Object.assign(Object.create(prototype), {
    processedFileInputs: new WeakSet(),
    certificateFillInFlight: false
  });
}

test('certificate file fill requires a user-initiated interaction', async () => {
  const { prototype } = loadContentPrototype();
  const instance = makeInstance(prototype);
  let nativeMessages = 0;

  instance.isLikelyCertificateFileInput = () => true;
  instance.sendMessage = async () => {
    nativeMessages += 1;
    return {
      success: true,
      certificateBase64: Buffer.from('certificate').toString('base64'),
      password: 'secret'
    };
  };

  const filled = await instance.tryCertificateFileFill({
    disabled: false,
    offsetParent: {},
    closest: () => null
  });

  assert.equal(filled, false);
  assert.equal(nativeMessages, 0);
});

test('unsupported page schemes skip initialization before scanning', async () => {
  const { prototype } = loadContentPrototype({ protocol: 'file:' });
  const instance = makeInstance(prototype);
  let scans = 0;

  instance.debugLog = () => {};
  instance.startPerformanceDebugMonitor = () => {};
  instance.startScanning = () => {
    scans += 1;
  };

  await instance.init();

  assert.equal(scans, 0);
});

test('native-message timeout enters a short cooldown', async () => {
  const { prototype } = loadContentPrototype();
  const instance = makeInstance(prototype);
  const before = Date.now();

  instance.debugLog = () => {};
  instance.nativeMessagesDisabledUntil = 0;
  instance.nativeMessageTimeoutMs = () => 1;
  instance.withTimeout = async () => ({ success: false, error: 'native-message-timeout' });

  const response = await instance.sendMessage({ action: 'checkSubdomains' });

  assert.deepEqual(response, { success: false, error: 'native-message-timeout' });
  assert.ok(instance.nativeMessagesDisabledUntil >= before + 4000);
});
