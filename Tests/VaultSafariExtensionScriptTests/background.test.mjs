import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

function loadBackground({
  nativeResponse = Promise.resolve({ success: true }),
  runtimeId = 'test.extension',
  runTimersImmediately = false
} = {}) {
  let listener = null;
  const nativeMessages = [];
  const context = {
    console,
    setTimeout: runTimersImmediately ? (fn) => {
      fn();
      return 1;
    } : setTimeout,
    clearTimeout,
    browser: {
      runtime: {
        id: runtimeId,
        onMessage: {
          addListener(fn) {
            listener = fn;
          }
        },
        sendNativeMessage(appId, message) {
          nativeMessages.push({ appId, message });
          return nativeResponse;
        }
      }
    }
  };

  const source = fs.readFileSync('Sources/VaultSafariExtension/Resources/background.js', 'utf8');
  vm.runInNewContext(source, context, { filename: 'background.js' });
  assert.equal(typeof listener, 'function');
  return { listener, nativeMessages };
}

function plain(value) {
  return JSON.parse(JSON.stringify(value));
}

test('origin-sensitive requests forward the browser-attested sender URL', async () => {
  const { listener, nativeMessages } = loadBackground();

  const response = await listener(
    {
      action: 'getPendingCredentialFill',
      url: 'https://attacker.example/login'
    },
    {
      url: 'https://vault.example/login'
    }
  );

  assert.deepEqual(plain(response), { success: true });
  assert.equal(nativeMessages.length, 1);
  assert.equal(nativeMessages[0].message.url, 'https://vault.example/login');
});

test('origin-sensitive requests without an attested sender are rejected', async () => {
  const { listener, nativeMessages } = loadBackground();

  const response = await listener(
    {
      action: 'saveCredential',
      url: 'https://attacker.example/login'
    },
    {}
  );

  assert.deepEqual(plain(response), { success: false, error: 'No verified sender origin' });
  assert.equal(nativeMessages.length, 0);
});

test('native messages time out and return a structured error', async () => {
  const { listener } = loadBackground({
    nativeResponse: new Promise(() => {}),
    runTimersImmediately: true
  });

  const response = await listener(
    { action: 'clearPendingCredentialFill' },
    { url: 'https://vault.example/login' }
  );

  assert.deepEqual(plain(response), { success: false, error: 'native-message-timeout' });
});
