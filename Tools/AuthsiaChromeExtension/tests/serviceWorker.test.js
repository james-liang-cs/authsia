const assert = require('assert');
const path = require('path');

function loadServiceWorker({ sendNativeMessageImpl, lastErrorMessage = null }) {
  let onMessageHandler = null;
  const calls = [];

  global.chrome = {
    runtime: {
      lastError: lastErrorMessage ? { message: lastErrorMessage } : null,
      sendNativeMessage(host, message, callback) {
        calls.push({ host, message });
        sendNativeMessageImpl(host, message, callback);
      },
      onMessage: {
        addListener(handler) {
          onMessageHandler = handler;
        },
      },
    },
  };

  const workerPath = path.join(__dirname, '..', 'service_worker.js');
  delete require.cache[require.resolve(workerPath)];
  require(workerPath);

  assert.ok(onMessageHandler, 'service worker should register onMessage handler');
  return { onMessageHandler, calls };
}

function invokeHandler(handler, message, sender = { url: message.currentURL || `https://${message.host}/` }) {
  return new Promise((resolve) => {
    let keepOpenValue;
    let responseValue;
    let responded = false;

    const sendResponse = (response) => {
      responseValue = response;
      responded = true;
      if (keepOpenValue !== undefined) {
        resolve({ keepOpen: keepOpenValue, response: responseValue });
      }
    };

    keepOpenValue = handler(message, sender, sendResponse);

    if (responded) {
      resolve({ keepOpen: keepOpenValue, response: responseValue });
      return;
    }

    if (keepOpenValue === false) {
      resolve({ keepOpen: keepOpenValue, response: undefined });
    }
  });
}

async function testValidHostForwardsNativeResponse() {
  const nativeResponse = { ok: true, credential: { username: 'u', password: 'p' } };
  const { onMessageHandler, calls } = loadServiceWorker({
    sendNativeMessageImpl(_host, _message, callback) {
      callback(nativeResponse);
    },
  });

  const result = await invokeHandler(onMessageHandler, {
    type: 'AUTHsia_GET_CREDENTIALS',
    host: 'Login.Example.com',
  });

  assert.strictEqual(calls.length, 1);
  assert.strictEqual(calls[0].host, 'com.authsia.nativehost');
  assert.deepStrictEqual(calls[0].message, {
    type: 'getCredentials',
    host: 'login.example.com',
    currentURL: 'https://login.example.com/',
  });
  assert.strictEqual(result.keepOpen, true);
  assert.deepStrictEqual(result.response, nativeResponse);
}

async function testCurrentUrlIsForwardedToNativeHost() {
  const nativeResponse = { ok: true, credentials: [] };
  const { onMessageHandler, calls } = loadServiceWorker({
    sendNativeMessageImpl(_host, _message, callback) {
      callback(nativeResponse);
    },
  });

  await invokeHandler(onMessageHandler, {
    type: 'AUTHsia_LIST_CREDENTIALS',
    host: 'example.com',
    currentURL: 'https://example.com/app/login',
    kind: 'otp',
  });

  assert.deepStrictEqual(calls[0].message, {
    type: 'listCredentials',
    host: 'example.com',
    currentURL: 'https://example.com/app/login',
    kind: 'otp',
  });
}

async function testInvalidCredentialKindRejected() {
  const { onMessageHandler, calls } = loadServiceWorker({
    sendNativeMessageImpl(_host, _message, callback) {
      callback({ ok: true });
    },
  });

  const result = await invokeHandler(onMessageHandler, {
    type: 'AUTHsia_LIST_CREDENTIALS',
    host: 'example.com',
    kind: 'secret',
  });

  assert.strictEqual(calls.length, 0);
  assert.deepStrictEqual(result.response, { ok: false, error: 'invalidCredentialKind' });
}

async function testInvalidHostRejected() {
  const { onMessageHandler, calls } = loadServiceWorker({
    sendNativeMessageImpl(_host, _message, callback) {
      callback({ ok: true });
    },
  });

  const result = await invokeHandler(onMessageHandler, {
    type: 'AUTHsia_GET_CREDENTIALS',
    host: 'bad host!',
  });

  assert.strictEqual(calls.length, 0);
  assert.strictEqual(result.keepOpen, false);
  assert.deepStrictEqual(result.response, { ok: false, error: 'invalidHost' });
}

async function testSenderHostMismatchRejected() {
  const { onMessageHandler, calls } = loadServiceWorker({
    sendNativeMessageImpl(_host, _message, callback) {
      callback({ ok: true });
    },
  });

  const result = await invokeHandler(onMessageHandler, {
    type: 'AUTHsia_GET_CREDENTIALS',
    host: 'vault.example.com',
    currentURL: 'https://vault.example.com/login',
  }, { url: 'https://attacker.example/login' });

  assert.strictEqual(calls.length, 0, 'mismatched page origins must not reach the native host');
  assert.deepStrictEqual(result.response, { ok: false, error: 'senderMismatch' });
}

async function testSenderPathMismatchUsesAttestedURL() {
  const { onMessageHandler, calls } = loadServiceWorker({
    sendNativeMessageImpl(_host, _message, callback) {
      callback({ ok: true, credentials: [] });
    },
  });

  const result = await invokeHandler(onMessageHandler, {
    type: 'AUTHsia_LIST_CREDENTIALS',
    host: 'example.com',
    currentURL: 'https://example.com/admin/login',
  }, { url: 'https://example.com/public/login' });

  assert.strictEqual(result.response.ok, true);
  assert.deepStrictEqual(calls[0].message, {
    type: 'listCredentials',
    host: 'example.com',
    currentURL: 'https://example.com/public/login',
  });
}

async function testGoogleStyleQueryDriftUsesSenderURL() {
  const { onMessageHandler, calls } = loadServiceWorker({
    sendNativeMessageImpl(_host, _message, callback) {
      callback({ ok: true, credentials: [] });
    },
  });
  const senderURL = 'https://accounts.google.com/v3/signin/identifier?continue=https%3A%2F%2Fmail.google.com%2Fmail%2F&flowName=GlifWebSignIn&ifkv=sender';
  const pageURL = 'https://accounts.google.com/v3/signin/identifier?continue=https%3A%2F%2Fmail.google.com%2Fmail%2F&flowName=GlifWebSignIn&ifkv=page';

  const result = await invokeHandler(onMessageHandler, {
    type: 'AUTHsia_LIST_CREDENTIALS',
    host: 'accounts.google.com',
    currentURL: pageURL,
    kind: 'password',
  }, { url: senderURL });

  assert.strictEqual(result.response.ok, true, 'query-string drift on Gaia must not look like a dead native host');
  assert.deepStrictEqual(calls[0].message, {
    type: 'listCredentials',
    host: 'accounts.google.com',
    currentURL: senderURL,
    kind: 'password',
  });
}

async function testMissingSenderURLAttestsOriginAndOmitsClaimedPath() {
  const { onMessageHandler, calls } = loadServiceWorker({
    sendNativeMessageImpl(_host, _message, callback) {
      callback({ ok: true, credentials: [] });
    },
  });

  const result = await invokeHandler(onMessageHandler, {
    type: 'AUTHsia_LIST_CREDENTIALS',
    host: 'accounts.google.com',
    currentURL: 'https://accounts.google.com/v3/signin/identifier?continue=https%3A%2F%2Fmail.google.com%2Fmail%2F',
    kind: 'password',
  }, { origin: 'https://accounts.google.com' });

  assert.strictEqual(result.response.ok, true);
  assert.deepStrictEqual(
    calls[0].message,
    { type: 'listCredentials', host: 'accounts.google.com', kind: 'password' },
    'without an attested frame URL, do not forward a page-claimed path'
  );
}

async function testSubframeIsAttestedAgainstItsOwnURL() {
  const { onMessageHandler, calls } = loadServiceWorker({
    sendNativeMessageImpl(_host, _message, callback) {
      callback({ ok: true, credentials: [] });
    },
  });
  const sender = { url: 'https://login.identity.example/embedded' };

  const allowed = await invokeHandler(onMessageHandler, {
    type: 'AUTHsia_LIST_CREDENTIALS',
    host: 'login.identity.example',
    currentURL: sender.url,
  }, sender);
  const rejected = await invokeHandler(onMessageHandler, {
    type: 'AUTHsia_LIST_CREDENTIALS',
    host: 'shop.example',
    currentURL: 'https://shop.example/checkout',
  }, sender);

  assert.strictEqual(allowed.response.ok, true);
  assert.strictEqual(calls.length, 1, 'only the frame-scoped host should reach the native host');
  assert.deepStrictEqual(rejected.response, { ok: false, error: 'senderMismatch' });
}

async function testPlainHttpSenderRejectedBeforeNativeMessage() {
  const { onMessageHandler, calls } = loadServiceWorker({
    sendNativeMessageImpl(_host, _message, callback) {
      callback({ ok: true });
    },
  });

  const result = await invokeHandler(onMessageHandler, {
    type: 'AUTHsia_LIST_CREDENTIALS',
    host: 'example.com',
    currentURL: 'http://example.com/login',
  });

  assert.strictEqual(calls.length, 0, 'plain HTTP pages must not reach the native host');
  assert.deepStrictEqual(result.response, { ok: false, error: 'insecureContext' });
}

async function testLoopbackHttpSendersAllowed() {
  for (const currentURL of ['http://localhost:3000/login', 'http://127.0.0.1/login']) {
    const { onMessageHandler, calls } = loadServiceWorker({
      sendNativeMessageImpl(_host, _message, callback) {
        callback({ ok: true, credentials: [] });
      },
    });
    const host = new URL(currentURL).hostname;

    const result = await invokeHandler(onMessageHandler, {
      type: 'AUTHsia_LIST_CREDENTIALS',
      host,
      currentURL,
    });

    assert.strictEqual(calls.length, 1, `${host} should reach the native host`);
    assert.strictEqual(result.response.ok, true);
  }
}

async function testWebAccessibleMenuCannotAssertPageOrigin() {
  const { onMessageHandler, calls } = loadServiceWorker({
    sendNativeMessageImpl(_host, _message, callback) {
      callback({ ok: true });
    },
  });

  const result = await invokeHandler(onMessageHandler, {
    type: 'AUTHsia_GET_CREDENTIALS',
    host: 'vault.example.com',
    currentURL: 'https://vault.example.com/login',
    credentialId: 'synthetic-id',
  }, { url: 'chrome-extension://fakeid/popup/menu.html' });

  assert.strictEqual(calls.length, 0, 'extension frames must use the attested content-script bridge');
  assert.deepStrictEqual(result.response, { ok: false, error: 'senderMismatch' });
}

async function testNativeMessagingFailureReported() {
  const { onMessageHandler } = loadServiceWorker({
    lastErrorMessage: 'No native host',
    sendNativeMessageImpl(_host, _message, callback) {
      callback(undefined);
    },
  });

  const result = await invokeHandler(onMessageHandler, {
    type: 'AUTHsia_GET_CREDENTIALS',
    host: 'example.com',
  });

  assert.strictEqual(result.keepOpen, true);
  assert.strictEqual(result.response.ok, false);
  assert.strictEqual(result.response.error, 'nativeMessagingFailed');
  assert.ok(typeof result.response.detail === 'string' && result.response.detail.includes('No native host'));
}

async function testNativeMessagingTimeoutReported() {
  const originalSetTimeout = global.setTimeout;
  const originalClearTimeout = global.clearTimeout;
  let scheduledDelay = 0;
  global.setTimeout = (fn, delay) => {
    scheduledDelay = delay;
    fn();
    return 1;
  };
  global.clearTimeout = () => {};

  try {
    const { onMessageHandler } = loadServiceWorker({
      sendNativeMessageImpl(_host, _message, _callback) {
        // Simulate a native host that never replies.
      },
    });

    const result = await invokeHandler(onMessageHandler, {
      type: 'AUTHsia_LIST_CREDENTIALS',
      host: 'example.com',
    });

    assert.strictEqual(result.keepOpen, true);
    assert.strictEqual(result.response.ok, false);
    assert.strictEqual(result.response.error, 'nativeMessagingTimeout');
    assert.ok(scheduledDelay >= 45000, 'native messaging must allow time for biometric approval');
  } finally {
    global.setTimeout = originalSetTimeout;
    global.clearTimeout = originalClearTimeout;
  }
}

async function run() {
  await testValidHostForwardsNativeResponse();
  await testCurrentUrlIsForwardedToNativeHost();
  await testInvalidCredentialKindRejected();
  await testInvalidHostRejected();
  await testSenderHostMismatchRejected();
  await testSenderPathMismatchUsesAttestedURL();
  await testGoogleStyleQueryDriftUsesSenderURL();
  await testMissingSenderURLAttestsOriginAndOmitsClaimedPath();
  await testSubframeIsAttestedAgainstItsOwnURL();
  await testPlainHttpSenderRejectedBeforeNativeMessage();
  await testLoopbackHttpSendersAllowed();
  await testWebAccessibleMenuCannotAssertPageOrigin();
  await testNativeMessagingFailureReported();
  await testNativeMessagingTimeoutReported();
  console.log('serviceWorker tests passed');
}

run().catch((error) => {
  console.error(error);
  process.exit(1);
});
