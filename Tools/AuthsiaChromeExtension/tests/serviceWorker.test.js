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

function invokeHandler(handler, message) {
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

    keepOpenValue = handler(message, null, sendResponse);

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
  assert.deepStrictEqual(calls[0].message, { type: 'getCredentials', host: 'login.example.com' });
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
  });

  assert.deepStrictEqual(calls[0].message, {
    type: 'listCredentials',
    host: 'example.com',
    currentURL: 'https://example.com/app/login',
  });
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
  global.setTimeout = (fn) => {
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
  } finally {
    global.setTimeout = originalSetTimeout;
    global.clearTimeout = originalClearTimeout;
  }
}

async function run() {
  await testValidHostForwardsNativeResponse();
  await testCurrentUrlIsForwardedToNativeHost();
  await testInvalidHostRejected();
  await testNativeMessagingFailureReported();
  await testNativeMessagingTimeoutReported();
  console.log('serviceWorker tests passed');
}

run().catch((error) => {
  console.error(error);
  process.exit(1);
});
