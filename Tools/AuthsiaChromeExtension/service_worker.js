const NATIVE_HOST_NAME = 'com.authsia.nativehost';
const MESSAGE_TYPE_GET_CREDENTIALS = 'AUTHsia_GET_CREDENTIALS';
const MESSAGE_TYPE_LIST_CREDENTIALS = 'AUTHsia_LIST_CREDENTIALS';
const NATIVE_MESSAGE_TIMEOUT_MS = 8000;

function sanitizeHost(host) {
  if (typeof host !== 'string') {
    return null;
  }
  const trimmed = host.trim().toLowerCase();
  if (!trimmed) {
    return null;
  }
  // Conservative host validation: letters, digits, dots, and hyphens.
  if (!/^[a-z0-9.-]+$/.test(trimmed)) {
    return null;
  }
  return trimmed;
}

function sanitizeCurrentURL(currentURL) {
  if (typeof currentURL !== 'string') {
    return null;
  }

  try {
    const url = new URL(currentURL);
    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
      return null;
    }
    return url.href;
  } catch {
    return null;
  }
}

function sendNativeMessage(message) {
  return new Promise((resolve, reject) => {
    let didSettle = false;
    const timeoutId = setTimeout(() => {
      didSettle = true;
      reject(new Error('nativeMessagingTimeout'));
    }, NATIVE_MESSAGE_TIMEOUT_MS);

    chrome.runtime.sendNativeMessage(NATIVE_HOST_NAME, message, (response) => {
      if (didSettle) {
        return;
      }
      didSettle = true;
      clearTimeout(timeoutId);

      const lastError = chrome.runtime.lastError;
      if (lastError) {
        reject(new Error(lastError.message));
        return;
      }
      resolve(response);
    });
  });
}

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (!message) {
    return false;
  }

  // Handle LIST_CREDENTIALS - returns metadata only (no passwords)
  if (message.type === MESSAGE_TYPE_LIST_CREDENTIALS) {
    const host = sanitizeHost(message.host);
    if (!host) {
      sendResponse({ ok: false, error: 'invalidHost' });
      return false;
    }

    (async () => {
      try {
        const requestPayload = { type: 'listCredentials', host };
        const currentURL = sanitizeCurrentURL(message.currentURL);
        if (currentURL) {
          requestPayload.currentURL = currentURL;
        }

        const response = await sendNativeMessage(requestPayload);
        if (!response || typeof response !== 'object') {
          sendResponse({ ok: false, error: 'invalidNativeResponse' });
          return;
        }
        // Response should contain credentials array with metadata only (no passwords)
        sendResponse(response);
      } catch (error) {
        const errorMessage = String(error && error.message ? error.message : error);
        sendResponse({
          ok: false,
          error: errorMessage === 'nativeMessagingTimeout' ? 'nativeMessagingTimeout' : 'nativeMessagingFailed',
          detail: errorMessage === 'nativeMessagingTimeout' ? 'Authsia native host did not respond.' : errorMessage
        });
      }
    })();

    return true; // Keep channel open for async response
  }

  // Handle GET_CREDENTIALS - returns full credential with password
  if (message.type === MESSAGE_TYPE_GET_CREDENTIALS) {
    const host = sanitizeHost(message.host);
    if (!host) {
      sendResponse({ ok: false, error: 'invalidHost' });
      return false;
    }

    (async () => {
      try {
        const requestPayload = { type: 'getCredentials', host };
        const currentURL = sanitizeCurrentURL(message.currentURL);
        if (currentURL) {
          requestPayload.currentURL = currentURL;
        }
        // If a specific credential ID is provided, include it
        if (message.credentialId) {
          requestPayload.credentialId = message.credentialId;
        }

        const response = await sendNativeMessage(requestPayload);
        if (!response || typeof response !== 'object') {
          sendResponse({ ok: false, error: 'invalidNativeResponse' });
          return;
        }
        // Do not log response contents to avoid leaking secrets.
        sendResponse(response);
      } catch (error) {
        // Do not include host or credentials in logs.
        const errorMessage = String(error && error.message ? error.message : error);
        sendResponse({
          ok: false,
          error: errorMessage === 'nativeMessagingTimeout' ? 'nativeMessagingTimeout' : 'nativeMessagingFailed',
          detail: errorMessage === 'nativeMessagingTimeout' ? 'Authsia native host did not respond.' : errorMessage
        });
      }
    })();

    // Keep the message channel open for the async response.
    return true;
  }

  // Handle OPEN_APP - launch Authsia via native host
  if (message.type === 'AUTHsia_OPEN_APP') {
    sendNativeMessage({ type: 'openApp' }).catch(() => {});
    return false;
  }

  return false;
});
