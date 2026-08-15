const NATIVE_HOST_NAME = 'com.authsia.nativehost';
const MESSAGE_TYPE_GET_CREDENTIALS = 'AUTHsia_GET_CREDENTIALS';
const MESSAGE_TYPE_LIST_CREDENTIALS = 'AUTHsia_LIST_CREDENTIALS';
const NATIVE_MESSAGE_TIMEOUT_MS = 45000;

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

function comparableURL(currentURL) {
  const sanitized = sanitizeCurrentURL(currentURL);
  if (!sanitized) {
    return null;
  }
  const url = new URL(sanitized);
  url.hash = '';
  return url.href;
}

function isLoopbackHostname(hostname) {
  return hostname === 'localhost' || hostname === '127.0.0.1';
}

function hostnameFromHTTPOrigin(origin) {
  if (typeof origin !== 'string' || !origin) {
    return null;
  }
  try {
    const url = new URL(origin);
    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
      return null;
    }
    return url.hostname.toLowerCase();
  } catch {
    return null;
  }
}

function rejectInsecureSender(protocol, hostname) {
  return protocol === 'http:' && !isLoopbackHostname(hostname)
    ? { error: 'insecureContext' }
    : null;
}

function attestPageRequest(message, sender) {
  const host = sanitizeHost(message.host);
  if (!host) {
    return { error: 'invalidHost' };
  }

  // Chrome attests the frame. Prefer sender.url; some sign-in pages (notably
  // Gaia) omit it or let it drift from location.href after replaceState.
  // A page-claimed path is never trusted over the attested frame URL.
  const senderURL = comparableURL(sender && sender.url);
  let senderHost = null;
  let senderProtocol = null;
  if (senderURL) {
    const parsedSenderURL = new URL(senderURL);
    senderHost = parsedSenderURL.hostname.toLowerCase();
    senderProtocol = parsedSenderURL.protocol;
  } else {
    senderHost = hostnameFromHTTPOrigin(sender && sender.origin);
    if (senderHost && sender && sender.origin) {
      try {
        senderProtocol = new URL(sender.origin).protocol;
      } catch {
        senderProtocol = null;
      }
    }
  }

  if (!senderHost || senderHost !== host) {
    return { error: 'senderMismatch' };
  }

  const insecure = rejectInsecureSender(senderProtocol, senderHost);
  if (insecure) {
    return insecure;
  }

  return { host, currentURL: senderURL };
}

function credentialKind(message) {
  if (message.kind === undefined) {
    return { kind: null };
  }
  if (message.kind === 'password' || message.kind === 'otp') {
    return { kind: message.kind };
  }
  return { error: 'invalidCredentialKind' };
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

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message) {
    return false;
  }

  // Handle LIST_CREDENTIALS - returns metadata only (no passwords)
  if (message.type === MESSAGE_TYPE_LIST_CREDENTIALS) {
    const kindResult = credentialKind(message);
    if (kindResult.error) {
      sendResponse({ ok: false, error: kindResult.error });
      return false;
    }
    const requestContext = attestPageRequest(message, sender);
    if (requestContext.error) {
      sendResponse({ ok: false, error: requestContext.error });
      return false;
    }

    (async () => {
      try {
        const requestPayload = { type: 'listCredentials', host: requestContext.host };
        if (requestContext.currentURL) {
          requestPayload.currentURL = requestContext.currentURL;
        }
        if (kindResult.kind) {
          requestPayload.kind = kindResult.kind;
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
    const kindResult = credentialKind(message);
    if (kindResult.error) {
      sendResponse({ ok: false, error: kindResult.error });
      return false;
    }
    const requestContext = attestPageRequest(message, sender);
    if (requestContext.error) {
      sendResponse({ ok: false, error: requestContext.error });
      return false;
    }

    (async () => {
      try {
        const requestPayload = { type: 'getCredentials', host: requestContext.host };
        if (requestContext.currentURL) {
          requestPayload.currentURL = requestContext.currentURL;
        }
        // If a specific credential ID is provided, include it
        if (message.credentialId) {
          requestPayload.credentialId = message.credentialId;
        }
        if (kindResult.kind) {
          requestPayload.kind = kindResult.kind;
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
