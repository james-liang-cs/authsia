(function initNativeClient(root) {
  const MESSAGE_TYPE_GET_CREDENTIALS = 'AUTHsia_GET_CREDENTIALS';

  async function requestCredentialsForHost(host) {
    return chrome.runtime.sendMessage({ type: MESSAGE_TYPE_GET_CREDENTIALS, host });
  }

  root.AuthsiaNativeClient = {
    requestCredentialsForHost,
  };
})(typeof globalThis !== 'undefined' ? globalThis : this);
