/**
 * Authsia Popup Menu
 * Handles credential list display and user interaction.
 */

(function initMenu() {
    'use strict';

    const MESSAGE_TYPE_LIST = 'AUTHsia_LIST_CREDENTIALS';
    const MESSAGE_TYPE_GET = 'AUTHsia_GET_CREDENTIALS';
    let nextRequestId = 1;
    const pendingRequests = new Map();

    // DOM Elements
    const listContainer = document.getElementById('authsia-list');
    const emptyState = document.getElementById('authsia-empty');
    const loadingState = document.getElementById('authsia-loading');
    const errorState = document.getElementById('authsia-error');
    const footerLink = document.getElementById('authsia-footer-link');

    // Parse URL parameters
    function getParams() {
        const params = new URLSearchParams(window.location.search);
        return {
            host: params.get('host') || '',
            currentURL: params.get('currentURL') || '',
            fieldType: params.get('fieldType') || 'username',
            frameId: params.get('frameId') || '',
        };
    }

    function pageOrigin() {
        try {
            return new URL(getParams().currentURL).origin;
        } catch (err) {
            return '*';
        }
    }

    function requestRuntime(message) {
        return new Promise(function (resolve) {
            const requestId = 'authsia-' + nextRequestId++;
            pendingRequests.set(requestId, resolve);
            window.parent.postMessage({
                type: 'AUTHSIA_REQUEST',
                requestId: requestId,
                message: message,
            }, pageOrigin());
        });
    }

    window.addEventListener('message', function (event) {
        if (event.source !== window.parent || event.origin !== pageOrigin() ||
            !event.data || event.data.type !== 'AUTHSIA_RESPONSE') {
            return;
        }
        const resolve = pendingRequests.get(event.data.requestId);
        if (!resolve) {
            return;
        }
        pendingRequests.delete(event.data.requestId);
        resolve(event.data.response);
    });

    // Show/hide states
    function showState(state, detail) {
        listContainer.style.display = state === 'list' ? 'block' : 'none';
        emptyState.style.display = state === 'empty' ? 'flex' : 'none';
        loadingState.style.display = state === 'loading' ? 'block' : 'none';
        errorState.style.display = state === 'error' ? 'flex' : 'none';

        // Show error detail hint if provided
        if (state === 'error' && detail) {
            var hint = errorState.querySelector('.authsia-error-hint');
            if (hint) {
                hint.textContent = detail;
            }
        }

        if (state === 'empty') {
            var params = getParams();
            var emptyText = emptyState.querySelector('.authsia-empty-text');
            if (emptyText) {
                emptyText.textContent = params.host
                    ? 'No passwords for ' + params.host
                    : 'No passwords for this site';
            }
        }

        postResize();
    }

    // Tell the content script to size the iframe to the rendered content.
    function postResize() {
        var height = 0;
        if (document.documentElement && document.documentElement.scrollHeight) {
            height = document.documentElement.scrollHeight;
        } else if (document.body && document.body.scrollHeight) {
            height = document.body.scrollHeight;
        }
        if (height > 0 && window.parent) {
            window.parent.postMessage({ type: 'AUTHSIA_RESIZE', height: height }, '*');
        }
    }

    // Extract a display host from a stored website URL.
    function websiteHost(website) {
        if (!website) return '';
        try {
            var withScheme = String(website).indexOf('://') === -1
                ? 'https://' + website
                : String(website);
            return new URL(withScheme).hostname || '';
        } catch (err) {
            return '';
        }
    }

    // Generate a deterministic HSL color from a name string
    function avatarColor(name) {
        let hash = 0;
        for (let i = 0; i < name.length; i++) {
            hash = name.charCodeAt(i) + ((hash << 5) - hash);
        }
        const hue = Math.abs(hash) % 360;
        return 'hsl(' + hue + ', 45%, 52%)';
    }

    // Create a credential item element with metadata only. Secrets are fetched
    // only after the user selects an item.
    function createCredentialItem(credential) {
        const title = credential.name || credential.username || 'Unknown';
        const subtitleText = credential.username || websiteHost(credential.website) || 'Authsia';

        const item = document.createElement('div');
        item.className = 'authsia-item';
        item.setAttribute('tabindex', '0');
        item.setAttribute('role', 'option');
        item.setAttribute(
            'aria-label',
            'Fill credentials for ' + (credential.username || title)
        );

        // Letter avatar
        const avatar = document.createElement('span');
        avatar.className = 'authsia-item-avatar';
        var siteName = credential.name || credential.website || '';
        var letter = siteName.charAt(0).toUpperCase() || '?';
        avatar.textContent = letter;
        avatar.style.backgroundColor = avatarColor(siteName);
        avatar.setAttribute('aria-hidden', 'true');

        // Info block
        const info = document.createElement('div');
        info.className = 'authsia-item-info';

        const name = document.createElement('span');
        name.className = 'authsia-item-name';
        name.textContent = title;

        const subtitle = document.createElement('span');
        subtitle.className = 'authsia-item-username';
        subtitle.textContent = subtitleText;

        info.appendChild(name);
        info.appendChild(subtitle);

        item.appendChild(avatar);
        item.appendChild(info);

        // Click handler
        item.addEventListener('click', function () { handleItemClick(credential); });
        item.addEventListener('keydown', function (e) {
            if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                handleItemClick(credential);
            }
        });

        return item;
    }

    // Handle credential item click
    async function handleItemClick(credential) {
        const params = getParams();

        try {
            // Request full credential (with password) from service worker
            const response = await requestRuntime({
                type: MESSAGE_TYPE_GET,
                credentialId: credential.id,
            });

            if (response && response.ok && response.credential && response.credential.otpCode) {
                window.parent.postMessage({
                    type: 'AUTHSIA_FILL',
                    otpCode: response.credential.otpCode,
                    frameId: params.frameId,
                }, pageOrigin());
            } else if (response && response.ok && response.credential) {
                // Send fill command to parent content script
                window.parent.postMessage({
                    type: 'AUTHSIA_FILL',
                    username: response.credential.username,
                    password: response.credential.password,
                    frameId: params.frameId,
                }, pageOrigin());
            } else {
                showState('error', (response && response.detail) || '');
            }
        } catch (err) {
            showState('error', String(err.message || err));
        }
    }

    // Render the credential list
    function renderCredentials(credentials) {
        listContainer.textContent = '';
        const params = getParams();
        const expectedKind = params.fieldType === 'otp' ? 'otp' : 'password';
        const filteredCredentials = (credentials || []).filter(function (credential) {
            const kind = credential.kind === 'otp' ? 'otp' : 'password';
            return kind === expectedKind;
        });

        if (filteredCredentials.length === 0) {
            showState('empty');
            return;
        }

        for (var i = 0; i < filteredCredentials.length; i++) {
            listContainer.appendChild(createCredentialItem(filteredCredentials[i]));
        }

        showState('list');

        // Focus first item for keyboard navigation
        var firstItem = listContainer.querySelector('.authsia-item');
        if (firstItem) {
            firstItem.focus();
        }
    }

    // Load credentials from service worker
    async function loadCredentials() {
        const params = getParams();

        if (!params.host) {
            showState('empty');
            return;
        }

        showState('loading');

        try {
            const response = await requestRuntime({ type: MESSAGE_TYPE_LIST });

            if (response && response.ok && Array.isArray(response.credentials)) {
                renderCredentials(response.credentials);
            } else if (response && response.error) {
                showState('error', response.detail || '');
            } else {
                showState('empty');
            }
        } catch (err) {
            showState('error', String(err.message || err));
        }
    }

    // Keyboard navigation
    document.addEventListener('keydown', function (e) {
        if (e.key === 'Escape') {
            window.parent.postMessage({ type: 'AUTHSIA_CLOSE' }, '*');
            return;
        }

        const items = listContainer.querySelectorAll('.authsia-item');
        if (items.length === 0) return;

        const currentIndex = Array.from(items).findIndex(function (item) {
            return item === document.activeElement;
        });

        if (e.key === 'ArrowDown') {
            e.preventDefault();
            const nextIndex = currentIndex < items.length - 1 ? currentIndex + 1 : 0;
            items[nextIndex].focus();
        } else if (e.key === 'ArrowUp') {
            e.preventDefault();
            const prevIndex = currentIndex > 0 ? currentIndex - 1 : items.length - 1;
            items[prevIndex].focus();
        }
    });

    // Footer link - open Authsia app, then close menu
    if (footerLink) {
        footerLink.addEventListener('click', function () {
            chrome.runtime.sendMessage({ type: 'AUTHsia_OPEN_APP' });
            window.parent.postMessage({ type: 'AUTHSIA_CLOSE' }, '*');
        });
    }

    // Initialize
    loadCredentials();

})();
