/**
 * Authsia Content Script
 * Focus-based inline menu injection for Pro-tier autofill UX.
 */

(function initContentScript(root) {
  'use strict';

  // ============================================================================
  // Constants
  // ============================================================================

  const MENU_WIDTH = 320;
  const MENU_MAX_HEIGHT = 300;
  const MENU_MIN_HEIGHT = 72;
  const MENU_OFFSET_Y = 4;
  const DEBOUNCE_MS = 100;
  const MATCH_CACHE_TTL_MS = 30000;
  const ICON_SIZE = 20;
  const ICON_MARGIN_RIGHT = 6;
  const MESSAGE_TYPE_LIST = 'AUTHsia_LIST_CREDENTIALS';
  const FRAME_ID = 'authsia-menu-frame-' + Math.random().toString(36).slice(2, 10);
  const FIELD_ICON_HTML =
    '<svg width="14" height="14" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">' +
    '<path d="M13.5 7h-1V5.5C12.5 3.02 10.48 1 8 1S3.5 3.02 3.5 5.5V7h-1a.5.5 0 00-.5.5v7a.5.5 0 00.5.5h11a.5.5 0 00.5-.5v-7a.5.5 0 00-.5-.5zM5 5.5C5 3.85 6.35 2.5 8 2.5s3 1.35 3 3V7H5V5.5z" fill="currentColor"/>' +
    '</svg>';

  // ============================================================================
  // State
  // ============================================================================

  let currentMenuFrame = null;
  let activeInput = null;
  let focusDebounceTimer = null;
  let loginFields = [];
  let isExtensionContextValid = true;
  let currentMenuHeight = MENU_MAX_HEIGHT;
  let fieldIcon = null;
  let iconInput = null;
  let focusedInput = null;
  let focusGeneration = 0;
  const matchCache = new Map();

  // ============================================================================
  // Utility Functions
  // ============================================================================

  function getHost() {
    return (root.location && root.location.hostname)
      ? root.location.hostname.toLowerCase()
      : '';
  }

  function getCurrentURL() {
    return (root.location && root.location.href) ? root.location.href : '';
  }

  function getExtensionURL(path) {
    try {
      if (!root.chrome || !root.chrome.runtime || !root.chrome.runtime.getURL) {
        return null;
      }
      return root.chrome.runtime.getURL(path);
    } catch (error) {
      if (error && String(error.message || error).includes('Extension context invalidated')) {
        isExtensionContextValid = false;
        removeMenu();
        return null;
      }
      throw error;
    }
  }

  function getExtensionOrigin() {
    const extensionURL = getExtensionURL('');
    const match = extensionURL && extensionURL.match(/^(chrome-extension:\/\/[^/]+)/);
    return match ? match[1] : null;
  }

  function removeMenu() {
    if (currentMenuFrame) {
      currentMenuFrame.remove();
      currentMenuFrame = null;
    }
    activeInput = null;
  }

  function credentialFieldType(input) {
    const Heuristics = root.AuthsiaHeuristics;
    if (!input || !Heuristics || !Heuristics.classifyCredentialField) {
      return null;
    }
    return Heuristics.classifyCredentialField(input, document);
  }

  function isCredentialField(input) {
    if (!input || input.tagName !== 'INPUT') {
      return false;
    }
    return loginFields.includes(input) || credentialFieldType(input) !== null;
  }

  // ============================================================================
  // Match Gating
  // ============================================================================
  // 1Password behavior: the inline menu only auto-opens when the vault has at
  // least one matching item for this page. The field icon remains available
  // for manual access to empty/error states.

  function expectedKindForFieldType(fieldType) {
    return fieldType === 'otp' ? 'otp' : 'password';
  }

  // Autofill already completed for this login form — keep the field icon for
  // manual access, but do not auto-open the picker again.
  function loginFormAlreadyFilled(input) {
    const Heuristics = root.AuthsiaHeuristics;
    if (!Heuristics || !input) {
      return false;
    }

    const forms = Heuristics.findLoginForms(document);
    for (let index = 0; index < forms.length; index++) {
      const form = forms[index];
      if (form.usernameInput !== input && form.passwordInput !== input) {
        continue;
      }
      const usernameFilled = Boolean(
        form.usernameInput && String(form.usernameInput.value || '').trim()
      );
      const passwordFilled = Boolean(
        form.passwordInput && String(form.passwordInput.value || '')
      );
      return usernameFilled && passwordFilled;
    }

    const fieldType = credentialFieldType(input);
    if (fieldType === 'otp') {
      return Boolean(String(input.value || '').trim());
    }
    return false;
  }

  function cachedMatchCount(key) {
    const entry = matchCache.get(key);
    if (!entry) {
      return null;
    }
    if (Date.now() - entry.timestamp > MATCH_CACHE_TTL_MS) {
      matchCache.delete(key);
      return null;
    }
    return entry.count;
  }

  function handleContextInvalidated(error) {
    if (error && String(error.message || error).includes('Extension context invalidated')) {
      isExtensionContextValid = false;
      removeMenu();
      hideFieldIcon();
      return true;
    }
    return false;
  }

  function fetchMatchCount(host, currentURL, fieldType) {
    const key = host + '|' + currentURL + '|' + expectedKindForFieldType(fieldType);
    const cached = cachedMatchCount(key);
    if (cached !== null) {
      return Promise.resolve(cached);
    }

    return new Promise((resolve) => {
      let settled = false;
      const finish = (count) => {
        if (settled) return;
        settled = true;
        if (count >= 0) {
          matchCache.set(key, { count, timestamp: Date.now() });
        }
        resolve(count);
      };

      let request;
      try {
        request = root.chrome.runtime.sendMessage({
          type: MESSAGE_TYPE_LIST,
          host: host,
          currentURL: currentURL,
        });
      } catch (error) {
        handleContextInvalidated(error);
        finish(-1);
        return;
      }

      Promise.resolve(request)
        .then((response) => {
          if (!response || !response.ok || !Array.isArray(response.credentials)) {
            finish(-1);
            return;
          }
          const kind = expectedKindForFieldType(fieldType);
          const count = response.credentials.filter(
            (credential) => (credential.kind === 'otp' ? 'otp' : 'password') === kind
          ).length;
          finish(count);
        })
        .catch(() => finish(-1));
    });
  }

  // ============================================================================
  // Field Icon
  // ============================================================================

  function ensureFieldIcon() {
    if (fieldIcon) {
      return fieldIcon;
    }
    const icon = document.createElement('div');
    icon.id = 'authsia-field-icon';
    icon.setAttribute('role', 'button');
    icon.setAttribute('aria-label', 'Authsia: show saved items');
    icon.setAttribute('tabindex', '-1');
    icon.innerHTML = FIELD_ICON_HTML;

    const style = icon.style;
    style.position = 'absolute';
    style.width = `${ICON_SIZE}px`;
    style.height = `${ICON_SIZE}px`;
    style.display = 'flex';
    style.alignItems = 'center';
    style.justifyContent = 'center';
    style.cursor = 'pointer';
    style.borderRadius = '4px';
    style.color = '#6e6e73';
    style.background = 'transparent';
    style.zIndex = '2147483647';

    // Keep keyboard focus on the input when the icon is used.
    icon.addEventListener('mousedown', (event) => {
      event.preventDefault();
      event.stopPropagation();
    });
    icon.addEventListener('click', (event) => {
      event.preventDefault();
      event.stopPropagation();
      if (!isExtensionContextValid || !iconInput) {
        return;
      }
      if (currentMenuFrame) {
        removeMenu();
      } else {
        injectMenu(iconInput);
      }
    });

    fieldIcon = icon;
    return icon;
  }

  function positionIcon(input) {
    if (!fieldIcon || !input) {
      return;
    }
    const rect = input.getBoundingClientRect();
    const scrollX = root.scrollX || root.pageXOffset || 0;
    const scrollY = root.scrollY || root.pageYOffset || 0;
    fieldIcon.style.top = `${Math.round(rect.top + scrollY + (rect.height - ICON_SIZE) / 2)}px`;
    fieldIcon.style.left = `${Math.round(rect.right + scrollX - ICON_SIZE - ICON_MARGIN_RIGHT)}px`;
  }

  function showFieldIcon(input) {
    if (!isExtensionContextValid || !input) {
      return;
    }
    const icon = ensureFieldIcon();
    if (!icon.parentNode) {
      document.body.appendChild(icon);
    }
    iconInput = input;
    positionIcon(input);
  }

  function hideFieldIcon() {
    if (fieldIcon && fieldIcon.parentNode) {
      fieldIcon.parentNode.removeChild(fieldIcon);
    }
    iconInput = null;
  }

  // ============================================================================
  // Menu Positioning
  // ============================================================================

  function positionMenu(input, iframe) {
    const rect = input.getBoundingClientRect();
    const scrollX = root.scrollX || root.pageXOffset || 0;
    const scrollY = root.scrollY || root.pageYOffset || 0;
    const menuHeight = currentMenuHeight;

    // Position below the input field
    let top = rect.bottom + scrollY + MENU_OFFSET_Y;
    let left = rect.left + scrollX;

    // Ensure menu doesn't overflow viewport horizontally
    const viewportWidth = root.innerWidth || document.documentElement.clientWidth;
    if (left + MENU_WIDTH > viewportWidth - 10) {
      left = Math.max(10, viewportWidth - MENU_WIDTH - 10);
    }

    // Ensure menu doesn't overflow viewport vertically (flip above if needed)
    const viewportHeight = root.innerHeight || document.documentElement.clientHeight;
    const spaceBelow = viewportHeight - rect.bottom;
    const spaceAbove = rect.top;

    if (spaceBelow < menuHeight && spaceAbove > spaceBelow) {
      // Position above the input
      top = rect.top + scrollY - menuHeight - MENU_OFFSET_Y;
    }

    iframe.style.position = 'absolute';
    iframe.style.top = `${Math.max(0, top)}px`;
    iframe.style.left = `${Math.max(0, left)}px`;
    iframe.style.width = `${MENU_WIDTH}px`;
    iframe.style.maxHeight = `${MENU_MAX_HEIGHT}px`;
    iframe.style.height = `${menuHeight}px`;
    iframe.style.zIndex = '2147483647';
    iframe.style.border = 'none';
    iframe.style.borderRadius = '12px';
    iframe.style.boxShadow = '0 4px 24px rgba(0, 0, 0, 0.3)';
    iframe.style.overflow = 'hidden';
    iframe.style.backgroundColor = 'transparent';
    iframe.style.colorScheme = 'normal';
  }

  // ============================================================================
  // Menu Injection
  // ============================================================================

  function injectMenu(input) {
    if (!isExtensionContextValid) {
      return;
    }

    if (!input || activeInput === input) {
      return;
    }

    // Remove any existing menu
    removeMenu();
    activeInput = input;
    // Start compact; AUTHSIA_RESIZE grows to the real card height. Starting at
    // MENU_MAX_HEIGHT left a blank band under short menus.
    currentMenuHeight = MENU_MIN_HEIGHT;

    const host = getHost();
    if (!host) {
      return;
    }

    const fieldType = credentialFieldType(input) || 'username';

    // Create iframe
    const iframe = document.createElement('iframe');
    iframe.id = FRAME_ID;
    iframe.setAttribute('aria-label', 'Authsia password menu');
    iframe.setAttribute('role', 'dialog');
    iframe.setAttribute('tabindex', '-1');

    // Build URL with parameters
    const menuUrl = getExtensionURL('popup/menu.html');
    if (!menuUrl) {
      return;
    }
    const params = new URLSearchParams({
      host: host,
      currentURL: getCurrentURL(),
      fieldType: fieldType,
      frameId: FRAME_ID,
    });
    iframe.src = `${menuUrl}?${params.toString()}`;

    // Style the iframe
    positionMenu(input, iframe);

    // Add to document
    document.body.appendChild(iframe);
    currentMenuFrame = iframe;

    // Reposition on scroll/resize
    const repositionHandler = () => {
      if (currentMenuFrame && activeInput) {
        positionMenu(activeInput, currentMenuFrame);
      }
      if (iconInput) {
        positionIcon(iconInput);
      }
    };

    root.addEventListener('scroll', repositionHandler, { passive: true });
    root.addEventListener('resize', repositionHandler, { passive: true });

    // Clean up listeners when menu is removed
    const observer = new MutationObserver((mutations) => {
      for (const mutation of mutations) {
        for (const node of mutation.removedNodes) {
          if (node === iframe) {
            root.removeEventListener('scroll', repositionHandler);
            root.removeEventListener('resize', repositionHandler);
            observer.disconnect();
            return;
          }
        }
      }
    });

    observer.observe(document.body, { childList: true });
  }

  // ============================================================================
  // Fill Handler
  // ============================================================================

  function setInputValue(input, value) {
    if (!input) return;

    // Focus and set value
    input.focus({ preventScroll: true });

    // Use native setter to bypass React/Angular wrappers
    const nativeInputValueSetter = Object.getOwnPropertyDescriptor(
      HTMLInputElement.prototype,
      'value'
    )?.set;

    if (nativeInputValueSetter) {
      nativeInputValueSetter.call(input, value);
    } else {
      input.value = value;
    }

    // Dispatch events for framework reactivity
    input.dispatchEvent(new Event('input', { bubbles: true, cancelable: true }));
    input.dispatchEvent(new Event('change', { bubbles: true, cancelable: true }));

    // Also dispatch keyboard event for some frameworks
    input.dispatchEvent(new KeyboardEvent('keydown', { bubbles: true }));
    input.dispatchEvent(new KeyboardEvent('keyup', { bubbles: true }));
  }

  function normalizedOTPCode(value) {
    return String(value || '').replace(/\s+/g, '');
  }

  function inputMaxLength(input) {
    const attr = input.getAttribute && input.getAttribute('maxlength');
    const parsedAttr = attr ? parseInt(attr, 10) : NaN;
    if (Number.isFinite(parsedAttr) && parsedAttr > 0) {
      return parsedAttr;
    }
    const propertyValue = Number(input.maxLength);
    return Number.isFinite(propertyValue) && propertyValue > 0 ? propertyValue : null;
  }

  function isSingleCharacterOTPInput(input) {
    const Heuristics = root.AuthsiaHeuristics;
    if (!input || !Heuristics || !Heuristics.isEditable || !Heuristics.isVisible) {
      return false;
    }

    if (!Heuristics.isEditable(input) || !Heuristics.isVisible(input)) {
      return false;
    }

    const type = (input.getAttribute('type') || 'text').toLowerCase();
    if (!['text', 'tel', 'number', 'search', ''].includes(type)) {
      return false;
    }

    return inputMaxLength(input) === 1;
  }

  function findSplitOTPInputs(anchorInput, otpCode) {
    const code = normalizedOTPCode(otpCode);
    if (!anchorInput || code.length < 2) {
      return null;
    }

    const Heuristics = root.AuthsiaHeuristics;
    if (!Heuristics || !Heuristics.scoreOTPField) {
      return null;
    }

    const inputs = Array.from(document.querySelectorAll('input')).filter(isSingleCharacterOTPInput);
    const anchorIndex = inputs.indexOf(anchorInput);
    if (anchorIndex === -1 || inputs.length < code.length) {
      return null;
    }

    const minStart = Math.max(0, anchorIndex - code.length + 1);
    const maxStart = Math.min(anchorIndex, inputs.length - code.length);
    for (let start = minStart; start <= maxStart; start++) {
      const group = inputs.slice(start, start + code.length);
      if (group.length === code.length && group.some((input) => Heuristics.scoreOTPField(input) > 0)) {
        return group;
      }
    }

    return null;
  }

  function fillOTPCode(otpCode) {
    const code = normalizedOTPCode(otpCode);
    const splitInputs = findSplitOTPInputs(activeInput, code);
    if (splitInputs) {
      for (let index = 0; index < splitInputs.length; index++) {
        setInputValue(splitInputs[index], code[index]);
      }
      return;
    }

    setInputValue(activeInput, code);
  }

  function fillActiveSingleField(data) {
    const fieldType = credentialFieldType(activeInput);
    if (fieldType === 'password') {
      setInputValue(activeInput, data.password);
      return true;
    }
    if (fieldType === 'username') {
      setInputValue(activeInput, data.username);
      return true;
    }
    return false;
  }

  function handleFillMessage(data) {
    if (data && data.otpCode) {
      fillOTPCode(data.otpCode);
      removeMenu();
      return;
    }

    if (!data || !data.username || !data.password) {
      return;
    }

    // Find the login form fields
    const Heuristics = root.AuthsiaHeuristics;
    if (!Heuristics) {
      return;
    }

    const forms = Heuristics.findLoginForms(document);
    if (forms.length === 0) {
      if (fillActiveSingleField(data)) {
        removeMenu();
      }
      return;
    }

    // Use the first form (or the one containing activeInput)
    let targetForm = forms[0];
    for (const form of forms) {
      if (form.usernameInput === activeInput || form.passwordInput === activeInput) {
        targetForm = form;
        break;
      }
    }

    // Fill the fields
    setInputValue(targetForm.usernameInput, data.username);
    setInputValue(targetForm.passwordInput, data.password);

    // Close the menu
    removeMenu();
  }

  // ============================================================================
  // Event Handlers
  // ============================================================================

  function handleFocusIn(event) {
    if (!isExtensionContextValid) {
      return;
    }

    const target = event.target;
    if (!target || target.tagName !== 'INPUT') {
      return;
    }

    // Check if this is a login field
    const Heuristics = root.AuthsiaHeuristics;
    if (!Heuristics) {
      return;
    }

    // Debounce to avoid rapid re-injection
    if (focusDebounceTimer) {
      clearTimeout(focusDebounceTimer);
    }
    const generation = ++focusGeneration;
    focusedInput = target;

    focusDebounceTimer = setTimeout(() => {
      focusDebounceTimer = null;
      if (generation !== focusGeneration || focusedInput !== target || !isCredentialField(target)) {
        return;
      }

      showFieldIcon(target);

      const host = getHost();
      if (!host) {
        return;
      }

      if (loginFormAlreadyFilled(target)) {
        return;
      }

      const fieldType = credentialFieldType(target) || 'username';
      fetchMatchCount(host, getCurrentURL(), fieldType).then((count) => {
        // Only auto-open when the vault has something to offer and the
        // field still has focus. The field icon covers every other case.
        if (
          count > 0 &&
          generation === focusGeneration &&
          focusedInput === target &&
          isExtensionContextValid &&
          !loginFormAlreadyFilled(target)
        ) {
          injectMenu(target);
        }
      });
    }, DEBOUNCE_MS);
  }

  function handleFocusOut(event) {
    if (focusedInput && event.target === focusedInput) {
      focusedInput = null;
      focusGeneration += 1;
      if (focusDebounceTimer) {
        clearTimeout(focusDebounceTimer);
        focusDebounceTimer = null;
      }
    }

    // Delay to allow click on menu items
    setTimeout(() => {
      const active = document.activeElement;

      // Focus moved to another login field: let its focusin take over.
      if (isCredentialField(active)) {
        return;
      }

      // Focus is inside the menu iframe.
      if (currentMenuFrame && active === currentMenuFrame) {
        return;
      }

      removeMenu();
      hideFieldIcon();
    }, 150);
  }

  function handleClickOutside(event) {
    // Icon clicks toggle the menu via their own handler.
    if (fieldIcon && (event.target === fieldIcon ||
        (fieldIcon.contains && fieldIcon.contains(event.target)))) {
      return;
    }

    if (!currentMenuFrame) return;

    // Check if click is outside the menu and outside login fields
    const target = event.target;
    if (target === currentMenuFrame) return;
    if (isCredentialField(target)) return;

    removeMenu();
  }

  function handleMessage(event) {
    if (!event.data || typeof event.data !== 'object') {
      return;
    }

    // Only accept messages from our own menu iframe
    if (!currentMenuFrame || event.source !== currentMenuFrame.contentWindow) {
      return;
    }

    const extensionOrigin = getExtensionOrigin();
    if (!extensionOrigin || event.origin !== extensionOrigin) {
      return;
    }

    switch (event.data.type) {
      case 'AUTHSIA_FILL':
        handleFillMessage(event.data);
        break;
      case 'AUTHSIA_CLOSE':
        removeMenu();
        break;
      case 'AUTHSIA_RESIZE': {
        const height = Number(event.data.height);
        if (Number.isFinite(height)) {
          currentMenuHeight = Math.max(MENU_MIN_HEIGHT, Math.min(MENU_MAX_HEIGHT, Math.round(height)));
          if (activeInput) {
            positionMenu(activeInput, currentMenuFrame);
          }
        }
        break;
      }
      case 'AUTHSIA_REQUEST': {
        const requestId = event.data.requestId;
        const requestedMessage = event.data.message;
        if (typeof requestId !== 'string' || !requestedMessage || typeof requestedMessage !== 'object') {
          break;
        }
        if (requestedMessage.type !== 'AUTHsia_LIST_CREDENTIALS' &&
            requestedMessage.type !== 'AUTHsia_GET_CREDENTIALS') {
          break;
        }

        const frame = currentMenuFrame;
        const runtimeMessage = {
          type: requestedMessage.type,
          host: getHost(),
          currentURL: getCurrentURL(),
        };
        if (requestedMessage.type === 'AUTHsia_GET_CREDENTIALS' &&
            typeof requestedMessage.credentialId === 'string') {
          runtimeMessage.credentialId = requestedMessage.credentialId;
        }

        Promise.resolve(root.chrome.runtime.sendMessage(runtimeMessage))
          .then((response) => {
            if (currentMenuFrame === frame) {
              frame.contentWindow.postMessage({
                type: 'AUTHSIA_RESPONSE',
                requestId,
                response,
              }, extensionOrigin);
            }
          })
          .catch((error) => {
            handleContextInvalidated(error);
            if (currentMenuFrame === frame) {
              frame.contentWindow.postMessage({
                type: 'AUTHSIA_RESPONSE',
                requestId,
                response: { ok: false, error: 'runtimeMessageFailed' },
              }, extensionOrigin);
            }
          });
        break;
      }
    }
  }

  // ============================================================================
  // Initialization
  // ============================================================================

  function scanForLoginFields() {
    const Heuristics = root.AuthsiaHeuristics;
    if (!Heuristics) {
      return;
    }

    loginFields = Heuristics.findAllLoginFields(document);
  }

  function init() {
    // Wait for heuristics to be available
    if (!root.AuthsiaHeuristics) {
      setTimeout(init, 50);
      return;
    }

    // Scan for login fields
    scanForLoginFields();

    // Set up observers for dynamic content
    const observer = new MutationObserver(() => {
      // Re-scan when DOM changes
      setTimeout(scanForLoginFields, 100);
    });

    observer.observe(document.body, {
      childList: true,
      subtree: true,
    });

    // Set up event listeners
    document.addEventListener('focusin', handleFocusIn, true);
    document.addEventListener('focusout', handleFocusOut, true);
    document.addEventListener('click', handleClickOutside, true);
    root.addEventListener('message', handleMessage);

    // Keep the field icon glued to its input while it is visible.
    const iconRepositionHandler = () => {
      if (iconInput) {
        positionIcon(iconInput);
      }
    };
    root.addEventListener('scroll', iconRepositionHandler, { passive: true, capture: true });
    root.addEventListener('resize', iconRepositionHandler, { passive: true });

    // Handle escape key globally
    document.addEventListener('keydown', (event) => {
      if (event.key === 'Escape' && currentMenuFrame) {
        removeMenu();
        event.preventDefault();
      }
    });
  }

  // Start initialization
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init, { once: true });
  } else {
    init();
  }

})(typeof globalThis !== 'undefined' ? globalThis : this);
