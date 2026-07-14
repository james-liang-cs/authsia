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
  const MENU_OFFSET_Y = 4;
  const DEBOUNCE_MS = 100;
  const FRAME_ID = 'authsia-menu-frame-' + Math.random().toString(36).slice(2, 10);

  // ============================================================================
  // State
  // ============================================================================

  let currentMenuFrame = null;
  let activeInput = null;
  let focusDebounceTimer = null;
  let loginFields = [];
  let isExtensionContextValid = true;

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

  function removeMenu() {
    if (currentMenuFrame) {
      currentMenuFrame.remove();
      currentMenuFrame = null;
    }
    activeInput = null;
  }

  function credentialFieldType(input) {
    const Heuristics = root.AuthsiaHeuristics;
    if (!input || !Heuristics) {
      return null;
    }

    if (Heuristics.scoreOTPField && Heuristics.scoreOTPField(input) > 0) {
      return 'otp';
    }

    if (Heuristics.scorePasswordField && Heuristics.scorePasswordField(input) > 0) {
      return 'password';
    }

    if (Heuristics.scoreUsernameField && Heuristics.scoreUsernameField(input) > 0) {
      return 'username';
    }

    return null;
  }

  function isCredentialField(input) {
    return loginFields.includes(input) || credentialFieldType(input) !== null;
  }

  // ============================================================================
  // Menu Positioning
  // ============================================================================

  function positionMenu(input, iframe) {
    const rect = input.getBoundingClientRect();
    const scrollX = root.scrollX || root.pageXOffset || 0;
    const scrollY = root.scrollY || root.pageYOffset || 0;

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

    if (spaceBelow < MENU_MAX_HEIGHT && spaceAbove > spaceBelow) {
      // Position above the input
      top = rect.top + scrollY - MENU_MAX_HEIGHT - MENU_OFFSET_Y;
    }

    iframe.style.position = 'absolute';
    iframe.style.top = `${Math.max(0, top)}px`;
    iframe.style.left = `${Math.max(0, left)}px`;
    iframe.style.width = `${MENU_WIDTH}px`;
    iframe.style.maxHeight = `${MENU_MAX_HEIGHT}px`;
    iframe.style.height = `${MENU_MAX_HEIGHT}px`;
    iframe.style.zIndex = '2147483647';
    iframe.style.border = 'none';
    iframe.style.borderRadius = '12px';
    iframe.style.boxShadow = '0 4px 24px rgba(0, 0, 0, 0.3)';
    iframe.style.overflow = 'hidden';
    iframe.style.colorScheme = 'dark';
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

    focusDebounceTimer = setTimeout(() => {
      // Check if it's a login field
      if (isCredentialField(target)) {
        injectMenu(target);
      }
    }, DEBOUNCE_MS);
  }

  function handleFocusOut(event) {
    // Delay to allow click on menu items
    setTimeout(() => {
      // Check if focus moved to the menu iframe
      if (currentMenuFrame && document.activeElement !== currentMenuFrame) {
        // Check if focus is still on a login field
        const stillOnLoginField = loginFields.includes(document.activeElement);
        if (!stillOnLoginField) {
          removeMenu();
        }
      }
    }, 150);
  }

  function handleClickOutside(event) {
    if (!currentMenuFrame) return;

    // Check if click is outside the menu and outside login fields
    const target = event.target;
    if (target === currentMenuFrame) return;
    if (loginFields.includes(target)) return;

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

    switch (event.data.type) {
      case 'AUTHSIA_FILL':
        handleFillMessage(event.data);
        break;
      case 'AUTHSIA_CLOSE':
        removeMenu();
        break;
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
