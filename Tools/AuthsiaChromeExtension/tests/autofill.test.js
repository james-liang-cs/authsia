/**
 * Authsia Autofill (Content Script) Tests
 * Tests the focus-based inline menu injection and AUTHSIA_FILL message handling.
 */

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const heuristicsCode = fs.readFileSync(
    path.join(__dirname, '..', 'heuristics.js'),
    'utf8'
);
const contentScriptCode = fs.readFileSync(
    path.join(__dirname, '..', 'content_script.js'),
    'utf8'
);

// ============================================================================
// Timer Helpers
// ============================================================================

/**
 * Creates a controlled timer system. setTimeout/clearTimeout queue callbacks
 * that only execute when flush() is called.
 */
function createTimerController() {
    let nextId = 1;
    const pending = new Map();

    function fakeSetTimeout(fn, delay) {
        const id = nextId++;
        pending.set(id, fn);
        return id;
    }

    function fakeClearTimeout(id) {
        pending.delete(id);
    }

    /** Execute all currently queued callbacks (one pass). */
    function flush() {
        const callbacks = Array.from(pending.values());
        pending.clear();
        for (const cb of callbacks) {
            cb();
        }
    }

    /** Repeatedly flush until no new timers are queued, up to maxIterations. */
    function drain(maxIterations = 20) {
        for (let i = 0; i < maxIterations && pending.size > 0; i++) {
            flush();
        }
    }

    return { fakeSetTimeout, fakeClearTimeout, flush, drain, pending };
}

// ============================================================================
// Mock DOM Helpers
// ============================================================================

function createMockInput(attrs = {}) {
    const attrMap = Object.assign(
        { type: 'text', name: '', id: '', autocomplete: '', placeholder: '' },
        attrs
    );
    const visible = attrMap.visible !== false;
    const events = [];
    let value = '';

    const input = {
        tagName: 'INPUT',
        disabled: Boolean(attrMap.disabled),
        readOnly: Boolean(attrMap.readOnly),
        id: attrMap.id || '',
        form: attrMap.form || null,
        events,
        get value() { return value; },
        set value(v) { value = v; },
        getAttribute(name) {
            return attrMap[name] !== undefined ? attrMap[name] : null;
        },
        setAttribute() {},
        getBoundingClientRect() {
            return visible
                ? { width: 200, height: 30, top: 100, bottom: 130, left: 50, right: 250 }
                : { width: 0, height: 0, top: 0, bottom: 0, left: 0, right: 0 };
        },
        offsetParent: visible ? {} : null,
        closest() { return null; },
        focus() {},
        dispatchEvent(event) {
            events.push(event.type);
            return true;
        },
    };

    return input;
}

/**
 * Creates a full mock environment (context) for running heuristics + content_script
 * in a VM. Returns the context, timer controller, and accessors.
 */
function createMockContext(opts = {}) {
    const timers = createTimerController();
    const inputs = opts.inputs || [];
    const host = opts.host || 'example.com';
    const appendedChildren = [];
    const docEventListeners = {};
    let activeElement = opts.activeElement || null;

    // Track root-level (window) event listeners
    let messageHandler = null;
    const rootListeners = {};

    // Sentinel object used as contentWindow for created iframes
    const iframeContentWindow = {};

    const document = {
        readyState: 'complete',
        body: {
            appendChild(child) {
                appendedChildren.push(child);
            },
        },
        createElement(tag) {
            if (tag === 'iframe') {
                const iframe = {
                    tagName: 'IFRAME',
                    id: '',
                    src: '',
                    style: {},
                    contentWindow: iframeContentWindow,
                    setAttribute(name, val) { iframe[name] = val; },
                    getAttribute(name) { return iframe[name] || null; },
                    remove() {
                        const idx = appendedChildren.indexOf(iframe);
                        if (idx !== -1) appendedChildren.splice(idx, 1);
                    },
                };
                return iframe;
            }
            return {
                tagName: tag.toUpperCase(),
                style: {},
                setAttribute() {},
                getAttribute() { return null; },
            };
        },
        addEventListener(type, handler, captureOpts) {
            if (!docEventListeners[type]) docEventListeners[type] = [];
            docEventListeners[type].push(handler);
        },
        removeEventListener() {},
        querySelectorAll(selector) {
            if (selector === 'input') return inputs;
            if (selector === 'input[type="password"]') {
                return inputs.filter(
                    (i) => (i.getAttribute('type') || '').toLowerCase() === 'password'
                );
            }
            return [];
        },
        querySelector() { return null; },
    };

    // Allow reading/writing activeElement dynamically
    Object.defineProperty(document, 'activeElement', {
        get() { return activeElement; },
        set(v) { activeElement = v; },
        configurable: true,
    });

    const context = {
        console,
        document,
        location: { hostname: host, href: 'https://' + host + '/' },
        setTimeout: timers.fakeSetTimeout,
        clearTimeout: timers.fakeClearTimeout,
        innerWidth: 1024,
        innerHeight: 768,
        scrollX: 0,
        scrollY: 0,
        pageXOffset: 0,
        pageYOffset: 0,
        getComputedStyle() {
            return { visibility: 'visible', display: 'block', opacity: '1' };
        },
        addEventListener(type, handler, opts) {
            if (!rootListeners[type]) rootListeners[type] = [];
            rootListeners[type].push(handler);
            if (type === 'message') {
                messageHandler = handler;
            }
        },
        removeEventListener() {},
        MutationObserver: class {
            constructor(cb) { this._cb = cb; }
            observe() {}
            disconnect() {}
        },
        HTMLInputElement: {
            prototype: {},
        },
        Event: class {
            constructor(type, opts = {}) {
                this.type = type;
                this.bubbles = Boolean(opts.bubbles);
                this.cancelable = Boolean(opts.cancelable);
            }
        },
        KeyboardEvent: class {
            constructor(type, opts = {}) {
                this.type = type;
                this.key = opts.key || '';
                this.bubbles = Boolean(opts.bubbles);
            }
            preventDefault() {}
        },
        URLSearchParams: URLSearchParams,
        chrome: {
            runtime: {
                getURL: opts.runtimeGetURL || function getURL(p) {
                    return 'chrome-extension://fakeid/' + p;
                },
                sendMessage() {},
            },
        },
        CSS: {
            escape(s) { return s; },
        },
        globalThis: undefined,
    };

    context.globalThis = context;

    return {
        context,
        timers,
        appendedChildren,
        docEventListeners,
        iframeContentWindow,
        getMessageHandler() { return messageHandler; },
        setActiveElement(el) { activeElement = el; },
    };
}

/**
 * Loads heuristics.js and content_script.js into the given context.
 * Drains timers so init() completes.
 */
function loadScripts(ctx, timers) {
    vm.createContext(ctx);
    vm.runInContext(heuristicsCode, ctx, { filename: 'heuristics.js' });
    vm.runInContext(contentScriptCode, ctx, { filename: 'content_script.js' });
    timers.drain();
}

// ============================================================================
// Tests
// ============================================================================

function testMenuInjectedOnLoginFieldFocus() {
    const usernameInput = createMockInput({
        type: 'email',
        name: 'email',
        autocomplete: 'username',
    });
    const passwordInput = createMockInput({
        type: 'password',
        name: 'password',
    });

    const { context, timers, appendedChildren, docEventListeners } = createMockContext({
        inputs: [usernameInput, passwordInput],
        host: 'login.example.com',
    });

    loadScripts(context, timers);

    // Simulate focusing on the username input
    const focusinHandlers = docEventListeners['focusin'] || [];
    assert.ok(focusinHandlers.length > 0, 'focusin handler should be registered');

    focusinHandlers.forEach((handler) =>
        handler({ target: usernameInput })
    );

    // Flush the debounce timer
    timers.flush();

    // An iframe should have been appended to document.body
    const iframes = appendedChildren.filter((c) => c.tagName === 'IFRAME');
    assert.strictEqual(iframes.length, 1, 'one iframe menu should be injected');
    assert.ok(
        iframes[0].src.includes('menu.html'),
        'iframe src should point to menu.html'
    );
    assert.ok(
        iframes[0].src.includes('host=login.example.com'),
        'iframe src should include the host parameter'
    );
    assert.strictEqual(iframes[0].style.height, '300px', 'iframe should reserve the full picker height');
}

function testMenuNotInjectedWhenNoLoginFields() {
    const searchInput = createMockInput({ type: 'text', name: 'q' });

    const { context, timers, appendedChildren, docEventListeners } = createMockContext({
        inputs: [searchInput],
        host: 'example.com',
    });

    loadScripts(context, timers);

    const focusinHandlers = docEventListeners['focusin'] || [];
    if (focusinHandlers.length > 0) {
        focusinHandlers.forEach((handler) =>
            handler({ target: searchInput })
        );
        timers.flush();
    }

    const iframes = appendedChildren.filter((c) => c.tagName === 'IFRAME');
    assert.strictEqual(iframes.length, 0, 'no menu should be injected for non-login fields');
}

function testFillMessagePopulatesFields() {
    const usernameInput = createMockInput({
        type: 'text',
        name: 'username',
        autocomplete: 'username',
    });
    const passwordInput = createMockInput({
        type: 'password',
        name: 'password',
    });

    const {
        context, timers, appendedChildren, docEventListeners,
        iframeContentWindow, getMessageHandler,
    } = createMockContext({
        inputs: [usernameInput, passwordInput],
        host: 'example.com',
    });

    loadScripts(context, timers);

    // First, inject the menu by focusing on a login field.
    // The content script's handleMessage checks event.source === currentMenuFrame.contentWindow
    const focusinHandlers = docEventListeners['focusin'] || [];
    focusinHandlers.forEach((handler) =>
        handler({ target: usernameInput })
    );
    timers.flush();

    // Verify menu was injected
    const iframes = appendedChildren.filter((c) => c.tagName === 'IFRAME');
    assert.strictEqual(iframes.length, 1, 'menu must be present before fill');

    // Now simulate AUTHSIA_FILL postMessage from the iframe.
    // event.source must match the iframe's contentWindow for the security check.
    const messageHandler = getMessageHandler();
    assert.ok(messageHandler, 'message event handler should be registered on root');

    messageHandler({
        source: iframeContentWindow,
        data: {
            type: 'AUTHSIA_FILL',
            username: 'alice@example.com',
            password: 'super-secret-123',
        },
    });

    assert.strictEqual(
        usernameInput.value,
        'alice@example.com',
        'username field should be filled'
    );
    assert.strictEqual(
        passwordInput.value,
        'super-secret-123',
        'password field should be filled'
    );

    // Verify reactivity events were dispatched
    assert.ok(
        usernameInput.events.includes('input'),
        'username should receive input event'
    );
    assert.ok(
        passwordInput.events.includes('change'),
        'password should receive change event'
    );
}

function testOtpMenuInjectedAndFillMessagePopulatesActiveField() {
    const otpInput = createMockInput({
        type: 'text',
        name: 'otp',
        autocomplete: 'one-time-code',
    });

    const {
        context, timers, appendedChildren, docEventListeners,
        iframeContentWindow, getMessageHandler,
    } = createMockContext({
        inputs: [otpInput],
        host: 'github.com',
    });

    loadScripts(context, timers);

    const focusinHandlers = docEventListeners['focusin'] || [];
    focusinHandlers.forEach((handler) =>
        handler({ target: otpInput })
    );
    timers.flush();

    const iframes = appendedChildren.filter((c) => c.tagName === 'IFRAME');
    assert.strictEqual(iframes.length, 1, 'one menu should be injected for OTP fields');
    assert.ok(
        iframes[0].src.includes('currentURL=https%3A%2F%2Fgithub.com%2F'),
        'iframe src should include currentURL'
    );

    const messageHandler = getMessageHandler();
    messageHandler({
        source: iframeContentWindow,
        data: {
            type: 'AUTHSIA_FILL',
            otpCode: '123456',
        },
    });

    assert.strictEqual(otpInput.value, '123456', 'OTP field should be filled');
    assert.ok(otpInput.events.includes('input'), 'OTP field should receive input event');
}

function testDynamicOTPFieldFocusInjectsMenuBeforeRescan() {
    const inputs = [];
    const otpInput = createMockInput({
        type: 'text',
        name: 'otp',
        autocomplete: 'one-time-code',
    });

    const { context, timers, appendedChildren, docEventListeners } = createMockContext({
        inputs,
        host: 'github.com',
    });

    loadScripts(context, timers);
    inputs.push(otpInput);

    const focusinHandlers = docEventListeners['focusin'] || [];
    focusinHandlers.forEach((handler) =>
        handler({ target: otpInput })
    );
    timers.flush();

    const iframes = appendedChildren.filter((c) => c.tagName === 'IFRAME');
    assert.strictEqual(iframes.length, 1, 'newly inserted OTP fields should open the menu on focus');
}

function testPasswordOnlyStepInjectsAndFillsActivePassword() {
    const passwordInput = createMockInput({
        type: 'password',
        name: 'password',
        autocomplete: 'current-password',
    });

    const {
        context, timers, appendedChildren, docEventListeners,
        iframeContentWindow, getMessageHandler,
    } = createMockContext({
        inputs: [passwordInput],
        host: 'accounts.example.com',
    });

    loadScripts(context, timers);

    const focusinHandlers = docEventListeners['focusin'] || [];
    focusinHandlers.forEach((handler) =>
        handler({ target: passwordInput })
    );
    timers.flush();

    const iframes = appendedChildren.filter((c) => c.tagName === 'IFRAME');
    assert.strictEqual(iframes.length, 1, 'password-only steps should still open the menu');

    const messageHandler = getMessageHandler();
    messageHandler({
        source: iframeContentWindow,
        data: {
            type: 'AUTHSIA_FILL',
            username: 'alice@example.com',
            password: 'super-secret-123',
        },
    });

    assert.strictEqual(passwordInput.value, 'super-secret-123', 'active password field should be filled');
}

function testUsernameOnlyStepInjectsAndFillsActiveUsername() {
    const usernameInput = createMockInput({
        type: 'email',
        name: 'email',
        autocomplete: 'username',
    });

    const {
        context, timers, appendedChildren, docEventListeners,
        iframeContentWindow, getMessageHandler,
    } = createMockContext({
        inputs: [usernameInput],
        host: 'accounts.example.com',
    });

    loadScripts(context, timers);

    const focusinHandlers = docEventListeners['focusin'] || [];
    focusinHandlers.forEach((handler) =>
        handler({ target: usernameInput })
    );
    timers.flush();

    const iframes = appendedChildren.filter((c) => c.tagName === 'IFRAME');
    assert.strictEqual(iframes.length, 1, 'username-only steps should still open the menu');

    const messageHandler = getMessageHandler();
    messageHandler({
        source: iframeContentWindow,
        data: {
            type: 'AUTHSIA_FILL',
            username: 'alice@example.com',
            password: 'super-secret-123',
        },
    });

    assert.strictEqual(usernameInput.value, 'alice@example.com', 'active username field should be filled');
}

function testSplitOTPFillDistributesDigits() {
    const otpInputs = Array.from({ length: 6 }, (_, index) => createMockInput({
        type: 'text',
        name: 'otp-' + index,
        autocomplete: index === 0 ? 'one-time-code' : '',
        maxlength: '1',
    }));

    const {
        context, timers, appendedChildren, docEventListeners,
        iframeContentWindow, getMessageHandler,
    } = createMockContext({
        inputs: otpInputs,
        host: 'github.com',
    });

    loadScripts(context, timers);

    const focusinHandlers = docEventListeners['focusin'] || [];
    focusinHandlers.forEach((handler) =>
        handler({ target: otpInputs[0] })
    );
    timers.flush();

    const iframes = appendedChildren.filter((c) => c.tagName === 'IFRAME');
    assert.strictEqual(iframes.length, 1, 'split OTP fields should open the menu');

    const messageHandler = getMessageHandler();
    messageHandler({
        source: iframeContentWindow,
        data: {
            type: 'AUTHSIA_FILL',
            otpCode: '123456',
        },
    });

    assert.deepStrictEqual(
        otpInputs.map((input) => input.value),
        ['1', '2', '3', '4', '5', '6'],
        'split OTP fields should receive one digit each'
    );
}

function testFillMessageIgnoredWithoutCredentials() {
    const usernameInput = createMockInput({
        type: 'text',
        name: 'username',
        autocomplete: 'username',
    });
    const passwordInput = createMockInput({
        type: 'password',
        name: 'password',
    });

    const {
        context, timers, docEventListeners,
        iframeContentWindow, getMessageHandler,
    } = createMockContext({
        inputs: [usernameInput, passwordInput],
        host: 'example.com',
    });

    loadScripts(context, timers);

    // Inject menu first
    const focusinHandlers = docEventListeners['focusin'] || [];
    focusinHandlers.forEach((handler) =>
        handler({ target: usernameInput })
    );
    timers.flush();

    const messageHandler = getMessageHandler();

    // Send incomplete fill message (missing password)
    messageHandler({
        source: iframeContentWindow,
        data: {
            type: 'AUTHSIA_FILL',
            username: 'alice@example.com',
        },
    });

    assert.strictEqual(usernameInput.value, '', 'username should not be filled without password');
    assert.strictEqual(passwordInput.value, '', 'password should not be filled');
}

function testFillMessageRejectedFromWrongSource() {
    const usernameInput = createMockInput({
        type: 'text',
        name: 'username',
        autocomplete: 'username',
    });
    const passwordInput = createMockInput({
        type: 'password',
        name: 'password',
    });

    const {
        context, timers, docEventListeners, getMessageHandler,
    } = createMockContext({
        inputs: [usernameInput, passwordInput],
        host: 'example.com',
    });

    loadScripts(context, timers);

    // Inject menu
    const focusinHandlers = docEventListeners['focusin'] || [];
    focusinHandlers.forEach((handler) =>
        handler({ target: usernameInput })
    );
    timers.flush();

    const messageHandler = getMessageHandler();

    // Send fill message from a WRONG source (not the iframe's contentWindow)
    messageHandler({
        source: {},
        data: {
            type: 'AUTHSIA_FILL',
            username: 'alice@example.com',
            password: 'super-secret-123',
        },
    });

    assert.strictEqual(usernameInput.value, '', 'fill from wrong source should be rejected');
    assert.strictEqual(passwordInput.value, '', 'fill from wrong source should be rejected');
}

function testCloseMessageRemovesMenu() {
    const usernameInput = createMockInput({
        type: 'email',
        name: 'email',
        autocomplete: 'username',
    });
    const passwordInput = createMockInput({
        type: 'password',
        name: 'password',
    });

    const {
        context, timers, appendedChildren, docEventListeners,
        iframeContentWindow, getMessageHandler,
    } = createMockContext({
        inputs: [usernameInput, passwordInput],
        host: 'example.com',
    });

    loadScripts(context, timers);

    // Inject menu by focusing
    const focusinHandlers = docEventListeners['focusin'] || [];
    focusinHandlers.forEach((handler) =>
        handler({ target: usernameInput })
    );
    timers.flush();

    assert.strictEqual(
        appendedChildren.filter((c) => c.tagName === 'IFRAME').length,
        1,
        'menu should be present before close'
    );

    // Send AUTHSIA_CLOSE from the iframe
    const messageHandler = getMessageHandler();
    messageHandler({
        source: iframeContentWindow,
        data: { type: 'AUTHSIA_CLOSE' },
    });

    const iframes = appendedChildren.filter((c) => c.tagName === 'IFRAME');
    assert.strictEqual(iframes.length, 0, 'menu should be removed after AUTHSIA_CLOSE');
}

function testMenuFieldTypeParameter() {
    const usernameInput = createMockInput({
        type: 'email',
        name: 'email',
        autocomplete: 'username',
    });
    const passwordInput = createMockInput({
        type: 'password',
        name: 'password',
    });

    const { context, timers, appendedChildren, docEventListeners } = createMockContext({
        inputs: [usernameInput, passwordInput],
        host: 'example.com',
    });

    loadScripts(context, timers);

    const focusinHandlers = docEventListeners['focusin'] || [];

    // Focus on username field
    focusinHandlers.forEach((handler) =>
        handler({ target: usernameInput })
    );
    timers.flush();

    let iframes = appendedChildren.filter((c) => c.tagName === 'IFRAME');
    assert.ok(
        iframes[0].src.includes('fieldType=username'),
        'focusing email input should set fieldType=username'
    );

    // Focus on password field (should replace the menu)
    focusinHandlers.forEach((handler) =>
        handler({ target: passwordInput })
    );
    timers.flush();

    iframes = appendedChildren.filter((c) => c.tagName === 'IFRAME');
    assert.strictEqual(iframes.length, 1, 'should have exactly one menu after re-focus');
    assert.ok(
        iframes[0].src.includes('fieldType=password'),
        'focusing password input should set fieldType=password'
    );
}

function testInvalidatedExtensionContextDoesNotThrowOnFocus() {
    const usernameInput = createMockInput({
        type: 'email',
        name: 'email',
        autocomplete: 'username',
    });
    const passwordInput = createMockInput({
        type: 'password',
        name: 'password',
    });

    const { context, timers, appendedChildren, docEventListeners } = createMockContext({
        inputs: [usernameInput, passwordInput],
        host: 'example.com',
        runtimeGetURL() {
            throw new Error('Extension context invalidated.');
        },
    });

    loadScripts(context, timers);

    const focusinHandlers = docEventListeners['focusin'] || [];
    assert.doesNotThrow(() => {
        focusinHandlers.forEach((handler) =>
            handler({ target: usernameInput })
        );
        timers.flush();
    }, 'stale content script should ignore focus instead of throwing');

    const iframes = appendedChildren.filter((c) => c.tagName === 'IFRAME');
    assert.strictEqual(iframes.length, 0, 'no iframe should be injected from a stale context');
}

function testInitRetriesUntilHeuristicsAvailable() {
    const timers = createTimerController();
    const docEventListeners = {};

    const document = {
        readyState: 'complete',
        body: { appendChild() {} },
        createElement(tag) {
            return {
                tagName: tag.toUpperCase(),
                style: {},
                setAttribute() {},
                getAttribute() { return null; },
                remove() {},
            };
        },
        addEventListener(type, handler) {
            if (!docEventListeners[type]) docEventListeners[type] = [];
            docEventListeners[type].push(handler);
        },
        removeEventListener() {},
        querySelectorAll() { return []; },
        querySelector() { return null; },
        get activeElement() { return null; },
    };

    const context = {
        console,
        document,
        location: { hostname: 'example.com', href: 'https://example.com/' },
        setTimeout: timers.fakeSetTimeout,
        clearTimeout: timers.fakeClearTimeout,
        innerWidth: 1024,
        innerHeight: 768,
        scrollX: 0,
        scrollY: 0,
        getComputedStyle() {
            return { visibility: 'visible', display: 'block', opacity: '1' };
        },
        addEventListener() {},
        removeEventListener() {},
        MutationObserver: class {
            constructor() {}
            observe() {}
            disconnect() {}
        },
        HTMLInputElement: { prototype: {} },
        Event: class { constructor(type) { this.type = type; } },
        KeyboardEvent: class {
            constructor(type) { this.type = type; }
            preventDefault() {}
        },
        URLSearchParams,
        chrome: {
            runtime: {
                getURL(p) { return 'chrome-extension://x/' + p; },
                sendMessage() {},
            },
        },
        CSS: { escape(s) { return s; } },
        globalThis: undefined,
    };
    context.globalThis = context;

    vm.createContext(context);

    // Load content script WITHOUT heuristics
    vm.runInContext(contentScriptCode, context, { filename: 'content_script.js' });

    assert.strictEqual(
        context.AuthsiaHeuristics,
        undefined,
        'heuristics should not exist yet'
    );

    // There should be a pending retry timer
    assert.ok(timers.pending.size > 0, 'init should have queued a retry timer');

    // Now load heuristics
    vm.runInContext(heuristicsCode, context, { filename: 'heuristics.js' });
    assert.ok(context.AuthsiaHeuristics, 'heuristics should now be available');

    // Drain timers so the retry picks up heuristics and finishes init
    timers.drain();

    // After init completes, focusin listener should be registered
    const hasFocusin = (docEventListeners['focusin'] || []).length > 0;
    assert.ok(hasFocusin, 'focusin handler should be registered after heuristics loads');
}

// ============================================================================
// Runner
// ============================================================================

function run() {
    testMenuInjectedOnLoginFieldFocus();
    testMenuNotInjectedWhenNoLoginFields();
    testFillMessagePopulatesFields();
    testOtpMenuInjectedAndFillMessagePopulatesActiveField();
    testDynamicOTPFieldFocusInjectsMenuBeforeRescan();
    testPasswordOnlyStepInjectsAndFillsActivePassword();
    testUsernameOnlyStepInjectsAndFillsActiveUsername();
    testSplitOTPFillDistributesDigits();
    testFillMessageIgnoredWithoutCredentials();
    testFillMessageRejectedFromWrongSource();
    testCloseMessageRemovesMenu();
    testMenuFieldTypeParameter();
    testInvalidatedExtensionContextDoesNotThrowOnFocus();
    testInitRetriesUntilHeuristicsAvailable();
    console.log('autofill tests passed');
}

run();
