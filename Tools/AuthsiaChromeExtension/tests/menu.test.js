/**
 * Authsia Menu Tests
 * Tests popup menu rendering and fill message behavior with a small DOM stub.
 */

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const menuCode = fs.readFileSync(path.join(__dirname, '..', 'popup', 'menu.js'), 'utf8');

class Element {
    constructor(tagName, id = '') {
        this.tagName = tagName.toUpperCase();
        this.id = id;
        this.children = [];
        this.style = {};
        this.attributes = {};
        this.listeners = {};
        this.textContent = '';
        this.className = '';
    }

    appendChild(child) {
        this.children.push(child);
        return child;
    }

    setAttribute(name, value) {
        this.attributes[name] = value;
    }

    addEventListener(type, handler) {
        this.listeners[type] = handler;
    }

    focus() {
        this.ownerDocument.activeElement = this;
    }

    querySelector(selector) {
        const classMatch = selector.match(/^\.([A-Za-z0-9_-]+)$/);
        if (classMatch) {
            return this.children.find((child) => child.className === classMatch[1]) || null;
        }
        return null;
    }

    querySelectorAll(selector) {
        if (selector === '.authsia-item') {
            return this.children.filter((child) => child.className === 'authsia-item');
        }
        return [];
    }
}

function attachDocument(element, document) {
    element.ownerDocument = document;
    return element;
}

function createContext(sendMessage, search, documentHeight) {
    const elements = new Map();
    const documentListeners = {};
    const document = {
        activeElement: null,
        documentElement: { scrollHeight: documentHeight || 0 },
        getElementById(id) {
            if (!elements.has(id)) {
                elements.set(id, attachDocument(new Element('div', id), document));
            }
            return elements.get(id);
        },
        createElement(tagName) {
            return attachDocument(new Element(tagName), document);
        },
        addEventListener(type, handler) {
            documentListeners[type] = handler;
        },
    };

    const errorHint = attachDocument(new Element('span'), document);
    errorHint.className = 'authsia-error-hint';
    document.getElementById('authsia-error').appendChild(errorHint);

    const emptyText = attachDocument(new Element('span'), document);
    emptyText.className = 'authsia-empty-text';
    document.getElementById('authsia-empty').appendChild(emptyText);

    const postedMessages = [];
    const windowListeners = {};
    const context = {
        console,
        document,
        URLSearchParams,
        URL,
        setInterval() { return 1; },
        clearInterval() {},
        window: {
            location: {
                search: search || '?host=github.com&currentURL=https%3A%2F%2Fgithub.com%2Flogin&frameId=test-frame',
            },
            parent: {
                postMessage(message) {
                    postedMessages.push(message);
                    if (message.type === 'AUTHSIA_REQUEST') {
                        Promise.resolve(sendMessage(message.message)).then((response) => {
                            const handler = windowListeners.message;
                            if (handler) {
                                const currentURL = new URLSearchParams(context.window.location.search).get('currentURL');
                                handler({
                                    source: context.window.parent,
                                    origin: new URL(currentURL).origin,
                                    data: {
                                        type: 'AUTHSIA_RESPONSE',
                                        requestId: message.requestId,
                                        response,
                                    },
                                });
                            }
                        });
                    }
                },
            },
            addEventListener(type, handler) {
                windowListeners[type] = handler;
            },
        },
    };

    context.globalThis = context;
    return { context, elements, postedMessages, documentListeners };
}

async function flushPromises() {
    for (let i = 0; i < 10; i++) {
        await Promise.resolve();
    }
}

async function testPasswordFieldFiltersOTPItems() {
    const { context, elements } = createContext(async () => ({
        ok: true,
        credentials: [
            { kind: 'password', id: 'p1', name: 'GitHub', username: 'alice', website: 'https://github.com' },
            { kind: 'otp', id: 'o1', name: 'GitHub', username: 'alice@example.com' },
        ],
    }));

    vm.createContext(context);
    vm.runInContext(menuCode, context, { filename: 'menu.js' });
    await flushPromises();

    const items = elements.get('authsia-list').querySelectorAll('.authsia-item');
    assert.strictEqual(items.length, 1, 'password fields should only show password items');
    assert.strictEqual(items[0].children[1].children[0].textContent, 'GitHub');
    assert.strictEqual(items[0].children[1].children[1].textContent, 'alice');
}

async function testOTPClickPostsFillMessage() {
    const messages = [];
    const { context, elements, postedMessages } = createContext(async (message) => {
        messages.push(message);
        if (message.type === 'AUTHsia_LIST_CREDENTIALS') {
            return {
                ok: true,
                credentials: [{ kind: 'otp', id: 'o1', name: 'GitHub', username: 'alice@example.com' }],
            };
        }
        return {
            ok: true,
            credential: { otpCode: '123456', remaining: 20 },
        };
    }, '?host=github.com&currentURL=https%3A%2F%2Fgithub.com%2Flogin&fieldType=otp&frameId=test-frame');

    vm.createContext(context);
    vm.runInContext(menuCode, context, { filename: 'menu.js' });
    await flushPromises();

    const item = elements.get('authsia-list').querySelector('.authsia-item');

    assert.strictEqual(messages.length, 1, 'rendering must request metadata only');

    item.listeners.click();
    await flushPromises();

    assert.strictEqual(messages.length, 2, 'selection should perform the only secret lookup');
    assert.deepStrictEqual(JSON.parse(JSON.stringify(messages[1])), {
        type: 'AUTHsia_GET_CREDENTIALS',
        credentialId: 'o1',
    });
    const fillMessage = postedMessages.find((message) => message.type === 'AUTHSIA_FILL');
    assert.deepStrictEqual(JSON.parse(JSON.stringify(fillMessage)), {
        type: 'AUTHSIA_FILL',
        otpCode: '123456',
        frameId: 'test-frame',
    });
}

async function testOTPFieldFiltersPasswordItems() {
    const { context, elements } = createContext(async () => ({
        ok: true,
        credentials: [
            { kind: 'password', id: 'p1', name: 'AWS', username: 'alice', website: 'https://aws.amazon.com' },
            { kind: 'otp', id: 'o1', name: 'AWS', username: 'alice@example.com' },
        ],
    }), '?host=signin.aws.amazon.com&currentURL=https%3A%2F%2Fsignin.aws.amazon.com%2Foauth&fieldType=otp&frameId=test-frame');

    vm.createContext(context);
    vm.runInContext(menuCode, context, { filename: 'menu.js' });
    await flushPromises();

    const items = elements.get('authsia-list').querySelectorAll('.authsia-item');
    assert.strictEqual(items.length, 1, 'OTP fields should only show OTP items');
    assert.strictEqual(items[0].children[1].children[0].textContent, 'AWS');
    assert.strictEqual(items[0].children[1].children[1].textContent, 'alice@example.com');
}

async function testOTPItemDoesNotDisplayOrFetchLiveCode() {
    const messages = [];
    const { context, elements } = createContext(async (message) => {
        messages.push(message);
        if (message.type === 'AUTHsia_LIST_CREDENTIALS') {
            return {
                ok: true,
                credentials: [{ kind: 'otp', id: 'o1', name: 'GitHub', username: 'alice@example.com' }],
            };
        }
        throw new Error('secret lookup must not occur while rendering');
    }, '?host=github.com&currentURL=https%3A%2F%2Fgithub.com%2Flogin&fieldType=otp&frameId=test-frame');

    vm.createContext(context);
    vm.runInContext(menuCode, context, { filename: 'menu.js' });
    await flushPromises();

    const item = elements.get('authsia-list').querySelector('.authsia-item');
    assert.strictEqual(item.children.length, 2, 'OTP rows should remain metadata-only before selection');
    assert.deepStrictEqual(JSON.parse(JSON.stringify(messages)), [{ type: 'AUTHsia_LIST_CREDENTIALS' }]);
}

async function testMenuPostsResizeAfterRender() {
    const { context, postedMessages } = createContext(async () => ({
        ok: true,
        credentials: [{ kind: 'password', id: 'p1', name: 'GitHub', username: 'alice', website: 'https://github.com' }],
    }), undefined, 240);

    vm.createContext(context);
    vm.runInContext(menuCode, context, { filename: 'menu.js' });
    await flushPromises();

    const resizeMessages = postedMessages.filter((m) => m.type === 'AUTHSIA_RESIZE');
    assert.ok(resizeMessages.length > 0, 'menu should post a resize message after rendering');
    assert.strictEqual(resizeMessages[0].height, 240);
}

async function testEmptyStateNamesCurrentHost() {
    const { context, elements } = createContext(async () => ({ ok: true, credentials: [] }));

    vm.createContext(context);
    vm.runInContext(menuCode, context, { filename: 'menu.js' });
    await flushPromises();

    const emptyText = elements.get('authsia-empty').querySelector('.authsia-empty-text');
    assert.ok(emptyText, 'empty state text element should exist');
    assert.strictEqual(emptyText.textContent, 'No passwords for github.com');
}

async function run() {
    await testPasswordFieldFiltersOTPItems();
    await testOTPClickPostsFillMessage();
    await testOTPFieldFiltersPasswordItems();
    await testOTPItemDoesNotDisplayOrFetchLiveCode();
    await testMenuPostsResizeAfterRender();
    await testEmptyStateNamesCurrentHost();
    console.log('menu tests passed');
}

run().catch((error) => {
    console.error(error);
    process.exit(1);
});
