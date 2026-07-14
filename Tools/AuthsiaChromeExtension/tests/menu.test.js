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
        if (selector === '.authsia-error-hint') {
            return this.children.find((child) => child.className === 'authsia-error-hint') || null;
        }
        if (selector === '.authsia-item') {
            return this.children.find((child) => child.className === 'authsia-item') || null;
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

function createContext(sendMessage, search) {
    const elements = new Map();
    const documentListeners = {};
    const document = {
        activeElement: null,
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

    const postedMessages = [];
    const context = {
        console,
        document,
        URLSearchParams,
        window: {
            location: {
                search: search || '?host=github.com&currentURL=https%3A%2F%2Fgithub.com%2Flogin&frameId=test-frame',
            },
            parent: {
                postMessage(message) {
                    postedMessages.push(message);
                },
            },
        },
        chrome: {
            runtime: {
                sendMessage,
            },
        },
    };

    context.globalThis = context;
    return { context, elements, postedMessages, documentListeners };
}

async function flushPromises() {
    await Promise.resolve();
    await Promise.resolve();
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
    assert.strictEqual(items[0].children[1].children[1].textContent, 'Password \u00B7 Authsia');
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
    item.listeners.click();
    await flushPromises();

    assert.deepStrictEqual(JSON.parse(JSON.stringify(messages[1])), {
        type: 'AUTHsia_GET_CREDENTIALS',
        host: 'github.com',
        currentURL: 'https://github.com/login',
        credentialId: 'o1',
    });
    assert.deepStrictEqual(JSON.parse(JSON.stringify(postedMessages[0])), {
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
    assert.strictEqual(items[0].children[1].children[1].textContent, 'OTP \u00B7 Authsia');
}

async function run() {
    await testPasswordFieldFiltersOTPItems();
    await testOTPClickPostsFillMessage();
    await testOTPFieldFiltersPasswordItems();
    console.log('menu tests passed');
}

run().catch((error) => {
    console.error(error);
    process.exit(1);
});
