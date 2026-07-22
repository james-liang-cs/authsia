/**
 * Authsia Heuristics Module
 * Advanced field detection for login forms with site-specific overrides.
 */

(function initHeuristics(root) {
    'use strict';

    // ============================================================================
    // Site-Specific Overrides (Redefinitions)
    // ============================================================================
    // Some sites use non-standard field names. Add overrides here.
    const SITE_OVERRIDES = {
        // Example: 'login.microsoftonline.com': { usernameSelector: 'input[name="loginfmt"]' }
    };

    // ============================================================================
    // Negative Keywords (hard reject for any credential classification)
    // ============================================================================
    // Fields whose name/id/placeholder/aria-label mention these are never
    // credential fields: search boxes, promo/invite/ZIP "code" fields, card
    // fields, newsletter signups, and contact-form fields.
    const NEGATIVE_KEYWORDS = [
        'search', 'promo', 'coupon', 'discount', 'invite', 'voucher', 'redeem',
        'gift', 'zip', 'postal', 'country', 'quantity', 'qty',
        'cvv', 'cvc', 'card', 'expiry', 'expiration',
        'newsletter', 'subscribe', 'comment', 'message',
    ];

    // ============================================================================
    // Field Scoring Weights
    // ============================================================================
    const WEIGHTS = {
        autocompleteUsername: 100,
        autocompleteEmail: 100,
        autocompleteCurrentPassword: 100,
        typeEmail: 50,
        typePassword: 100,
        nameContainsUser: 40,
        nameContainsEmail: 35,
        nameContainsLogin: 30,
        nameContainsPass: 40,
        idContainsUser: 40,
        idContainsEmail: 35,
        idContainsLogin: 30,
        idContainsPass: 40,
        placeholderContainsUser: 25,
        placeholderContainsEmail: 25,
        placeholderContainsPass: 30,
        ariaLabelContainsUser: 20,
        ariaLabelContainsEmail: 20,
        ariaLabelContainsPass: 25,
        labelTextContainsUser: 35,
        labelTextContainsEmail: 35,
        labelTextContainsPass: 40,
        autocompleteOTP: 100,
        nameContainsOTP: 50,
        idContainsOTP: 50,
        placeholderContainsOTP: 40,
        ariaLabelContainsOTP: 35,
        labelTextContainsOTP: 45,
    };

    // ============================================================================
    // Utility Functions
    // ============================================================================

    function toArray(nodeList) {
        return Array.prototype.slice.call(nodeList || []);
    }

    function isVisible(element) {
        if (!element) return false;
        const style = root.getComputedStyle ? root.getComputedStyle(element) : null;
        if (style && (style.visibility === 'hidden' || style.display === 'none')) {
            return false;
        }
        if (style && parseFloat(style.opacity) < 0.1) {
            return false;
        }
        // Check if element has dimensions
        const rect = element.getBoundingClientRect();
        if (rect.width < 10 || rect.height < 10) {
            return false;
        }
        return element.offsetParent !== null || element.tagName === 'BODY';
    }

    function isEditable(element) {
        if (!element || element.disabled || element.readOnly) return false;
        const tagName = (element.tagName || '').toLowerCase();
        return tagName === 'input';
    }

    function getLabelText(input) {
        if (!input) return '';

        // Check for associated label via 'for' attribute
        if (input.id) {
            const label = document.querySelector(`label[for="${CSS.escape(input.id)}"]`);
            if (label) return (label.textContent || '').toLowerCase();
        }

        // Check for wrapping label
        const parentLabel = input.closest('label');
        if (parentLabel) {
            return (parentLabel.textContent || '').toLowerCase();
        }

        return '';
    }

    function containsAny(str, keywords) {
        if (!str) return false;
        const lower = str.toLowerCase();
        return keywords.some(keyword => lower.includes(keyword));
    }

    function hasNegativeSignal(input) {
        if (!input) return false;
        return [
            input.getAttribute('name'),
            input.getAttribute('id'),
            input.getAttribute('placeholder'),
            input.getAttribute('aria-label'),
        ].some(value => {
            if (!value) return false;
            const tokens = String(value)
                .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
                .toLowerCase()
                .split(/[^a-z0-9]+/)
                .filter(Boolean);
            return tokens.some(token => NEGATIVE_KEYWORDS.includes(token));
        });
    }

    // OTP keywords. A bare "code" is NOT sufficient (promo/invite/ZIP code
    // fields); it only counts when the same attribute qualifies it, e.g.
    // "security code" or "authentication code".
    const OTP_KEYWORDS = ['otp', 'totp', 'mfa', '2fa', 'verification', 'passcode', 'one-time-code'];
    const OTP_CODE_QUALIFIERS = ['security', 'authentication', 'verification'];

    function containsOTPSignal(value) {
        if (!value) return false;
        const lower = value.toLowerCase();
        if (OTP_KEYWORDS.some(keyword => lower.includes(keyword))) {
            return true;
        }
        return lower.includes('code') &&
            OTP_CODE_QUALIFIERS.some(qualifier => lower.includes(qualifier));
    }

    // ============================================================================
    // Field Scoring
    // ============================================================================

    function scoreUsernameField(input) {
        if (!input || !isEditable(input) || !isVisible(input)) return 0;

        const type = (input.getAttribute('type') || 'text').toLowerCase();
        const validTypes = ['text', 'email', 'tel', 'url', 'search', ''];
        if (!validTypes.includes(type)) return 0;

        if (hasNegativeSignal(input)) return 0;

        const autocomplete = (input.getAttribute('autocomplete') || '').toLowerCase();
        const name = (input.getAttribute('name') || '').toLowerCase();
        const id = (input.getAttribute('id') || '').toLowerCase();
        const placeholder = (input.getAttribute('placeholder') || '').toLowerCase();
        const ariaLabel = (input.getAttribute('aria-label') || '').toLowerCase();
        const labelText = getLabelText(input);

        let score = 0;

        // Autocomplete hints (highest priority)
        if (autocomplete === 'username') score += WEIGHTS.autocompleteUsername;
        if (autocomplete === 'email') score += WEIGHTS.autocompleteEmail;

        // Type hints
        if (type === 'email') score += WEIGHTS.typeEmail;

        // Name attribute
        if (containsAny(name, ['user', 'username', 'usr'])) score += WEIGHTS.nameContainsUser;
        if (containsAny(name, ['email', 'mail'])) score += WEIGHTS.nameContainsEmail;
        if (containsAny(name, ['login', 'signin', 'account'])) score += WEIGHTS.nameContainsLogin;

        // ID attribute
        if (containsAny(id, ['user', 'username', 'usr'])) score += WEIGHTS.idContainsUser;
        if (containsAny(id, ['email', 'mail'])) score += WEIGHTS.idContainsEmail;
        if (containsAny(id, ['login', 'signin', 'account'])) score += WEIGHTS.idContainsLogin;

        // Placeholder
        if (containsAny(placeholder, ['user', 'username'])) score += WEIGHTS.placeholderContainsUser;
        if (containsAny(placeholder, ['email', 'mail'])) score += WEIGHTS.placeholderContainsEmail;

        // Aria-label
        if (containsAny(ariaLabel, ['user', 'username'])) score += WEIGHTS.ariaLabelContainsUser;
        if (containsAny(ariaLabel, ['email', 'mail'])) score += WEIGHTS.ariaLabelContainsEmail;

        // Label text
        if (containsAny(labelText, ['user', 'username'])) score += WEIGHTS.labelTextContainsUser;
        if (containsAny(labelText, ['email', 'mail'])) score += WEIGHTS.labelTextContainsEmail;

        return score;
    }

    function scorePasswordField(input) {
        if (!input || !isEditable(input) || !isVisible(input)) return 0;

        const type = (input.getAttribute('type') || '').toLowerCase();
        if (type !== 'password') return 0;

        if (hasNegativeSignal(input)) return 0;

        const autocomplete = (input.getAttribute('autocomplete') || '').toLowerCase();
        const name = (input.getAttribute('name') || '').toLowerCase();
        const id = (input.getAttribute('id') || '').toLowerCase();

        // Registration / change-password / confirmation fields are not login
        // targets: reject them outright instead of merely penalizing.
        if (autocomplete === 'new-password') return 0;
        if (containsAny(name, ['confirm', 'retype', 'repeat', 'verify'])) return 0;
        if (containsAny(id, ['confirm', 'retype', 'repeat', 'verify'])) return 0;

        const placeholder = (input.getAttribute('placeholder') || '').toLowerCase();
        const ariaLabel = (input.getAttribute('aria-label') || '').toLowerCase();
        const labelText = getLabelText(input);

        let score = WEIGHTS.typePassword; // Base score for being a password field

        // Autocomplete hints
        if (autocomplete === 'current-password') score += WEIGHTS.autocompleteCurrentPassword;

        // Name/ID hints for login vs registration
        if (containsAny(name, ['pass', 'password', 'pwd'])) score += WEIGHTS.nameContainsPass;
        if (containsAny(id, ['pass', 'password', 'pwd'])) score += WEIGHTS.idContainsPass;

        // Placeholder
        if (containsAny(placeholder, ['pass', 'password'])) score += WEIGHTS.placeholderContainsPass;

        // Aria-label
        if (containsAny(ariaLabel, ['pass', 'password'])) score += WEIGHTS.ariaLabelContainsPass;

        // Label text
        if (containsAny(labelText, ['pass', 'password'])) score += WEIGHTS.labelTextContainsPass;

        return score;
    }

    function scoreOTPField(input) {
        if (!input || !isEditable(input) || !isVisible(input)) return 0;

        const type = (input.getAttribute('type') || 'text').toLowerCase();
        const validTypes = ['text', 'tel', 'number', 'search', ''];
        if (!validTypes.includes(type)) return 0;

        if (hasNegativeSignal(input)) return 0;

        const autocomplete = (input.getAttribute('autocomplete') || '').toLowerCase();
        const name = (input.getAttribute('name') || '').toLowerCase();
        const id = (input.getAttribute('id') || '').toLowerCase();
        const placeholder = (input.getAttribute('placeholder') || '').toLowerCase();
        const ariaLabel = (input.getAttribute('aria-label') || '').toLowerCase();
        const labelText = getLabelText(input);

        let score = 0;
        if (autocomplete === 'one-time-code') score += WEIGHTS.autocompleteOTP;
        if (containsOTPSignal(name)) score += WEIGHTS.nameContainsOTP;
        if (containsOTPSignal(id)) score += WEIGHTS.idContainsOTP;
        if (containsOTPSignal(placeholder)) score += WEIGHTS.placeholderContainsOTP;
        if (containsOTPSignal(ariaLabel)) score += WEIGHTS.ariaLabelContainsOTP;
        if (containsOTPSignal(labelText)) score += WEIGHTS.labelTextContainsOTP;

        return score;
    }

    // ============================================================================
    // Form Detection
    // ============================================================================

    function findLoginForms(doc) {
        const host = (root.location && root.location.hostname) ? root.location.hostname.toLowerCase() : '';
        const override = SITE_OVERRIDES[host];

        // If we have a site-specific override, use it
        if (override && override.usernameSelector && override.passwordSelector) {
            const username = doc.querySelector(override.usernameSelector);
            const password = doc.querySelector(override.passwordSelector);
            if (username && password) {
                return [{
                    usernameInput: username,
                    passwordInput: password,
                    form: username.form || password.form || null,
                    confidence: 'override'
                }];
            }
        }

        // Find all password fields
        const passwordInputs = toArray(doc.querySelectorAll('input[type="password"]'))
            .filter(input => isEditable(input) && isVisible(input))
            .map(input => ({ input, score: scorePasswordField(input) }))
            .filter(item => item.score > 0)
            .sort((a, b) => b.score - a.score);

        if (passwordInputs.length === 0) {
            return [];
        }

        const results = [];

        for (const { input: passwordInput } of passwordInputs) {
            const scope = passwordInput.form || doc;

            // Find the best username field in the same form/scope
            const usernameInputs = toArray(scope.querySelectorAll('input'))
                .filter(input => input !== passwordInput && isEditable(input) && isVisible(input))
                .map(input => ({ input, score: scoreUsernameField(input) }))
                .filter(item => item.score > 0)
                .sort((a, b) => b.score - a.score);

            if (usernameInputs.length > 0) {
                results.push({
                    usernameInput: usernameInputs[0].input,
                    passwordInput: passwordInput,
                    form: passwordInput.form || null,
                    confidence: 'heuristic'
                });
            }
        }

        return results;
    }

    function findAllLoginFields(doc) {
        const fields = new Set();

        const loginForms = findLoginForms(doc);
        for (const form of loginForms) {
            if (form.usernameInput) fields.add(form.usernameInput);
            if (form.passwordInput) fields.add(form.passwordInput);
        }

        for (const input of toArray(doc.querySelectorAll('input'))) {
            if (classifyCredentialField(input, doc) !== null) {
                fields.add(input);
            }
        }

        return Array.from(fields);
    }

    // ============================================================================
    // Page-Context Classification
    // ============================================================================
    // A bare username/email field is only a login field when the page shows
    // login intent: a visible password field exists, or the field explicitly
    // declares autocomplete="username" (multi-step sign-in flows). This keeps
    // newsletter/contact/email fields from opening the menu.

    function pageHasPasswordField(doc) {
        return toArray(doc.querySelectorAll('input[type="password"]'))
            .some(input => scorePasswordField(input) > 0);
    }

    function usernameContextAllowed(input, doc) {
        const autocomplete = (input.getAttribute('autocomplete') || '').toLowerCase();
        if (autocomplete === 'username') return true;
        return pageHasPasswordField(doc);
    }

    function classifyCredentialField(input, doc) {
        if (scoreOTPField(input) > 0) {
            return 'otp';
        }
        if (scorePasswordField(input) > 0) {
            return 'password';
        }
        if (scoreUsernameField(input) > 0 && usernameContextAllowed(input, doc)) {
            return 'username';
        }
        return null;
    }

    // ============================================================================
    // Public API
    // ============================================================================

    root.AuthsiaHeuristics = {
        scoreUsernameField,
        scorePasswordField,
        scoreOTPField,
        findLoginForms,
        findAllLoginFields,
        pageHasPasswordField,
        classifyCredentialField,
        isVisible,
        isEditable,
        SITE_OVERRIDES,
    };

})(typeof globalThis !== 'undefined' ? globalThis : this);
