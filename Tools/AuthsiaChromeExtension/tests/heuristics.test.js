/**
 * Authsia Heuristics Tests
 * Tests for advanced field detection and scoring.
 */

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const heuristicsCode = fs.readFileSync(
    path.join(__dirname, '..', 'heuristics.js'),
    'utf8'
);

// ============================================================================
// Mock Helpers
// ============================================================================

/**
 * Creates a minimal mock input element that satisfies the heuristics module's
 * isVisible, isEditable, and attribute inspection requirements.
 */
function createMockInput(attributes = {}) {
    const attrMap = Object.assign({}, attributes);
    const visible = attrMap.visible !== false;
    const disabled = Boolean(attrMap.disabled);
    const readOnly = Boolean(attrMap.readOnly);

    return {
        tagName: 'INPUT',
        disabled: disabled,
        readOnly: readOnly,
        id: attrMap.id || '',
        form: attrMap.form || null,
        getAttribute(name) {
            return attrMap[name] !== undefined ? attrMap[name] : null;
        },
        getBoundingClientRect() {
            return visible
                ? { width: 200, height: 30, top: 100, bottom: 130, left: 50, right: 250 }
                : { width: 0, height: 0, top: 0, bottom: 0, left: 0, right: 0 };
        },
        offsetParent: visible ? {} : null,
        closest() { return null; },
    };
}

/**
 * Creates a mock document that contains a set of inputs, optionally inside
 * a form. Supports querySelectorAll and querySelector.
 */
function createMockDocument(inputs, opts = {}) {
    const labels = opts.labels || [];

    function querySelectorAll(selector) {
        if (selector === 'input') return inputs;
        if (selector === 'input[type="password"]') {
            return inputs.filter(
                (i) => (i.getAttribute('type') || '').toLowerCase() === 'password'
            );
        }
        return [];
    }

    function querySelector(selector) {
        // Support label[for="..."] queries
        const forMatch = selector.match(/^label\[for="(.+)"\]$/);
        if (forMatch) {
            const forId = forMatch[1];
            return labels.find((l) => l.forId === forId) || null;
        }
        return null;
    }

    return { querySelectorAll, querySelector };
}

/**
 * Loads heuristics.js into a fresh VM context and returns the
 * AuthsiaHeuristics API object.
 */
function loadHeuristics(overrides = {}) {
    const context = {
        console,
        globalThis: undefined, // will be set below
        location: overrides.location || { hostname: 'example.com' },
        getComputedStyle: overrides.getComputedStyle || function () {
            return { visibility: 'visible', display: 'block', opacity: '1' };
        },
        document: overrides.document || {
            querySelector() { return null; },
        },
        CSS: {
            escape(s) { return s; },
        },
    };
    // globalThis should point to the context itself
    context.globalThis = context;

    vm.createContext(context);
    vm.runInContext(heuristicsCode, context, { filename: 'heuristics.js' });

    assert.ok(context.AuthsiaHeuristics, 'AuthsiaHeuristics should be exported');
    return context.AuthsiaHeuristics;
}

// ============================================================================
// Tests: Username Field Scoring
// ============================================================================

function testUsernameAutocompleteHighest() {
    const H = loadHeuristics();

    const withAutocomplete = createMockInput({ type: 'text', autocomplete: 'username' });
    const withoutAutocomplete = createMockInput({ type: 'text', name: 'login' });

    const scoreWith = H.scoreUsernameField(withAutocomplete);
    const scoreWithout = H.scoreUsernameField(withoutAutocomplete);

    assert.ok(scoreWith > 0, 'autocomplete=username should produce positive score');
    assert.ok(
        scoreWith > scoreWithout,
        `autocomplete=username score (${scoreWith}) should be higher than name=login (${scoreWithout})`
    );
}

function testUsernameEmailType() {
    const H = loadHeuristics();

    const emailInput = createMockInput({ type: 'email', name: 'user_email' });
    const textInput = createMockInput({ type: 'text', name: 'user_email' });

    const emailScore = H.scoreUsernameField(emailInput);
    const textScore = H.scoreUsernameField(textInput);

    assert.ok(emailScore > 0, 'type=email should score positively');
    assert.ok(
        emailScore > textScore,
        `type=email score (${emailScore}) should be higher than type=text (${textScore}) with same name`
    );
}

function testUsernameNameContainsUser() {
    const H = loadHeuristics();

    const userInput = createMockInput({ type: 'text', name: 'username' });
    const genericInput = createMockInput({ type: 'text', name: 'data_field' });

    const userScore = H.scoreUsernameField(userInput);
    const genericScore = H.scoreUsernameField(genericInput);

    assert.ok(userScore > 0, 'name=username should produce positive score');
    assert.strictEqual(genericScore, 0, 'name=data_field should not score as username');
}

function testUsernameHiddenInputScoresZero() {
    const H = loadHeuristics();

    const hidden = createMockInput({ type: 'text', name: 'username', visible: false });
    assert.strictEqual(H.scoreUsernameField(hidden), 0, 'hidden inputs should score 0');
}

function testUsernameDisabledInputScoresZero() {
    const H = loadHeuristics();

    const disabled = createMockInput({ type: 'text', name: 'username', disabled: true });
    assert.strictEqual(H.scoreUsernameField(disabled), 0, 'disabled inputs should score 0');
}

function testUsernameReadOnlyInputScoresZero() {
    const H = loadHeuristics();

    const readOnly = createMockInput({ type: 'text', name: 'username', readOnly: true });
    assert.strictEqual(H.scoreUsernameField(readOnly), 0, 'readOnly inputs should score 0');
}

function testUsernamePasswordTypeScoresZero() {
    const H = loadHeuristics();

    // A password-type field should not score as a username field
    const passwordInput = createMockInput({ type: 'password', name: 'username' });
    assert.strictEqual(
        H.scoreUsernameField(passwordInput),
        0,
        'type=password should score 0 for username'
    );
}

// ============================================================================
// Tests: Password Field Scoring
// ============================================================================

function testPasswordRequiresType() {
    const H = loadHeuristics();

    const passwordInput = createMockInput({ type: 'password' });
    const textInput = createMockInput({ type: 'text', name: 'password' });

    assert.ok(
        H.scorePasswordField(passwordInput) > 0,
        'type=password should produce positive score'
    );
    assert.strictEqual(
        H.scorePasswordField(textInput),
        0,
        'type=text should score 0 even with name=password'
    );
}

function testPasswordCurrentPasswordHigher() {
    const H = loadHeuristics();

    const currentPw = createMockInput({ type: 'password', autocomplete: 'current-password' });
    const plainPw = createMockInput({ type: 'password' });

    assert.ok(
        H.scorePasswordField(currentPw) > H.scorePasswordField(plainPw),
        'autocomplete=current-password should score higher than plain password'
    );
}

function testPasswordNewPasswordPenalized() {
    const H = loadHeuristics();

    const newPw = createMockInput({ type: 'password', autocomplete: 'new-password' });
    const currentPw = createMockInput({ type: 'password', autocomplete: 'current-password' });

    assert.ok(
        H.scorePasswordField(currentPw) > H.scorePasswordField(newPw),
        'autocomplete=new-password should score lower than current-password'
    );
}

function testPasswordConfirmFieldPenalized() {
    const H = loadHeuristics();

    const confirmPw = createMockInput({ type: 'password', name: 'confirm_password' });
    const loginPw = createMockInput({ type: 'password', name: 'password' });

    assert.ok(
        H.scorePasswordField(loginPw) > H.scorePasswordField(confirmPw),
        'confirm password should score lower than login password'
    );
}

function testPasswordHiddenScoresZero() {
    const H = loadHeuristics();

    const hidden = createMockInput({ type: 'password', visible: false });
    assert.strictEqual(H.scorePasswordField(hidden), 0, 'hidden password should score 0');
}

function testPasswordDisabledScoresZero() {
    const H = loadHeuristics();

    const disabled = createMockInput({ type: 'password', disabled: true });
    assert.strictEqual(H.scorePasswordField(disabled), 0, 'disabled password should score 0');
}

// ============================================================================
// Tests: findLoginForms
// ============================================================================

function testFindLoginFormsDetectsUsernamePasswordForm() {
    const H = loadHeuristics();

    const usernameInput = createMockInput({ type: 'email', name: 'email', autocomplete: 'username' });
    const passwordInput = createMockInput({ type: 'password', name: 'password' });
    const doc = createMockDocument([usernameInput, passwordInput]);

    const forms = H.findLoginForms(doc);

    assert.strictEqual(forms.length, 1, 'should detect one login form');
    assert.strictEqual(forms[0].usernameInput, usernameInput, 'should identify the username input');
    assert.strictEqual(forms[0].passwordInput, passwordInput, 'should identify the password input');
    assert.strictEqual(forms[0].confidence, 'heuristic');
}

function testFindLoginFormsReturnsEmptyWhenNoPassword() {
    const H = loadHeuristics();

    const textInput = createMockInput({ type: 'text', name: 'search' });
    const doc = createMockDocument([textInput]);

    const forms = H.findLoginForms(doc);
    assert.strictEqual(forms.length, 0, 'no password field means no login forms');
}

function testFindLoginFormsReturnsEmptyWhenNoUsername() {
    const H = loadHeuristics();

    // A password field with no qualifying username field should yield no forms
    const passwordInput = createMockInput({ type: 'password', name: 'password' });
    const doc = createMockDocument([passwordInput]);

    const forms = H.findLoginForms(doc);
    assert.strictEqual(forms.length, 0, 'password field without username yields no forms');
}

// ============================================================================
// Tests: findAllLoginFields
// ============================================================================

function testFindAllLoginFieldsReturnsCorrectInputs() {
    const H = loadHeuristics();

    const usernameInput = createMockInput({ type: 'text', name: 'username', autocomplete: 'username' });
    const passwordInput = createMockInput({ type: 'password', name: 'password' });
    const unrelatedInput = createMockInput({ type: 'text', name: 'search' });
    const doc = createMockDocument([usernameInput, passwordInput, unrelatedInput]);

    const fields = H.findAllLoginFields(doc);

    assert.strictEqual(fields.length, 2, 'should return 2 login fields');
    assert.ok(fields.includes(usernameInput), 'should include username input');
    assert.ok(fields.includes(passwordInput), 'should include password input');
    assert.ok(!fields.includes(unrelatedInput), 'should not include unrelated input');
}

function testFindAllLoginFieldsReturnsEmptyWhenNoLoginForm() {
    const H = loadHeuristics();

    const searchInput = createMockInput({ type: 'text', name: 'q' });
    const doc = createMockDocument([searchInput]);

    const fields = H.findAllLoginFields(doc);
    assert.strictEqual(fields.length, 0, 'should return empty when no login form');
}

// ============================================================================
// Tests: isVisible
// ============================================================================

function testIsVisibleDisplayNone() {
    const H = loadHeuristics({
        getComputedStyle() {
            return { visibility: 'visible', display: 'none', opacity: '1' };
        },
    });

    const input = createMockInput({ type: 'text' });
    assert.strictEqual(H.isVisible(input), false, 'display:none should be invisible');
}

function testIsVisibleVisibilityHidden() {
    const H = loadHeuristics({
        getComputedStyle() {
            return { visibility: 'hidden', display: 'block', opacity: '1' };
        },
    });

    const input = createMockInput({ type: 'text' });
    assert.strictEqual(H.isVisible(input), false, 'visibility:hidden should be invisible');
}

function testIsVisibleLowOpacity() {
    const H = loadHeuristics({
        getComputedStyle() {
            return { visibility: 'visible', display: 'block', opacity: '0.05' };
        },
    });

    const input = createMockInput({ type: 'text' });
    assert.strictEqual(H.isVisible(input), false, 'opacity < 0.1 should be invisible');
}

function testIsVisibleZeroDimensions() {
    const H = loadHeuristics();

    const input = createMockInput({ type: 'text', visible: false });
    assert.strictEqual(H.isVisible(input), false, 'zero dimensions should be invisible');
}

function testIsVisibleNormalElement() {
    const H = loadHeuristics();

    const input = createMockInput({ type: 'text' });
    assert.strictEqual(H.isVisible(input), true, 'normal element should be visible');
}

// ============================================================================
// Tests: isEditable
// ============================================================================

function testIsEditableNormalInput() {
    const H = loadHeuristics();

    const input = createMockInput({ type: 'text' });
    assert.strictEqual(H.isEditable(input), true, 'normal input should be editable');
}

function testIsEditableDisabled() {
    const H = loadHeuristics();

    const input = createMockInput({ type: 'text', disabled: true });
    assert.strictEqual(H.isEditable(input), false, 'disabled input should not be editable');
}

function testIsEditableReadOnly() {
    const H = loadHeuristics();

    const input = createMockInput({ type: 'text', readOnly: true });
    assert.strictEqual(H.isEditable(input), false, 'readOnly input should not be editable');
}

// ============================================================================
// Tests: Negative Keywords & OTP Tightening
// ============================================================================

function testNegativeKeywordRejectsPromoCodeField() {
    const H = loadHeuristics();

    const promo = createMockInput({ type: 'text', name: 'promo_code', placeholder: 'Promo code' });
    assert.strictEqual(H.scoreOTPField(promo), 0, 'promo code field should not score as OTP');
    assert.strictEqual(H.scoreUsernameField(promo), 0, 'promo code field should not score as username');
}

function testNegativeKeywordRejectsInviteZipCouponFields() {
    const H = loadHeuristics();

    const invite = createMockInput({ type: 'text', name: 'invite_code' });
    const zip = createMockInput({ type: 'text', placeholder: 'ZIP code' });
    const coupon = createMockInput({ type: 'text', id: 'coupon' });
    const gift = createMockInput({ type: 'text', placeholder: 'Gift card code' });

    assert.strictEqual(H.scoreOTPField(invite), 0, 'invite code should not score as OTP');
    assert.strictEqual(H.scoreOTPField(zip), 0, 'ZIP code should not score as OTP');
    assert.strictEqual(H.scoreOTPField(coupon), 0, 'coupon should not score as OTP');
    assert.strictEqual(H.scoreOTPField(gift), 0, 'gift card code should not score as OTP');
}

function testNegativeKeywordRejectsCardAndNewsletterFields() {
    const H = loadHeuristics();

    const cvv = createMockInput({ type: 'tel', name: 'cvv', placeholder: 'Security code' });
    const card = createMockInput({ type: 'text', name: 'card_number' });
    const newsletter = createMockInput({ type: 'email', name: 'newsletter_email' });

    assert.strictEqual(H.scoreOTPField(cvv), 0, 'CVV "security code" should not score as OTP');
    assert.strictEqual(H.scoreOTPField(card), 0, 'card field should not score as OTP');
    assert.strictEqual(H.scoreUsernameField(newsletter), 0, 'newsletter email should not score as username');
}

function testNegativeKeywordsDoNotRejectEmbeddedWords() {
    const H = loadHeuristics();

    const researcher = createMockInput({ type: 'email', name: 'researcher_email' });
    const discard = createMockInput({ type: 'text', id: 'discard_username' });

    assert.ok(H.scoreUsernameField(researcher) > 0, 'researcher must not match the search token');
    assert.ok(H.scoreUsernameField(discard) > 0, 'discard must not match the card token');
}

function testOTPBareCodeNoLongerScores() {
    const H = loadHeuristics();

    const bareCode = createMockInput({ type: 'text', name: 'code', placeholder: 'Enter code' });
    assert.strictEqual(H.scoreOTPField(bareCode), 0, 'bare "code" field should not score as OTP');
}

function testOTPQualifiedCodeStillScores() {
    const H = loadHeuristics();

    const verification = createMockInput({ type: 'text', name: 'verification_code' });
    const authCode = createMockInput({ type: 'text', placeholder: 'Authentication code' });
    const otp = createMockInput({ type: 'text', name: 'otp' });
    const autocompleteOTP = createMockInput({ type: 'text', autocomplete: 'one-time-code' });

    assert.ok(H.scoreOTPField(verification) > 0, 'verification code should score as OTP');
    assert.ok(H.scoreOTPField(authCode) > 0, 'authentication code should score as OTP');
    assert.ok(H.scoreOTPField(otp) > 0, 'otp name should score as OTP');
    assert.ok(H.scoreOTPField(autocompleteOTP) > 0, 'autocomplete=one-time-code should score as OTP');
}

// ============================================================================
// Tests: Registration / Confirm Password Rejection
// ============================================================================

function testNewPasswordScoresZero() {
    const H = loadHeuristics();

    const newPw = createMockInput({ type: 'password', autocomplete: 'new-password' });
    assert.strictEqual(H.scorePasswordField(newPw), 0, 'new-password should be rejected, not penalized');
}

function testConfirmPasswordScoresZero() {
    const H = loadHeuristics();

    const confirmPw = createMockInput({ type: 'password', name: 'confirm_password' });
    const repeatPw = createMockInput({ type: 'password', id: 'repeat-password' });

    assert.strictEqual(H.scorePasswordField(confirmPw), 0, 'confirm password should be rejected');
    assert.strictEqual(H.scorePasswordField(repeatPw), 0, 'repeat password should be rejected');
}

// ============================================================================
// Tests: Page-Context Classification
// ============================================================================

function testClassifyEmailFieldRequiresLoginContext() {
    const H = loadHeuristics();

    const emailInput = createMockInput({ type: 'email', name: 'email' });
    const docWithoutPassword = createMockDocument([emailInput]);
    assert.strictEqual(
        H.classifyCredentialField(emailInput, docWithoutPassword),
        null,
        'email field without a password field on the page should not classify'
    );

    const passwordInput = createMockInput({ type: 'password', name: 'password' });
    const docWithPassword = createMockDocument([emailInput, passwordInput]);
    assert.strictEqual(
        H.classifyCredentialField(emailInput, docWithPassword),
        'username',
        'email field with a password field on the page should classify as username'
    );
}

function testClassifyAutocompleteUsernameWithoutPasswordContext() {
    const H = loadHeuristics();

    const usernameInput = createMockInput({ type: 'email', name: 'email', autocomplete: 'username' });
    const doc = createMockDocument([usernameInput]);
    assert.strictEqual(
        H.classifyCredentialField(usernameInput, doc),
        'username',
        'autocomplete=username should classify even without a password field (multi-step flow)'
    );
}

function testClassifyOTPFieldWithoutPasswordContext() {
    const H = loadHeuristics();

    const otpInput = createMockInput({ type: 'text', name: 'otp', autocomplete: 'one-time-code' });
    const doc = createMockDocument([otpInput]);
    assert.strictEqual(
        H.classifyCredentialField(otpInput, doc),
        'otp',
        'OTP fields classify without any password context'
    );
}

function testFindAllLoginFieldsSkipsContextlessEmailField() {
    const H = loadHeuristics();

    const emailInput = createMockInput({ type: 'email', name: 'email', placeholder: 'Your email' });
    const doc = createMockDocument([emailInput]);

    const fields = H.findAllLoginFields(doc);
    assert.strictEqual(fields.length, 0, 'contextless email field should not be a login field');
}

// ============================================================================
// Runner
// ============================================================================

function run() {
    // Username scoring
    testUsernameAutocompleteHighest();
    testUsernameEmailType();
    testUsernameNameContainsUser();
    testUsernameHiddenInputScoresZero();
    testUsernameDisabledInputScoresZero();
    testUsernameReadOnlyInputScoresZero();
    testUsernamePasswordTypeScoresZero();

    // Password scoring
    testPasswordRequiresType();
    testPasswordCurrentPasswordHigher();
    testPasswordNewPasswordPenalized();
    testPasswordConfirmFieldPenalized();
    testPasswordHiddenScoresZero();
    testPasswordDisabledScoresZero();

    // Form detection
    testFindLoginFormsDetectsUsernamePasswordForm();
    testFindLoginFormsReturnsEmptyWhenNoPassword();
    testFindLoginFormsReturnsEmptyWhenNoUsername();

    // findAllLoginFields
    testFindAllLoginFieldsReturnsCorrectInputs();
    testFindAllLoginFieldsReturnsEmptyWhenNoLoginForm();

    // Negative keywords & OTP tightening
    testNegativeKeywordRejectsPromoCodeField();
    testNegativeKeywordRejectsInviteZipCouponFields();
    testNegativeKeywordRejectsCardAndNewsletterFields();
    testNegativeKeywordsDoNotRejectEmbeddedWords();
    testOTPBareCodeNoLongerScores();
    testOTPQualifiedCodeStillScores();

    // Registration / confirm password rejection
    testNewPasswordScoresZero();
    testConfirmPasswordScoresZero();

    // Page-context classification
    testClassifyEmailFieldRequiresLoginContext();
    testClassifyAutocompleteUsernameWithoutPasswordContext();
    testClassifyOTPFieldWithoutPasswordContext();
    testFindAllLoginFieldsSkipsContextlessEmailField();

    // Visibility
    testIsVisibleDisplayNone();
    testIsVisibleVisibilityHidden();
    testIsVisibleLowOpacity();
    testIsVisibleZeroDimensions();
    testIsVisibleNormalElement();

    // Editable
    testIsEditableNormalInput();
    testIsEditableDisabled();
    testIsEditableReadOnly();

    console.log('heuristics tests passed');
}

run();
