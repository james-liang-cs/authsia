# Authsia Chrome Autofill - Testing Guide

## Table of Contents

- [Prerequisites](#prerequisites)
- [Step 1: Load the Chrome Extension](#step-1-load-the-chrome-extension)
- [Step 2: Build and Install the Native Host](#step-2-build-and-install-the-native-host)
- [Step 3: Prepare a Test Password](#step-3-prepare-a-test-password)
- [Step 4: Verify the Setup](#step-4-verify-the-setup)
  - [Test 1: Native Host Communication](#test-1-native-host-communication)
  - [Test 2: Autofill on a Login Page](#test-2-autofill-on-a-login-page)
- [Troubleshooting](#troubleshooting)
  - ["Native host has exited" error](#native-host-has-exited-error)
  - [Fields not filling](#fields-not-filling)
  - ["No match" or "Multiple matches"](#no-match-or-multiple-matches)
- [Verification Checklist](#verification-checklist)
- [Running Automated Tests](#running-automated-tests)
  - [JavaScript Tests (extension logic)](#javascript-tests-extension-logic)
  - [Swift Tests (native host)](#swift-tests-native-host)
  - [CLI Tests](#cli-tests)
  - [Bridge Tests](#bridge-tests)

This guide walks you through setting up and verifying the Chrome autofill feature.

## Prerequisites

- macOS 15+
- Google Chrome installed
- Authsia app installed and `authsia status` reports a healthy bridge
- At least one password entry in your vault with:
  - `isCliEnabled` set to `true`
  - A valid `website` URL
- Optional OTP entry testing requires:
  - `isCliEnabled` set to `true`
  - Hosts metadata matching the sign-in page, or issuer/label text that matches the site

## Step 1: Load the Chrome Extension

1. Open Chrome and navigate to `chrome://extensions`
2. Enable **Developer mode** (toggle in top-right)
3. Click **Load unpacked**
4. Select the folder: `Tools/AuthsiaChromeExtension`
5. The extension "Authsia Autofill (Dev)" should appear
6. Copy the extension ID

## Step 2: Build and Install the Native Host

```bash
bash Tools/AuthsiaNativeHost/scripts/install-chrome-native-host.sh YOUR_EXTENSION_ID_HERE
```

This will:
- Build the native host in release mode
- Install the binary to `~/Library/Application Support/Authsia/native-host/AuthsiaNativeHost`
- Write the Chrome native messaging manifest with your extension ID

**Restart Chrome completely** after installing the manifest.

## Step 3: Prepare a Test Password

In the Authsia app:

1. Create or edit a password entry
2. Set the **Website** field to a test URL (e.g., `https://example.com`)
3. Enable **CLI Access** for this entry
4. Note the username and password values

## Step 4: Verify the Setup

### Test 1: Native Host Communication

Open Chrome DevTools (F12) on any page, go to the Console, and check for errors related to native messaging. No errors means the connection is working.

### Test 2: Autofill on a Login Page

1. Navigate to a page matching your test password's website
2. The page should have a visible login form with:
   - A username/email field, password field, or multi-step single-field login
3. Focus the login field
4. Select a matching Authsia item from the inline picker
5. The focused field or detected login form should fill with your credentials
6. On MFA prompts, focus the OTP field and select a matching OTP item

## Troubleshooting

### "Native host has exited" error

- Verify the native host is installed: `ls -la ~/Library/Application\ Support/Authsia/native-host/AuthsiaNativeHost`
- Check the manifest exists: `ls -la ~/Library/Application\ Support/Google/Chrome/NativeMessagingHosts/`
- Ensure the extension ID in the manifest matches your loaded extension

### Fields not filling

- Confirm `authsia status` reports a healthy bridge
- Verify the password entry has `isCliEnabled = true`
- Check that the website URL matches the page hostname. `www.example.com` and `example.com` are treated as the same site.
- Open DevTools Console to see any error messages

### "No match" or "Multiple matches"

- The inline picker can show multiple matching CLI-enabled items for a site.
- A direct native-host `getCredentials` request without a selected item still fails closed when multiple matches are ambiguous.
- Check your vault for duplicate entries with the same website if a direct lookup reports ambiguity.

## Verification Checklist

- [ ] Native host binary exists at `~/Library/Application Support/Authsia/native-host/AuthsiaNativeHost`
- [ ] Manifest exists at `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/com.authsia.nativehost.json`
- [ ] Extension loaded in Chrome (visible at `chrome://extensions`)
- [ ] Extension ID in manifest matches loaded extension
- [ ] Chrome restarted after manifest installation
- [ ] Authsia app is running
- [ ] Test password has CLI access enabled
- [ ] Test password website matches target page hostname
- [ ] Login page has a visible username, password, or OTP field

## Running Automated Tests

### JavaScript Tests (extension logic)

```bash
cd Tools/AuthsiaChromeExtension/tests
node hostMatching.test.js
node heuristics.test.js
node serviceWorker.test.js
node menu.test.js
node autofill.test.js
```

### Swift Tests (native host)

```bash
cd Tools/AuthsiaNativeHost
swift test
```

### CLI Tests

```bash
cd Packages/AuthsiaCLI
swift test
```

### Bridge Tests

```bash
cd Packages/AuthenticatorBridge
swift test
```

All tests should pass before manual verification.

### Live E2E (private app harness)

From the private Authenticator app repository (not this public package alone),
run the opt-in Playwright harness outside the sandbox:

```bash
bash scripts/test/chrome-autofill-live.sh
```

That script loads this unpacked extension in Playwright Chromium (branded Chrome
137+ dropped `--load-extension`), serves local HTTPS fixtures, and runs
`password`, `redirect`, `redirect-cross`, and `otp` scenarios. Matching uses the
**post-redirect** page host. OTP is SKIPPED until a CLI-enabled OTP exists with
matching Hosts/issuer. Details: `scripts/test/chrome-autofill-live/README.md`
in the private app repo.
