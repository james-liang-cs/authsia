# Chrome Autofill Feature

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
  - [Data Flow](#data-flow)
  - [Components](#components)
- [Features](#features)
  - [✅ Implemented](#implemented)
  - [User Experience](#user-experience)
- [Setup](#setup)
  - [Prerequisites](#prerequisites)
  - [Installation Steps](#installation-steps)
  - [Preparing Credentials](#preparing-credentials)
- [Security](#security)
  - [Trust Boundaries](#trust-boundaries)
  - [Security Measures](#security-measures)
- [Development](#development)
  - [Project Structure](#project-structure)
  - [Running Tests](#running-tests)
  - [Key Implementation Details](#key-implementation-details)
- [Troubleshooting](#troubleshooting)
  - [Common Issues](#common-issues)
  - [Debug Steps](#debug-steps)
- [Future Enhancements](#future-enhancements)
  - [Planned](#planned)
  - [Under Consideration](#under-consideration)
- [References](#references)

**Status:** ✅ **Production Ready**

The Chrome autofill feature provides seamless password autofill from the Authsia vault directly into website login forms. This feature uses a local-only architecture with native messaging between Chrome and the Authsia app.

## Overview

When you focus on a login field on any website, Authsia detects matching credentials from your vault and presents them in a convenient inline menu. Selecting a credential automatically fills both the username and password fields.

## Architecture

### Data Flow

```
Chrome Extension ←→ Native Host ←→ Authsia CLI ←→ Keychain/App
```

**Security Model:**
- All data stays local (no cloud/network calls)
- Native host acts as a security boundary
- Extension never directly accesses secrets
- Host matching prevents credential leakage

### Components

1. **Chrome Extension** (`Tools/AuthsiaChromeExtension/`)
   - `content_script.js` - In-page field detection and menu injection
   - `service_worker.js` - Message routing and native communication
   - `heuristics.js` - Smart login form detection
   - `host_matching.js` - Host validation and matching
   - `popup/menu.js` - Credential selection UI

2. **Native Host** (`Tools/AuthsiaNativeHost/`)
   - Swift binary that bridges Chrome and the CLI
   - Validates all requests
   - Enforces `isCliEnabled` filtering
   - Performs host matching on the secure side

3. **CLI Integration** (`Packages/AuthsiaCLI/`)
   - `authsia` command-line tool
   - Provides password listing and retrieval
   - Communicates with the main app via XPC

## Features

### ✅ Implemented

- **Inline Menu** - Popup appears when focusing login fields
- **Smart Form Detection** - Heuristic-based username/password field identification
- **Host Matching** - Exact and subdomain matching with security validation
- **CLI Gating** - Only items with `isCliEnabled=true` are eligible
- **Keyboard Navigation** - Arrow keys + Enter to select credentials
- **Visual Feedback** - Loading, empty, and error states
- **React/Angular Support** - Proper event dispatching for frameworks
- **Site-Specific Overrides** - Configurable selectors for non-standard sites

### User Experience

1. Navigate to a website with saved credentials
2. Click on a username or password field
3. Authsia menu appears with matching credentials
4. Select a credential (click or keyboard)
5. Both fields are filled automatically

## Setup

### Prerequisites

- macOS 13+
- Google Chrome
- Authsia app installed

### Installation Steps

1. **Build and Install Native Host**
   ```bash
   cd Tools/AuthsiaNativeHost
   ./install_native_host.sh
   ```

2. **Load Chrome Extension**
   - Open `chrome://extensions`
   - Enable Developer mode
   - Click "Load unpacked"
   - Select `Tools/AuthsiaChromeExtension`

3. **Configure Extension ID**
   ```bash
   ./install_native_host.sh --extension-id YOUR_EXTENSION_ID
   ```

4. **Restart Chrome**

### Preparing Credentials

For a password to be available for autofill:

1. Set a valid **Website** URL (e.g., `https://github.com`)
2. Enable **CLI Access** toggle in the password details
3. The website hostname must match the current page

## Security

### Trust Boundaries

1. **Chrome Extension (Untrusted)**
   - Runs in hostile page environment
   - Cannot access secrets directly
   - All input must be validated

2. **Native Host (Trusted Boundary)**
   - Validates extension input
   - Performs host matching
   - Controls access to CLI

3. **CLI and App (Secure)**
   - Accesses Keychain secrets
   - Ultimate authority on credential access

### Security Measures

- Host sanitization in both extension and native host
- `isCliEnabled` acts as per-item allowlist
- Exact host matches preferred over subdomain matches
- Ambiguous matches rejected (multiple exact matches)
- No credential logging in extension or native host
- Minimal response shape (only required fields)

See [SECURITY.md](../../SECURITY.md) for full security documentation.

## Development

### Project Structure

```
Tools/
├── AuthsiaChromeExtension/      # Chrome extension
│   ├── manifest.json           # Extension manifest v3
│   ├── content_script.js       # Page injection logic
│   ├── service_worker.js       # Background service worker
│   ├── heuristics.js           # Form detection heuristics
│   ├── host_matching.js        # Host validation
│   ├── native_client.js        # Native messaging client
│   ├── popup/
│   │   ├── menu.html          # Credential selection UI
│   │   ├── menu.css           # Menu styles
│   │   └── menu.js            # Menu logic
│   └── tests/                 # JavaScript tests
├── AuthsiaNativeHost/         # Swift native host
│   ├── Sources/
│   │   ├── NativeHostHandler.swift
│   │   ├── CredentialResolver.swift
│   │   └── ...
│   └── Tests/
└── authsia_cli_install/       # CLI installer
```

### Running Tests

**JavaScript Tests (Extension Logic)**
```bash
cd Tools/AuthsiaChromeExtension/tests
node hostMatching.test.js
node serviceWorker.test.js
node autofill.test.js
node heuristics.test.js
node menu.test.js
```

**Swift Tests (Native Host)**
```bash
cd Tools/AuthsiaNativeHost
swift test
```

**CLI Tests**
```bash
cd Packages/AuthsiaCLI
swift test
```

### Key Implementation Details

**Heuristic Scoring** (`heuristics.js`)
- Weights for autocomplete, type, name, id, placeholder, aria-label
- Penalizes confirmation and new-password fields
- Site-specific overrides available

**Host Matching Rules** (`host_matching.js`)
- Exact match: `github.com` ↔ `github.com`
- Subdomain match: `api.github.com` ↔ `github.com`
- No match: `evil-github.com` ↔ `github.com`

**Form Detection** (`content_script.js`)
- Scans page for login forms on load and DOM changes
- Uses MutationObserver for SPAs
- Debounced focus handling (100ms)

## Troubleshooting

### Common Issues

| Issue | Solution |
|-------|----------|
| Menu doesn't appear | Check native host installation and extension ID match |
| "No credentials found" | Verify `isCliEnabled=true` and website URL matches |
| "Multiple matches" | Remove duplicate entries for the same website |
| Fields don't fill | Ensure Authsia app is running and unlocked |

### Debug Steps

1. Check Chrome DevTools Console for errors
2. Verify native host binary exists: `ls -la /usr/local/bin/AuthsiaNativeHost`
3. Check manifest: `cat ~/Library/Application\ Support/Google/Chrome/NativeMessagingHosts/com.authsia.nativehost.json`
4. Run CLI manually: `authsia list`

## Future Enhancements

### Planned

- [ ] Firefox extension support
- [ ] Safari extension support
- [ ] TOTP code autofill (2FA fields)
- [ ] Automatic form submission option
- [ ] Password generation in browser

### Under Consideration

- iCloud Keychain integration hints
- Biometric approval for sensitive sites
- Site-specific autofill preferences

## References

- [Testing Guide](./TESTING_GUIDE.md) - Detailed setup and verification
- [SECURITY.md](../../SECURITY.md) - Security properties and guidelines
- [Chrome Native Messaging Docs](https://developer.chrome.com/docs/apps/nativeMessaging/)

---

**Last Updated:** 2026-02-01  
**Version:** 0.2.0
