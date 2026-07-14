# Privacy Policy

## Table of Contents

- [Overview](#overview)
- [Data Collection](#data-collection)
- [Data Storage](#data-storage)
- [Permissions](#permissions)
- [Third-Party Services](#third-party-services)
- [Changes to This Policy](#changes-to-this-policy)
- [Contact Us](#contact-us)

**Effective Date:** 2026-06-10

## Overview
Authenticator ("the App") is designed with a "Privacy First" philosophy. We do
not collect, store, or share your personal data. App data is stored locally on
your device by default. If you enable iCloud Keychain Sync, Authsia also stores
syncable copies in your personal iCloud Keychain.

## Data Collection
**We do not collect any personal information.**
- No analytics.
- No tracking pixels.
- No third-party SDKs that collect data.

## Data Storage
- **Secrets:** OTP seeds, passwords, secure note contents, certificate private
  keys, SSH private keys, and passphrases are stored in Apple Keychain
  (`kSecClassGenericPassword`). By default, Authsia writes local Keychain
  records only. If you enable iCloud Keychain Sync in Settings, Authsia also
  keeps iCloud-synchronizable Keychain copies. Your synchronizable secrets are
  end-to-end encrypted by Apple if you use iCloud Keychain.
- **Metadata:** Names, issuers, folders, settings, and list-safe vault fields are
  JSON-encoded and stored in Keychain records using the same local-only default
  and optional iCloud Keychain Sync setting. The macOS CLI metadata snapshot is a
  local JSON cache containing non-secret list metadata only; it never contains
  OTP seeds, passwords, note contents, certificate private keys, SSH private
  keys, or passphrases.
- **Sync toggle:** Turning iCloud Keychain Sync off stops future sync writes from
  this device. It does not delete existing local or iCloud Keychain records.
  Data deletion only happens through explicit delete actions.

## Permissions
The App requests the following permissions only for functional purposes:
- **Camera:** strictly to scan QR codes for adding new accounts. No images are sent to any server.

## Third-Party Services
The App does not use any third-party services for data processing. All operations (QR decoding, Code generation) happen on-device.

## Changes to This Policy
We may update this policy to reflect changes in our practices. If we do, we will update the "Effective Date" at the top of this policy.

## Contact Us
If you have any questions about this Privacy Policy, please contact us at support@authsia.app.
