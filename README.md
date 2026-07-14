# Authsia Security Core

Authsia's public security core contains the code that mediates local CLI,
agent, browser, and SSH access to an Authsia vault. It is licensed under
Apache-2.0 so developers can inspect, test, and contribute to the authorization
boundary.

The SwiftUI application, approval presentation, product assets, signing
credentials, and private release infrastructure are not part of this
repository. See [OPEN_SOURCE.md](OPEN_SOURCE.md) for the exact boundary and
[TRUST.md](TRUST.md) for claim-to-code verification paths.

## Products

- `AuthenticatorCore`: parsing and vault-domain models.
- `AuthenticatorData`: Keychain-backed persistence and repositories.
- `AuthenticatorBridge`: IPC, grant, policy, audit, and session models.
- `AuthsiaBridgeHost`: XPC caller validation, request authorization, and SSH
  agent runtime.
- `authsia`: the macOS command-line client.
- `AuthsiaNativeHost`: the standalone Chrome native-messaging host under
  `Tools/AuthsiaNativeHost`.

The reusable root package targets macOS 15+ and iOS 16+. Host and CLI behavior
is macOS-only. The standalone native host retains its macOS 13+ package floor.

## Build and test

Use Xcode 26 or a compatible Swift 6.2 toolchain:

```bash
swift package resolve
swift test
swift build -c release --product authsia
swift test --package-path Tools/AuthsiaNativeHost
swift build -c release --package-path Tools/AuthsiaNativeHost --product AuthsiaNativeHost
Tools/AuthsiaChromeExtension/scripts/run-tests.sh
```

These source builds do not install or sign the private Authsia app. For
security reports, follow [SECURITY.md](SECURITY.md) and never include a real
secret in an issue or reproduction.
