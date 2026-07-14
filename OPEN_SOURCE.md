# Open-source boundary

This repository is the Apache-2.0-licensed Authsia security core. It includes
the vault domain and Keychain data layers, shared Bridge models and policies,
the Bridge host authorization runtime, the CLI, SSH-agent runtime, Chrome
native host and extension, tests, and public trust documentation.

The following are not included or licensed by this repository:

- the Authsia SwiftUI application and private design system;
- approval windows, Touch ID presentation, app activation, and app lifecycle;
- product icons, logos, screenshots, and other brand assets;
- signing, notarization, app-update, upload, and private release operations;
- credentials, private endpoints, commercial plans, and private roadmap work.

The private application supplies presentation and lifecycle adapters through
narrow public protocols. Authorization decisions remain in the public host
package. Official app builds pin one exact commit of this repository; they do
not maintain a separate copy of the security implementation.

See [TRADEMARKS.md](TRADEMARKS.md) for brand-use limits.
