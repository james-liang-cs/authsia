# Contributing

Thank you for helping improve Authsia's public security core.

1. Open an issue for behavior changes that alter policy, storage, or protocol
   compatibility. Report vulnerabilities privately through `SECURITY.md`.
2. Keep changes narrow and include a focused failing test before a behavior
   fix. Preserve fail-closed outcomes.
3. Use only unmistakably synthetic fixtures. Never commit or print a real
   secret, OTP seed or code, private key, passphrase, personal path, private
   endpoint, signing file, or automation credential.
4. Run the root Swift tests, native-host tests, release builds, and Chrome test
   script shown below.
5. Explain security-boundary effects and any compatibility tradeoff in the pull
   request. Contributions are accepted under Apache-2.0.

Do not add app UI, brand assets, signing/notarization operations, updater
credentials, or private release infrastructure to this repository. See
[OPEN_SOURCE.md](OPEN_SOURCE.md) for the ownership boundary.

Install the released app and CLI with Homebrew; this repository is the
inspectable security core, not the product download:

```bash
brew install --cask james-liang-cs/authsia/authsia
```

Product site: [https://authsia.clarionstack.com](https://authsia.clarionstack.com).

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

These source builds do not install or sign the private Authsia app.

The reusable root package targets macOS 15+ and iOS 17+. Host and CLI behavior
is macOS-only. The standalone native host retains its macOS 13+ package floor.

Public packages:

- `AuthenticatorCore`: parsing and vault-domain models.
- `AuthenticatorData`: Keychain-backed persistence and repositories.
- `AuthenticatorBridge`: IPC, grant, policy, audit, and session models.
- `AuthsiaBridgeHost`: XPC caller validation, request authorization, and SSH
  agent runtime.
- `authsia`: the macOS command-line client.
- `AuthsiaNativeHost`: the standalone Chrome native-messaging host under
  `Tools/AuthsiaNativeHost`.

## Local MCP server

MCP integrations are disabled by default. Enable **MCP Integrations** in the
Authsia app under **Settings > Developer Access** before connecting a client.
Client configuration does not enable this app-level control.

Print a user-global local MCP configuration for a supported client:

```bash
authsia mcp configure --client codex
authsia mcp configure --client claude
authsia mcp configure --client cursor
authsia mcp configure --client vscode
```

The command prints configuration for the exact Authsia binary; it does not edit
client files. Generated proxy entries use a stable `mcp proxy` argv and set
`AUTHSIA_MCP_UPSTREAM` to the workspace name so a company MCP allowlist can
match Authsia without enumerating child tools. For Codex, Claude Code, and
VS Code, it also prints a direct MCP installation command; other clients
retain manual configuration guidance.
The generated Codex manual configuration forwards optional local
`NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`, and `SSL_CERT_FILE` TLS trust
settings without forwarding credentials or other ambient variables. Use that
manual entry on a network with a custom CA; Codex's direct installer cannot
forward local environment names.
`authsia mcp serve` runs the same local stdio server directly and
is included in CLI help and shell completion. One global client configuration
can serve every repository: workspace-dependent tools accept the active
repository's validated absolute path as `workspaceRoot`, with Cursor's safe
launch hint or the client working directory as compatibility fallbacks. An
explicit `--workspace` remains available and authoritative. Claude Code and
Codex CLI retain their existing working-directory behavior. Otherwise status remains available while
workspace-dependent tools fail closed. The local `stdio` server exposes six
constrained tools for status, workspace inspection, scoped metadata listing,
mediated execution, grant status, and grant revocation. It never exposes a
raw-secret or global-audit tool. See the
[Local Authsia MCP Server specification](Doc/specs/authsia-mcp.md) for the tool,
JIT authorization, audit-correlation, and Access Center contracts. Wrapping
another local stdio MCP server is specified in
[Local Authsia MCP Proxy](Doc/specs/authsia-mcp-proxy.md).

## Release artifacts and verification

Each `v<app-version>` source tag publishes a source archive, public macOS CLI,
SPDX 2.3 JSON SBOM, and SHA-256 checksums. GitHub artifact attestations bind the
public CLI and SBOM to the tag workflow that built them.

The private macOS app release publishes a separate provenance JSON file. Use
[`scripts/verify-release.sh`](scripts/verify-release.sh) with the DMG and that
provenance file to check the outer hash before mounting, Apple Developer ID
authority, Team ID `33M8QU65SP`, notarization, Gatekeeper, bundled CLI hash,
public source tag/SHA, and SBOM hash:

```bash
scripts/verify-release.sh Authsia-<version>.dmg Authsia-<version>.provenance.json
gh attestation verify authsia-v<version>-macos-<architecture> \
  --repo james-liang-cs/authsia
```

This repository attests its public artifacts only. It does not claim that the
private Authsia application is reproducibly built from public source.
