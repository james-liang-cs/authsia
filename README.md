# Authsia

**Runtime security for AI coding agents.**

Agents can run commands. They don’t inherit your secrets until you say so.
Authsia keeps credentials in your Mac Keychain and lets coding agents request
scoped, time-boxed access only when you approve.

[Website](https://authsia.clarionstack.com) · Local Keychain · Scoped JIT · Revoke anytime

## Install

```bash
brew install --cask james-liang-cs/authsia/authsia
```

Launch Authsia once, then enable **CLI Access** in Authsia > Settings > Security.

If `/Applications/Authsia.app` is already installed from the DMG, let Homebrew
adopt it:

```bash
brew install --cask --adopt james-liang-cs/authsia/authsia
```

Then check readiness:

```bash
authsia status
```

Download, CLI guide, and product docs: [authsia.clarionstack.com](https://authsia.clarionstack.com).

## What it does

- **Approve each secret use.** Access Center shows who is asking, the scope, and how long access lasts. Approve, deny, or revoke without changing project files.
- **Keep the parent shell clean.** Authsia resolves commit-safe refs and injects credentials into approved child processes only.
- **Wire a workspace.** Bind environments, run guarded terminals, and launch agents through the Authsia CLI.
- **Connect local agents.** MCP for Codex, Claude Code, Cursor, and VS Code — no raw-secret tools.
- **Cover the last mile.** Chrome autofill and SSH agent signing stay on your Mac.

## This repository

This is the Apache-2.0 public security core: vault domain, Keychain data,
Bridge host authorization, CLI, SSH runtime, Chrome native host, and extension.
Inspect the authorization boundary here. The SwiftUI app, approval presentation,
and private release infrastructure are not in this repository.

- [OPEN_SOURCE.md](OPEN_SOURCE.md) — public / private boundary
- [TRUST.md](TRUST.md) — claim-to-code verification
- [SECURITY.md](SECURITY.md) — vulnerability reports (never include a real secret)
- [CONTRIBUTING.md](CONTRIBUTING.md) — build, test, and contribution rules
