# Authsia

**Runtime security for AI coding agents.**

Agents can run commands. They don’t inherit your secrets until you say so.
Authsia is a macOS vault and execution broker: credentials stay in your local
Keychain, coding agents request scoped, time-boxed access, and you approve,
deny, or revoke from Access Center.

[Website](https://authsia.clarionstack.com) · [CLI guide](https://authsia.clarionstack.com/cli.html) · [User guide](https://authsia.clarionstack.com/user-guide.html)

Local Keychain. Scoped JIT. Revoke anytime.

## Contents

- [Overview](#overview)
- [Core features](#core-features)
  - [Vault](#vault)
  - [Workspace](#workspace)
  - [Access Center](#access-center)
  - [CLI and agents](#cli-and-agents)
  - [SSH and browser](#ssh-and-browser)
  - [Audit](#audit)
- [Install](#install)
- [This repository](#this-repository)

## Overview

A coding agent runs with your permissions. It can launch tools, touch cloud
CLIs, and act on your machine. A vault that only protects secrets at rest does
not decide whether that agent should receive a credential at runtime.

Authsia closes that gap on your Mac — locally, with a human in the loop.

You store passwords, API keys, notes, certificates, SSH keys, and OTP accounts
in Apple Keychain. Projects keep commit-safe `authsia://` references instead of
plaintext. When a terminal, script, or agent needs a value, Authsia resolves
the reference at the last mile and injects it into the approved child process
only. The parent shell stays clean. Known secret values can be masked on
mediated output.

Access is a grant, not a standing environment variable. You see who is asking,
the workspace and command scope, and how long access lasts. End the grant when
the task is done.

Authsia does not replace a team vault for sharing and lifecycle. It is the
local enforcement layer between your Mac, the AI agent, and the process that
needs the secret.

## Core features

### Vault

Store developer credentials and 2FA accounts on this Mac. Folders are an access
boundary: later grants and CLI scopes follow the same tree (for example
`Team/API` or `Infra/SSH`). Per-item CLI access can stay off so a secret never
leaves the app UI.

Copy Path gives you an Authsia URI or a shell `export` line without revealing
the secret. Folders and multi-select copy newline-delimited references for
paste into scripts.

### Workspace

Point Authsia at a repo, bind env files or explicit env references, pick one
local environment (Default, or a named tag such as `Prod`), and run through
the same boundary:

```bash
authsia workspace init
authsia workspace env list
authsia workspace run -- npm test
```

Guarded terminals and agent launch keep the parent environment free of
resolved secrets. Named environments use exact-tagged and `All` items; Default
items stay inactive until you clear the selection.

### Access Center

Every secret use by a coding agent is a visible grant. Access Center shows the
caller (Codex, Claude Code, Cursor, and similar), the requested folder and
command capability, and the remaining TTL. Approve, deny, or revoke without
changing project files.

Grants are workspace-aware and expire. They do not leave a standing secret in
the agent-visible parent shell.

### CLI and agents

The `authsia` CLI is the terminal surface for the same policy: `exec`,
`workspace run`, `status`, `audit`, MCP configure/serve. MCP for Codex, Claude
Code, Cursor, and VS Code lists metadata and mediates runs — it never returns
plaintext secrets.

Enable **CLI Access** in Authsia > Settings > Security after the first launch,
then enable it on the items an agent is allowed to use.

### SSH and browser

SSH signing goes through Authsia’s agent (`SSH_AUTH_SOCK`) with the same
approval and item-access policy — not by exporting a private key into the
shell. Chrome autofill uses a native messaging host so the browser can fill
saved logins for the current site without enumerating the vault.

### Audit

Local audit history records what was released, who approved it, and what ran
under that grant. It does not send telemetry away. Review in Access Center or
with `authsia audit list`.

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

## This repository

This is the Apache-2.0 public security core: vault domain, Keychain data,
Bridge host authorization, CLI, SSH runtime, Chrome native host, and extension.
Inspect the authorization boundary here. The SwiftUI app, approval presentation,
and private release infrastructure are not in this repository.

- [OPEN_SOURCE.md](OPEN_SOURCE.md) — public / private boundary
- [TRUST.md](TRUST.md) — claim-to-code verification
- [SECURITY.md](SECURITY.md) — vulnerability reports (never include a real secret)
- [CONTRIBUTING.md](CONTRIBUTING.md) — build, test, and contribution rules
