# Authsia Agent Guide

This repository is the Apache-2.0 security core. Follow `CONTRIBUTING.md` and
`OPEN_SOURCE.md`. Do not add app UI, brand assets, or private release
infrastructure.

## In this gitlink (Authenticator checkout)

1. Classify with the parent `Doc/assistant/README.md` and read **one** route
   card.
2. Use the parent worktree `codegraph` index. Expected paths start with
   `Dependencies/Authsia/`.
3. Specs: follow the owner path on the route card. Publication copies in this
   repo live under `Doc/specs/`.

## Standalone clone

1. Run `codegraph status` in this root. Query a unique type or a filename with
   extension (`ExecCommand.swift`, not `ExecCommand`). Keep the hit whose
   `filePath` matches. Then `codegraph impact <symbol> --depth 1` and prefer
   `Sources/` edges.
2. CodeGraph does not index markdown. Open `Doc/specs/` directly.
3. Run the focused package test for the files you change.
