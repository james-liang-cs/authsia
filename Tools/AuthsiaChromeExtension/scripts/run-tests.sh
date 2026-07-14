#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
EXT_DIR="$ROOT_DIR/Tools/AuthsiaChromeExtension"

node "$EXT_DIR/tests/hostMatching.test.js"
node "$EXT_DIR/tests/heuristics.test.js"
node "$EXT_DIR/tests/serviceWorker.test.js"
node "$EXT_DIR/tests/menu.test.js"
node "$EXT_DIR/tests/autofill.test.js"

echo "[authsia-extension] All extension tests passed."
