#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORKFLOW="$REPO_ROOT/.github/workflows/release-source.yml"

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

test -f "$WORKFLOW" || fail "release-source workflow is missing"

checksum_block="$(sed -n '/shasum -a 256/,/SHA256SUMS/p' "$WORKFLOW")"
test -n "$checksum_block" || fail "checksum generation block is missing"

if printf '%s\n' "$checksum_block" | grep -Fq 'dist/'; then
    fail "release checksum entries must not contain the local dist/ prefix"
fi

printf '%s\n' "$checksum_block" | grep -Fq '> SHA256SUMS' \
    || fail "release checksums must be written from inside the dist directory"

echo "release source workflow tests passed"
