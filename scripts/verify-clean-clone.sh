#!/usr/bin/env bash
set -euo pipefail

source_root="$(git rev-parse --show-toplevel)"
tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/authsia-clean-clone.XXXXXX")"
trap 'rm -rf "$tmp_dir"' EXIT

"$source_root/scripts/check-no-secret-output.sh" --self-test
git clone --quiet --no-local --no-hardlinks "$source_root" "$tmp_dir/repository"
cd "$tmp_dir/repository"
git remote remove origin

private_pattern='/Users/[^/]+/PlayGround/Auth''enticator|Authenticator''UI|R2''_|sparkle''-private'
if rg -n "$private_pattern" .; then
    echo "Clean clone contains a private source reference" >&2
    exit 1
fi

mkdir -p "$tmp_dir/home"
export HOME="$tmp_dir/home"
unset AUTHSIA_ACCESS_TOKEN AUTHSIA_AUTOMATION_TOKEN AUTHSIA_PRIVATE_ROOT

swift package resolve
swift test
swift build -c release --product authsia
swift test --package-path Tools/AuthsiaNativeHost
swift build -c release \
    --package-path Tools/AuthsiaNativeHost \
    --product AuthsiaNativeHost
Tools/AuthsiaChromeExtension/scripts/run-tests.sh

echo "PASS clean-clone verification"
