#!/usr/bin/env bash
set -euo pipefail

EXPECTED_TEAM_ID="33M8QU65SP"
EXPECTED_AUTHORITY="Developer ID Application: CHEN LIANG (33M8QU65SP)"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
MOUNT_DIR=""

usage() {
    cat <<'EOF'
Usage: scripts/verify-release.sh <dmg> <provenance.json> [options]
       scripts/verify-release.sh --self-test

Options:
  --source-dir <path>  Public Authsia source clone containing the release tag
  --sbom <path>        SPDX JSON file (defaults beside the provenance file)
EOF
}

cleanup() {
    if [ -n "$MOUNT_DIR" ] && mount | grep -Fq " on $MOUNT_DIR "; then
        hdiutil detach "$MOUNT_DIR" -quiet || true
    fi
    if [ -n "$MOUNT_DIR" ]; then
        rm -rf "$MOUNT_DIR"
    fi
}
trap cleanup EXIT

sha256_file() {
    shasum -a 256 "$1" | awk '{print $1}'
}

verify_sha256() {
    local path="$1"
    local expected="$2"
    local actual
    actual="$(sha256_file "$path")"
    if [ "$actual" != "$expected" ]; then
        echo "error: SHA-256 mismatch for $(basename "$path")" >&2
        return 1
    fi
}

json_value() {
    local document="$1"
    local key_path="$2"
    python3 - "$document" "$key_path" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    value = json.load(handle)
for component in sys.argv[2].split("."):
    value = value[component]
if isinstance(value, (dict, list)):
    raise SystemExit(f"expected scalar at {sys.argv[2]}")
print(value)
PY
}

verify_relative_path() {
    case "$1" in
        ""|/*|../*|*/../*|*/..)
            echo "error: unsafe relative artifact path in provenance" >&2
            return 1
            ;;
    esac
}

self_test() {
    local fixture_dir fixture expected
    fixture_dir="$(mktemp -d "${TMPDIR:-/tmp}/authsia-verify-self-test.XXXXXX")"
    fixture="$fixture_dir/artifact"
    printf 'authsia verification fixture\n' > "$fixture"
    expected="$(sha256_file "$fixture")"
    verify_sha256 "$fixture" "$expected"
    if verify_sha256 "$fixture" "0000000000000000000000000000000000000000000000000000000000000000" \
        >/dev/null 2>&1; then
        echo "error: checksum self-test accepted a mismatch" >&2
        rm -rf "$fixture_dir"
        exit 1
    fi
    verify_relative_path "Authsia.app/Contents/Helpers/authsia"
    if verify_relative_path "../authsia" >/dev/null 2>&1; then
        echo "error: path self-test accepted traversal" >&2
        rm -rf "$fixture_dir"
        exit 1
    fi
    rm -rf "$fixture_dir"
    echo "verify-release self-test passed"
}

if [ "${1:-}" = "--self-test" ]; then
    self_test
    exit 0
fi

if [ "$#" -lt 2 ]; then
    usage >&2
    exit 64
fi

DMG_PATH="$1"
PROVENANCE_PATH="$2"
SOURCE_DIR="$REPO_ROOT"
SBOM_PATH=""
shift 2

while [ "$#" -gt 0 ]; do
    case "$1" in
        --source-dir)
            SOURCE_DIR="$2"
            shift 2
            ;;
        --sbom)
            SBOM_PATH="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            exit 64
            ;;
    esac
done

for command in python3 shasum codesign xcrun spctl hdiutil git; do
    command -v "$command" >/dev/null 2>&1 || {
        echo "error: required command not found: $command" >&2
        exit 1
    }
done

test -f "$DMG_PATH" || { echo "error: DMG not found" >&2; exit 1; }
test -f "$PROVENANCE_PATH" || { echo "error: provenance file not found" >&2; exit 1; }

DMG_SHA="$(json_value "$PROVENANCE_PATH" artifacts.dmg.sha256)"
DMG_FILENAME="$(json_value "$PROVENANCE_PATH" artifacts.dmg.filename)"
CLI_RELATIVE_PATH="$(json_value "$PROVENANCE_PATH" artifacts.bundledCLI.path)"
CLI_SHA="$(json_value "$PROVENANCE_PATH" artifacts.bundledCLI.sha256)"
SBOM_FILENAME="$(json_value "$PROVENANCE_PATH" artifacts.sbom.filename)"
SBOM_SHA="$(json_value "$PROVENANCE_PATH" artifacts.sbom.sha256)"
SOURCE_TAG="$(json_value "$PROVENANCE_PATH" publicSource.tag)"
SOURCE_SHA="$(json_value "$PROVENANCE_PATH" publicSource.sha)"
TEAM_ID="$(json_value "$PROVENANCE_PATH" signing.teamID)"
AUTHORITY="$(json_value "$PROVENANCE_PATH" signing.authority)"
NOTARIZATION="$(json_value "$PROVENANCE_PATH" signing.notarization)"
GATEKEEPER="$(json_value "$PROVENANCE_PATH" signing.gatekeeper)"

if [ "$(basename "$DMG_PATH")" != "$DMG_FILENAME" ]; then
    echo "error: DMG filename does not match provenance" >&2
    exit 1
fi

# The outer hash is always checked before the image is mounted or any bundled
# executable is inspected.
verify_sha256 "$DMG_PATH" "$DMG_SHA"

if [ "$TEAM_ID" != "$EXPECTED_TEAM_ID" ] || [ "$AUTHORITY" != "$EXPECTED_AUTHORITY" ]; then
    echo "error: provenance signing identity does not match Authsia's published identity" >&2
    exit 1
fi
if [ "$NOTARIZATION" != "accepted" ] || [ "$GATEKEEPER" != "accepted" ]; then
    echo "error: provenance does not record accepted notarization and Gatekeeper results" >&2
    exit 1
fi

verify_relative_path "$CLI_RELATIVE_PATH"
verify_relative_path "$SBOM_FILENAME"
if [ -z "$SBOM_PATH" ]; then
    SBOM_PATH="$(cd "$(dirname "$PROVENANCE_PATH")" && pwd)/$SBOM_FILENAME"
fi
test -f "$SBOM_PATH" || { echo "error: SBOM not found" >&2; exit 1; }
verify_sha256 "$SBOM_PATH" "$SBOM_SHA"
grep -Fq '"spdxVersion": "SPDX-2.3"' "$SBOM_PATH" || {
    echo "error: SBOM is not SPDX 2.3 JSON" >&2
    exit 1
}

TAG_SHA="$(git -C "$SOURCE_DIR" rev-parse -q --verify "refs/tags/$SOURCE_TAG^{commit}" 2>/dev/null)" || {
    echo "error: public source tag $SOURCE_TAG is unavailable in $SOURCE_DIR" >&2
    exit 1
}
if [ "$TAG_SHA" != "$SOURCE_SHA" ]; then
    echo "error: public source tag does not resolve to the provenance SHA" >&2
    exit 1
fi

codesign --verify --strict --verbose=2 "$DMG_PATH"
SIGNING_INFO="$(codesign -dvvv "$DMG_PATH" 2>&1)"
printf '%s\n' "$SIGNING_INFO" | grep -Fq "Authority=$EXPECTED_AUTHORITY" || {
    echo "error: DMG signing authority does not match Authsia's published identity" >&2
    exit 1
}
xcrun stapler validate "$DMG_PATH"
spctl --assess --type open --context context:primary-signature --verbose=2 "$DMG_PATH"

MOUNT_DIR="$(mktemp -d "${TMPDIR:-/tmp}/authsia-verify-mount.XXXXXX")"
hdiutil attach "$DMG_PATH" -nobrowse -readonly -mountpoint "$MOUNT_DIR" -quiet
CLI_PATH="$MOUNT_DIR/$CLI_RELATIVE_PATH"
test -f "$CLI_PATH" || { echo "error: bundled CLI not found" >&2; exit 1; }
verify_sha256 "$CLI_PATH" "$CLI_SHA"
hdiutil detach "$MOUNT_DIR" -quiet
rm -rf "$MOUNT_DIR"
MOUNT_DIR=""

echo "Authsia release verification passed"
