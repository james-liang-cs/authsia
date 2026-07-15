#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT_PATH="${1:-$REPO_ROOT/dist/authsia.spdx.json}"

case "$OUTPUT_PATH" in
    /*) ;;
    *) OUTPUT_PATH="$PWD/$OUTPUT_PATH" ;;
esac

if ! command -v python3 >/dev/null 2>&1; then
    echo "error: python3 is required to generate the SPDX SBOM" >&2
    exit 1
fi

mkdir -p "$(dirname "$OUTPUT_PATH")"
DEPENDENCY_JSON="$(mktemp "${TMPDIR:-/tmp}/authsia-dependencies.XXXXXX")"
trap 'rm -f "$DEPENDENCY_JSON"' EXIT

swift package show-dependencies --package-path "$REPO_ROOT" --format json > "$DEPENDENCY_JSON"

SOURCE_SHA="$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || printf 'unknown')"
SOURCE_VERSION="$(git -C "$REPO_ROOT" describe --tags --exact-match 2>/dev/null || printf '%s' "$SOURCE_SHA")"

python3 - "$DEPENDENCY_JSON" "$OUTPUT_PATH" "$SOURCE_SHA" "$SOURCE_VERSION" <<'PY'
import json
import re
import sys
from datetime import datetime, timezone

dependency_path, output_path, source_sha, source_version = sys.argv[1:]
with open(dependency_path, encoding="utf-8") as handle:
    root = json.load(handle)


def spdx_id(value):
    normalized = re.sub(r"[^A-Za-z0-9.-]", "-", value or "package")
    return f"SPDXRef-Package-{normalized}"


packages = {}
relationships = set()


def visit(node, parent_id=None, is_root=False):
    identity = node.get("identity") or node.get("name") or "package"
    package_id = spdx_id("authsia" if is_root else identity)
    version = source_version if is_root else (node.get("version") or "NOASSERTION")
    download = "https://github.com/james-liang-cs/authsia" if is_root else node.get("url")
    if not download or not str(download).startswith(("https://", "http://")):
        download = "NOASSERTION"

    packages[package_id] = {
        "SPDXID": package_id,
        "name": "authsia" if is_root else (node.get("name") or identity),
        "versionInfo": version,
        "downloadLocation": download,
        "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "NOASSERTION",
        "copyrightText": "NOASSERTION",
    }
    if parent_id:
        relationships.add((parent_id, "DEPENDS_ON", package_id))
    for child in node.get("dependencies") or []:
        visit(child, package_id)
    return package_id


root_id = visit(root, is_root=True)
created = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
document = {
    "spdxVersion": "SPDX-2.3",
    "dataLicense": "CC0-1.0",
    "SPDXID": "SPDXRef-DOCUMENT",
    "name": f"authsia-{source_version}",
    "documentNamespace": f"https://github.com/james-liang-cs/authsia/spdx/{source_sha}",
    "creationInfo": {
        "created": created,
        "creators": ["Tool: Authsia scripts/generate-sbom.sh"],
    },
    "documentDescribes": [root_id],
    "packages": sorted(packages.values(), key=lambda item: item["SPDXID"]),
    "relationships": [
        {
            "spdxElementId": source,
            "relationshipType": relation,
            "relatedSpdxElement": target,
        }
        for source, relation, target in sorted(relationships)
    ],
}

with open(output_path, "w", encoding="utf-8") as handle:
    json.dump(document, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY

echo "Wrote SPDX SBOM: $OUTPUT_PATH"
