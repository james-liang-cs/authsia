#!/usr/bin/env bash
set -euo pipefail

check_file() {
    local file=$1
    local category
    local pattern

    [[ -f "$file" ]] || {
        echo "Output log is not a file" >&2
        return 2
    }

    while IFS=$'\t' read -r category pattern; do
        if LC_ALL=C rg --pcre2 -q -- "$pattern" "$file"; then
            echo "Potential secret output detected: $category" >&2
            return 1
        fi
    done <<'PATTERNS'
private-key	-----BEGIN (?:OPENSSH |RSA |EC |DSA )?PRIVATE KEY-----
resolved-environment	(?i)\bresolved(?:[_ -]?(?:environment|value|secret))s?\b\s*[:=]
otp	(?i)\b(?:otp|one[-_ ]time(?:[-_ ](?:password|code))?)\b\s*[:=]\s*["']?\d{6,8}\b
secret-assignment	(?i)\b(?:secret|password|passphrase|api[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key)\b\s*[:=]\s*["']?(?!(?:set|unset|true|false|null|nil|none|redacted)\b|authsia://|\$\(|<redacted>|<concealed\b)[^\s"',;}]{6,}
PATTERNS

    return 0
}

self_test() {
    local tmp_dir
    tmp_dir="$(mktemp -d)"
    trap 'rm -rf "$tmp_dir"' RETURN

    printf '%s\n' \
        'API_KEY=set' \
        'PASSWORD=unset' \
        'secret=<concealed by authsia>' \
        'All security tests passed' \
        > "$tmp_dir/safe.log"
    check_file "$tmp_dir/safe.log" || {
        echo "FAIL: safe redacted output was rejected" >&2
        return 1
    }

    local fixture
    local fixtures=(
        'api_key=AUTHSIA_FAKE_SECRET_4c7e2b91'
        '-----BEGIN OPENSSH PRIVATE KEY-----'
        'passphrase=AUTHSIA_FAKE_PASSPHRASE_83a1'
        'otp=123456'
        'resolvedEnvironment={"SERVICE_TOKEN":"AUTHSIA_FAKE_VALUE_7f2a"}'
    )

    for fixture in "${fixtures[@]}"; do
        printf '%s\n' "$fixture" > "$tmp_dir/leak.log"
        if check_file "$tmp_dir/leak.log" >/dev/null 2>&1; then
            echo "FAIL: synthetic leak fixture was accepted" >&2
            return 1
        fi
    done

    echo "PASS check-no-secret-output self-test"
}

case "${1:-}" in
    --self-test)
        [[ $# -eq 1 ]] || { echo "Usage: $0 --self-test" >&2; exit 2; }
        self_test
        ;;
    "")
        stdin_log="$(mktemp)"
        trap 'rm -f "$stdin_log"' EXIT
        tee "$stdin_log" >/dev/null
        check_file "$stdin_log"
        ;;
    *)
        failed=0
        for log_file in "$@"; do
            check_file "$log_file" || failed=1
        done
        exit "$failed"
        ;;
esac
