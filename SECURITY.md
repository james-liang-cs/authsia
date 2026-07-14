# Security policy

## Supported versions

Before the first tagged source release, security fixes are made on `main`.
After releases begin, the latest tagged source release and `main` are supported.
Older versions may be asked to upgrade before a fix is evaluated.

## Private reporting

Do not open a public issue for a suspected vulnerability. Private vulnerability
reporting will be enabled before this repository is published at:

`https://github.com/james-liang-cs/authsia/security/advisories/new`

This URL is provisional until the repository security setting is enabled. Do
not send a report until the private advisory form is available.

We aim to acknowledge a report within three business days, provide an initial
triage within seven business days, and send a status update at least every 14
days while remediation is active. These are response targets, not disclosure
deadlines.

## Safe reports

- Use synthetic fixtures and a disposable local vault.
- Never submit a real password, API key, OTP seed or code, private key,
  passphrase, automation token, personal path, or private endpoint.
- Include the source commit, platform version, minimal reproduction, expected
  authorization result, and redacted observed result.
- Do not access another person's data, bypass approval on systems you do not
  own, or disrupt a service.
- Coordinate disclosure through the private advisory until a fix and release
  plan are agreed.

Installation and Homebrew-cask problems that do not expose a security boundary
belong in the relevant public issue tracker after publication.
