# Contributing

Thank you for helping improve Authsia's public security core.

1. Open an issue for behavior changes that alter policy, storage, or protocol
   compatibility. Report vulnerabilities privately through `SECURITY.md`.
2. Keep changes narrow and include a focused failing test before a behavior
   fix. Preserve fail-closed outcomes.
3. Use only unmistakably synthetic fixtures. Never commit or print a real
   secret, OTP seed or code, private key, passphrase, personal path, private
   endpoint, signing file, or automation credential.
4. Run the root Swift tests, native-host tests, release builds, and Chrome test
   script shown in `README.md`.
5. Explain security-boundary effects and any compatibility tradeoff in the pull
   request. Contributions are accepted under Apache-2.0.

Do not add app UI, brand assets, signing/notarization operations, updater
credentials, or private release infrastructure to this repository. See
`OPEN_SOURCE.md` for the ownership boundary.
