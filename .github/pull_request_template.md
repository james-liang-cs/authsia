## Summary

Describe the smallest behavior or documentation change and why it is needed.

## Security boundary

- [ ] I identified any effect on caller validation, approval, JIT, automation,
      storage, native messaging, SSH signing, audit, or output redaction.
- [ ] The change remains fail closed when authorization or callbacks fail.
- [ ] No real secret, OTP data, private key, passphrase, token, personal path,
      private endpoint, signing file, or private app source is included.

## Verification

- [ ] Focused tests reproduce the changed behavior.
- [ ] `swift test`
- [ ] Native-host tests and Chrome extension tests, when relevant.
- [ ] Release products build, when relevant.
- [ ] Documentation and `TRUST.md` are updated when a public claim changes.
