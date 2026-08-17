# SAML Security Hardening Plan

This checklist tracks the first hardening iteration following an AWS Client VPN
security notification about credentials being logged on unsupported third-party
SAML client paths.

AWS documents that federated Client VPN users must use the AWS-provided client.
The CRV1 implementation in this repository is therefore compatibility code,
not an AWS-supported integration. The wire protocol still requires the SAML
assertion to be carried in the OpenVPN key-method-2 password field; moving it to
another field is not a mitigation and would break authentication.

## Iteration 1: engine hardening

- [x] Remove credentials and credential prefixes from mock-server logs.
- [x] Keep SAML URLs and assertions out of generic events, logs, and errors.
- [x] Add regression tests using canary secrets to detect disclosure.
- [x] Clear cached SAML assertions and server-issued authentication tokens after
      terminal teardown, while preserving controlled transient reconnects.
- [x] Enforce bounded, strict SAML callback parsing and HTTP server timeouts.
- [x] Deprecate command-line SAML assertions, retain the compatible `-relay`
      organisation selector, and provide protected file/file-descriptor inputs
      for private relay bearer tokens.
- [x] Rename misleading CRV1 "username" helpers while retaining deprecated
      compatibility wrappers where practical.
- [x] Correct the security documentation to match the implemented credential
      lifecycle and residual risks.
- [x] Run formatting, unit, race, vet, and focused integration validation.

## Later, separately approved work

- [ ] Add user-facing unsupported-client warnings to each desktop/mobile app.
- [ ] Release a patched engine version using the repository version workflow.
- [ ] Update pinned engine versions in downstream applications.
- [ ] Validate an approved release against an isolated AWS Client VPN endpoint.
- [ ] Update the public demo login to submit a bounded, well-formed mock SAML
      response before releasing the stricter ACS parser; the legacy opaque demo
      token is intentionally rejected.

## Rollout and rollback

Iteration 1 changes only this repository and does not deploy or tag a release.
After review, ship through the normal patch-release process. Downstream clients
can roll back by pinning the previous engine tag; deprecated wrappers should
keep the hardening release source-compatible wherever possible.
