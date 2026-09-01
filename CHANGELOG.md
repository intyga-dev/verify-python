# Changelog

All notable changes to `intyga-verify` (Python) are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [SemVer](https://semver.org/).

This distribution is **assembled at build time** rather than kept as a standalone source tree:
`scripts/build-public-tree.sh verify-python` extracts the verifier out of `sdk-python`'s
`crypto.py` (everything above `class PolicyCrypto:`) and pairs it with the template here. So an
entry below describes a change to that extracted surface, which usually arrives as a change to
`packages/sdk-python` — check its changelog too when tracing a behaviour.

## [Unreleased]

- **Refuse a forward-dated offline proof or delegation (DIV §5a.3 rule 3, §5a.6 step 1).** The
  window caps bounded a proof's WIDTH but never its POSITION, so a quorum-signed proof dated years
  ahead with a compliant 60-minute (or 72-hour) window verified today and kept verifying until that
  date arrived. The check is unconditional — the audit/`allow_expired` override exists to re-examine
  a proof that WAS valid and has since lapsed, which says nothing about one dated in the future.
- **Refuse a signed `requirement.requiredApprovals` below 1 (DIV §4.3.2).** §5 step 7's "at least
  `requiredApprovals`" is satisfied vacuously by `0`, so a receipt carrying no valid witness
  signature could verify. The minimum is now enforced explicitly rather than by an undocumented
  floor, and `True` is rejected along with `0` — in Python a bool is an int.

## [1.0.0]

Initial public release.

- Offline approval-receipt verification (ES256 and WebAuthn) against a caller-supplied trust
  anchor — no Intyga secret, no network. Depends only on `cryptography`.
- Canonical payload reconstruction held byte-identical to the TypeScript, Go, Rust and Java
  verifiers by the shared cross-language golden vectors.
- DEWP Core Profile primitives and §5.2 single-anchor signature verification. §5.3 anchor-quorum
  evaluation and DIV §5b agent-authority verification are deliberately out of scope — see the
  README's limits section, which states them precisely rather than implying full parity.
