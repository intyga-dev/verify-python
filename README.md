# intyga-verify — Offline INTYGA receipt verification for Python

Independently confirm that a human cryptographically approved **exactly** the action you are about to run — in your own process, with no INTYGA secret and no network call. You recompute the canonical payload from your own parameters, check it byte-matches what was signed, and verify the human's **ES256** or **WebAuthn** signature.

Depends only on [`cryptography`](https://pypi.org/project/cryptography/). This is the verify-only surface of the INTYGA Python SDK, published on its own so a relying party that only needs verification does not install the full client. Its canonicalization is held byte-identical to the TypeScript, Go, Rust, and Java verifiers by shared cross-language test vectors.

> Status: **not yet published** to PyPI. The full client (which bundles this verifier) is [`sdk-python`](https://github.com/intyga-dev/sdk-python).

## Install

```sh
pip install intyga-verify
```

## Verify an approval receipt

```python
import intyga_verify

# The approver keys YOU trust, resolved from your own key management — never from the receipt.
# A receipt's own `signerPublicKey` proves only that the receipt is self-consistent.
APPROVERS = {"publicKeys": [MY_ENROLLED_APPROVER_KEY_B64]}

# `expected` is what you are ABOUT to execute. `target`, `nonce` and `approvers` are REQUIRED and
# are asserted from your side; the verifier refuses outright without them.
EXPECTED = {
    "target": "prod-db-cluster-01",       # THIS service (DIV Target Isolation)
    "actionType": "wipe_production",
    "params": {"database": "prod-db-1"},
    "nonce": nonce,                       # the challenge YOU issued
    "approvers": APPROVERS,
}

result = intyga_verify.verify_approval_receipt(receipt, EXPECTED)
if not result["ok"]:
    raise SystemExit(f"refusing to proceed: {result['reason']}")
```

One byte of drift — a swapped target, an appended region — and verification fails, because the signature was over the exact bytes you just recomputed.

## Whose quorum? (the requirement floor)

The signed `requirement` is the signers' own statement: its signature stops a third party from
altering it, not the approvers it constrains from writing a weaker one. One approver who is also the
requester can sign a 1-of-1 payload alone. **Without a floor this verifier proves only the quorum the
signers stated.** When you know the rule, add it to the expectation (DIV §5 step 3d):

```python
EXPECTED["requirement"] = {"requiredApprovals": 3, "requesterCannotApprove": True}
```

A signed requirement weaker on any field — fewer approvals, no four-eyes or no hardware key where the
floor demands one — is refused before any signature is counted, with a reason starting "signed
requirement is weaker than the relying party's policy"; an equal or stricter one passes. A malformed
floor (quorum below 1) is refused rather than ignored. The same field exists on the delegation
expectation (pass the ordinary rule) and the agent-authority expectation (your sealing policy).
Omitting it keeps the previous behaviour.

## WebAuthn (passkey) receipts

A passkey assertion harvested at *any* relying party would otherwise verify, so WebAuthn receipts require you to pin the expected origin and RP ID:

```python
result = intyga_verify.verify_approval_receipt(
    receipt,
    EXPECTED,
    expected_origin="https://app.example.com",
    expected_rp_id="app.example.com",
)
```

`require_user_verification` defaults to `True`; pass `False` to accept mere user presence. Policy `AUTO_APPROVED` receipts carry no human signature and fail closed unless you pass `allow_auto_approved=True`.

## Receipt and audit verification

The package also exports `verify_platform_receipt`, `verify_agent_authority` and `ledger`.
The ledger module exposes `verify_bundle`, `verify_evidence_bundle`, `verify_roots_chain`,
`verify_anchor_signature` and `verify_anchor_quorum`. It is assembled from the same source as
`intyga_sdk`, including the shared cross-language regression fixtures.

RFC 3161 anchors can be checked with `verify_rfc3161_anchor(anchor, trust)` and count toward quorum
when `external_keys={"rfc3161": {issuer: trust}}` is supplied. This optional adapter invokes an
installed OpenSSL 3 executable without network access. Trust pins the CA and TSA certificate digest;
`revocation` must explicitly be `"crl"` with an offline CRL or `"unchecked"`. The caller may select
an integer `verification_time`; the default rounds the current time up by at most one second so a
fresh fractional timestamp is not spuriously rejected. Historical verification proves certificate
validity at issuance but cannot reconstruct historical revocation state.

The five language verifiers support the same receipt and audit verification features, pinned by
`canonical-vectors.json`, `ledger-vectors.json` and `verifier-parity-vectors.json`:

- DIV approval/offline/delegation receipts, agent-authority seals (§5b), and platform receipts (§5c).
  Platform receipts require WebAuthn and caller-pinned digest, RP, nonce, origin and subject keys.
  Authority/delegation verification never substitutes for approval of an action.
- Self-certifying DIDs, with explicit caller key mappings taking precedence.
- DEWP single-event and multi-event proof bundles: inclusion, canonical content/header binding,
  embedded ES256 signatures, tenant identity, sequence gaps/duplicates and claimed range endpoints.
- Checkpoint continuity (§5.4), and anchor quorum (§5.3) under the caller's policy: ES256, Ed25519,
  RSA-PSS and Rekor SET/payload verification under a separately pinned log key.

Trust inputs must come from the caller. A root carried in the bundle proves only internal
consistency; a producer's `externallyAnchored` flag is a claim, not verification. Bundle-carried
anchors can count under caller-trusted keys, but only independently fetched, checkpoint-attributed
anchors may establish divergence. For multi-checkpoint exports, key caller anchors by checkpoint ID
or root; a flat list cannot establish exact attribution across checkpoints.
For a multi-issuer policy, scope the Rekor key with `external_keys["rekor_issuer"]`; an unscoped
legacy key is accepted only when exactly one issuer is trusted.

Limits remain explicit: no NDJSON evidence streaming and no WEBHOOK
anchor verifier. Those anchors do not count toward quorum. No implementation claims the complete
DEWP Extended Profile (§9.2). WebAuthn audit signatures require profile-carried assertion data and caller trust; verify the
full DIV receipt separately for authorization and quorum. Offline authority verification checks the seal, not subsequent online
revocation. Verification does not consume a nonce or prove execution.

## Also available in
- TypeScript — [`@intyga/verify`](https://github.com/intyga-dev/verify)
- Go — [`verify-go`](https://github.com/intyga-dev/verify-go)
- Rust — [`intyga-verify`](https://github.com/intyga-dev/verify-rust)
- Java — [`com.intyga:intyga-verify`](https://github.com/intyga-dev/verify-java)

## License

Apache-2.0.


### Audit event signatures

The `trust.intyga.audit.v1` profile carries WebAuthn assertion data in the committed
`canonical.metadata.webauthn.authenticatorData` and `clientDataJSON` fields. Both single-proof and
bulk-evidence verification check these assertions when given caller-owned signer trust. This is a
signature over the exact `signedPayload`, not approval quorum, action authorization, hardware
attestation, current credential status or proof that the deploy executed. Verify the full DIV receipt
against the expected operation and approval policy for those authorization checks.

The per-event signature result distinguishes `verified`, `invalid`, `not_checked` (missing trust,
missing material or unsupported algorithm) and `not_applicable` (unsigned/system or AUTO_APPROVED).
A reason accompanies each status. `trusted: true` requires a valid signature under a caller-supplied
key mapped to that signer DID. WebAuthn requires caller-selected origin and RP ID, user presence and
user verification, and refuses cross-origin assertions. Supply COSE keys for WebAuthn and SPKI keys
for ES256. Multiple keys per DID support deliberate key rotation; the evidence's key is never added
to the caller's trusted set.

Without a signature policy, legacy ES256 checks still use the embedded key and report `trusted: false`;
WebAuthn reports `not_checked`. Diagnostic ledger validity does not imply signature validity. The
strict signature option requires **every selected entry** to have a verified, caller-trusted signature;
unsigned, redacted, incomplete and invalid entries fail that option. Anchor quorum is a separate policy.

Pass `signature_policy={"trustedSigners": {did: [public_key]}, "expectedOrigin": origin, "expectedRpId": rp_id}`
and `require_signatures=True` to `verify_bundle` / `verify_evidence_bundle`.
