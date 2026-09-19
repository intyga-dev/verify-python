# intyga-verify — Offline Intyga receipt verification for Python

Independently confirm that a human cryptographically approved **exactly** the action you are about to run — in your own process, with no Intyga secret and no network call. You recompute the canonical payload from your own parameters, check it byte-matches what was signed, and verify the human's **ES256** or **WebAuthn** signature.

Depends only on [`cryptography`](https://pypi.org/project/cryptography/). This is the verify-only surface of the Intyga Python SDK, published on its own so a relying party that only needs verification does not install the full client. Its canonicalization is held byte-identical to the TypeScript, Go, Rust, and Java verifiers by shared cross-language test vectors.

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

Limits remain explicit: no NDJSON evidence streaming, no RFC 3161/CMS verification, and no WEBHOOK
anchor verifier. Those anchors do not count toward quorum. No implementation claims the complete
DEWP Extended Profile (§9.2). Embedded WebAuthn material is incomplete in the audit leaf; verify the
full DIV receipt separately. Offline authority verification checks the seal, not subsequent online
revocation. Verification does not consume a nonce or prove execution.

## Also available in
- TypeScript — [`@intyga/verify`](https://github.com/intyga-dev/verify)
- Go — [`verify-go`](https://github.com/intyga-dev/verify-go)
- Rust — [`intyga-verify`](https://github.com/intyga-dev/verify-rust)
- Java — [`com.intyga:intyga-verify`](https://github.com/intyga-dev/verify-java)

## License

Apache-2.0.
