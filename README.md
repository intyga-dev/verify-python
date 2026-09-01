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

## Also available in
- TypeScript — [`@intyga/verify`](https://github.com/intyga-dev/verify)
- Go — [`verify-go`](https://github.com/intyga-dev/verify-go)
- Rust — [`intyga-verify`](https://github.com/intyga-dev/verify-rust)
- Java — [`com.intyga:intyga-verify`](https://github.com/intyga-dev/verify-java)

## License

Apache-2.0.
