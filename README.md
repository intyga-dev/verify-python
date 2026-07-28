# intyga-verify — Offline Intyga receipt verification for Python

Independently confirm that a human cryptographically approved **exactly** the action you are about to run — in your own process, with no Intyga secret and no network call. You recompute the canonical payload from your own parameters, check it byte-matches what was signed, and verify the human's **ES256** or **WebAuthn** signature.

Depends only on [`cryptography`](https://pypi.org/project/cryptography/). This is the verify-only surface of the Intyga Python SDK, published on its own so a relying party that only needs verification does not install the full client. Its canonicalization is held byte-identical to the TypeScript, Go, and Rust verifiers by shared cross-language test vectors.

> Status: **not yet published** to PyPI. The full client (which bundles this verifier) is [`sdk-python`](https://github.com/intyga-dev/sdk-python).

## Install

```sh
pip install intyga-verify
```

## Verify an approval receipt

```python
import intyga_verify

# `expected` is what you are ABOUT to execute; `nonce` is the challenge YOU issued.
result = intyga_verify.verify_approval_receipt(
    receipt,
    {"actionType": "wipe_production", "params": {"target": "prod-db-1"}, "nonce": nonce},
)
if not result["ok"]:
    raise SystemExit(f"refusing to proceed: {result['reason']}")
```

One byte of drift — a swapped target, an appended region — and verification fails, because the signature was over the exact bytes you just recomputed.

## WebAuthn (passkey) receipts

A passkey assertion harvested at *any* relying party would otherwise verify, so WebAuthn receipts require you to pin the expected origin and RP ID:

```python
result = intyga_verify.verify_approval_receipt(
    receipt,
    {"actionType": "wipe_production", "params": {"target": "prod-db-1"}, "nonce": nonce},
    expected_origin="https://app.example.com",
    expected_rp_id="app.example.com",
)
```

`require_user_verification` defaults to `True`; pass `False` to accept mere user presence. Policy `AUTO_APPROVED` receipts carry no human signature and fail closed unless you pass `allow_auto_approved=True`.

## Also available in
- TypeScript — [`@intyga/verify`](https://github.com/intyga-dev/verify)
- Go — [`verify-go`](https://github.com/intyga-dev/verify-go)
- Rust — [`intyga-verify`](https://github.com/intyga-dev/verify-rust)

## License

Apache-2.0.
