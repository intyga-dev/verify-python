"""sakra-verify — offline verification of SÄKRA approval receipts.

The verifier and its canonicalization helpers, with no SÄKRA secret and no network. This is the
verify-only surface of the Python SDK, published on its own so a relying party that only needs to
verify receipts does not have to install the full client. Kept byte-identical to the TypeScript, Go,
and Rust verifiers by shared cross-language test vectors.
"""

from .crypto import (
    stable_stringify,
    canonical_challenge_payload,
    canonical_authorization_payload,
    canonical_authorization_payload_v3,
    canonical_intent_payload,
    canonical_action_payload,
    canonical_enroll_payload,
    canonical_login_payload,
    payload_digest_hex,
    verification_code,
    verify_ecdsa_p256,
    verify_approval_receipt,
)

__all__ = [
    "stable_stringify",
    "canonical_challenge_payload",
    "canonical_authorization_payload",
    "canonical_authorization_payload_v3",
    "canonical_intent_payload",
    "canonical_action_payload",
    "canonical_enroll_payload",
    "canonical_login_payload",
    "payload_digest_hex",
    "verification_code",
    "verify_ecdsa_p256",
    "verify_approval_receipt",
]
