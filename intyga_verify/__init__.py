"""intyga-verify — offline verification of Intyga approval receipts.

The verifier and its canonicalization helpers, with no Intyga secret and no network. This is the
verify-only surface of the Python SDK, published on its own so a relying party that only needs to
verify receipts does not have to install the full client. Kept byte-identical to the TypeScript, Go,
Rust, and Java verifiers by shared cross-language test vectors.
"""

# NOTE: the pre-DIV canonical_authorization_payload / _v3 builders were removed with the v2/v3
# formats (ADR 005/014) — do not re-add them here; verify_approval_receipt rejects v != 1.
from . import ledger
from .rfc3161 import verify_rfc3161_anchor
from .crypto import (
    canonical_agent_authority_payload,
    canonical_platform_intent_payload,
    verify_agent_authority,
    verify_platform_receipt,
    self_certifying_did,
    stable_stringify,
    canonical_challenge_payload,
    canonical_intent_payload,
    canonical_action_payload,
    canonical_enroll_payload,
    canonical_login_payload,
    payload_digest_hex,
    verification_code,
    verify_ecdsa_p256,
    verify_approval_receipt,
    # DIV §5a. Without these the published verifier cannot check an offline approval or a delegation
    # at all — the two mechanisms a relying party most needs to verify locally, since they exist
    # precisely for when the gateway is unreachable.
    canonical_offline_intent_payload,
    canonical_delegation_payload,
    verify_delegation,
    NonCanonicalValue,
    # DIV §5 step 3d: the refusal stem for a signed requirement below expected["requirement"].
    WEAKER_REQUIREMENT_REASON,
)

__all__ = [
    "ledger",
    "verify_rfc3161_anchor",
    "canonical_agent_authority_payload",
    "canonical_platform_intent_payload",
    "verify_agent_authority",
    "verify_platform_receipt",
    "self_certifying_did",
    "stable_stringify",
    "canonical_offline_intent_payload",
    "canonical_delegation_payload",
    "verify_delegation",
    "NonCanonicalValue",
    "canonical_challenge_payload",
    "canonical_intent_payload",
    "canonical_action_payload",
    "canonical_enroll_payload",
    "canonical_login_payload",
    "payload_digest_hex",
    "verification_code",
    "verify_ecdsa_p256",
    "verify_approval_receipt",
    "WEAKER_REQUIREMENT_REASON",
]
