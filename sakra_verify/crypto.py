import base64
import hashlib
import hmac
import json
import math
import os
from datetime import datetime, timezone
from typing import Any, Dict, Tuple

# DIV protocol constants (docs/DIV.md v1).
DIV_VERSION = 1
DIV_INTENT_TYPE = "div-intent-verification"
# RECOMMENDED expiry tolerance in seconds (DIV §6.2).
DEFAULT_CLOCK_SKEW_SECONDS = 30

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# WebAuthn authenticatorData flag bits (WebAuthn L3 §6.1).
AUTH_DATA_FLAG_UP = 0x01  # User Present
AUTH_DATA_FLAG_UV = 0x04  # User Verified

def base64url_encode(data: bytes) -> str:
    """Encode bytes to base64url format without padding."""
    return base64.urlsafe_b64encode(data).decode("utf-8").replace("=", "")

def base64url_decode(s: str) -> bytes:
    """Decode a base64url string, adding padding if necessary."""
    s += "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s)

def base64_decode_flexible(s: str) -> bytes:
    """Decode standard base64 or base64url with or without padding."""
    s = s.replace("-", "+").replace("_", "/")
    s += "=" * ((4 - len(s) % 4) % 4)
    return base64.b64decode(s)

def stable_stringify(value: Any) -> str:
    """Deterministic JSON stringification with UTF-16 code unit sorted keys."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        if isinstance(value, float):
            if math.isnan(value) or math.isinf(value):
                return "null"
            if value.is_integer():
                return str(int(value))
        return json.dumps(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(stable_stringify(x) for x in value) + "]"
    if isinstance(value, dict):
        keys = sorted(value.keys(), key=lambda k: k.encode("utf-16-be"))
        parts = []
        for k in keys:
            k_str = json.dumps(k, ensure_ascii=False)
            v_str = stable_stringify(value[k])
            parts.append(f"{k_str}:{v_str}")
        return "{" + ",".join(parts) + "}"
    try:
        return json.dumps(value, ensure_ascii=False)
    except Exception:
        return "null"

def canonical_challenge_payload(nonce: str, action_description: str) -> str:
    """v1 canonical challenge payload (flat JSON, no nested sorting)."""
    nonce_json = json.dumps(nonce, ensure_ascii=False)
    action_json = json.dumps(action_description, ensure_ascii=False)
    return f'{{"v":1,"nonce":{nonce_json},"action":{action_json}}}'

def canonical_authorization_payload(nonce: str, action_type: str, action_description: str, params: Dict[str, Any]) -> str:
    """v2 canonical authorization payload (recursively sorted params)."""
    nonce_json = json.dumps(nonce, ensure_ascii=False)
    action_type_json = json.dumps(action_type, ensure_ascii=False)
    action_json = json.dumps(action_description, ensure_ascii=False)
    params_json = stable_stringify(params)
    return (
        f'{{"v":2,"type":"agent-authorization","nonce":{nonce_json},'
        f'"actionType":{action_type_json},"action":{action_json},'
        f'"params":{params_json}}}'
    )

def canonical_authorization_payload_v3(
    nonce: str,
    action_type: str,
    action_description: str,
    params: Dict[str, Any],
    requester: Dict[str, Any],
    expires_at: str | None = None,
) -> str:
    """v3 canonical authorization payload — v2 plus WHO REQUESTED the action.

    Byte-identical to ``canonicalAuthorizationPayloadV3`` in @sakra-trust/mcp-schemas and
    @sakra-trust/verify. ``requester`` is ``{"did": str, "attestation": {"method","issuer","subject"}
    | None}``. The requester block is hand-concatenated with a FIXED key order (``did`` then
    ``attestation``; and within an attestation, ``method``, ``issuer``, ``subject``) — it deliberately
    does NOT go through ``stable_stringify``, because key order is part of the signed contract. When the
    requester is unattested the attestation is the literal ``null`` — that null is load-bearing and is
    signed (it distinguishes "an attested workload asked" from "something holding an API key asked").
    """
    nonce_json = json.dumps(nonce, ensure_ascii=False)
    action_type_json = json.dumps(action_type, ensure_ascii=False)
    action_json = json.dumps(action_description, ensure_ascii=False)
    params_json = stable_stringify(params)
    did_json = json.dumps(requester.get("did", ""), ensure_ascii=False)
    attestation_val = requester.get("attestation")
    if attestation_val is None:
        attestation = "null"
    else:
        method_json = json.dumps(attestation_val.get("method", ""), ensure_ascii=False)
        issuer_json = json.dumps(attestation_val.get("issuer", ""), ensure_ascii=False)
        subject_json = json.dumps(attestation_val.get("subject", ""), ensure_ascii=False)
        attestation = f'{{"method":{method_json},"issuer":{issuer_json},"subject":{subject_json}}}'
    expires_suffix = f',"expiresAt":{json.dumps(expires_at, ensure_ascii=False)}' if expires_at else ""
    return (
        f'{{"v":3,"type":"agent-authorization","nonce":{nonce_json},'
        f'"actionType":{action_type_json},"action":{action_json},'
        f'"params":{params_json},'
        f'"requester":{{"did":{did_json},"attestation":{attestation}}}'
        f'{expires_suffix}}}'
    )

def canonical_intent_payload(
    target: str,
    action_type: str,
    display: str,
    params: Dict[str, Any],
    requester: Dict[str, Any],
    nonce: str,
    expires_at: str,
) -> str:
    """Canonical DIV Intent Payload (docs/DIV.md v1).

    Byte-identical to ``canonicalIntentPayload`` in @sakra-trust/mcp-schemas, @sakra-trust/verify and
    the Go/Rust ports. Strict RFC 8785 JCS: the WHOLE object is serialized via ``stable_stringify``,
    which sorts every key recursively by UTF-16 code unit — so, unlike the legacy builders, key order
    is NOT hand-templated. ``requester`` is ``{"did": str, "attestation": {...} | None}``; the null
    attestation is load-bearing and signed.
    """
    attestation_val = requester.get("attestation")
    if attestation_val is None:
        attestation: Any = None
    else:
        attestation = {
            "method": attestation_val.get("method", ""),
            "issuer": attestation_val.get("issuer", ""),
            "subject": attestation_val.get("subject", ""),
        }
    return stable_stringify(
        {
            "v": DIV_VERSION,
            "type": DIV_INTENT_TYPE,
            "target": target,
            "actionType": action_type,
            "display": display,
            "params": params,
            "requester": {"did": requester.get("did", ""), "attestation": attestation},
            "nonce": nonce,
            "expiresAt": expires_at,
        }
    )

def canonical_action_payload(nonce: str, action_type: str, summary: str, params: Dict[str, Any]) -> str:
    """v2 canonical console-action payload."""
    nonce_json = json.dumps(nonce, ensure_ascii=False)
    action_type_json = json.dumps(action_type, ensure_ascii=False)
    summary_json = json.dumps(summary, ensure_ascii=False)
    params_json = stable_stringify(params)
    return (
        f'{{"v":2,"type":"console-action","nonce":{nonce_json},'
        f'"actionType":{action_type_json},"summary":{summary_json},'
        f'"params":{params_json}}}'
    )

def canonical_enroll_payload(token: str, public_key: str) -> str:
    """v1 canonical wallet-enroll payload."""
    token_json = json.dumps(token, ensure_ascii=False)
    pub_json = json.dumps(public_key, ensure_ascii=False)
    return f'{{"v":1,"type":"wallet-enroll","token":{token_json},"publicKey":{pub_json}}}'

def canonical_login_payload(nonce: str, account_id: str) -> str:
    """v1 canonical dashboard-login payload."""
    nonce_json = json.dumps(nonce, ensure_ascii=False)
    acc_json = json.dumps(account_id, ensure_ascii=False)
    return f'{{"v":1,"type":"dashboard-login","nonce":{nonce_json},"accountId":{acc_json}}}'

def payload_digest_hex(canonical: str) -> str:
    """SHA-256 digest of the canonical string as a lowercase hex string."""
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

def verification_code(canonical: str) -> str:
    """Grouped human-readable verification code (XXXX-XXXX)."""
    digest = payload_digest_hex(canonical)
    hex_prefix = digest[:8].upper()
    return f"{hex_prefix[:4]}-{hex_prefix[4:]}"

def verify_ecdsa_p256(public_key_b64: str, payload: str, signature_b64: str) -> bool:
    """Verify an ECDSA P-256 signature (IEEE-P1363 64-byte or ASN.1 DER) against a SPKI public key."""
    try:
        pub_bytes = base64_decode_flexible(public_key_b64)
        public_key = serialization.load_der_public_key(pub_bytes)

        # Pin the key to EC / P-256. load_der_public_key accepts RSA and other curves just as happily,
        # and the receipt claims ES256 — so enforce the label rather than trusting it. The key is
        # chosen by whoever enrolled the wallet.
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            return False
        if not isinstance(public_key.curve, ec.SECP256R1):
            return False

        signature_bytes = base64_decode_flexible(signature_b64)
        data = payload.encode("utf-8")

        # Raw IEEE-P1363 (r||s) is always exactly 64 bytes for P-256. DER is usually 70-72 but can in
        # principle also be 64, so length is not a reliable discriminator — try both encodings rather
        # than inferring one, and let a wrong guess fall through instead of failing the whole verify.
        candidates = []
        if len(signature_bytes) == 64:
            r = int.from_bytes(signature_bytes[:32], byteorder="big")
            s = int.from_bytes(signature_bytes[32:], byteorder="big")
            candidates.append(encode_dss_signature(r, s))
        candidates.append(signature_bytes)

        for der_signature in candidates:
            try:
                public_key.verify(der_signature, data, ec.ECDSA(hashes.SHA256()))
                return True
            except Exception:
                continue
        return False
    except Exception:
        return False

# ── Minimal CBOR reader (COSE_Key only) ──────────────────────────────────────
# Byte-for-byte the same subset the TypeScript verifier walks: ints, byte/text strings, arrays, maps.
# Deliberately not a general decoder — anything outside the subset is rejected rather than guessed.

def _cbor_fail(detail: str):
    raise ValueError(f"Invalid COSE public key format: {detail}")

def _cbor_read_head(buf: bytes, pos: int) -> Tuple[int, int, int]:
    """Return (major, value, next_pos)."""
    if pos + 1 > len(buf):
        _cbor_fail("truncated CBOR item")
    initial = buf[pos]
    major = initial >> 5
    info = initial & 0x1F
    nxt = pos + 1
    if info < 24:
        return major, info, nxt
    for bits, size in ((24, 1), (25, 2), (26, 4)):
        if info == bits:
            if nxt + size > len(buf):
                _cbor_fail("truncated CBOR item")
            return major, int.from_bytes(buf[nxt : nxt + size], "big"), nxt + size
    # 27 = 64-bit, 28-30 reserved, 31 = indefinite length. No COSE_Key needs any of them.
    _cbor_fail("unsupported CBOR length encoding")

def _cbor_decode_item(buf: bytes, pos: int) -> Tuple[Any, int]:
    major, value, pos = _cbor_read_head(buf, pos)
    if major == 0:  # unsigned int
        return value, pos
    if major == 1:  # negative int — COSE labels like -1 (crv), -2 (x), -3 (y)
        return -1 - value, pos
    if major in (2, 3):  # byte string / text string
        if pos + value > len(buf):
            _cbor_fail("truncated CBOR item")
        raw = buf[pos : pos + value]
        return (raw if major == 2 else raw.decode("utf-8")), pos + value
    if major == 4:  # array
        items = []
        cursor = pos
        for _ in range(value):
            item, cursor = _cbor_decode_item(buf, cursor)
            items.append(item)
        return items, cursor
    if major == 5:  # map
        out: Dict[Any, Any] = {}
        cursor = pos
        for _ in range(value):
            key, cursor = _cbor_decode_item(buf, cursor)
            val, cursor = _cbor_decode_item(buf, cursor)
            out[key] = val
        return out, cursor
    _cbor_fail(f"unsupported CBOR major type {major}")

def parse_cose_public_key(cose_bytes: bytes) -> Tuple[bytes, bytes]:
    """
    Extract the P-256 coordinates from a WebAuthn COSE_Key by WALKING the CBOR structure.

    The previous implementation scanned for the `0x21 0x58 0x20` / `0x22 0x58 0x20` byte patterns.
    That can match those bytes *inside* another field's payload, and it cannot tell whether the 32
    bytes it slices actually exist — a truncated buffer silently yielded a short coordinate. kty/crv
    are pinned too, so a key for another curve can never be reinterpreted as P-256.
    """
    # Decode only the leading item; trailing bytes are tolerated, as some wallets slice the COSE key
    # out of attestedCredentialData without trimming what follows it.
    value, _ = _cbor_decode_item(cose_bytes, 0)
    if not isinstance(value, dict):
        _cbor_fail("expected a CBOR map")

    kty = value.get(1)
    if kty != 2:
        _cbor_fail(f"expected kty EC2 (2), got {kty}")
    crv = value.get(-1)
    if crv != 1:
        _cbor_fail(f"expected crv P-256 (1), got {crv}")
    alg = value.get(3)
    if alg is not None and alg != -7:
        _cbor_fail(f"expected alg ES256 (-7), got {alg}")

    def coordinate(label: int, name: str) -> bytes:
        raw = value.get(label)
        if not isinstance(raw, bytes):
            _cbor_fail(f"missing {name} coordinate")
        if len(raw) != 32:
            _cbor_fail(f"{name} coordinate must be 32 bytes, got {len(raw)}")
        return raw

    return coordinate(-2, "x"), coordinate(-3, "y")

def _parse_rfc3339(ts: str):
    """Parse an RFC3339 timestamp to an aware datetime, or None. Accepts a trailing 'Z'."""
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        return None

def verify_approval_receipt(
    receipt: Dict[str, Any],
    expected: Dict[str, Any],
    allow_auto_approved: bool = False,
    expected_origin: str = None,
    expected_rp_id: str = None,
    require_user_verification: bool = True,
    allow_expired: bool = False,
    as_of: "datetime | None" = None,
    clock_skew_seconds: int = DEFAULT_CLOCK_SKEW_SECONDS,
) -> Dict[str, Any]:
    """
    Independently verify a DIV Proof Envelope. Returns {'ok': True} or {'ok': False, 'reason': ...}.

    `expected` MUST carry 'target' and 'nonce' — the relying party's own identifier (DIV Target
    Isolation) and the challenge you issued and are redeeming.

    WHAT THIS PROVES: a specific human key signed exactly this action, with exactly these params, for
    exactly this target and nonce, and the proof has not expired.

    Expiry (DIV §5.8/§6.2) is enforced fail-closed by default; pass allow_expired=True ONLY for
    post-hoc audit re-verification. WEBAUTHN receipts additionally require expected_origin and
    expected_rp_id — without them an assertion harvested at any relying party would verify.
    """
    canonical_payload = receipt.get("canonicalPayload", "")
    try:
        payload_data = json.loads(canonical_payload)
    except Exception:
        return {"ok": False, "reason": "malformed canonicalPayload"}
    if not isinstance(payload_data, dict):
        return {"ok": False, "reason": "malformed canonicalPayload"}
    nonce = payload_data.get("nonce", "")

    version = payload_data.get("v")
    if version != DIV_VERSION:
        shown = version if isinstance(version, int) and version else "unparseable"
        return {"ok": False, "reason": f"unsupported DIV payload version ({shown})"}
    if payload_data.get("type") != DIV_INTENT_TYPE:
        return {"ok": False, "reason": "payload is not a div-intent-verification"}

    # Bind the receipt to the challenge the caller is redeeming, before anything else.
    if nonce != expected.get("nonce"):
        return {"ok": False, "reason": "receipt is for a different challenge"}

    # Rebuild the expected payload (DIV Local Payload Reconstruction). target/actionType/params come
    # from what YOU are about to execute; display/requester/nonce/expiresAt are taken from the receipt
    # and MUST byte-match the signed bytes below, so trusting them for the rebuild is not circular.
    requester = receipt.get("requester")
    if not requester:
        return {"ok": False, "reason": "receipt missing requester"}
    expires_at = payload_data.get("expiresAt")
    if not isinstance(expires_at, str) or not expires_at:
        return {"ok": False, "reason": "receipt missing expiresAt"}
    recomputed = canonical_intent_payload(
        target=expected.get("target", ""),
        action_type=expected.get("actionType", ""),
        display=receipt.get("actionDescription", ""),
        params=expected.get("params", {}),
        requester=requester,
        nonce=nonce,
        expires_at=expires_at,
    )
    if recomputed != canonical_payload:
        return {"ok": False, "reason": "target/params/actionType do not match what was approved"}

    # Expiration (DIV §5.8/§6.2). Fail-closed by default; opt out only for audit re-verification.
    if not allow_expired:
        expiry = _parse_rfc3339(expires_at)
        if expiry is None:
            return {"ok": False, "reason": "expiresAt is not a valid RFC3339 timestamp"}
        now = as_of or datetime.now(timezone.utc)
        if now.timestamp() > expiry.timestamp() + clock_skew_seconds:
            return {"ok": False, "reason": "proof has expired (pass allow_expired=True for audit re-verification)"}

    # Optional: assert WHICH workload the approval was granted to.
    requester_did = expected.get("requesterDid")
    if requester_did is not None:
        actual_did = (receipt.get("requester") or {}).get("did")
        if actual_did != requester_did:
            return {"ok": False, "reason": "approval was requested by a different principal"}

    sig_alg = receipt.get("sigAlg")
    if sig_alg == "AUTO_APPROVED":
        if allow_auto_approved:
            return {"ok": True, "autoApproved": True}
        else:
            return {
                "ok": False,
                "autoApproved": True,
                "reason": "auto-approved by policy — no human signature to verify (pass allow_auto_approved=True to accept)"
            }

    signer_public_key = receipt.get("signerPublicKey")
    signature = receipt.get("signature")
    if not signer_public_key or not signature:
        return {"ok": False, "reason": "receipt missing signature material"}

    if sig_alg == "WEBAUTHN":
        authenticator_data = receipt.get("authenticatorData")
        client_data_json = receipt.get("clientDataJSON")
        if not authenticator_data or not client_data_json:
            return {"ok": False, "reason": "WebAuthn receipt missing authenticatorData or clientDataJSON"}
        # FAIL CLOSED: without an expected origin and RP ID there is nothing to pin the assertion to.
        if not expected_origin or not expected_rp_id:
            return {
                "ok": False,
                "reason": "WebAuthn receipts require expected_origin and expected_rp_id — without them "
                          "an assertion from any relying party would verify",
            }
        try:
            client_data_buf = base64_decode_flexible(client_data_json)
            client_data = json.loads(client_data_buf.decode("utf-8"))

            # An assertion, not a registration: webauthn.create signs a different ceremony over the
            # same challenge bytes and must never be accepted as approval.
            if client_data.get("type") != "webauthn.get":
                return {"ok": False, "reason": "clientDataJSON is not a webauthn.get assertion"}
            if client_data.get("origin") != expected_origin:
                return {"ok": False, "reason": "assertion origin does not match expected_origin"}

            expected_challenge = base64url_encode(canonical_payload.encode("utf-8"))
            client_challenge_clean = client_data.get("challenge", "").replace("=", "")
            if client_challenge_clean != expected_challenge:
                return {"ok": False, "reason": "clientDataJSON challenge does not match canonical payload"}

            # authenticatorData is signed but was previously never INSPECTED: it carries the RP ID the
            # credential answered for and whether the user was actually present/verified.
            auth_data_buf = base64_decode_flexible(authenticator_data)
            if len(auth_data_buf) < 37:
                return {"ok": False, "reason": "authenticatorData is too short"}
            rp_id_hash = hashlib.sha256(expected_rp_id.encode("utf-8")).digest()
            if not hmac.compare_digest(auth_data_buf[:32], rp_id_hash):
                return {"ok": False, "reason": "authenticatorData rpIdHash does not match expected_rp_id"}
            flags = auth_data_buf[32]
            if not flags & AUTH_DATA_FLAG_UP:
                return {"ok": False, "reason": "authenticatorData user-present flag is not set"}
            if require_user_verification and not flags & AUTH_DATA_FLAG_UV:
                return {"ok": False, "reason": "authenticatorData user-verified flag is not set"}

            cose_buf = base64_decode_flexible(signer_public_key)
            x_bytes, y_bytes = parse_cose_public_key(cose_buf)
            x_int = int.from_bytes(x_bytes, byteorder="big")
            y_int = int.from_bytes(y_bytes, byteorder="big")

            public_numbers = ec.EllipticCurvePublicNumbers(x_int, y_int, ec.SECP256R1())
            key_object = public_numbers.public_key()

            client_data_hash = hashlib.sha256(client_data_buf).digest()
            signature_verify_data = auth_data_buf + client_data_hash

            signature_buf = base64_decode_flexible(signature)

            key_object.verify(
                signature_buf,
                signature_verify_data,
                ec.ECDSA(hashes.SHA256())
            )
            return {"ok": True}
        except Exception as e:
            return {"ok": False, "reason": f"WebAuthn verification failed: {str(e)}"}
    else:
        if not verify_ecdsa_p256(signer_public_key, canonical_payload, signature):
            return {"ok": False, "reason": "signature does not verify against signer key"}
        return {"ok": True}

# ── Policy Crypto Namespace ───────────────────────────────────────────────────

