import base64
import functools
import hashlib
import hmac
import json
import math
import os
import re
import unicodedata
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Tuple, Optional

# DIV protocol constants (docs/DIV.md v1).
DIV_VERSION = 1
DIV_INTENT_TYPE = "div-intent-verification"
# Sealed break-glass: an approval signed ahead of time for a pre-declared emergency runbook and
# verified offline while the gateway is unreachable. The distinct type is INSIDE the signed bytes, so
# a sealed token can never verify as a normal approval, or the reverse. Mirrors @intyga/verify.
# Offline approval (DIV §5a.2): a normal quorum approval collected OUT OF BAND at incident time
# because the gateway is unreachable. The relying party builds the challenge itself, humans sign it on
# a disconnected device, and this verifier checks the result. The distinct type lives INSIDE the signed
# bytes, so an offline proof can never verify as a normal approval, or the reverse.
DIV_OFFLINE_INTENT_TYPE = "div-offline-intent"
# Delegation (DIV §5a.5): a pre-signed statement transferring the AUTHORITY TO APPROVE one
# pre-declared action to named local operators. It authorizes NOTHING on its own —
# verify_approval_receipt refuses this type outright, with no opt-in. Use verify_delegation.
DIV_DELEGATION_TYPE = "div-delegation"
DIV_AGENT_AUTHORITY_TYPE = "div-agent-authority"
DIV_PLATFORM_INTENT_TYPE = "div-platform-intent"
# Hard cap on an offline proof's validity window, enforced at verification and not only at mint. An
# offline relying party has no revocation channel, so the short window is the only bound (DIV §5a.3).
MAX_OFFLINE_WINDOW_MINUTES = 60
# Hard cap on a delegation's window (DIV §5a.6). Hours, not weeks: a delegation cannot be recalled
# from a relying party that is offline.
MAX_DELEGATION_WINDOW_HOURS = 72

#: Upper bound on witnesses in one receipt (mirrors MAX_WITNESSES in @intyga/verify).
#: Each witness costs an ECDSA verification, and the list is attacker-supplied: 20,000 of them
#: measured at ~1.5s of CPU and a 1.16 MB failure string, per request, from a JSON body. A real
#: quorum is single digits.
MAX_WITNESSES = 64

#: Failure reasons reported before truncating. An unbounded join over the witness list was itself
#: the memory half of the amplification.
MAX_REPORTED_FAILURES = 8


def _never_raises(fn):
    """Turn any escape from a verifier into a refusal.

    These functions are documented as returning {'ok': False, 'reason': ...}, and callers rely on
    that: an uncaught exception is not "invalid", it is a crash, and any caller that treats a
    traceback as anything other than a refusal fails open. Hostile receipts reached AttributeError,
    TypeError and RecursionError at several sites BEFORE any byte comparison — i.e.
    pre-authentication — because `requester` and `requirement` are read straight out of
    attacker-controlled JSON.

    The generic branch reports only the exception TYPE. Python prints locals in traceback frames, and
    those frames hold key material here; the type name is enough to debug with and carries nothing.
    """

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except NonCanonicalValue as exc:
            return {"ok": False, "reason": f"not canonicalizable: {exc}"}
        except RecursionError:
            return {"ok": False, "reason": "input is nested too deeply to canonicalize"}
        except Exception as exc:  # noqa: BLE001 - a verifier must not propagate
            return {"ok": False, "reason": f"malformed input ({type(exc).__name__})"}

    return wrapper
# RECOMMENDED expiry tolerance in seconds (DIV §6.2).
DEFAULT_CLOCK_SKEW_SECONDS = 30

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# WebAuthn authenticatorData flag bits (WebAuthn L3 §6.1).
AUTH_DATA_FLAG_UP = 0x01  # User Present
AUTH_DATA_FLAG_UV = 0x04  # User Verified
AUTH_DATA_FLAG_BE = 0x08  # Backup Eligible — the credential may be synced to other devices
AUTH_DATA_FLAG_BS = 0x10  # Backup State — the credential is currently backed up

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

class NonCanonicalValue(ValueError):
    """A value that cannot be canonicalized identically across every DIV port.

    Raised rather than coerced. `stable_stringify` used to fall through to `return "null"` for
    anything `json.dumps` refused, which silently collapsed distinct parameter sets to identical
    signed bytes: `Decimal("1.00")` and `Decimal("9999999.00")` both became `null`, so a relying
    party recomputing the payload accepted a receipt a human had approved for a different amount.
    Decimal and datetime are the idiomatic Python types for exactly the values an approval exists to
    bind, which is what made this reachable rather than theoretical.

    Callers verify with `expected` they own, so failing loudly here surfaces as a refusal, never as
    an accidental match. Mirrors `NonCanonicalValue` in @intyga/verify.
    """


def _check_portable_number(value: float) -> None:
    """Reject numbers whose JSON text differs between ports (DIV §4.1).

    Mirrors `isPortableNumber` in mcp-schemas: outside this range Python's repr and JavaScript's
    Number#toString diverge (`1e21` vs `1000000000000000000000`, `1e-7` vs `1e-07`), so the two
    would sign different bytes for the same value. A TS producer refuses these, and a Python signer
    that accepted them would mint bytes no other port could reproduce.
    """
    if isinstance(value, bool):
        return
    # NaN/Inf are float-only states, and the test must not be applied to an int: ``math.isnan`` first
    # converts to double, so an arbitrary-precision int above the double range raised OverflowError
    # out of the public signing APIs instead of the documented NonCanonicalValue refusal. The
    # magnitude comparison below is exact for any int, so it catches those without a conversion.
    if isinstance(value, float) and (math.isnan(value) or math.isinf(value)):
        raise NonCanonicalValue(f"{value!r} has no portable JSON representation")
    if isinstance(value, float) and value == 0.0 and math.copysign(1.0, value) < 0:
        raise NonCanonicalValue("-0 is not portable: JS serializes it as 0")
    magnitude = abs(value)
    if magnitude != 0 and (magnitude >= 1e16 or magnitude < 1e-4):
        raise NonCanonicalValue(
            f"{value!r} is outside the portable range (1e-4 .. 1e16); JS and Python disagree on its JSON text"
        )


def format_jcs_number(value: "int | float") -> str:
    """The JSON number text JS ``JSON.stringify`` would emit, for values in the portable range.

    Whole-valued floats fold to integer text (JS has ONE number type, so ``100.0`` IS ``100`` and
    serializes as ``"100"``); everything else takes Python's shortest-round-trip repr via
    ``json.dumps``, which agrees with JS inside the portable range (1e-4 <= |x| < 1e16).

    Callers that must GUARANTEE cross-port bytes call ``_check_portable_number`` first —
    ``stable_stringify`` does, because a signer must refuse rather than mint bytes no other port
    can reproduce. The ledger's ``_jcs`` deliberately does NOT: a verifier recomputing a leaf must
    fail-to-match on out-of-range input, never crash. Outside the portable range this text can
    diverge from JS (``1e-05`` vs ``0.00001``) — that divergence is the check's whole point.
    """
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return json.dumps(value)


_SURROGATE = re.compile("[\ud800-\udfff]")


def _canonical_string(s: str) -> str:
    """A string (value or member name) as RFC 8785 serializes it, refusing invalid Unicode.

    RFC 8785 builds on I-JSON (RFC 7493 §2.1), which forbids unpaired surrogates. ``json.loads``
    yields one from a ``\\udXXX`` escape, and ``json.dumps`` would emit it raw — bytes no UTF-8
    encoder can produce — so such a string is refused (DIV §4.1). In a Python ``str`` every
    surrogate code point is unpaired: a valid pair decodes to one astral character.
    """
    if not isinstance(s, str):
        raise NonCanonicalValue("object keys must be strings")
    if _SURROGATE.search(s):
        raise NonCanonicalValue("a string contains an unpaired UTF-16 surrogate, which is not I-JSON")
    return json.dumps(s, ensure_ascii=False)


def stable_stringify(value: Any) -> str:
    """Deterministic JSON stringification with UTF-16 code unit sorted keys."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        _check_portable_number(value)
        return format_jcs_number(value)
    if isinstance(value, str):
        return _canonical_string(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(stable_stringify(x) for x in value) + "]"
    if isinstance(value, dict):
        keys = sorted(value.keys(), key=lambda k: k.encode("utf-16-be", "surrogatepass"))
        parts = []
        for k in keys:
            k_str = _canonical_string(k)
            v_str = stable_stringify(value[k])
            parts.append(f"{k_str}:{v_str}")
        return "{" + ",".join(parts) + "}"
    # Anything left is not JSON, and guessing at it is how two different amounts became the same
    # signed bytes. Decimal, datetime, set, bytes and class instances all land here.
    raise NonCanonicalValue(
        f"{type(value).__name__} cannot be canonicalized; convert it to a JSON type "
        f"(str/int/float/bool/None/list/dict) before signing or verifying"
    )

def canonical_challenge_payload(nonce: str, action_description: str) -> str:
    """v1 canonical challenge payload (flat JSON, no nested sorting)."""
    nonce_json = json.dumps(nonce, ensure_ascii=False)
    action_json = json.dumps(action_description, ensure_ascii=False)
    return f'{{"v":1,"nonce":{nonce_json},"action":{action_json}}}'

def canonical_intent_payload(
    target: str,
    action_type: str,
    display: str,
    params: Dict[str, Any],
    requester: Dict[str, Any],
    requirement: Dict[str, Any],
    nonce: str,
    expires_at: str,
    agent_context: Optional[Dict[str, Any]] = None,
) -> str:
    """Canonical DIV Intent Payload (docs/DIV.md v1).

    Byte-identical to ``canonicalIntentPayload`` in @intyga/mcp-schemas, @intyga/verify and
    the Go/Rust ports. Strict RFC 8785 JCS: the WHOLE object is serialized via ``stable_stringify``,
    which sorts every key recursively by UTF-16 code unit — so, unlike the legacy builders, key order
    is NOT hand-templated. ``requester`` is ``{"did": str, "attestation": {...} | None}``; the null
    attestation is load-bearing and signed.

    ``requirement`` is the approval policy in force (quorum, four-eyes, hardware class), frozen at
    challenge creation. It is signed so the approver attests to the policy their signature is counted
    toward, and so a relying party can check the quorum offline instead of trusting the gateway for it.
    ``allowedAaguids`` is sorted here: the SET is the policy, and an unordered list would make two
    identical policies produce different signed bytes.
    """
    req, rq = _canonical_common(requester, requirement)
    payload = {
            "v": DIV_VERSION,
            "type": DIV_INTENT_TYPE,
            "target": target,
            "actionType": action_type,
            "display": display,
            "params": params,
            # DIV §4.3.4. Reserved and REQUIRED in the bytes; None states that no external-evidence
            # condition applied. A literal, never requirement.get("evidence") — a caller that omitted
            # it would then mint bytes no verifier reproduces, the same trap the signerClass default
            # below exists to avoid.
            "evidence": None,
            "requester": req,
            "requirement": rq,
            "nonce": nonce,
        }
    if agent_context is None:
        payload["expiresAt"] = expires_at
    else:
        payload.update({key: agent_context[key] for key in ("action", "agent", "session", "nbf")})
        payload["exp"] = expires_at
    return stable_stringify(payload)



def _canonical_common(
    requester: Dict[str, Any], requirement: Dict[str, Any]
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """The requester + requirement projection shared by all three canonical builders.

    One definition rather than three copies: these bytes are the contract, and a field added to one
    builder but not the others is exactly the drift the cross-language vectors exist to catch.
    ``allowedAaguids`` is sorted because the SET is the policy — an unordered list would make two
    identical policies produce different signed bytes.
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
    return (
        {"did": requester.get("did", ""), "attestation": attestation},
        {
            "requiredApprovals": requirement.get("requiredApprovals", 1),
            "requireHardwareKey": requirement.get("requireHardwareKey", False),
            # UTF-16 code units, not Python's native code-point order — the same key the object keys
            # use (line ~165). They differ only for non-BMP characters, which no AAGUID (hex UUID) or
            # DID carries today, but a set sorted one way here and another in the TS reference
            # produces different SIGNED BYTES, caught by nothing until a receipt fails. DIV §4.3.3.
            "allowedAaguids": sorted(
                requirement.get("allowedAaguids", []), key=lambda a: a.encode("utf-16-be")
            ),
            "requesterCannotApprove": requirement.get("requesterCannotApprove", False),
            # The required signer CLASS (DIV §4.3.2) — "human" is the only value defined today.
            # Defaulted to "" (never "human") so a caller that forgot the field produces bytes no
            # verifier accepts, rather than silently minting a human-class attestation.
            "signerClass": requirement.get("signerClass", ""),
        },
    )


def canonical_offline_intent_payload(
    target: str,
    action_type: str,
    display: str,
    params: Dict[str, Any],
    requester: Dict[str, Any],
    requirement: Dict[str, Any],
    nonce: str,
    challenged_at: str,
    expires_at: str,
) -> str:
    """Canonical OFFLINE APPROVAL payload (docs/DIV.md §5a.2).

    Byte-identical to ``canonicalOfflineIntentPayload`` in @intyga/verify and @intyga/mcp-schemas,
    pinned by ``offlineIntentPayloads`` in the committed vectors.

    Deliberately a separate function rather than a ``type`` argument on ``canonical_intent_payload``,
    so the ordinary approval path cannot accidentally emit an offline payload.

    ``challenged_at`` exists so a verifier can bound the validity WINDOW, not merely the expiry: a
    payload minted with an over-long ``expires_at`` is otherwise indistinguishable from a correct one.
    """
    req, rq = _canonical_common(requester, requirement)
    return stable_stringify(
        {
            "v": DIV_VERSION,
            "type": DIV_OFFLINE_INTENT_TYPE,
            "target": target,
            "actionType": action_type,
            "display": display,
            "params": params,
            # DIV §4.3.4. Reserved and REQUIRED in the bytes; None states that no external-evidence
            # condition applied. A literal, never requirement.get("evidence") — a caller that omitted
            # it would then mint bytes no verifier reproduces, the same trap the signerClass default
            # below exists to avoid.
            "evidence": None,
            "requester": req,
            "requirement": rq,
            "nonce": nonce,
            "challengedAt": challenged_at,
            "expiresAt": expires_at,
        }
    )


def canonical_delegation_payload(
    target: str,
    action_type: str,
    display: str,
    params: Dict[str, Any],
    requester: Dict[str, Any],
    requirement: Dict[str, Any],
    delegated_to: list,
    delegated_quorum: int,
    nonce: str,
    sealed_at: str,
    expires_at: str,
) -> str:
    """Canonical DELEGATION payload (docs/DIV.md §5a.5) — a signed statement about WHO MAY APPROVE,
    not about what may run.

    ``delegated_to`` is sorted because it is a SET, exactly as ``allowedAaguids`` is. ``requirement``
    describes the quorum that signed this delegation; ``delegated_quorum`` is how many of
    ``delegated_to`` must sign at incident time. Two different quorums, so both are in the signed bytes.
    """
    req, rq = _canonical_common(requester, requirement)
    return stable_stringify(
        {
            "v": DIV_VERSION,
            "type": DIV_DELEGATION_TYPE,
            "target": target,
            "actionType": action_type,
            "display": display,
            "params": params,
            "requester": req,
            "requirement": rq,
            "delegatedTo": sorted(delegated_to, key=lambda d: d.encode("utf-16-be")),
            "delegatedQuorum": delegated_quorum,
            "nonce": nonce,
            "sealedAt": sealed_at,
            "expiresAt": expires_at,
        }
    )


def canonical_agent_authority_payload(
    target: str, action_patterns: list, display: str, agent: Dict[str, Any],
    requester: Dict[str, Any], requirement: Dict[str, Any], nonce: str,
    sealed_at: str, expires_at: str, parent_receipt_hash: Optional[str] = None,
) -> str:
    """DIV §5b governance evidence; never an execution approval."""
    req, rq = _canonical_common(requester, requirement)
    return stable_stringify({
        "v": DIV_VERSION, "type": DIV_AGENT_AUTHORITY_TYPE, "target": target,
        "actionPatterns": sorted(action_patterns, key=lambda p: p.encode("utf-16-be")),
        "display": display, "agent": {"did": agent["did"]}, "parentReceiptHash": parent_receipt_hash, "requester": req,
        "requirement": rq, "nonce": nonce, "sealedAt": sealed_at, "expiresAt": expires_at,
    })


def canonical_platform_intent_payload(
    payload_hash: str, rp_id: str, subject_external_id: str, signed_at: str,
    expires_at: str, nonce: str,
) -> str:
    """Reproduce DIV §5c bytes; digest validation belongs to the verifier."""
    return stable_stringify({
        "v": DIV_VERSION, "type": DIV_PLATFORM_INTENT_TYPE, "hashAlg": "SHA-256",
        "payloadHash": payload_hash, "rpId": rp_id,
        "subject": {"externalId": subject_external_id}, "signedAt": signed_at,
        "expiresAt": expires_at, "nonce": nonce,
    })


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

# RFC 3339 §5.6 `date-time`, strictly: four-digit year, uppercase T and Z, seconds present, an
# optional 1-9 digit fraction and an explicit zone with offset hours 00-23, minutes 00-59.
_RFC3339 = re.compile(
    r"([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})(?:\.([0-9]{1,9}))?"
    r"(Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])\Z"
)


def _parse_rfc3339(ts: str):
    """Parse a signed RFC 3339 timestamp to an aware datetime, or None (DIV §6.2).

    One grammar in every port: the date must exist, hours 00-23, minutes and seconds 00-59 (no leap
    second). ``datetime.fromisoformat`` alone accepted a bare date (returning a NAIVE datetime), a
    zone-less time, a space separator and lowercase separators, where the Go port refused them.
    """
    if not isinstance(ts, str):
        return None
    m = _RFC3339.match(ts)
    if not m:
        return None
    try:
        base = datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        return None
    micros = int((m.group(2) or "0").ljust(9, "0")[:6])
    zone = m.group(3)
    if zone == "Z":
        tz = timezone.utc
    else:
        delta = timedelta(hours=int(zone[1:3]), minutes=int(zone[4:6]))
        tz = timezone(-delta if zone[0] == "-" else delta)
    return base.replace(microsecond=micros, tzinfo=tz)


_AGENT_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_AGENT_SEQUENCE = re.compile(r"[1-9][0-9]{0,17}\Z")
_AGENT_DECIMAL = re.compile(r"(?:0|[1-9][0-9]{0,29})(?:\.[0-9]{1,9})?\Z")
_AGENT_CURRENCY = re.compile(r"[A-Z]{3}\Z")
_AGENT_TIME = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z\Z")


def _validate_agent_context(context, exp, sig_alg):
    """Validate the PEP's independently supplied agent context before reconstructing bytes."""
    action = context.get("action")
    if not isinstance(action, dict) or action.get("reversibility") not in ("reversible", "irreversible"):
        return "invalid agent action reversibility"
    agent = context.get("agent")
    if not isinstance(agent, dict):
        return "invalid agent identity or configuration digest"
    label, config_digest = agent.get("label"), agent.get("configDigest")
    if not isinstance(label, str) or not label or len(label.encode("utf-16-le")) // 2 > 200 or not isinstance(config_digest, str) or not _AGENT_DIGEST.fullmatch(config_digest):
        return "invalid agent identity or configuration digest"
    session = context.get("session")
    if not isinstance(session, dict):
        return "invalid agent session identity or sequence"
    session_id = session.get("id")
    if unicodedata.normalize("NFC", label) != label or not isinstance(session_id, str) or unicodedata.normalize("NFC", session_id) != session_id:
        return "agent labels and session identifiers must be NFC"
    delegated_by = agent.get("delegatedBy")
    if "delegatedBy" not in agent or (delegated_by is not None and (not isinstance(delegated_by, str) or not _AGENT_DIGEST.fullmatch(delegated_by))):
        return "invalid parent authority digest"
    seq = session.get("seq")
    if not _AGENT_DIGEST.fullmatch(session_id) or not isinstance(seq, str) or not _AGENT_SEQUENCE.fullmatch(seq):
        return "invalid agent session identity or sequence"
    prev = session.get("prev")
    if "prev" not in session or (seq == "1") != (prev is None) or (prev is not None and (not isinstance(prev, str) or not _AGENT_DIGEST.fullmatch(prev))):
        return "invalid agent session predecessor"
    def valid_money(value):
        return isinstance(value, dict) and isinstance(value.get("amount"), str) and bool(_AGENT_DECIMAL.fullmatch(value["amount"])) and isinstance(value.get("currency"), str) and bool(_AGENT_CURRENCY.fullmatch(value["currency"]))
    amount, aggregate = action.get("amount"), session.get("aggregate")
    if "amount" not in action or "aggregate" not in session:
        return "invalid agent monetary amount"
    if (amount is not None and not valid_money(amount)) or (aggregate is not None and not valid_money(aggregate)):
        return "invalid agent monetary amount"
    if (amount is None) != (aggregate is None) or (amount is not None and amount["currency"] != aggregate["currency"]):
        return "agent monetary amount and aggregate disagree"
    nbf = context.get("nbf")
    if not isinstance(nbf, str) or not isinstance(exp, str) or not _AGENT_TIME.fullmatch(nbf) or not _AGENT_TIME.fullmatch(exp):
        return "agent intent must use canonical UTC times within five minutes"
    from_time, to_time = _parse_rfc3339(nbf), _parse_rfc3339(exp)
    if from_time is None or to_time is None or not from_time < to_time or (to_time - from_time).total_seconds() > 300:
        return "agent intent must use canonical UTC times within five minutes"
    if action["reversibility"] == "irreversible" and sig_alg == "AUTO_APPROVED":
        return "irreversible agent action requires a human signature"
    return None


#: The signer classes this verifier can reason about (DIV §4.3.2). "human" is the only class
#: defined today.
KNOWN_SIGNER_CLASSES = frozenset({"human"})


def _evidence_problem(payload_data: Dict[str, Any]) -> "str | None":
    """Validate the reserved ``evidence`` field out of the signed bytes (DIV §4.3.4).

    REQUIRED to be present and REQUIRED to be ``None`` in v1. A non-null value is an
    evidence-conditioned authorization whose semantics this verifier has not been taught, and must
    never verify as if it were unconditioned.

    Uses ``in`` for presence and an identity check for the value, never ``.get()``: ``.get()``
    returns ``None`` for an absent key AND for a present null, so it cannot express the distinction
    this check is made of. Collapsing the two turns the whole reservation into a no-op.
    """
    if "evidence" not in payload_data:
        return "the signed payload is missing evidence (DIV §4.3.4)"
    if payload_data["evidence"] is not None:
        return (
            "the signed payload declares an evidence condition, which this verifier does not "
            "support — refusing rather than treating it as unconditioned (DIV §4.3.4)"
        )
    return None


def _signer_class_problem(requirement: Dict[str, Any]) -> "str | None":
    """Validate ``requirement.signerClass`` out of the signed bytes (DIV §4.3.2).

    FAIL CLOSED both ways: an absent class predates (or dropped) the field, and an unrecognized
    class must never verify as if it were human-approved — that is the entire point of putting the
    class in the signed bytes.
    """
    signer_class = requirement.get("signerClass")
    if not isinstance(signer_class, str) or not signer_class:
        return "the signed requirement is missing signerClass (DIV §4.3.2)"
    if signer_class not in KNOWN_SIGNER_CLASSES:
        return (
            f'the signed requirement declares signerClass "{signer_class}", which this verifier '
            "does not recognize — refusing rather than treating it as human-approved (DIV §4.3.2)"
        )
    return None


INVALID_QUORUM_REASON = (
    "signed requirement.requiredApprovals must be an integer of at least 1 (DIV §4.3.2)"
)


def _quorum_problem(requirement: Dict[str, Any]) -> "str | None":
    """Enforce DIV §4.3.2: ``requiredApprovals`` is an integer ≥ 1.

    Stated as its own refusal rather than clamped, because §5 step 7 rejects unless the counted
    identities are AT LEAST this number — 0 is satisfied by counting nothing, so an unenforced
    minimum would attest an envelope carrying no valid witness signature. ``bool`` is excluded
    deliberately: in Python ``True`` is an ``int``, and a quorum of ``True`` is not a quorum of 1.
    """
    required = requirement.get("requiredApprovals")
    if not isinstance(required, int) or isinstance(required, bool) or required < 1:
        return INVALID_QUORUM_REASON
    return None


#: The reason stem every port uses for a signed requirement below the caller's floor.
WEAKER_REQUIREMENT_REASON = "signed requirement is weaker than the relying party's policy"


def _requirement_floor_problem(requirement: Dict[str, Any], expected: Any) -> "str | None":
    """DIV §5 step 3d: compare the SIGNED requirement against the relying party's own floor.

    The signed requirement is authored by whoever composed the bytes the approvers signed — the
    issuer, or any one approver composing their own payload — so its signature protects it against
    third parties but NOT against the signers the quorum constrains. Without a floor a verifier proves
    only the signers' OWN stated quorum: an approver who is also the requester can sign
    ``{"requiredApprovals": 1, "requesterCannotApprove": False}`` alone and it verifies.

    ``expected["requirement"]`` (optional, STRONGLY RECOMMENDED) is
    ``{"requiredApprovals": int >= 1, "requesterCannotApprove": bool, "requireHardwareKey": bool}``
    (both flags default False). Only strictly weaker signed values are refused. Absent means "no
    floor" (legacy behaviour); a malformed floor fails CLOSED rather than silently meaning "no floor".
    """
    floor = expected.get("requirement") if isinstance(expected, dict) else None
    if floor is None:
        return None
    required = floor.get("requiredApprovals") if isinstance(floor, dict) else None
    flags = [floor.get(k, False) for k in ("requesterCannotApprove", "requireHardwareKey")] if isinstance(floor, dict) else []
    if (
        not isinstance(required, int) or isinstance(required, bool) or required < 1
        or not all(isinstance(f, bool) for f in flags)
    ):
        return ("expected.requirement is malformed: requiredApprovals must be an integer of at least 1 "
                "and the flags booleans")
    signed = requirement.get("requiredApprovals")
    if signed < required:
        return (f"{WEAKER_REQUIREMENT_REASON}: it requires {signed} approval(s), the policy {required} "
                "(DIV §5 step 3d)")
    if floor.get("requesterCannotApprove") is True and requirement.get("requesterCannotApprove") is not True:
        return f"{WEAKER_REQUIREMENT_REASON}: it does not forbid the requester approving (DIV §5 step 3d)"
    if floor.get("requireHardwareKey") is True and requirement.get("requireHardwareKey") is not True:
        return f"{WEAKER_REQUIREMENT_REASON}: it does not require a hardware key (DIV §5 step 3d)"
    return None


def _binding_fields_problem(expected: Dict[str, Any], artifact: str) -> "str | None":
    """Require the caller to state ``actionType`` and ``params`` (DIV §4.4.1).

    Together with ``target`` these are the security-binding fields, which "MUST come exclusively
    from the Relying Party's own runtime during reconstruction". Defaulting an ABSENT key to
    ``""``/``{}`` — which this did — rebuilt a payload bound to nothing, so a receipt minted with
    those same empty values verified against an expectation that never named the action. The TS
    reference cannot reach that state: ``stableStringify(undefined)`` throws and the rebuild is
    refused. An explicitly written ``""``/``{}`` is still accepted; only omission is refused.
    """
    for key, label in (("actionType", "the action being executed"), ("params", "its parameters")):
        if key not in expected:
            return (
                f"expected['{key}'] is required — {label} MUST come from YOUR runtime, not from the "
                f"{artifact} (DIV §4.4.1); pass it explicitly even when it is empty"
            )
    return None


def _backup_flags_problem(witness: Dict[str, Any]) -> Optional[str]:
    """Under a signed ``requireHardwareKey``, a WEBAUTHN witness whose authenticatorData carries the
    Backup Eligible or Backup State flag cannot count (DIV §4.4.5 rule 6). The flags are covered by
    the assertion signature, so a relying party can catch an issuer that let a synced passkey sign a
    hardware-pinned action. BE=0 is the authenticator's own claim, not attestation. Called only for a
    witness that already verified, so authenticatorData decodes to at least 37 bytes."""
    if witness.get("sigAlg") != "WEBAUTHN":
        return None
    try:
        auth_data = base64_decode_flexible(witness.get("authenticatorData") or "")
    except Exception:
        return "authenticatorData is unreadable"
    if len(auth_data) < 37:
        return "authenticatorData is unreadable"
    if not auth_data[32] & (AUTH_DATA_FLAG_BE | AUTH_DATA_FLAG_BS):
        return None
    return (
        f"signer {witness.get('signerDid')} used a backup-eligible (synced) passkey — authenticatorData "
        "BE/BS flag set — but the signed policy requires a hardware-backed WebAuthn credential"
    )


def requires_hardware_credential(requirement: Dict[str, Any]) -> bool:
    """A signed requirement only a hardware-backed WebAuthn credential can meet: ``requireHardwareKey``
    or a non-empty ``allowedAaguids`` model allowlist. A bare key satisfies neither and neither can be
    met offline (DIV §4.3.2), so every check treats them alike."""
    aaguids = requirement.get("allowedAaguids") if isinstance(requirement, dict) else None
    return bool(isinstance(requirement, dict) and (
        requirement.get("requireHardwareKey") is True or (isinstance(aaguids, list) and len(aaguids) > 0)))


@_never_raises
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
    allow_cross_origin: bool = False,
    allow_offline: bool = False,
    delegation: "Dict[str, Any] | None" = None,
) -> Dict[str, Any]:
    """
    Independently verify a DIV Proof Envelope. Returns {'ok': True} or {'ok': False, 'reason': ...}.

    `expected` MUST carry 'target', 'nonce' and 'approvers' — the relying party's own identifier
    (DIV Target Isolation), the challenge you issued and are redeeming, and the approver keys you
    trust.

    THE TRUST ANCHOR IS NOT OPTIONAL. `expected['approvers']` is either
    ``{"publicKeys": [b64, ...]}`` or ``{"dids": [...], "resolveKey": callable}``. Verification uses
    the key YOU resolve, never ``receipt['signerPublicKey']``: a receipt checked against its own
    embedded key proves only internal consistency, and per the DIV threat model anyone who can hand
    you a receipt (including the untrusted agent) could have minted that keypair themselves.

    WHAT THIS PROVES: enough approvers you already trust signed exactly this action, with exactly
    these params, for exactly this target and nonce; the number of distinct valid signatures meets the
    quorum recorded in the signed payload; the requester did not self-approve when the signed policy
    forbids it; and the proof has not expired.

    THE SIGNED QUORUM IS THE SIGNERS' OWN STATEMENT. One approver (possibly the requester) can sign a
    1-of-1 payload alone. Pass ``expected["requirement"]`` — your own rule, e.g.
    ``{"requiredApprovals": 3, "requesterCannotApprove": True}`` — and a weaker signed requirement is
    refused (DIV §5 step 3d). Without it, "quorum met" means only "the quorum the signers stated".
    Under a delegation pass the ORDINARY rule; the delegated quorum must already be at least as strict.

    Expiry (DIV §5.8/§6.2) is enforced fail-closed by default; pass allow_expired=True ONLY for
    post-hoc audit re-verification. WEBAUTHN receipts additionally require expected_origin and
    expected_rp_id — without them an assertion harvested at any relying party would verify.

    OFFLINE APPROVALS (DIV §5a.3) are refused unless ``allow_offline=True``, exactly like
    AUTO_APPROVED ones. Pass it at the SPECIFIC call permitted to run under one, never globally: a
    process-wide default would make every gated action accept an out-of-band approval. It weakens
    nothing else — the quorum, four-eyes and target binding are still enforced, the window is capped at
    MAX_OFFLINE_WINDOW_MINUTES, and a proof whose signed policy demands a hardware key is REFUSED
    because that cannot be satisfied offline.

    ``delegation`` is a delegation ALREADY verified by :func:`verify_delegation`, substituting the
    eligible approver set and quorum for this one verification (DIV §5a.6). It narrows, never widens.
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
    payload_type = payload_data.get("type")
    # A DELEGATION authorizes nothing (DIV §5a.5). Refused here unconditionally — there is deliberately
    # NO option that would let one through, because a delegation that could authorize its own action
    # would be exactly the pre-signed bearer capability the design exists to avoid.
    if payload_type == DIV_DELEGATION_TYPE:
        return {
            "ok": False,
            "reason": "this is a delegation, which authorizes no action on its own — verify it with "
                      "verify_delegation and pass the result as delegation=, together with an offline "
                      "approval signed by the delegated operators",
        }
    offline = payload_type == DIV_OFFLINE_INTENT_TYPE
    if not offline and payload_type != DIV_INTENT_TYPE:
        return {"ok": False, "reason": "payload is not a div-intent-verification"}
    if offline and not allow_offline:
        return {
            "ok": False,
            "reason": "this is an offline approval; pass allow_offline=True at the specific call site "
                      "permitted to run under one",
        }
    # A delegation only ever substitutes the approver set for an OFFLINE proof. Accepting it against an
    # ordinary gateway-mediated receipt would silently replace the quorum the gateway enforced.
    if delegation is not None and not offline:
        return {"ok": False, "reason": "a delegation can only substitute the approver set for an offline approval"}

    # FAIL CLOSED on a missing target or nonce, mirroring verify_delegation and the TS reference:
    # every caller of this package is untyped, and defaulting to the receipt's OWN values would have
    # the receipt vouch for its own scope (DIV Target Isolation) or its own challenge (DIV §5 — a
    # stateless verifier MUST require the caller to name the nonce being redeemed).
    if not expected.get("target"):
        return {
            "ok": False,
            "reason": "expected['target'] is required — it must be YOUR target identifier, asserted "
                      "independently of the receipt (DIV Target Isolation)",
        }
    if not isinstance(expected.get("nonce"), str) or not expected["nonce"]:
        return {
            "ok": False,
            "reason": "expected['nonce'] is required — the caller MUST name the challenge being "
                      "redeemed (DIV §5); a receipt cannot vouch for its own nonce",
        }
    binding_problem = _binding_fields_problem(expected, "receipt")
    if binding_problem:
        return {"ok": False, "reason": binding_problem}

    # Bind the receipt to the challenge the caller is redeeming, before anything else.
    if nonce != expected.get("nonce"):
        return {"ok": False, "reason": "receipt is for a different challenge"}

    # Rebuild the expected payload (DIV Local Payload Reconstruction). target/actionType/params come
    # from what YOU are about to execute; display/requester/nonce/expiresAt are taken from the receipt
    # and MUST byte-match the signed bytes below, so trusting them for the rebuild is not circular.
    requester = receipt.get("requester")
    if not requester:
        return {"ok": False, "reason": "receipt missing requester"}
    approvers = expected.get("approvers")
    if not isinstance(approvers, dict) or not (approvers.get("publicKeys") or approvers.get("dids")):
        return {
            "ok": False,
            "reason": "expected['approvers'] is required — the Approver key MUST come from your own "
                      "trust policy, never from the receipt (DIV Invariant 3)",
        }
    agent_intent = "agent" in payload_data
    agent_context = expected.get("agentContext")
    if agent_intent and not isinstance(agent_context, dict):
        return {"ok": False, "reason": "agent receipt requires independently asserted PEP context"}
    if not agent_intent and agent_context is not None:
        return {"ok": False, "reason": "agent context was expected but is absent from the signed payload"}
    expires_at = payload_data.get("exp" if agent_intent else "expiresAt")
    if not isinstance(expires_at, str) or not expires_at:
        return {"ok": False, "reason": "receipt missing expiration"}
    if agent_intent:
        context_problem = _validate_agent_context(agent_context, expires_at, receipt.get("sigAlg"))
        if context_problem:
            return {"ok": False, "reason": "invalid independently asserted agent context: " + context_problem}
        agent = agent_context.get("agent")
        if isinstance(agent, dict) and agent.get("delegatedBy") is not None:
            return {"ok": False, "reason": "delegated agent receipt requires a trusted root-to-leaf authority chain"}
        nbf = _parse_rfc3339(agent_context.get("nbf"))
        expiry = _parse_rfc3339(expires_at)
        now = as_of or datetime.now(timezone.utc)
        if nbf.timestamp() > now.timestamp() + clock_skew_seconds:
            return {"ok": False, "reason": "agent approval is not valid yet"}
    # The requirement is part of the SIGNED bytes, so a third party cannot alter it: a forged value
    # changes the string and fails the byte comparison below. It does NOT bind the signers themselves
    # — they authored it — which is why step 3d compares it against expected["requirement"].
    requirement = payload_data.get("requirement")
    if not isinstance(requirement, dict) or not isinstance(requirement.get("requiredApprovals"), int):
        return {"ok": False, "reason": "receipt payload is missing the signed approval requirement"}
    quorum_problem = _quorum_problem(requirement)
    if quorum_problem:
        return {"ok": False, "reason": quorum_problem}
    signer_class_problem = _signer_class_problem(requirement)
    if signer_class_problem:
        return {"ok": False, "reason": signer_class_problem}
    floor_problem = _requirement_floor_problem(requirement, expected)
    if floor_problem:
        return {"ok": False, "reason": floor_problem}
    # DIV §5-step-3c. Before Local Payload Reconstruction, so an unsupported payload shape does not
    # surface as a params mismatch.
    evidence_problem = _evidence_problem(payload_data)
    if evidence_problem:
        return {"ok": False, "reason": evidence_problem}
    # Offline proofs carry challengedAt so the validity WINDOW can be bounded here, not merely at mint.
    challenged_at = ""
    if offline:
        challenged_at = payload_data.get("challengedAt")
        if not isinstance(challenged_at, str) or not challenged_at:
            return {"ok": False, "reason": "offline proof is missing challengedAt"}
        challenged = _parse_rfc3339(challenged_at)
        if challenged is None:
            return {"ok": False, "reason": "challengedAt is not a valid RFC3339 timestamp"}
        # An unparseable expiresAt must be refused HERE rather than skipping the window cap and
        # relying on the expiry check further down — that check is disabled by allow_expired, so the
        # allow_offline + allow_expired combination (the documented forensic re-verification mode,
        # and the only mode under which an offline proof is examined at all) left the cap unenforced
        # on a proof whose window could not be computed at all.
        #
        # expiresAt is inside the signed bytes, but an offline proof is minted by whoever constructs
        # it and the verifier reconstructs the payload from the receipt's OWN expiresAt, so any
        # string round-trips. Measured before this fix: the ES5 extended-year form
        # "+002036-01-01T00:00:00.000Z" — which Date.parse accepts and datetime.fromisoformat does
        # not — passed a 10-year window against a 60-minute cap. DIV §5a.3 makes the window the
        # entire revocation story for an offline proof (an offline relying party has no channel to
        # recall one), so an unbounded window turns a 60-minute incident credential into a permanent
        # bearer capability.
        expiry_probe = _parse_rfc3339(expires_at)
        if expiry_probe is None:
            return {"ok": False, "reason": "expiresAt is not a valid RFC3339 timestamp"}
        window_minutes = (expiry_probe.timestamp() - challenged.timestamp()) / 60.0
        if window_minutes < 0:
            return {"ok": False, "reason": "offline proof expires before it was challenged"}
        if window_minutes > MAX_OFFLINE_WINDOW_MINUTES:
            return {
                "ok": False,
                "reason": f"offline window is {window_minutes:.1f} minutes, over the "
                          f"{MAX_OFFLINE_WINDOW_MINUTES}-minute maximum",
            }
        # The cap above bounds the window's WIDTH; this bounds its POSITION (DIV §5a.3 rule 3).
        # Without it a proof challenged for a date years out, with a compliant 60-minute window,
        # verifies today and keeps verifying until that date — the pre-signed bearer capability
        # §5a.1 rejects. NOT gated on allow_expired: that override re-examines a proof that WAS
        # valid and has lapsed, and says nothing about one dated in the future.
        now = as_of or datetime.now(timezone.utc)
        if challenged.timestamp() > now.timestamp() + clock_skew_seconds:
            return {"ok": False, "reason": "offline proof is challenged in the future (DIV §5a.3)"}
        # A hardware-key policy CANNOT be satisfied offline (DIV §5a.3 step 4). WebAuthn needs a secure
        # context and an RP ID an offline signing surface will not match, so an offline witness is
        # always a bare key. Accepting the proof anyway would silently downgrade the policy the approver
        # attested to, so it is refused instead — fail closed, and say why. A non-empty
        # authenticator-model allowlist is the same class of policy: a bare key has no model at all.
        if requires_hardware_credential(requirement):
            return {
                "ok": False,
                "reason": "the signed policy requires a hardware-backed WebAuthn credential, which "
                          "cannot be produced offline — this action cannot be approved out of band "
                          "(DIV §5a.3)",
            }

    # A delegation substitutes WHO may approve and HOW MANY, and nothing else (DIV §5a.6). Every
    # agreement check is on the SIGNED bytes of both proofs, so neither can widen the other.
    delegated_to = None
    delegated_quorum = None
    if delegation is not None:
        delegation_expiry = _parse_rfc3339(delegation.get("expiresAt"))
        if delegation_expiry is None:
            return {"ok": False, "reason": "delegation expiresAt is not a valid RFC3339 timestamp"}
        if not allow_expired:
            now = as_of or datetime.now(timezone.utc)
            if now.timestamp() > delegation_expiry.timestamp() + clock_skew_seconds:
                return {
                    "ok": False,
                    "reason": "delegation has expired (pass allow_expired=True for audit re-verification)",
                }
        if delegation.get("target") != expected.get("target"):
            return {"ok": False, "reason": "the delegation was issued for a different target"}
        if delegation.get("actionType") != expected.get("actionType"):
            return {"ok": False, "reason": "the delegation was issued for a different actionType"}
        if stable_stringify(delegation.get("params", {})) != stable_stringify(expected.get("params", {})):
            return {"ok": False, "reason": "the delegation was issued for different params"}
        # The offline payload's signed quorum must equal the delegated one, so the operators signed the
        # policy their signatures are being counted toward rather than a different one.
        if requirement.get("requiredApprovals") != delegation.get("delegatedQuorum"):
            return {
                "ok": False,
                "reason": f"offline proof declares {requirement.get('requiredApprovals')} required "
                          f"approval(s) but the delegation delegates a quorum of "
                          f"{delegation.get('delegatedQuorum')}",
            }
        delegated_to = list(delegation.get("delegatedTo") or [])
        delegated_quorum = delegation.get("delegatedQuorum")

    if offline:
        recomputed = canonical_offline_intent_payload(
            target=expected.get("target", ""),
            action_type=expected.get("actionType", ""),
            display=receipt.get("actionDescription", ""),
            params=expected.get("params", {}),
            requester=requester,
            requirement=requirement,
            nonce=nonce,
            challenged_at=challenged_at,
            expires_at=expires_at,
        )
    else:
        recomputed = canonical_intent_payload(
            target=expected.get("target", ""),
            action_type=expected.get("actionType", ""),
            display=receipt.get("actionDescription", ""),
            params=expected.get("params", {}),
            requester=requester,
            requirement=requirement,
            nonce=nonce,
            expires_at=expires_at,
            agent_context=agent_context if agent_intent else None,
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
    if sig_alg == "AUTO_APPROVED" and offline:
        # An offline approval with no human signature is a contradiction: the entire premise is that
        # humans signed out of band, so allow_auto_approved must not rescue it.
        return {
            "ok": False,
            "autoApproved": True,
            "reason": "an offline approval cannot be auto-approved — there is no human signature to verify",
        }
    if sig_alg == "AUTO_APPROVED":
        if allow_auto_approved:
            return {"ok": True, "autoApproved": True}
        else:
            return {
                "ok": False,
                "autoApproved": True,
                "reason": "auto-approved by policy — no human signature to verify (pass allow_auto_approved=True to accept)"
            }

    witnesses = _witnesses_of(receipt)
    if not witnesses:
        return {"ok": False, "reason": "receipt missing signature material"}
    if len(witnesses) > MAX_WITNESSES:
        # Refuse before spending an ECDSA verification per entry. A genuine quorum is single digits.
        return {
            "ok": False,
            "reason": f"receipt carries {len(witnesses)} witnesses, above the maximum of {MAX_WITNESSES}",
        }

    # Count DISTINCT approvers whose signature verifies under a key we independently trust. Distinct
    # is load-bearing: without it, N copies of one approver's signature would satisfy an N-of-M quorum.
    if requirement["requiredApprovals"] > 1 and approvers.get("publicKeys"):
        return {"ok": False, "reason": "multi-approver quorum requires a DID-mode trust anchor (DIV §5 step 3b)"}
    if requirement.get("requesterCannotApprove") is True and approvers.get("publicKeys"):
        return {"ok": False, "reason": "requesterCannotApprove requires a DID-mode trust anchor"}
    verified_signers = set()
    counted_keys: Dict[bytes, str] = {}
    failures = []
    for witness in witnesses:
        candidates, reason = _candidate_keys(approvers, witness, delegated_to)
        if reason is not None:
            failures.append(reason)
            continue
        matched = None
        matched_key = None
        last_reason = "signature does not verify against any trusted approver key"
        for key, identity in candidates:
            ok, why = _verify_witness(
                witness, key, canonical_payload,
                expected_origin, expected_rp_id, require_user_verification, allow_cross_origin,
            )
            if ok:
                matched = identity
                matched_key = key
                break
            last_reason = why
        if matched is None:
            failures.append(last_reason)
            continue
        # A hardware-key policy is only partially checkable offline: a bare P-256 key carries no
        # attestation at all, so it can never satisfy the requirement, while a WebAuthn assertion is
        # accepted without proving the authenticator's model.
        if requires_hardware_credential(requirement) and witness.get("sigAlg") != "WEBAUTHN":
            failures.append(
                f"signer {witness.get('signerDid')} used a bare key, but the signed policy requires "
                "a hardware-backed WebAuthn credential"
            )
            continue
        if requirement.get("requireHardwareKey") is True:
            synced = _backup_flags_problem(witness)
            if synced:
                failures.append(synced)
                continue
        # Four-eyes, verified offline against the requester in the same signed payload.
        if requirement.get("requesterCannotApprove") is True and witness.get("signerDid") == requester.get("did"):
            failures.append(f"four-eyes: requester {witness.get('signerDid')} cannot approve their own action")
            continue
        shared = _shared_key_problem(counted_keys, matched_key, matched)
        if shared:
            failures.append(shared)
            continue
        verified_signers.add(matched)

    # Under a delegation the quorum is the DELEGATED one. Already checked to equal the offline payload's
    # signed requiredApprovals, so this is the same number by a different route — stated explicitly so
    # the substitution is visible where it takes effect.
    # Both numbers were refused above unless they are integers ≥ 1, so no floor is applied here.
    required = int(delegated_quorum if delegated_quorum is not None else requirement["requiredApprovals"])
    if len(verified_signers) < required:
        shown = failures[:MAX_REPORTED_FAILURES]
        if len(failures) > MAX_REPORTED_FAILURES:
            shown = shown + [f"+{len(failures) - MAX_REPORTED_FAILURES} more"]
        detail = f" ({'; '.join(shown)})" if shown else ""
        return {
            "ok": False,
            "reason": f"quorum not met: {len(verified_signers)} of {required} required approver signatures verified{detail}",
        }
    return {"ok": True, "signers": sorted(verified_signers)}


@_never_raises
def verify_delegation(
    receipt: Dict[str, Any],
    expected: Dict[str, Any],
    allow_expired: bool = False,
    as_of: "datetime | None" = None,
    clock_skew_seconds: int = DEFAULT_CLOCK_SKEW_SECONDS,
    expected_origin: str = None,
    expected_rp_id: str = None,
    require_user_verification: bool = True,
    allow_cross_origin: bool = False,
) -> Dict[str, Any]:
    """Verify a DELEGATION (docs/DIV.md §5a.6 step 1).

    A delegation is a statement, signed in advance by the ordinary quorum, naming local operators who
    may approve one pre-declared action while the gateway is unreachable.

    Deliberately a SEPARATE function from :func:`verify_approval_receipt`, which refuses this payload
    type outright. A delegation authorizes nothing, and the only way to keep that true structurally is
    to make it impossible to hand one to the approval verifier and get ``ok: True`` back. What you get
    here is a dict to pass as ``delegation=`` to a later approval check — an input, never a substitute.

    ``expected['approvers']`` MUST be the ORDINARY approver set, not the delegated operators: the point
    of the check is that the people entitled to approve this action are the ones who signed away that
    entitlement.
    """
    canonical_payload = receipt.get("canonicalPayload", "")
    try:
        payload_data = json.loads(canonical_payload)
    except Exception:
        return {"ok": False, "reason": "malformed canonicalPayload"}
    if not isinstance(payload_data, dict):
        return {"ok": False, "reason": "malformed canonicalPayload"}
    if payload_data.get("v") != DIV_VERSION:
        return {"ok": False, "reason": "unsupported DIV payload version"}
    if payload_data.get("type") != DIV_DELEGATION_TYPE:
        return {"ok": False, "reason": "payload is not a div-delegation"}

    # DIV §4.4.6: a Delegation REQUIRES an identity-associating anchor and MUST be refused under a
    # key-set anchor — at seal verification too, not only when delegatedTo is enforced at use time.
    # The sealing quorum names PEOPLE; in publicKeys mode it would count credentials instead.
    # Checked HERE, before any payload field, so this port refuses in the same ORDER as the TS
    # reference: a caller misconfiguring its anchor must hear about that, not about the artifact.
    if isinstance(expected.get("approvers"), dict) and expected["approvers"].get("publicKeys"):
        return {
            "ok": False,
            "reason": "a delegation requires a DID-mode trust anchor ({'dids': [...], 'resolveKey': ...}); "
                      "a key-set anchor cannot associate identities (DIV §4.4.6)",
        }

    delegated_to = payload_data.get("delegatedTo")
    if not isinstance(delegated_to, list) or not delegated_to or not all(
        isinstance(d, str) and d for d in delegated_to
    ):
        return {"ok": False, "reason": "delegation is missing a valid delegatedTo set"}
    delegated_quorum = payload_data.get("delegatedQuorum")
    if not isinstance(delegated_quorum, int) or isinstance(delegated_quorum, bool) or delegated_quorum < 1:
        return {"ok": False, "reason": "delegation is missing a valid delegatedQuorum"}
    # Deduplicate before the size check: a delegatedTo listing one operator three times would otherwise
    # appear to support a 3-of-3 quorum that one person could satisfy alone.
    distinct = list(dict.fromkeys(delegated_to))
    if len(distinct) < delegated_quorum:
        return {
            "ok": False,
            "reason": f"delegation names {len(distinct)} distinct operator(s) but delegates a quorum of "
                      f"{delegated_quorum} — it can never be satisfied",
        }

    sealed_at = payload_data.get("sealedAt")
    expires_at = payload_data.get("expiresAt")
    if not isinstance(sealed_at, str) or not sealed_at:
        return {"ok": False, "reason": "delegation is missing sealedAt"}
    if not isinstance(expires_at, str) or not expires_at:
        return {"ok": False, "reason": "delegation is missing expiresAt"}
    sealed = _parse_rfc3339(sealed_at)
    expiry = _parse_rfc3339(expires_at)
    if sealed is None:
        return {"ok": False, "reason": "sealedAt is not a valid RFC3339 timestamp"}
    if expiry is None:
        return {"ok": False, "reason": "expiresAt is not a valid RFC3339 timestamp"}
    window_hours = (expiry.timestamp() - sealed.timestamp()) / 3600.0
    if window_hours < 0:
        return {"ok": False, "reason": "delegation expires before it was sealed"}
    if window_hours > MAX_DELEGATION_WINDOW_HOURS:
        return {
            "ok": False,
            "reason": f"delegation window is {window_hours:.1f} hours, over the "
                      f"{MAX_DELEGATION_WINDOW_HOURS}-hour maximum",
        }
    # Position, not just width (DIV §5a.6 step 1, mirroring §5a.3 rule 3). A forward-dated sealedAt
    # slides the 72-hour window arbitrarily far out, and §5a.8 names that cap as Delegation's ONLY
    # mitigation. Unconditional, like the offline mirror: allow_expired does not reach it.
    now = as_of or datetime.now(timezone.utc)
    if sealed.timestamp() > now.timestamp() + clock_skew_seconds:
        return {"ok": False, "reason": "delegation is sealed in the future (DIV §5a.6)"}

    requester = receipt.get("requester")
    if not requester:
        return {"ok": False, "reason": "delegation missing requester"}
    requirement = payload_data.get("requirement")
    if not isinstance(requirement, dict) or not isinstance(requirement.get("requiredApprovals"), int):
        return {"ok": False, "reason": "delegation payload is missing the signed approval requirement"}
    quorum_problem = _quorum_problem(requirement)
    if quorum_problem:
        return {"ok": False, "reason": quorum_problem}
    signer_class_problem = _signer_class_problem(requirement)
    if signer_class_problem:
        return {"ok": False, "reason": signer_class_problem}
    floor_problem = _requirement_floor_problem(requirement, expected)
    if floor_problem:
        return {"ok": False, "reason": floor_problem}
    approvers = expected.get("approvers")
    if not isinstance(approvers, dict) or not (approvers.get("publicKeys") or approvers.get("dids")):
        return {
            "ok": False,
            "reason": "expected['approvers'] is required — the delegating approvers MUST come from your "
                      "own trust policy, never from the delegation (DIV Invariant 3)",
        }
    if not expected.get("target"):
        return {
            "ok": False,
            "reason": "expected['target'] is required — it must be YOUR target identifier, asserted "
                      "independently of the delegation (DIV Target Isolation)",
        }
    binding_problem = _binding_fields_problem(expected, "delegation")
    if binding_problem:
        return {"ok": False, "reason": binding_problem}

    nonce = payload_data.get("nonce", "")
    recomputed = canonical_delegation_payload(
        target=expected.get("target", ""),
        action_type=expected.get("actionType", ""),
        display=receipt.get("actionDescription", ""),
        params=expected.get("params", {}),
        requester=requester,
        requirement=requirement,
        delegated_to=delegated_to,
        delegated_quorum=delegated_quorum,
        nonce=nonce,
        sealed_at=sealed_at,
        expires_at=expires_at,
    )
    if recomputed != canonical_payload:
        return {"ok": False, "reason": "target/params/actionType do not match what was delegated"}

    if not allow_expired:
        if now.timestamp() > expiry.timestamp() + clock_skew_seconds:
            return {"ok": False, "reason": "delegation has expired (pass allow_expired=True for audit re-verification)"}

    if receipt.get("sigAlg") == "AUTO_APPROVED":
        return {
            "ok": False,
            "reason": "a delegation cannot be auto-approved — delegating approval authority requires "
                      "human signatures",
        }

    witnesses = _witnesses_of(receipt)
    if not witnesses:
        return {"ok": False, "reason": "delegation missing signature material"}
    if len(witnesses) > MAX_WITNESSES:
        # Refuse before spending an ECDSA verification per entry. A genuine quorum is single digits.
        return {
            "ok": False,
            "reason": f"delegation carries {len(witnesses)} witnesses, above the maximum of {MAX_WITNESSES}",
        }

    if requirement["requiredApprovals"] > 1 and approvers.get("publicKeys"):
        return {"ok": False, "reason": "multi-approver quorum requires a DID-mode trust anchor (DIV §5 step 3b)"}
    if requirement.get("requesterCannotApprove") is True and approvers.get("publicKeys"):
        return {"ok": False, "reason": "requesterCannotApprove requires a DID-mode trust anchor"}
    verified_signers = set()
    counted_keys: Dict[bytes, str] = {}
    failures = []
    for witness in witnesses:
        candidates, reason = _candidate_keys(approvers, witness)
        if reason is not None:
            failures.append(reason)
            continue
        matched = None
        matched_key = None
        last_reason = "signature does not verify against any trusted approver key"
        for key, identity in candidates:
            ok, why = _verify_witness(
                witness, key, canonical_payload,
                expected_origin, expected_rp_id, require_user_verification, allow_cross_origin,
            )
            if ok:
                matched = identity
                matched_key = key
                break
            last_reason = why
        if matched is None:
            failures.append(last_reason)
            continue
        if requires_hardware_credential(requirement) and witness.get("sigAlg") != "WEBAUTHN":
            failures.append(
                f"signer {witness.get('signerDid')} used a bare key, but the signed policy requires "
                "a hardware-backed WebAuthn credential"
            )
            continue
        if requirement.get("requireHardwareKey") is True:
            synced = _backup_flags_problem(witness)
            if synced:
                failures.append(synced)
                continue
        if requirement.get("requesterCannotApprove") is True and witness.get("signerDid") == requester.get("did"):
            failures.append(f"four-eyes: requester {witness.get('signerDid')} cannot delegate to themselves")
            continue
        shared = _shared_key_problem(counted_keys, matched_key, matched)
        if shared:
            failures.append(shared)
            continue
        verified_signers.add(matched)

    required = int(requirement["requiredApprovals"])
    if len(verified_signers) < required:
        shown = failures[:MAX_REPORTED_FAILURES]
        if len(failures) > MAX_REPORTED_FAILURES:
            shown = shown + [f"+{len(failures) - MAX_REPORTED_FAILURES} more"]
        detail = f" ({'; '.join(shown)})" if shown else ""
        return {
            "ok": False,
            "reason": f"delegation quorum not met: {len(verified_signers)} of {required} required "
                      f"approver signatures verified{detail}",
        }

    return {
        "ok": True,
        "delegation": {
            # The DEDUPLICATED set: this is what gets enforced against witness DIDs later, and a
            # duplicate entry must not create the illusion of a larger eligible pool.
            "delegatedTo": distinct,
            "delegatedQuorum": delegated_quorum,
            "target": expected.get("target", ""),
            "actionType": expected.get("actionType", ""),
            "params": expected.get("params", {}),
            "nonce": nonce,
            "signers": sorted(verified_signers),
            "expiresAt": expires_at,
        },
    }

def _witnesses_of(receipt: Dict[str, Any]) -> list:
    """Normalize a receipt to a witness list: ``signatures`` if present, else the single-sig fields."""
    sigs = receipt.get("signatures")
    if isinstance(sigs, list) and sigs:
        return sigs
    if receipt.get("signerPublicKey") and receipt.get("signature"):
        return [{
            "signerDid": receipt.get("signerDid") or "",
            "signerPublicKey": receipt.get("signerPublicKey"),
            "signature": receipt.get("signature"),
            "sigAlg": receipt.get("sigAlg"),
            "authenticatorData": receipt.get("authenticatorData"),
            "clientDataJSON": receipt.get("clientDataJSON"),
        }]
    return []

def self_certifying_did(public_key_b64: str) -> str:
    """Commit to exact decoded enrolled key bytes, matching the gateway and TS verifier."""
    return "did:intyga:key:" + base64url_encode(hashlib.sha256(base64_decode_flexible(public_key_b64)).digest())


def _candidate_keys(approvers: Dict[str, Any], witness: Dict[str, Any], restrict_to=None):
    """
    The keys we will accept this witness under, drawn ENTIRELY from the caller's trust anchor.

    Keys come from the caller's allowlist/resolver, or are authenticated by hashing the witness's
    carried key against a caller-pinned self-certifying DID. Returns
    ``(candidates, None)`` or ``(None, reason)``; each candidate is ``(key, identity)`` so quorum
    counts distinct APPROVERS. In publicKeys mode the identity is the key itself, because the
    receipt's ``signerDid`` is an unverified string there and counting it would let one approver
    claim to be three.

    ``resolveKey`` may return a LIST of keys for one DID. An approver commonly holds a software key plus
    one or more registered authenticators, and any of them is legitimately theirs; returning them all
    keeps the identity intact instead of forcing callers into publicKeys mode and losing the DID
    binding. Every key returned for a DID counts as that ONE approver.

    ``restrict_to`` narrows eligibility to the identities a delegation names (DIV §5a.6 step 3),
    applied ON TOP of the trust anchor rather than instead of it.
    """
    public_keys = approvers.get("publicKeys")
    if public_keys is not None:
        # A delegation names identities, and in publicKeys mode signerDid is an unverified string —
        # enforcing delegatedTo against it would be security theatre. Refuse rather than pretend.
        if restrict_to is not None:
            return None, (
                "a delegation names approver identities, so it requires a DID-mode trust anchor "
                "({'dids': [...], 'resolveKey': ...}); in publicKeys mode signerDid is unverified and "
                "delegatedTo cannot be enforced"
            )
        if not public_keys:
            return None, "trusted approver allowlist is empty"
        return [(k, k) for k in public_keys], None
    dids = approvers.get("dids") or []
    resolve = approvers.get("resolveKey") or approvers.get("resolve_key")
    signer_did = witness.get("signerDid")
    if not signer_did or signer_did not in dids:
        return None, f"signer {signer_did or '(unknown)'} is not an authorized approver"
    if restrict_to is not None and signer_did not in restrict_to:
        return None, f"signer {signer_did} is not named in the delegation"
    resolved = resolve(signer_did) if callable(resolve) else None
    keys = resolved if isinstance(resolved, (list, tuple)) else [resolved]
    # All keys for one DID share that DID as their identity, so quorum still counts one approver.
    candidates = [(k, signer_did) for k in keys if k]
    if candidates:
        return candidates, None
    # A caller-pinned key-derived DID independently authenticates the carried key. Never infer
    # trust from an arbitrary receipt DID, and never override a nonempty caller key mapping.
    if signer_did.startswith("did:intyga:key:"):
        carried = witness.get("signerPublicKey")
        if not carried or self_certifying_did(carried) != signer_did:
            return None, "witness public key does not hash to the pinned self-certifying DID"
        return [(carried, signer_did)], None
    return None, f"no trusted key could be resolved for {signer_did}"

def _shared_key_problem(counted: Dict[bytes, str], key: str, identity: str) -> Optional[str]:
    """One key, one person (DIV §4.4.6).

    An identity-associating anchor that maps the SAME key to two DIDs would otherwise let that key's
    holder count as two approvers, since quorum counts distinct identities. A key already counted for
    one identity cannot count for another. Keys compare by decoded bytes (padding and base64/base64url
    spellings of one encoding match; the same key in another encoding, COSE vs SPKI, is not detected).
    Records the key when it is free.
    """
    try:
        fingerprint = base64_decode_flexible(key)
    except Exception:
        fingerprint = key.encode("utf-8", "surrogatepass")
    owner = counted.get(fingerprint)
    if owner is not None and owner != identity:
        return (
            f"signer {identity} verified under a key already counted for {owner}; "
            "two approver identities sharing one key count once (DIV §4.4.6)"
        )
    counted[fingerprint] = identity
    return None


def _verify_witness(
    witness: Dict[str, Any],
    trusted_key: str,
    canonical_payload: str,
    expected_origin,
    expected_rp_id,
    require_user_verification: bool,
    allow_cross_origin: bool,
):
    """Verify one witness signature using an already-TRUSTED key. Returns ``(ok, reason)``."""
    signature = witness.get("signature")
    if not signature:
        return False, "witness missing signature"

    # DIV §4.4.2: unknown/absent labels fall back to ES256, except AUTO_APPROVED.
    if witness.get("sigAlg") == "AUTO_APPROVED" or (witness.get("sigAlg") is not None and not isinstance(witness["sigAlg"], str)):
        return False, "unsupported witness signature algorithm"
    if witness.get("sigAlg") != "WEBAUTHN":
        if not verify_ecdsa_p256(trusted_key, canonical_payload, signature):
            return False, "signature does not verify against the trusted signer key"
        return True, None

    authenticator_data = witness.get("authenticatorData")
    client_data_json = witness.get("clientDataJSON")
    if not authenticator_data or not client_data_json:
        return False, "WebAuthn witness missing authenticatorData or clientDataJSON"
    # FAIL CLOSED: without an expected origin and RP ID there is nothing to pin the assertion to.
    if not expected_origin or not expected_rp_id:
        return False, (
            "WebAuthn receipts require expected_origin and expected_rp_id — without them "
            "an assertion from any relying party would verify"
        )
    try:
        client_data_buf = base64_decode_flexible(client_data_json)
        client_data = json.loads(client_data_buf.decode("utf-8"))

        # An assertion, not a registration: webauthn.create signs a different ceremony over the
        # same challenge bytes and must never be accepted as approval.
        if client_data.get("type") != "webauthn.get":
            return False, "clientDataJSON is not a webauthn.get assertion"
        if client_data.get("origin") != expected_origin:
            return False, "assertion origin does not match expected_origin"
        # origin and rpIdHash both match for an embedded RP frame, so crossOrigin is the only signal
        # separating "approved on our page" from "approved inside someone else's page"
        # (W3C WebAuthn L3 §7.2 step 9).
        if client_data.get("crossOrigin") is True and not allow_cross_origin:
            return False, "assertion was produced in a cross-origin frame (crossOrigin=true)"
        # A topOrigin that differs from origin is the same embedding reported another way, refused
        # exactly like crossOrigin=true (DIV §4.4.5 rule 5) — the gateway refuses it at ingest.
        if "topOrigin" in client_data and client_data["topOrigin"] != client_data.get("origin") and not allow_cross_origin:
            return False, "assertion was produced in a frame embedded by another origin (topOrigin differs from origin)"

        expected_challenge = base64url_encode(canonical_payload.encode("utf-8"))
        client_challenge_clean = client_data.get("challenge", "").replace("=", "")
        if client_challenge_clean != expected_challenge:
            return False, "clientDataJSON challenge does not match canonical payload"

        # authenticatorData is signed but was previously never INSPECTED: it carries the RP ID the
        # credential answered for and whether the user was actually present/verified.
        auth_data_buf = base64_decode_flexible(authenticator_data)
        if len(auth_data_buf) < 37:
            return False, "authenticatorData is too short"
        rp_id_hash = hashlib.sha256(expected_rp_id.encode("utf-8")).digest()
        if not hmac.compare_digest(auth_data_buf[:32], rp_id_hash):
            return False, "authenticatorData rpIdHash does not match expected_rp_id"
        flags = auth_data_buf[32]
        if not flags & AUTH_DATA_FLAG_UP:
            return False, "authenticatorData user-present flag is not set"
        if require_user_verification and not flags & AUTH_DATA_FLAG_UV:
            return False, "authenticatorData user-verified flag is not set"

        # The COSE key is parsed from the TRUSTED key, not the receipt's copy.
        cose_buf = base64_decode_flexible(trusted_key)
        x_bytes, y_bytes = parse_cose_public_key(cose_buf)
        x_int = int.from_bytes(x_bytes, byteorder="big")
        y_int = int.from_bytes(y_bytes, byteorder="big")

        public_numbers = ec.EllipticCurvePublicNumbers(x_int, y_int, ec.SECP256R1())
        key_object = public_numbers.public_key()

        client_data_hash = hashlib.sha256(client_data_buf).digest()
        signature_verify_data = auth_data_buf + client_data_hash

        key_object.verify(
            base64_decode_flexible(signature),
            signature_verify_data,
            ec.ECDSA(hashes.SHA256())
        )
        return True, None
    except Exception as e:
        return False, f"WebAuthn verification failed: {str(e)}"

def _parity_signers(receipt, approvers, requirement, requester, *, platform=False,
                    expected_origin=None, expected_rp_id=None,
                    require_user_verification=True, allow_cross_origin=False):
    """Check new receipt families using the same trust and signature primitives as approvals."""
    witnesses = _witnesses_of(receipt)
    if not witnesses or len(witnesses) > MAX_WITNESSES:
        return set(), ["missing signature material or witness limit exceeded"]
    if not platform and requirement["requiredApprovals"] > 1 and approvers.get("publicKeys"):
        return set(), ["multi-approver quorum requires a DID-mode trust anchor (DIV §5 step 3b)"]
    if requirement.get("requesterCannotApprove") is True and approvers.get("publicKeys"):
        return set(), ["requesterCannotApprove requires a DID-mode trust anchor"]
    signers, failures = set(), []
    counted_keys: Dict[bytes, str] = {}
    for witness in witnesses:
        if not isinstance(witness, dict):
            failures.append("malformed witness")
            continue
        if platform and witness.get("sigAlg") != "WEBAUTHN":
            failures.append("platform receipts are WebAuthn-only")
            continue
        candidates, reason = _candidate_keys(approvers, witness)
        if reason:
            failures.append(reason)
            continue
        matched = None
        matched_key = None
        reason = "signature does not verify against any trusted key"
        for key, identity in candidates:
            valid, reason = _verify_witness(witness, key, receipt["canonicalPayload"],
                expected_origin, expected_rp_id, require_user_verification, allow_cross_origin)
            if valid:
                matched = identity
                matched_key = key
                break
        if matched is None:
            failures.append(reason)
            continue
        if requires_hardware_credential(requirement) and witness.get("sigAlg") != "WEBAUTHN":
            failures.append("signed policy requires a hardware-backed WebAuthn credential")
            continue
        if requirement.get("requireHardwareKey") is True:
            synced = _backup_flags_problem(witness)
            if synced:
                failures.append(synced)
                continue
        if requirement.get("requesterCannotApprove") is True and witness.get("signerDid") == requester.get("did"):
            failures.append("four-eyes: requester cannot seal their own request")
            continue
        shared = _shared_key_problem(counted_keys, matched_key, matched)
        if shared:
            failures.append(shared)
            continue
        signers.add(matched)
    return signers, failures[:MAX_REPORTED_FAILURES]


@_never_raises
def verify_platform_receipt(receipt: Dict[str, Any], expected: Dict[str, Any], *,
    expected_origin=None, expected_rp_id=None, require_user_verification: bool = True,
    allow_cross_origin: bool = False, allow_expired: bool = False, as_of=None,
    clock_skew_seconds: float = DEFAULT_CLOCK_SKEW_SECONDS,
) -> Dict[str, Any]:
    """Verify a §5c WebAuthn receipt against YOUR digest, RP, nonce and subject trust anchor.

    Does not redeem the nonce. Single use remains the executing application's responsibility.
    No auto-approval override exists for this receipt family.
    """
    payload = json.loads(receipt.get("canonicalPayload", ""))
    if not isinstance(payload, dict) or type(payload.get("v")) is not int or payload["v"] != DIV_VERSION:
        return {"ok": False, "reason": "unsupported DIV payload version"}
    if payload.get("type") != DIV_PLATFORM_INTENT_TYPE:
        return {"ok": False, "reason": "payload is not a div-platform-intent"}
    nonce = expected.get("nonce")
    if not isinstance(nonce, str) or not nonce or payload.get("nonce") != nonce:
        return {"ok": False, "reason": "receipt is for a different challenge or nonce is missing"}
    approvers = expected.get("approvers")
    if not isinstance(approvers, dict) or not (approvers.get("dids") or approvers.get("publicKeys")):
        return {"ok": False, "reason": "expected.approvers is required"}
    digest, rp_id = expected.get("payloadHash"), expected.get("rpId")
    if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        return {"ok": False, "reason": "expected.payloadHash must be 64-character lowercase hex"}
    if not isinstance(rp_id, str) or not rp_id:
        return {"ok": False, "reason": "expected.rpId is required"}
    if expected_rp_id is not None and expected_rp_id != rp_id:
        return {"ok": False, "reason": "expected_rp_id conflicts with expected.rpId"}
    subject = payload.get("subject")
    external_id = subject.get("externalId") if isinstance(subject, dict) else None
    if not isinstance(external_id, str) or not external_id:
        return {"ok": False, "reason": "receipt missing subject.externalId"}
    if "subjectExternalId" in expected and expected["subjectExternalId"] != external_id:
        return {"ok": False, "reason": "receipt was signed by a different subject"}
    signed_at, expires_at = payload.get("signedAt"), payload.get("expiresAt")
    signed, expiry = _parse_rfc3339(signed_at), _parse_rfc3339(expires_at)
    if signed is None or expiry is None:
        return {"ok": False, "reason": "signedAt/expiresAt is not a valid RFC3339 timestamp"}
    recomputed = canonical_platform_intent_payload(digest, rp_id, external_id, signed_at, expires_at, nonce)
    if recomputed != receipt["canonicalPayload"]:
        return {"ok": False, "reason": "payloadHash/rpId do not match what was signed"}
    now = as_of or datetime.now(timezone.utc)
    if expiry < signed:
        return {"ok": False, "reason": "receipt expires before it was signed"}
    if signed.timestamp() > now.timestamp() + clock_skew_seconds:
        return {"ok": False, "reason": "receipt is signed in the future"}
    if not allow_expired and now.timestamp() > expiry.timestamp() + clock_skew_seconds:
        return {"ok": False, "reason": "proof has expired"}
    if receipt.get("sigAlg") == "AUTO_APPROVED":
        return {"ok": False, "reason": "a platform receipt cannot be auto-approved"}
    # User verification is UNCONDITIONAL on this plane (DIV §5c.3): the ordinary-receipt waiver
    # require_user_verification=False is accepted for signature compatibility but never honoured.
    signers, failures = _parity_signers(receipt, approvers, {}, {}, platform=True,
        expected_origin=expected_origin, expected_rp_id=rp_id,
        require_user_verification=True, allow_cross_origin=allow_cross_origin)
    if not signers:
        return {"ok": False, "reason": "no valid subject signature: " + "; ".join(failures)}
    return {"ok": True, "signers": sorted(signers)}


@_never_raises
def verify_agent_authority(receipt: Dict[str, Any], expected: Dict[str, Any], *,
    expected_origin=None, expected_rp_id=None, require_user_verification: bool = True,
    allow_cross_origin: bool = False, allow_expired: bool = False, as_of=None,
    clock_skew_seconds: float = DEFAULT_CLOCK_SKEW_SECONDS,
) -> Dict[str, Any]:
    """Verify §5b governance evidence. This never approves execution or proves non-revocation."""
    payload = json.loads(receipt.get("canonicalPayload", ""))
    if not isinstance(payload, dict) or type(payload.get("v")) is not int or payload["v"] != DIV_VERSION:
        return {"ok": False, "reason": "unsupported DIV payload version"}
    if payload.get("type") != DIV_AGENT_AUTHORITY_TYPE:
        return {"ok": False, "reason": "payload is not a div-agent-authority"}
    patterns = payload.get("actionPatterns")
    if not isinstance(patterns, list) or not patterns or not all(isinstance(p, str) and p for p in patterns):
        return {"ok": False, "reason": "authority is missing a valid actionPatterns set"}
    if "parentReceiptHash" not in payload:
        return {"ok": False, "reason": "authority is missing parentReceiptHash"}
    parent = payload["parentReceiptHash"]
    if parent is not None and (not isinstance(parent, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", parent)):
        return {"ok": False, "reason": "authority has invalid parentReceiptHash"}
    target, agent_did = expected.get("target"), expected.get("agentDid")
    if not isinstance(target, str) or not target or not isinstance(agent_did, str) or not agent_did:
        return {"ok": False, "reason": "expected.target and expected.agentDid are required"}
    approvers = expected.get("approvers")
    if not isinstance(approvers, dict) or not (approvers.get("dids") or approvers.get("publicKeys")):
        return {"ok": False, "reason": "expected.approvers is required"}
    requester, requirement = receipt.get("requester"), payload.get("requirement")
    if not isinstance(requester, dict) or not isinstance(requirement, dict):
        return {"ok": False, "reason": "authority missing requester or signed approval requirement"}
    problem = (
        _quorum_problem(requirement) or _signer_class_problem(requirement)
        or _requirement_floor_problem(requirement, expected)
    )
    if problem:
        return {"ok": False, "reason": problem}
    sealed_at, expires_at, nonce = payload.get("sealedAt"), payload.get("expiresAt"), payload.get("nonce", "")
    sealed, expiry = _parse_rfc3339(sealed_at), _parse_rfc3339(expires_at)
    if sealed is None or expiry is None:
        return {"ok": False, "reason": "sealedAt/expiresAt is not a valid RFC3339 timestamp"}
    if expiry < sealed:
        return {"ok": False, "reason": "authority expires before it was sealed"}
    now = as_of or datetime.now(timezone.utc)
    if sealed.timestamp() > now.timestamp() + clock_skew_seconds:
        return {"ok": False, "reason": "authority is sealed in the future"}
    recomputed = canonical_agent_authority_payload(target, patterns, receipt.get("actionDescription", ""),
        {"did": agent_did}, requester, requirement, nonce, sealed_at, expires_at, parent)
    if recomputed != receipt["canonicalPayload"]:
        return {"ok": False, "reason": "target/agent/actionPatterns do not match what was sealed"}
    if not allow_expired and now.timestamp() > expiry.timestamp() + clock_skew_seconds:
        return {"ok": False, "reason": "authority has expired"}
    if receipt.get("sigAlg") == "AUTO_APPROVED":
        return {"ok": False, "reason": "an agent authority cannot be auto-approved"}
    signers, failures = _parity_signers(receipt, approvers, requirement, requester,
        expected_origin=expected_origin, expected_rp_id=expected_rp_id,
        require_user_verification=require_user_verification, allow_cross_origin=allow_cross_origin)
    if len(signers) < requirement["requiredApprovals"]:
        return {"ok": False, "reason": "authority sealing quorum not met: " + "; ".join(failures)}
    return {"ok": True, "authority": {
        "agentDid": agent_did, "target": target,
        "actionPatterns": sorted(set(patterns), key=lambda p: p.encode("utf-16-be")),
        "parentReceiptHash": parent,
        "nonce": nonce, "signers": sorted(signers), "sealedAt": sealed_at, "expiresAt": expires_at,
    }}


# ── Policy Crypto Namespace ───────────────────────────────────────────────────

