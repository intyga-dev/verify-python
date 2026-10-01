"""DEWP audit-ledger verification (docs/DEWP.md) — Python port.

Byte-identical to the TypeScript reference (`@intyga/verify` ledger-*.ts) and the Go/Rust ports,
locked by the shared cross-language vectors (packages/mcp-schemas/vectors/ledger-vectors.json).

Domain separation: 0x00 leaf, 0x01 node, 0x02 empty root, 0x03 anchor. Node children are HEX-DECODED
to raw bytes before hashing; the anchor signature covers the raw 32-byte digest.
"""

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

LEAF_TAG = b"\x00"
NODE_TAG = b"\x01"
EMPTY_TAG = b"\x02"
ANCHOR_TAG = b"\x03"

#: The only bundle shape this verifier implements (DEWP §6.5). An evidence-bundle or an
#: evidence-stream carries different semantics and a different completeness guarantee, so returning a
#: verdict on one under inclusion-proof rules would vouch for something never checked.
BUNDLE_KIND = "dewp.audit.inclusion-proof"

#: The Application Profile whose leaf layout `canonical_preimage` reproduces (DEWP §4.5). A bundle
#: declaring another profile has a preimage this port cannot rebuild — the honest answer is "unknown
#: layout", not a leaf mismatch that reads as tampering.
AUDIT_PROFILE = "trust.intyga.audit.v1"


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_leaf(preimage: str) -> str:
    """Domain-separated leaf digest: sha256(0x00 || UTF8(preimage))."""
    return sha256_hex(LEAF_TAG + preimage.encode("utf-8"))


def hash_pair(left_hex: str, right_hex: str) -> str:
    """Domain-separated node: sha256(0x01 || rawBytes(left) || rawBytes(right)). Order matters."""
    return sha256_hex(NODE_TAG + bytes.fromhex(left_hex) + bytes.fromhex(right_hex))


def empty_root() -> str:
    """Empty-tree root (DEWP §5.1.1): sha256(0x02)."""
    return sha256_hex(EMPTY_TAG)


def merkle_root(leaves: List[str]) -> str:
    if len(leaves) == 0:
        return empty_root()
    level = list(leaves)
    while len(level) > 1:
        nxt: List[str] = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else left  # duplicate-last
            nxt.append(hash_pair(left, right))
        level = nxt
    return level[0]


def expected_path_length(leaf_count: int) -> int:
    """Audit-path length for a duplicate-last tree of leaf_count leaves: ceil(log2(n)), 0 when n <= 1."""
    if leaf_count <= 1:
        return 0
    n = 0
    size = leaf_count
    while size > 1:
        size = (size + 1) // 2
        n += 1
    return n


def _is_hash64(s: Any) -> bool:
    """Exactly 64 lowercase hex characters (DEWP §4.4)."""
    return isinstance(s, str) and len(s) == 64 and all(c in "0123456789abcdef" for c in s)


def verify_merkle_proof(
    leaf: str, proof: List[Dict[str, str]], root: str, bounds: Dict[str, int]
) -> bool:
    """Recompute the root from a leaf + its (leaf→root) proof, bounded by the leaf's position.

    Each step: {siblingHash, siblingPosition}. `bounds` is {"index", "leafCount"} and is REQUIRED
    (DEWP §3 invariant 3: "The bounds are REQUIRED, not advisory").

    Bounds are what make this a proof of MEMBERSHIP rather than a proof that A path exists. This tree
    pads an unpaired trailing node by hashing it against ITSELF, so merkle_root([a,b,c]) equals
    merkle_root([a,b,c,c]) and a path built for the nonexistent index 3 recomputes the 3-leaf root
    exactly. DEWP §11.1 states outright that an implementation stopping at root recomputation is
    non-conformant — this port did exactly that.
    """
    if not _is_hash64(leaf) or not _is_hash64(root):
        return False
    # `bounds` is REQUIRED (see above), but Python enforces nothing at the boundary of an untyped
    # caller — `bounds.get(...)` on `None` would raise AttributeError instead of returning a bool.
    # Refusing here keeps this a predicate for that caller instead of a crash.
    if not isinstance(bounds, dict) or not isinstance(proof, list):
        return False
    index = bounds.get("index")
    leaf_count = bounds.get("leafCount")
    if not isinstance(index, int) or not isinstance(leaf_count, int):
        return False
    if isinstance(index, bool) or isinstance(leaf_count, bool):
        return False
    if leaf_count < 1 or index < 0 or index >= leaf_count:
        return False
    if len(proof) != expected_path_length(leaf_count):
        return False

    idx = index
    level_size = leaf_count
    node = leaf
    for step in proof:
        sibling = step.get("siblingHash")
        if not _is_hash64(sibling):
            return False
        # The side follows from the index; a prover-chosen side would restore the flexibility the
        # length check just removed.
        expected_side = "LEFT" if idx % 2 == 1 else "RIGHT"
        if step.get("siblingPosition") != expected_side:
            return False
        # Self-pairing is legitimate ONLY at the unpaired end of an odd-sized level. Anywhere else it
        # is the signature of an index pointing into padding — the check that actually closes the
        # forgery, since leafCount arrives inside the proof and a prover can inflate it.
        self_paired = sibling == node
        legitimately_unpaired = idx == level_size - 1 and level_size % 2 == 1
        if self_paired and not legitimately_unpaired:
            return False
        node = hash_pair(sibling, node) if expected_side == "LEFT" else hash_pair(node, sibling)
        idx //= 2
        level_size = (level_size + 1) // 2
    return node == root


# ── Leaf preimage (DEWP intyga.v1 profile: 18-element array, tenantSeq last) ───────────────────────
# Order MUST match packages/verify ledger-leaf.ts and the producer. metadata is embedded as a JCS
# string (DEWP §4.2, normative): keys sorted recursively by UTF-16 code unit, number text as JS
# `JSON.stringify` emits it — matching @intyga/verify's `jcsStringify`.
def _jcs(value: Any) -> str:
    """RFC 8785 JCS serialization — keys sorted by UTF-16 code unit at every depth.

    `json.dumps(..., sort_keys=True)` is NOT this. Python sorts `str` by Unicode CODE POINT, while
    JCS (and therefore `@intyga/verify`'s `jcsStringify`, which uses `Object.keys().sort()`) orders by
    UTF-16 CODE UNIT. The two disagree for every character above the BMP: an astral key such as
    U+1F600 sorts AFTER U+E000 by code point but BEFORE it by code unit, because its surrogate pair
    begins 0xD83D.

    A leaf whose metadata mixes an astral key with one in U+E000..U+FFFF therefore hashed differently
    here than at the producer, and `verify_bundle` reported a leaf mismatch — content-mismatch, which
    is indistinguishable from tampering — for a genuine, untampered event. `crypto.py` already had the
    right comparator; this path did not reuse it, and at the time no ledger vector contained a
    non-BMP character, so the golden-vector gate could not catch it (the `metadata-utf16-key-order`
    vector now pins this).
    """
    if isinstance(value, dict):
        parts = [
            f"{json.dumps(k, ensure_ascii=False)}:{_jcs(value[k])}"
            for k in sorted(value.keys(), key=lambda k: k.encode("utf-16-be"))
        ]
        return "{" + ",".join(parts) + "}"
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_jcs(v) for v in value) + "]"
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        # Number TEXT is part of the hashed bytes, and `json.dumps` alone diverges from JS for
        # whole-valued floats: a runtime-built metadata value of 100.0 serialized as "100.0" where
        # the TS producer wrote "100" — same event, different leaf hash, reported as tampering.
        # Reuse the canonical formatter from crypto.py rather than a second copy of the rule.
        # Imported lazily so this module stays hashlib-only at import time (see verify_bundle).
        #
        # RESIDUAL, bounded: outside the portable range (DEWP §4.3.1 — |x| < 1e16 for integers,
        # 1e-4 <= |x| < 1e16 otherwise) Python's repr and JS can still disagree (0.00001 -> "1e-05"
        # here, "0.00001" in JS). Deliberately NOT refused: the TS reference jcs has no guard here,
        # and a verifier must fail-to-match on such a leaf rather than crash. A conformant producer
        # never commits one — the reference producer refuses at ingestion (assertPortableJson in
        # packages/db) and stable_stringify refuses on the signing path — so this is reachable only
        # for a foreign or legacy leaf. verify-go answers the same case by refusing to canonicalize;
        # the spec permits either, and both beat computing bytes the other ports do not share.
        from .crypto import format_jcs_number

        return format_jcs_number(value)
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


def canonical_preimage(row: Dict[str, Any]) -> str:
    metadata = row.get("metadata", None)
    # DEWP §4.2: metadata is a JCS string — keys sorted recursively, so the leaf hash is
    # insertion-order- and language-independent. Matches @intyga/verify jcsStringify.
    metadata_str = _jcs(metadata) if metadata is not None else "null"
    arr = [
        row.get("seq"),
        row.get("createdAt"),
        row.get("event"),
        row.get("outcome"),
        row.get("detail"),
        metadata_str,
        row.get("signerDid"),
        row.get("signerPublicKey"),
        row.get("signedPayload"),
        row.get("signature"),
        row.get("sigAlg"),
        bool(row.get("isBillable", False)),
        row.get("tenantId"),
        row.get("actorNodeId"),
        row.get("subjectNodeId"),
        row.get("edgeId"),
        row.get("challengeId"),
        row.get("tenantSeq"),
    ]
    return json.dumps(arr, separators=(",", ":"), ensure_ascii=False)


def leaf_hash(row: Dict[str, Any]) -> str:
    return hash_leaf(canonical_preimage(row))


def verify_inclusion_proof(proof: Dict[str, Any], daily_root: str) -> bool:
    """Two-hop DEWP proof: leaf → block root, then hashLeaf(block root) → daily root.

    Each hop is bounded by its position (DEWP §3 invariant 3, steps 1 and 2). A proof that cannot say
    where its leaf sits does not establish inclusion, so missing position fields are a rejection.

    Every field is read with ``get``, for the reason ``verify_merkle_proof`` states about ``bounds``:
    this is a documented predicate, and a relying party calling it directly on a malformed artifact
    must get ``False`` rather than a ``KeyError`` a caller could handle as something other than a
    refusal. ``verify_bundle``'s try/except used to be the only thing hiding that.
    """
    if not isinstance(proof, dict):
        return False
    block_root = proof.get("blockRoot")
    if not verify_merkle_proof(
        proof.get("leaf"),
        proof.get("blockProof", []),
        block_root,
        {"index": proof.get("leafIndex"), "leafCount": proof.get("blockLeafCount")},
    ):
        return False
    return verify_merkle_proof(
        hash_leaf(block_root),
        proof.get("checkpointProof", []),
        daily_root,
        {
            "index": proof.get("checkpointLeafIndex"),
            "leafCount": proof.get("checkpointLeafCount"),
        },
    )


# ── Signed anchors (DEWP §5.2) ────────────────────────────────────────────────────────────────────
def anchor_preimage(anchor: Dict[str, str]) -> str:
    """JCS of [dailyRoot, timestamp, issuer, algorithm, seqStart, seqEnd, chainHash] — for string
    arrays this is compact JSON. The last three bind the checkpoint's POSITION (DEWP §5.2)."""
    return json.dumps(
        [anchor["dailyRoot"], anchor["timestamp"], anchor["issuer"], anchor["algorithm"],
         anchor["seqStart"], anchor["seqEnd"], anchor["chainHash"]],
        separators=(",", ":"),
        ensure_ascii=False,
    )


_HEX64 = re.compile(r"[0-9a-f]{64}")
_SEQ = re.compile(r"[0-9]{1,20}")
_DEWP_TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z")


def parse_anchor_timestamp_ms(ts: Any) -> Optional[int]:
    """Milliseconds since the epoch for an exact DEWP §4.3 timestamp (YYYY-MM-DDTHH:mm:ss.sssZ), else
    None. Strict for the same reason as the TypeScript reference: every port must read one instant."""
    if not isinstance(ts, str) or not _DEWP_TIMESTAMP.fullmatch(ts):
        return None
    try:
        parsed = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    return int(parsed.timestamp()) * 1000 + parsed.microsecond // 1000


def is_well_formed_anchor(anchor: Any) -> bool:
    """All seven signed fields present with the shapes DEWP §5.2 requires. A missing position field is
    refused rather than hashed: the preimage would not be the one any conformant producer signed."""
    return bool(
        isinstance(anchor, dict)
        and isinstance(anchor.get("dailyRoot"), str) and _HEX64.fullmatch(anchor["dailyRoot"])
        and parse_anchor_timestamp_ms(anchor.get("timestamp")) is not None
        and isinstance(anchor.get("issuer"), str)
        # §5.2 algorithm registry: the label is signed, so any other one is not a §5.2 anchor at all.
        and anchor.get("algorithm") in ("ES256", "Ed25519", "RSA-PSS")
        and isinstance(anchor.get("seqStart"), str) and _SEQ.fullmatch(anchor["seqStart"])
        and isinstance(anchor.get("seqEnd"), str) and _SEQ.fullmatch(anchor["seqEnd"])
        and isinstance(anchor.get("chainHash"), str) and _HEX64.fullmatch(anchor["chainHash"])
    )


def anchor_digest_hex(anchor: Dict[str, str]) -> str:
    """Raw 32-byte anchor digest (hex): sha256(0x03 || UTF8(anchor_preimage))."""
    return sha256_hex(ANCHOR_TAG + anchor_preimage(anchor).encode("utf-8"))


def verify_anchor_signature(anchor: Dict[str, Any], public_key_spki_b64: str) -> bool:
    """Verify one ES256, Ed25519 or RSA-PSS anchor under a caller-pinned SPKI key.

    The message is the raw domain-separated digest; quorum is a separate check.
    """
    try:
        if not is_well_formed_anchor(anchor) or anchor.get("algorithm") not in ("ES256", "Ed25519", "RSA-PSS"):
            return False
        signature_b64 = anchor.get("signature")
        if not isinstance(signature_b64, str) or not signature_b64:
            return False

        # Import cryptography lazily; hash/proof primitives remain usable without loading it.
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa, padding
        from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

        # base64url as well as standard, matching the rest of this package and `Buffer.from(s,
        # "base64")` in @intyga/verify. `base64.b64decode` without `validate` silently DISCARDS `-`
        # and `_` instead of erroring, so a base64url-encoded issuer key or signature — which §5.2
        # exists to admit, from issuers the producer does not control — decoded to different bytes
        # here and read as an invalid signature on input the TS reference accepts.
        from .crypto import base64_decode_flexible

        public_key = serialization.load_der_public_key(base64_decode_flexible(public_key_spki_b64))
        digest = bytes.fromhex(anchor_digest_hex(anchor))
        signature = base64_decode_flexible(signature_b64)
        if anchor["algorithm"] == "Ed25519":
            if not isinstance(public_key, ed25519.Ed25519PublicKey):
                return False
            public_key.verify(signature, digest)
            return True
        if anchor["algorithm"] == "RSA-PSS":
            # DEWP §5.2 RSA-PSS profile: a modulus of at least 2048 bits, SHA-256 with MGF1-SHA-256
            # and a salt exactly the hash length. PSS.AUTO accepted any salt length.
            if not isinstance(public_key, rsa.RSAPublicKey) or public_key.key_size < 2048:
                return False
            public_key.verify(signature, digest,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
                hashes.SHA256())
            return True
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            return False
        if not isinstance(public_key.curve, ec.SECP256R1):
            return False

        digest = bytes.fromhex(anchor_digest_hex(anchor))
        signature = base64_decode_flexible(signature_b64)

        # Raw IEEE-P1363 (r||s) is always exactly 64 bytes for P-256; DER can in principle also be
        # 64, so length is not a reliable discriminator — try both encodings rather than inferring.
        candidates = []
        if len(signature) == 64:
            r = int.from_bytes(signature[:32], byteorder="big")
            s = int.from_bytes(signature[32:], byteorder="big")
            candidates.append(encode_dss_signature(r, s))
        candidates.append(signature)
        for candidate in candidates:
            try:
                public_key.verify(candidate, digest, ec.ECDSA(hashes.SHA256()))
                return True
            except Exception:
                continue
        return False
    except Exception:
        return False


# ── Bundle verification with the DEWP §7.1 property model ─────────────────────────────────────────
def verify_bundle(bundle: Dict[str, Any], trusted_root: Optional[str] = None, *,
                  anchors=None, anchor_policy=None, resolve_anchor_key=None, external_keys=None,
                  trusted_checkpoint=None, signature_policy=None, require_signatures=False) -> Dict[str, Any]:
    """Verify a single inclusion-proof bundle. Returns the four independent properties + summary level.

    `trusted_root` is independently obtained. Anchor verification additionally requires the
    caller's policy and trusted-key resolver; the bundle alone never establishes root provenance.

    `trusted_checkpoint` is the caller's record of the proof's checkpoint (its roots-file line, a dict
    with ``root`` and optionally ``seqStart``/``seqEnd``/``entryCount``/``anchoredAt``/``chainHash``). A
    single proof carries no checkpoint, so without it no EXTERNAL anchor counts: the DEWP §5.3 time
    bound would be measured against the anchor's own producer-chosen timestamp. Its root stands in for
    `trusted_root` when that is absent and must equal it otherwise; its entry count bounds the proof's
    leaf counts.
    """
    try:
        return _verify_bundle_checked(bundle, trusted_root, anchors=anchors, anchor_policy=anchor_policy,
                                      resolve_anchor_key=resolve_anchor_key, external_keys=external_keys,
                                      trusted_checkpoint=trusted_checkpoint, signature_policy=signature_policy, require_signatures=require_signatures)
    except Exception as exc:
        return _invalid(f"malformed bundle or verification input ({type(exc).__name__})")


def _supported_envelope(bundle):
    # Numeric revisions 1 and 2 without a protocol is the legacy export format, not a future version.
    protocol, version = bundle.get("protocol"), bundle.get("version")
    if protocol is not None and protocol != "DEWP":
        return False
    if version != "1.0" and not (protocol is None and type(version) in (int, float) and version in (1, 2)):
        return False
    if "algorithmRegistry" not in bundle:
        return True
    a = bundle["algorithmRegistry"]
    return (isinstance(a, dict) and a.get("hashAlgorithm") == "SHA-256"
            and a.get("serialization") == "RFC8785-JCS"
            and type(a.get("merkleVersion")) in (int, float) and a["merkleVersion"] == 1)


def _verify_bundle_checked(bundle, trusted_root, *, anchors, anchor_policy, resolve_anchor_key, external_keys,
                           trusted_checkpoint=None, signature_policy=None, require_signatures=False):
    notes: List[str] = []
    if trusted_checkpoint is not None and not isinstance(trusted_checkpoint, dict):
        return _invalid("trusted_checkpoint must be a checkpoint record")
    conflict = bool(trusted_checkpoint is not None and trusted_root is not None
                    and trusted_checkpoint.get("root") != trusted_root)
    if conflict:
        notes.append("the supplied trusted checkpoint names a different root than trusted_root; refusing to pick one")
    if trusted_root is None and trusted_checkpoint is not None:
        trusted_root = trusted_checkpoint.get("root")

    # Every field below comes from an untrusted artifact. Shape-check before use: a verifier that
    # raises on a malformed bundle has not returned "invalid", it has crashed, and a caller that
    # treats an exception as anything other than a refusal fails open.
    if not isinstance(bundle, dict):
        return _invalid("bundle is not an object")
    proof = bundle.get("proof")
    if not isinstance(proof, dict):
        return _invalid("bundle.proof is missing or not an object")
    event = bundle.get("event")
    if not isinstance(event, dict):
        event = {}
    canonical = event.get("canonical")
    if canonical is not None and not isinstance(canonical, dict):
        return _invalid("bundle.event.canonical is present but not an object")
    leaf = proof.get("leaf")

    # DEWP §6.5: a compliant verifier MUST reject any kind other than the ones it implements — and
    # the authoritative JSON Schema (docs/schemas/dewp/inclusion-proof.schema.json) makes `kind`
    # required, so an ABSENT kind is refused too, matching the TS reference.
    kind = bundle.get("kind")
    if kind != BUNDLE_KIND:
        return _invalid(f'refusing bundle kind "{kind}" (expected "{BUNDLE_KIND}") — DEWP §6.5')

    if not _supported_envelope(bundle):
        return _invalid("unsupported DEWP protocol, version or algorithm registry")

    # DEWP §4.5: an unknown Application Profile means the leaf layout is one this port cannot
    # reproduce. Leaf binding is then NOT ATTEMPTED (None), never silently "failed" — and the bundle
    # cannot be ok, because vouching for a layout we do not implement is the thing to avoid.
    profile = bundle.get("profile")
    unknown_profile = profile is not None and profile != AUDIT_PROFILE
    if unknown_profile:
        notes.append(
            f'bundle declares profile "{profile}"; this verifier implements only "{AUDIT_PROFILE}", '
            "so leaf binding was not attempted"
        )

    anchor = bundle.get("anchor")
    anchor = anchor if isinstance(anchor, dict) else {}
    legacy_anchor = bundle.get("legacyAnchor")
    legacy_anchor = legacy_anchor if isinstance(legacy_anchor, dict) else {}
    # The root the bundle asserts about itself, in the TS reference's order: the signed anchor, then
    # the legacy pre-§6.2 `anchor` object, then the proof's own checkpoint root. All three are
    # equally self-asserted, which is why none of them can make the bundle `ok`. Stopping at the
    # first of the three reported INVALID — the verdict that reads as "forged" — for the reference
    # producer's ORDINARY export, which omits `anchor` entirely until signed anchors exist.
    self_asserted_root = (
        anchor.get("dailyRoot") or legacy_anchor.get("dailyRoot") or proof.get("checkpointRoot")
    )
    if trusted_root is not None:
        daily_root = trusted_root
        # The verifier cannot tell a root recorded independently from one copied out of this bundle,
        # so it reports only what it knows: the caller supplied it.
        root_source = "caller-supplied"
    elif self_asserted_root:
        daily_root = self_asserted_root
        root_source = "self-asserted"
        notes.append(
            "no root supplied — verifying against the root inside the bundle. This proves the bundle "
            "is internally consistent, NOT that it matches the anchored log; re-run with a root you "
            "obtained earlier or from the published roots file for a real verdict"
        )
    else:
        daily_root = None
        root_source = "none"
        notes.append("no daily root available (event not yet committed to an anchored checkpoint)")

    # DEWP §17.3: the proof's own leaf counts are bound to the trusted checkpoint's entry count.
    count_mismatch = (leaf_count_mismatch(proof, trusted_checkpoint.get("entryCount"))
                      if trusted_checkpoint is not None and daily_root == trusted_checkpoint.get("root") else None)
    if count_mismatch:
        notes.append(count_mismatch)
    try:
        inclusion_ok = daily_root is not None and not count_mismatch and verify_inclusion_proof(proof, daily_root)
    except Exception:
        inclusion_ok = False
    root_consistency = daily_root is not None and proof.get("checkpointRoot") == daily_root
    commitment_verified = bool(inclusion_ok and root_consistency)

    # None = not attempted (unknown profile / no preimage), True = bound, False = mismatch.
    leaf_binding: Optional[bool]
    if unknown_profile or canonical is None:
        leaf_binding = None
    else:
        try:
            leaf_binding = leaf_hash(canonical) == leaf
        except Exception:
            leaf_binding = False

    # The bundle duplicates seq/createdAt/type/outcome/detail/signerDid/signature/sigAlg alongside
    # `canonical`, and ONLY `canonical` is hashed into the leaf. Unchecked, a bundle could display
    # outcome "SUCCESS" over a committed "FAILURE" and still return FULLY_VERIFIED — the commitment
    # genuine, the caption over it free-form. The auditor reads the caption.
    header_binding: Optional[bool]
    if canonical is None:
        header_binding = None
    else:
        mismatch = None
        for label, shown, committed in (
            ("seq", event.get("seq"), canonical.get("seq")),
            ("proof.seq", proof.get("seq"), canonical.get("seq")),
            ("createdAt", event.get("createdAt"), canonical.get("createdAt")),
            ("type", event.get("type"), canonical.get("event")),
            ("outcome", event.get("outcome"), canonical.get("outcome")),
            ("detail", event.get("detail"), canonical.get("detail")),
            ("signerDid", event.get("signerDid"), canonical.get("signerDid")),
            ("signature", event.get("signature"), canonical.get("signature")),
            ("sigAlg", event.get("sigAlg"), canonical.get("sigAlg")),
        ):
            if shown is not None and str(shown) != str(committed):
                mismatch = f'displayed {label} ("{shown}") does not match the committed value ("{committed}")'
                break
        header_binding = mismatch is None
        if mismatch:
            notes.append(f"{mismatch} — the bundle displays something other than what was committed")

    content_verified = bool(commitment_verified and leaf_binding is True and header_binding is not False)

    # `ok` is the flag callers branch on (`if not ok: raise`), so a NOT-APPLICABLE leaf binding must
    # be distinguished from a failed one. A redacted, commitment-only entry ships no preimage by
    # design (DEWP §15: verify inclusion against the retained leaf and do NOT attempt contentVerified),
    # and requiring content_verified rejected that valid export. An unknown `profile` is the case
    # that must still disqualify: a prover could otherwise switch leaf binding off for content the
    # bundle DID ship. Mirrors `contentBoundWhenPresent` in @intyga/verify ledger-bundle.ts.
    content_bound_when_present = (leaf_binding is True) if canonical is not None else True

    signature = verify_audit_signature(canonical, signature_policy) if content_verified and canonical else unchecked_signature()
    signature_verified = signature["status"] == "verified"
    anchor_verified, divergence = False, False
    witness_times: Dict[str, int] = {}
    external_check = bool(external_keys and (external_keys.get("rekor") or external_keys.get("rfc3161")))
    if anchor_policy is not None and (callable(resolve_anchor_key) or external_check) and daily_root:
        candidates = anchors if anchors is not None else [
            *(bundle.get("anchors") or []), *([bundle["anchor"]] if bundle.get("anchor") else [])]
        # The caller's record is the only position and time an anchor over a single proof can be held
        # to; an empty expectation keeps external witnesses from counting without one.
        record = trusted_checkpoint or {}
        expected = {k: record.get(k) for k in ("seqStart", "seqEnd", "chainHash", "anchoredAt")}
        verdict = verify_anchor_quorum(candidates, daily_root, anchor_policy, resolve_anchor_key,
            divergence_anchors=anchors or [], external_keys=external_keys, checkpoint=expected)
        anchor_verified = commitment_verified and verdict["ok"]
        divergence = verdict["divergence"]
        witness_times = verdict.get("witnessTimes") or {}
        if divergence:
            notes.append("ANCHOR DIVERGENCE: " + verdict.get("reason", "conflicting roots"))
        elif not verdict["ok"]:
            notes.append(verdict.get("reason", "anchor quorum not met"))
        else:
            notes.append("Anchor quorum met under caller policy and keys")
        if verdict.get("note"):
            notes.append(verdict["note"])
    elif anchor_policy is not None:
        notes.append("Anchor quorum could not be evaluated: a daily root and caller trust are required")
    elif commitment_verified and root_source == "caller-supplied":
        notes.append("A caller-supplied root was used, but no anchor quorum policy was supplied; anchorVerified stays false")

    # DEWP §6.2 asks verifiers to SURFACE the producer's own quorum claim alongside their verdict.
    # Reporting it is not trusting it: `anchor_verified` above is the independent check, not this
    # way. But a reader comparing two exports needs the claim AND the threshold behind it — a
    # deployment requiring one issuer and one requiring three both publish `externallyAnchored: true`,
    # and the boolean alone cannot tell them apart.
    claimed = bundle.get("externallyAnchored")
    if claimed is None and isinstance(proof, dict):
        claimed = proof.get("externallyAnchored")
    if claimed is not None:
        required = bundle.get("externallyAnchoredRequired")
        if required is None and isinstance(proof, dict):
            required = proof.get("externallyAnchoredRequired")
        quorum = f"{required} distinct independent issuer(s)" if required else "an unstated quorum"
        notes.append(
            f"producer CLAIMS external anchoring: {claimed} (against {quorum}). Claim only — this "
            "claim is separate from the anchorVerified result under the caller policy"
        )

    properties = {
        "commitmentVerified": commitment_verified,
        "contentVerified": content_verified,
        "signatureVerified": signature_verified,
        "anchorVerified": anchor_verified,
    }
    has_signer = signature["status"] != "not_applicable"
    if divergence or not commitment_verified:
        level = "INVALID"
    elif not content_verified:
        level = "COMMITMENT_VERIFIED"
    elif anchor_verified and (signature_verified or not has_signer):
        level = "FULLY_VERIFIED"
    elif signature_verified:
        level = "SIGNATURE_VERIFIED"
    else:
        level = "CONTENT_VERIFIED"

    return {
        "ok": bool(
            commitment_verified
            and not conflict
            and root_source == "caller-supplied"
            and leaf_binding is not False
            and header_binding is not False
            and content_bound_when_present
            and not divergence
            and (anchor_policy is None or anchor_verified)
            and (not require_signatures or (signature_verified and signature["trusted"]))
        ),
        "dailyRoot": daily_root,
        "rootSource": root_source,
        "witnessTimes": witness_times,
        "properties": properties,
        "signature": signature,
        "checks": {"leafBinding": leaf_binding, "headerBinding": header_binding},
        "verificationLevel": level,
        "notes": notes,
    }


def _invalid(reason: str) -> Dict[str, Any]:
    """A refusal shaped like every other verdict, so a caller never has to catch to stay safe."""
    return {
        "ok": False,
        "rootSource": "none",
        "witnessTimes": {},
        "properties": {
            "commitmentVerified": False,
            "contentVerified": False,
            "signatureVerified": False,
            "anchorVerified": False,
        },
        "checks": {"leafBinding": None, "headerBinding": None},
        "verificationLevel": "INVALID",
        "notes": [reason],
    }


# Imported after the primitives to keep the public ledger namespace backwards compatible.
from .ledger_advanced import (
    EVIDENCE_BUNDLE_KIND, CHAIN_TAG, GENESIS_PREV_CHAIN_HASH,
    verify_embedded_signature, verify_audit_signature, unchecked_signature, derive_verification_level, leaf_count_mismatch,
    parse_rekor_evidence, rekor_payload_hash_for, verify_rekor_anchor, verify_anchor_quorum,
    chain_preimage, chain_hash, verify_roots_chain, verify_evidence_bundle,
)
from .rfc3161 import verify_rfc3161_anchor
