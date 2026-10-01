"""DEWP bundle, anchor and continuity checks, mirroring the TypeScript reference.

All trust inputs come from the caller. A producer's anchoring claims never establish trust.
This module is re-exported by ``ledger``; it does not perform network requests.
"""
import functools
import hashlib
import json
import re
from typing import Any, Dict

from .ledger import (
    anchor_digest_hex, is_well_formed_anchor, leaf_hash, parse_anchor_timestamp_ms,
    verify_anchor_signature, verify_inclusion_proof,
)
from .rfc3161 import verify_rfc3161_anchor

EVIDENCE_BUNDLE_KIND = "dewp.audit.evidence-bundle"
CHAIN_TAG = b"\x04"
GENESIS_PREV_CHAIN_HASH = ""
#: Default bound on how long after a checkpoint's claimed time an external witness may first have seen
#: its anchor (DEWP §5.3). Caller-overridable via the policy's ``maxAnchorLagSeconds``.
DEFAULT_MAX_ANCHOR_LAG_SECONDS = 86_400
#: Tolerated witness time BEFORE the claimed time (producer clock ahead of the witness).
ANCHOR_CLOCK_SKEW_SECONDS = 300


def _safe_result(kind):
    def decorate(fn):
        @functools.wraps(fn)
        def check(*args, **kwargs):
            try:
                return fn(*args, **kwargs)
            except Exception as exc:
                reason = f"malformed {kind} ({type(exc).__name__})"
                if kind == "evidence bundle":
                    return {"ok": False, "total": 0, "contentVerified": 0, "commitmentOnly": 0,
                            "failed": [{"seq": "-", "reason": reason}], "roots": [],
                            "signatures": {"verified": 0, "invalid": [], "notCheckable": 0}, "notes": [reason]}
                if kind == "roots chain":
                    return {"ok": False, "verifiedCount": 0, "brokenAt": -1, "unchained": False, "reason": reason}
                if kind == "anchor quorum":
                    return {"ok": False, "verifiedIssuers": [], "divergence": False, "reason": reason,
                            "witnessTimes": {}}
                return {"ok": False, "reason": reason}
        return check
    return decorate


def verify_embedded_signature(canonical: Dict[str, Any]) -> bool:
    """Check committed ES256 material, not signer entitlement or WebAuthn assertions."""
    from .crypto import verify_ecdsa_p256
    try:
        return bool(canonical.get("sigAlg") == "ES256" and canonical.get("signedPayload")
                    and canonical.get("signerPublicKey") and canonical.get("signature")
                    and verify_ecdsa_p256(canonical["signerPublicKey"], canonical["signedPayload"], canonical["signature"]))
    except Exception:
        return False


def unchecked_signature():
    return {"status": "not_checked", "reason": "Content not verified or unavailable.", "trusted": False}


def verify_audit_signature(c, policy=None):
    """Committed signature only, not authorization/quorum. Policy is independently provisioned."""
    from .crypto import _verify_witness
    def result(status, reason, trusted=False):
        return {"status": status, "reason": reason, "trusted": trusted}
    alg = c.get("sigAlg")
    if not alg and (c.get("signature") or c.get("signedPayload") or c.get("signerPublicKey")):
        return result("not_checked", "Signature algorithm is missing.")
    if not alg or alg == "AUTO_APPROVED":
        return result("not_applicable", "No human signature is declared.")
    if alg not in ("ES256", "WEBAUTHN"):
        return result("not_checked", "Unsupported signature algorithm.")
    if not c.get("signature") or not c.get("signedPayload"):
        return result("not_checked", "Signature or signed payload is missing.")
    if policy is None and alg == "ES256":
        if not c.get("signerPublicKey"):
            return result("not_checked", "Signer public key is missing.")
        return (result("verified", "Signature valid under embedded key; signer identity is not established.")
                if verify_embedded_signature(c) else result("invalid", "Signature does not verify."))
    keys = (policy or {}).get("trustedSigners", {}).get(c.get("signerDid"))
    if not isinstance(keys, list) or not keys or not all(isinstance(k, str) and k for k in keys):
        return result("not_checked", "No caller-trusted key for this signer.")
    if alg == "WEBAUTHN" and (not policy.get("expectedOrigin") or not policy.get("expectedRpId")):
        return result("not_checked", "Caller-selected WebAuthn origin and RP ID are required.")
    m = c.get("metadata")
    w = m.get("webauthn") if isinstance(m, dict) else None
    w = w if isinstance(w, dict) else {}
    if alg == "WEBAUTHN" and not all(isinstance(w.get(k), str) and w[k] for k in ("authenticatorData", "clientDataJSON")):
        return result("not_checked", "WebAuthn authenticatorData or clientDataJSON is missing.")
    for key in keys:
        try:
            ok, _ = _verify_witness({**w, "sigAlg": alg, "signature": c["signature"]}, key,
                                   c["signedPayload"], policy.get("expectedOrigin"), policy.get("expectedRpId"), True, False)
            if ok:
                return result("verified", "Signature valid under caller-trusted signer key.", True)
        except Exception:
            pass
    return result("invalid", "Signature or WebAuthn assertion does not verify under caller trust.")


def derive_verification_level(properties, has_signer: bool) -> str:
    if not properties["commitmentVerified"]:
        return "INVALID"
    if not properties["contentVerified"]:
        return "COMMITMENT_VERIFIED"
    if properties["anchorVerified"] and (properties["signatureVerified"] or not has_signer):
        return "FULLY_VERIFIED"
    return "SIGNATURE_VERIFIED" if properties["signatureVerified"] else "CONTENT_VERIFIED"


def parse_rekor_evidence(evidence_b64):
    from .crypto import base64_decode_flexible
    try:
        parsed = json.loads(base64_decode_flexible(evidence_b64))
        return parsed if isinstance(parsed, dict) else None
    except Exception:
        return None


def rekor_payload_hash_for(anchor) -> str:
    return hashlib.sha256(bytes.fromhex(anchor_digest_hex(anchor))).hexdigest()


def _spki_der(key_text):
    """DER SPKI of a PEM or base64 key, or None."""
    from .crypto import base64_decode_flexible
    from cryptography.hazmat.primitives import serialization
    try:
        key = (serialization.load_pem_public_key(key_text.encode()) if "BEGIN" in key_text
               else serialization.load_der_public_key(base64_decode_flexible(key_text)))
        return key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    except Exception:
        return None


def _submitted_by_pinned_key(record, anchor, pinned) -> bool:
    """The hashedrekord was submitted under a caller-pinned producer key whose ES256 signature covers
    the anchor digest. Rekor accepts ANY key, so without this anyone who can compute the digest (it is
    built from public fields) can get it logged. ``publicKey.content`` is base64 of the PEM text."""
    from .crypto import base64_decode_flexible
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    signature = ((record.get("spec") or {}).get("signature") or {})
    content = (signature.get("publicKey") or {}).get("content")
    sig_b64 = signature.get("content")
    if not isinstance(content, str) or not isinstance(sig_b64, str):
        return False
    try:
        submitted = _spki_der(base64_decode_flexible(content).decode("utf-8"))
    except Exception:
        return False
    if submitted is None or not any(_spki_der(k) == submitted for k in pinned):
        return False
    try:
        key = serialization.load_der_public_key(submitted)
        if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
            return False
        sig = base64_decode_flexible(sig_b64)
        digest = bytes.fromhex(anchor_digest_hex(anchor))
        candidates = []
        if len(sig) == 64:
            candidates.append(encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")))
        candidates.append(sig)
        for candidate in candidates:
            try:
                key.verify(candidate, digest, ec.ECDSA(hashes.SHA256()))
                return True
            except Exception:
                continue
    except Exception:
        return False
    return False


@_safe_result("Rekor evidence")
def verify_rekor_anchor(evidence, anchor, rekor_public_key: str, submitter_keys=None):
    from .crypto import base64_decode_flexible, stable_stringify
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    body = evidence.get("body")
    signature = (evidence.get("verification") or {}).get("signedEntryTimestamp")
    if not body or not signature:
        return {"ok": False, "reason": "rekor evidence requires entry body and signedEntryTimestamp"}
    if type(evidence.get("logIndex")) is not int or type(evidence.get("integratedTime")) is not int:
        return {"ok": False, "reason": "rekor evidence is missing logIndex/integratedTime"}
    record = json.loads(base64_decode_flexible(body))
    digest = ((record.get("spec") or {}).get("data") or {}).get("hash") or {}
    if record.get("kind") != "hashedrekord" or digest.get("algorithm") != "sha256":
        return {"ok": False, "reason": "rekor entry body is not a readable hashedrekord"}
    if not isinstance(digest.get("value"), str) or digest["value"].lower() != rekor_payload_hash_for(anchor):
        return {"ok": False, "reason": "rekor entry attests a different payload"}
    if submitter_keys and not _submitted_by_pinned_key(record, anchor, submitter_keys):
        return {"ok": False, "reason": "rekor entry was not submitted under a pinned producer key with a valid signature over this anchor"}
    key = (serialization.load_pem_public_key(rekor_public_key.encode()) if "BEGIN" in rekor_public_key
           else serialization.load_der_public_key(base64_decode_flexible(rekor_public_key)))
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        return {"ok": False, "reason": "rekor public key is not an EC P-256 key"}
    signed = {k: evidence[k] for k in ("body", "integratedTime", "logID", "logIndex") if k in evidence}
    try:
        key.verify(base64_decode_flexible(signature), stable_stringify(signed).encode(), ec.ECDSA(hashes.SHA256()))
    except Exception:
        return {"ok": False, "reason": "rekor SET does not verify under the supplied log key"}
    return {"ok": True, **{k: evidence[k] for k in ("logIndex", "logID", "integratedTime") if k in evidence}}


def _position_mismatch(anchor, expected):
    """Which signed field names a different checkpoint than ``expected``, or None."""
    if not expected:
        return None
    for field, key in (("seqStart", "seqStart"), ("seqEnd", "seqEnd"), ("chainHash", "chainHash"),
                       ("timestamp", "anchoredAt")):
        want = expected.get(key)
        if want is not None and anchor.get(field) != want:
            return field
    return None


@_safe_result("anchor quorum")
def verify_anchor_quorum(anchors, daily_root, policy, resolve_key, *, divergence_anchors=None, external_keys=None,
                         checkpoint=None):
    """Count distinct trusted issuers; only caller-attributed anchors may prove divergence.

    An anchor counts only when its evidence verifies under caller trust, its signed position matches
    ``checkpoint`` where known, and — for an external witness — the witness time lies within
    [-ANCHOR_CLOCK_SKEW_SECONDS, maxAnchorLagSeconds] of the checkpoint's claimed time (DEWP §5.3).
    """
    if (not isinstance(policy, dict) or type(policy.get("requiredAnchors")) is not int
            or policy["requiredAnchors"] < 1 or policy.get("quorum") not in ("ALL_MUST_AGREE", "N_OF_M")
            or not isinstance(policy.get("trustedIssuers"), list)
            or resolve_key is not None and not callable(resolve_key)):
        return {"ok": False, "verifiedIssuers": [], "divergence": False, "reason": "invalid anchor policy or resolver",
                "witnessTimes": {}}
    max_lag = policy.get("maxAnchorLagSeconds", DEFAULT_MAX_ANCHOR_LAG_SECONDS)
    if type(max_lag) not in (int, float):
        return {"ok": False, "verifiedIssuers": [], "divergence": False, "reason": "invalid maxAnchorLagSeconds",
                "witnessTimes": {}}
    trusted = [a for a in anchors if a.get("issuer") in policy["trustedIssuers"]]
    rekor_scope = (external_keys or {}).get("rekor_issuer", (external_keys or {}).get("rekorIssuer"))
    rekor_allowed = lambda issuer: rekor_scope == issuer or rekor_scope is None and len(set(policy["trustedIssuers"])) == 1
    submitter_keys = (external_keys or {}).get("rekorSubmitterKeys") or (external_keys or {}).get("rekor_submitter_keys")

    def verifies(anchor):
        """(ok, witness time in Unix seconds or None)."""
        if not is_well_formed_anchor(anchor):
            return False, None
        kind = anchor.get("kind")
        if kind == "REKOR":
            key = (external_keys or {}).get("rekor")
            evidence = parse_rekor_evidence(anchor.get("evidence"))
            if not (rekor_allowed(anchor.get("issuer")) and key and evidence):
                return False, None
            result = verify_rekor_anchor(evidence, anchor, key, submitter_keys)
            witness = result.get("integratedTime")
            return bool(result["ok"] and type(witness) is int), witness
        if kind == "RFC3161":
            rfc_trust = ((external_keys or {}).get("rfc3161") or {}).get(anchor.get("issuer"))
            if not rfc_trust:
                return False, None
            result = verify_rfc3161_anchor(anchor, rfc_trust)
            witness = result.get("genTime")
            return bool(result["ok"] and type(witness) is int), witness
        if kind in (None, "SELF"):
            key = resolve_key(anchor) if callable(resolve_key) else None
            return bool(key and verify_anchor_signature(anchor, key)), None
        return False, None

    # A NAMED checkpoint without its claimed time leaves only the anchor's producer-chosen timestamp to
    # bound an external witness against, which bounds nothing (DEWP §5.3): such a witness does not count.
    time_unknown = checkpoint is not None and checkpoint.get("anchoredAt") is None
    expected = checkpoint or {}
    def within_bound(anchor, witness):
        """(lag in ms, inside the §5.3 window around the anchor's own signed checkpoint time)."""
        lag_ms = witness * 1000 - parse_anchor_timestamp_ms(anchor["timestamp"])
        return lag_ms, -ANCHOR_CLOCK_SKEW_SECONDS * 1000 <= lag_ms <= max_lag * 1000

    # Divergence is fatal, so its evidence meets the quorum rules (DEWP §5.3): this checkpoint's seq
    # range, an external witness inside the time bound of the anchor's signed time, and — for Rekor,
    # which logs any digest anyone submits — a pinned producer submission key. Chain hash and claimed
    # time are not compared: both commit to the root, so a rewritten checkpoint differs in them.
    for anchor in divergence_anchors or []:
        if anchor.get("issuer") not in policy["trustedIssuers"] or anchor.get("dailyRoot") == daily_root:
            continue
        # A caller-supplied anchor whose own signed range names another checkpoint is not divergence.
        if (expected.get("seqStart") is not None and anchor.get("seqStart") != expected["seqStart"]) or (
                expected.get("seqEnd") is not None and anchor.get("seqEnd") != expected["seqEnd"]):
            continue
        if anchor.get("kind") == "REKOR" and not submitter_keys:
            continue
        valid, witness = verifies(anchor)
        if valid and witness is not None and not within_bound(anchor, witness)[1]:
            continue
        if valid:
            return {"ok": False, "verifiedIssuers": [], "divergence": True,
                    "reason": "anchor divergence: trusted issuer signed a different root for this checkpoint",
                    "witnessTimes": {}}
    verified, tsa_unverified, notes, witness_times = [], 0, [], {}
    for anchor in trusted:
        if anchor.get("dailyRoot") != daily_root:
            continue
        mismatch = _position_mismatch(anchor, expected)
        if mismatch:
            notes.append(f"anchor from {anchor.get('issuer')} binds a different checkpoint {mismatch}; it does not count")
            continue
        valid, witness = verifies(anchor)
        if not valid:
            if anchor.get("kind") == "RFC3161":
                tsa_unverified += 1
            continue
        if witness is not None:
            issuer = anchor["issuer"]
            witness_times[issuer] = min(witness_times.get(issuer, witness), witness)
            if time_unknown:
                notes.append(f"anchor from {issuer} has an external witness time but no trusted checkpoint time "
                             "to hold it to (DEWP §5.3); it does not count")
                continue
            lag_ms, inside = within_bound(anchor, witness)
            if not inside:
                notes.append(f"anchor from {issuer} was witnessed {round(lag_ms / 1000)}s from its checkpoint time; "
                             "it does not count")
                continue
        if anchor["issuer"] not in verified:
            verified.append(anchor["issuer"])
    if tsa_unverified:
        notes.append(f"{tsa_unverified} RFC 3161 TSA anchor(s) not verified; configure RFC3161 trust/OpenSSL or inspect evidence")
    present = len({a["issuer"] for a in trusted if a.get("dailyRoot") == daily_root})
    required = max(policy["requiredAnchors"], present) if policy["quorum"] == "ALL_MUST_AGREE" else policy["requiredAnchors"]
    result = {"ok": len(verified) >= required, "verifiedIssuers": verified, "divergence": False,
              "witnessTimes": witness_times}
    if not result["ok"]:
        result["reason"] = f"anchor quorum not met ({len(verified)}/{required})"
    if notes:
        result["note"] = "; ".join(notes)
    return result


def chain_preimage(entry) -> str:
    values = [entry["prevChainHash"], entry["root"], entry["seqStart"], entry["seqEnd"],
              str(entry["entryCount"]), entry["anchoredAt"]]
    return json.dumps(values, ensure_ascii=False, separators=(",", ":"))


def chain_hash(entry) -> str:
    return hashlib.sha256(CHAIN_TAG + chain_preimage(entry).encode()).hexdigest()


@_safe_result("roots chain")
def verify_roots_chain(entries):
    def fail(index, reason, count=0):
        return {"ok": False, "verifiedCount": count, "brokenAt": index, "unchained": False, "reason": reason}
    if not isinstance(entries, list):
        return fail(-1, "entries must be an array")
    if not entries:
        return {"ok": True, "verifiedCount": 0, "brokenAt": -1, "unchained": False}
    chained = [e for e in entries if "chainHash" in e]
    if not chained:
        return {"ok": False, "verifiedCount": 0, "brokenAt": -1, "unchained": True,
                "reason": "roots file carries no chain hashes; continuity cannot be checked"}
    if len(chained) != len(entries):
        return fail(next(i for i, e in enumerate(entries) if "chainHash" not in e), "roots file mixes chained and unchained entries")
    previous = None
    for index, entry in enumerate(entries):
        predecessor = previous["chainHash"] if previous is not None else GENESIS_PREV_CHAIN_HASH
        declared = entry.get("prevChainHash", GENESIS_PREV_CHAIN_HASH)
        if declared != predecessor:
            return fail(index, "chain link broken", index)
        if chain_hash({**entry, "prevChainHash": declared}) != entry["chainHash"]:
            return fail(index, "chain hash mismatch", index)
        # The entry's OWN range is checked unconditionally: a non-integer or self-inverted range is
        # malformed wherever it sits, and gating it on a predecessor left the FIRST entry unchecked,
        # so a single-entry roots file was never range-checked. Only the overlap check is relational.
        try:
            start, end = int(entry["seqStart"]), int(entry["seqEnd"])
        except (TypeError, ValueError):
            return fail(index, "non-integer seq range", index)
        if end < start:
            return fail(index, "seq range inverted", index)
        if previous is not None and start <= int(previous["seqEnd"]):
            return fail(index, "seq ranges overlap or regress", index)
        previous = entry
    return {"ok": True, "verifiedCount": len(entries), "brokenAt": -1, "unchained": False}


def _counter(value):
    return int(value) if isinstance(value, str) and re.fullmatch(r"-?[0-9]{1,20}", value) else None


def leaf_count_mismatch(proof, entry_count):
    """Why a proof's prover-supplied leaf counts cannot belong to a checkpoint committing
    ``entry_count`` events (the sum of its blocks' leaf counts), or None (DEWP §17.3)."""
    if type(entry_count) is not int or entry_count < 0:
        return None
    block, cps = proof.get("blockLeafCount"), proof.get("checkpointLeafCount")
    if type(block) is not int or type(cps) is not int:
        return None
    if cps > entry_count or block + cps - 1 > entry_count or (cps == 1 and block != entry_count):
        return (f"proof claims {block} leaves in its block and {cps} block(s) under the checkpoint, which "
                f"cannot sum to the checkpoint's {entry_count} committed events")
    return None


@_safe_result("evidence bundle")
def verify_evidence_bundle(bundle, *, trusted_roots=None, anchors=None, anchor_policy=None,
                           resolve_anchor_key=None, external_keys=None, trusted_checkpoints=None,
                           signature_policy=None, require_signatures=False):
    """Verify a multi-event export, including committed counters and optional anchor quorum.

    ``trusted_checkpoints`` are checkpoint records YOU hold (chain-verified roots-file lines, DEWP
    §5.4.1). Their roots are trusted roots; a bundle checkpoint over one must agree with it on every
    field both state, and anchors are held to the record's range, chain hash and time (§5.3).
    """
    from .ledger import AUDIT_PROFILE, _supported_envelope
    failed, notes, roots = [], [], []
    content, commitment, redacted = 0, 0, 0
    signatures = {"verified": 0, "invalid": [], "notCheckable": 0}
    signature_checks = {}
    entries, checkpoints = bundle["entries"], bundle["checkpoints"]
    if not isinstance(entries, list) or not isinstance(checkpoints, list):
        raise ValueError("entries/checkpoints must be arrays")
    if bundle.get("kind") != EVIDENCE_BUNDLE_KIND or not _supported_envelope(bundle):
        failed.append({"seq": "-", "reason": "refusing bundle kind"})
    unknown = "profile" in bundle and bundle["profile"] != AUDIT_PROFILE
    if unknown:
        notes.append("Unknown canonical profile; content cannot be bound to its leaf, so an entry carrying a "
                     "preimage fails")
    records = {}
    for record in trusted_checkpoints or []:
        records.setdefault(record["root"], record)
    trusted = None
    if trusted_roots is not None or trusted_checkpoints is not None:
        trusted = set(trusted_roots or []) | set(records)
    if trusted is None:
        notes.append("No roots supplied; only internal consistency can be checked — use roots obtained "
                     "earlier or from the published roots file")
    # §5.4 chain fields, where the export carries them: the chain hash must recompute from the
    # checkpoint's own fields, since every anchor binds it (§5.2).
    for cp in checkpoints:
        if cp.get("chainHash") is None:
            continue
        complete = (isinstance(cp.get("prevChainHash"), str) and isinstance(cp.get("anchoredAt"), str)
                    and type(cp.get("entryCount")) is int)
        recomputed = chain_hash({**cp, "prevChainHash": cp["prevChainHash"]}) if complete else None
        if recomputed != cp["chainHash"]:
            failed.append({"seq": "-", "reason": f"checkpoint {cp.get('id')} chainHash does not recompute"
                           if complete else f"checkpoint {cp.get('id')} chainHash lacks the fields it commits to"})
    # A checkpoint the caller holds a record for must agree with it on every field both state: a
    # re-dated anchoredAt with a self-consistent chain over a made-up predecessor recomputes above.
    for cp in checkpoints:
        record = records.get(cp["root"])
        if record is None:
            continue
        for field in ("seqStart", "seqEnd", "entryCount", "anchoredAt", "chainHash"):
            shown, held = cp.get(field), record.get(field)
            if shown is not None and held is not None and shown != held:
                failed.append({"seq": "-", "reason": f"checkpoint {cp.get('id')} {field} contradicts your "
                               "trusted checkpoint record for its root"})
    known = {cp["root"]: cp.get("anchorRef") for cp in checkpoints}
    by_root = {}
    for cp in checkpoints:
        by_root.setdefault(cp["root"], cp)

    def effective(root):
        """The position and time anchors over ``root`` are held to: the caller's record where it states
        a field, the bundle's checkpoint otherwise."""
        cp, record = by_root.get(root) or {}, records.get(root) or {}
        return {k: record.get(k) if record.get(k) is not None else cp.get(k)
                for k in ("seqStart", "seqEnd", "chainHash", "anchoredAt", "entryCount")}

    bundle_anchors = {cp["root"]: cp["anchors"] for cp in checkpoints if cp.get("anchors")}
    lookup = {cp["id"]: cp["root"] for cp in checkpoints if cp.get("id")}
    lookup.update({root: root for root in known})
    caller, attributed, unattributed = [], {}, False
    keyed = isinstance(anchors, dict)
    if isinstance(anchors, list):
        caller.extend(anchors)
    elif keyed:
        for key, values in anchors.items():
            if not isinstance(values, list) or not values:
                continue
            caller.extend(values)
            if key not in lookup:
                unattributed = True
            else:
                attributed.setdefault(lookup[key], []).extend(values)
    tenant = (bundle.get("tenant") or {}).get("id")
    seen_leaves, seen_seqs, block_counts, checkpoint_counts = set(), set(), {}, {}
    for entry in entries:
        event, proof = entry["event"], entry["proof"]
        seq, root, canonical = event["seq"], proof.get("checkpointRoot"), event.get("canonical")
        # One committed event appears once; a genuine leaf used twice can otherwise fill two holes.
        if proof.get("leaf") in seen_leaves or seq in seen_seqs:
            failed.append({"seq": seq, "reason": "duplicate entry: this leaf or seq already appears in the bundle"})
            continue
        seen_leaves.add(proof.get("leaf"))
        seen_seqs.add(seq)
        reason = None
        if not root:
            reason = "no checkpoint root"
        elif root not in known:
            reason = "proof's checkpoint root is not in the bundle's checkpoint list"
        elif trusted is not None and root not in trusted:
            reason = "proof's checkpoint root is not among supplied trusted roots"
        elif not verify_inclusion_proof(proof, root):
            reason = "inclusion proof does not recompute to the daily root"
        elif ((root in checkpoint_counts and checkpoint_counts[root] != proof.get("checkpointLeafCount"))
              or (proof.get("blockRoot") in block_counts
                  and block_counts[proof.get("blockRoot")] != proof.get("blockLeafCount"))):
            # DEWP §17.3: leaf counts are prover-supplied; bind them to each other and to the entry count.
            reason = "proofs into the same block or checkpoint disagree on its leaf count"
        else:
            reason = leaf_count_mismatch(proof, effective(root)["entryCount"])
        if reason:
            failed.append({"seq": seq, "reason": reason})
            continue
        block_counts[proof.get("blockRoot")] = proof.get("blockLeafCount")
        checkpoint_counts[root] = proof.get("checkpointLeafCount")
        redaction = event.get("redaction")
        is_redacted = redaction.get("mode") == "COMMITMENT_ONLY" if redaction else event.get("redacted") is True
        if is_redacted and canonical is None:
            retained = (redaction.get("commitment") or {}).get("leaf") if redaction else None
            if retained is not None and retained != proof["leaf"]:
                failed.append({"seq": seq, "reason": "redaction commitment leaf does not match the proof leaf"})
                continue
            redacted += 1
            commitment += 1
        elif unknown and canonical is not None:
            # A preimage cannot be bound under a layout this verifier does not implement, and passing it
            # would let the producer switch leaf binding off (DEWP §4.5/§7.2 rule 1).
            failed.append({"seq": seq, "reason": "canonical preimage under an unknown profile cannot be bound to its leaf"})
            continue
        elif unknown:
            commitment += 1
        elif canonical is not None:
            if leaf_hash(canonical) != proof["leaf"]:
                failed.append({"seq": seq, "reason": "leaf binding failed"})
                continue
            mismatch = next((field for field in ("seq", "createdAt", "type", "outcome", "signerDid", "sigAlg", "tenantSeq")
                if event.get(field) is not None and str(event[field]) != str(canonical.get("event" if field == "type" else field))), None)
            if mismatch:
                failed.append({"seq": seq, "reason": f"displayed {mismatch} does not match committed value"})
                continue
            # The redaction record is unsigned and is no counter source where a preimage exists (§7.2).
            recorded = ((redaction or {}).get("commitment") or {}).get("tenantSeq")
            if recorded is not None and recorded != canonical.get("tenantSeq"):
                failed.append({"seq": seq, "reason": "redaction record tenantSeq does not match the committed value"})
                continue
            # A bundle naming no tenant has none for a tenant-bound entry to belong to.
            if canonical.get("tenantId") is not None and canonical["tenantId"] != tenant:
                failed.append({"seq": seq, "reason": "entry belongs to another tenant"})
                continue
            check = verify_audit_signature(canonical, signature_policy)
            signature_checks[seq] = check
            if check["status"] == "verified":
                signatures["verified"] += 1
            elif check["status"] == "invalid":
                signatures["invalid"].append({"seq": seq})
            else:
                signatures["notCheckable"] += 1
            content += 1
        else:
            failed.append({"seq": seq, "reason": "unredacted entry is missing its canonical preimage"})
    # An entry WITH a preimage reads its counter from it alone — None means no counter (§7.2 rule 5);
    # only an entry without one falls back to the unsigned redaction record and display copy (rule 2).
    first, last, uncounted, unbound = None, None, False, False
    for entry in entries:
        event = entry["event"]
        canonical = event.get("canonical")
        if canonical is not None:
            if unknown:
                continue  # not leaf-bound under an unknown profile; that entry already failed
            value = canonical.get("tenantSeq")
        else:
            value = ((event.get("redaction") or {}).get("commitment") or {}).get("tenantSeq")
            if value is None:
                value = event.get("tenantSeq")
            if value is not None:
                unbound = True
        if value is None:
            uncounted = True
            continue
        counter = _counter(value)
        if counter is None:
            failed.append({"seq": event["seq"], "reason": "tenantSeq is not a valid integer counter"})
            continue
        if last is not None and counter != last + 1:
            reason = "per-tenant sequence is not strictly increasing" if counter <= last else "per-tenant omission detected: sequence gap"
            failed.append({"seq": event["seq"], "reason": reason})
        if first is None:
            first = counter
        last = counter
    if redacted:
        notes.append("COMMITMENT_ONLY entries: displayed content rests on the producer's redaction record, not the anchored log")
    if uncounted:
        notes.append("Some entries carry no tenantSeq; gapless completeness could not be checked across them")
    if unbound:
        notes.append("Some entries carry no canonical preimage (COMMITMENT_ONLY), so their tenantSeq was read from "
                     "the redaction record or display copy and is NOT covered by the Merkle leaf")
    declared = bundle.get("tenantSequenceCommitment")
    if declared:
        if first is None or last is None:
            notes.append("tenantSequenceCommitment declared but no entry carries a counter")
        else:
            low, high = _counter(declared.get("firstTenantSeq")), _counter(declared.get("lastTenantSeq"))
            if low is None or high is None:
                failed.append({"seq": entries[0]["event"]["seq"], "reason": "tenantSequenceCommitment has non-numeric endpoints"})
            else:
                if first != low:
                    failed.append({"seq": entries[0]["event"]["seq"], "reason": "bundle start differs from declared tenant sequence"})
                if last != high:
                    failed.append({"seq": entries[-1]["event"]["seq"], "reason": "bundle end differs from declared tenant sequence"})
            if declared.get("tenantId") != tenant:
                notes.append("tenantSequenceCommitment names a different tenant")
    external_check = bool(external_keys and (external_keys.get("rekor") or external_keys.get("rfc3161")))
    can_check = bool(anchor_policy and (callable(resolve_anchor_key) or external_check))
    for root, reference in known.items():
        if not can_check:
            roots.append({"root": root, "anchorRef": reference, "anchorVerified": None, "verifiedIssuers": [],
                          "witnessTimes": {}})
            continue
        position = effective(root)
        expected = {k: position[k] for k in ("seqStart", "seqEnd", "chainHash", "anchoredAt")}
        # §5.3/§6.3: a checkpoint stating no chain hash or time (and no record supplying them) cannot
        # hold its anchors to anything, so it never counts as anchored. Divergence is still evaluated.
        position_unknown = expected["chainHash"] is None or expected["anchoredAt"] is None
        if position_unknown:
            notes.append(f"checkpoint for root {root[:16]}… carries no chainHash/anchoredAt and no trusted checkpoint "
                         "record supplies them; its anchors cannot be held to a position and time (DEWP §5.3), so it "
                         "is not anchored")
        candidates = caller if caller else bundle_anchors.get(root, [])
        divergence = attributed.get(root, []) if keyed else [a for a in caller if a.get("dailyRoot") == root or a.get("dailyRoot") not in known]
        verdict = verify_anchor_quorum(candidates, root, anchor_policy, resolve_anchor_key,
            divergence_anchors=divergence, external_keys=external_keys, checkpoint=expected)
        if verdict["divergence"]:
            failed.append({"seq": "-", "reason": "ANCHOR DIVERGENCE: " + verdict["reason"]})
        elif not verdict["ok"]:
            notes.append(verdict.get("reason", "anchor quorum not met"))
        if verdict.get("note"):
            notes.append(verdict["note"])
        roots.append({"root": root, "anchorRef": reference, "anchorVerified": verdict["ok"] and not position_unknown,
                      "verifiedIssuers": [] if position_unknown else verdict["verifiedIssuers"],
                      "witnessTimes": verdict.get("witnessTimes") or {}})
    if can_check and not caller and bundle_anchors:
        notes.append("Anchors carried in the bundle were checked under caller keys; divergence requires caller-fetched anchors")
    if can_check and caller and not keyed and len(known) > 1:
        notes.append("Flat caller anchor list spans multiple checkpoints; key anchors by checkpoint for exact divergence attribution")
    if unattributed:
        notes.append("Some caller anchor keys name unknown checkpoints; they cannot establish divergence")
    if not can_check:
        notes.append("No complete anchor policy or caller trust supplied; no anchor quorum evaluated")
    signatures["checks"] = [{"seq": e["event"]["seq"], **signature_checks.get(e["event"]["seq"], unchecked_signature())} for e in entries]
    if require_signatures:
        for check in signatures["checks"]:
            if check["status"] != "verified" or not check["trusted"]:
                failed.append({"seq": check["seq"], "reason": "Required trusted signature: " + check["reason"]})
    if signatures["invalid"]:
        notes.append("Committed signature material does not verify; this is not bundle tampering")
    all_anchored = anchor_policy is None or (can_check and all(r["anchorVerified"] is True for r in roots))
    return {"ok": not failed and bool(entries) and trusted is not None and all_anchored,
            "total": len(entries), "contentVerified": content, "commitmentOnly": commitment,
            "failed": failed, "roots": roots, "signatures": signatures, "notes": notes}
