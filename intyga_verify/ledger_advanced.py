"""DEWP bundle, anchor and continuity checks, mirroring the TypeScript reference.

All trust inputs come from the caller. A producer's anchoring claims never establish trust.
This module is re-exported by ``ledger``; it does not perform network requests.
"""
import functools
import hashlib
import json
import re
from typing import Any, Dict

from .ledger import anchor_digest_hex, leaf_hash, verify_anchor_signature, verify_inclusion_proof

EVIDENCE_BUNDLE_KIND = "dewp.audit.evidence-bundle"
CHAIN_TAG = b"\x04"
GENESIS_PREV_CHAIN_HASH = ""


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
                    return {"ok": False, "verifiedIssuers": [], "divergence": False, "reason": reason}
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


@_safe_result("Rekor evidence")
def verify_rekor_anchor(evidence, anchor, rekor_public_key: str):
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


@_safe_result("anchor quorum")
def verify_anchor_quorum(anchors, daily_root, policy, resolve_key, *, divergence_anchors=None, external_keys=None):
    """Count distinct trusted issuers; only caller-attributed anchors may prove divergence."""
    if (not isinstance(policy, dict) or type(policy.get("requiredAnchors")) is not int
            or policy["requiredAnchors"] < 1 or policy.get("quorum") not in ("ALL_MUST_AGREE", "N_OF_M")
            or not isinstance(policy.get("trustedIssuers"), list) or not callable(resolve_key)):
        return {"ok": False, "verifiedIssuers": [], "divergence": False, "reason": "invalid anchor policy or resolver"}
    trusted = [a for a in anchors if a.get("issuer") in policy["trustedIssuers"]]
    for anchor in divergence_anchors or []:
        if anchor.get("issuer") not in policy["trustedIssuers"] or anchor.get("dailyRoot") == daily_root:
            continue
        key = resolve_key(anchor)
        if key and verify_anchor_signature(anchor, key):
            return {"ok": False, "verifiedIssuers": [], "divergence": True,
                    "reason": "anchor divergence: trusted issuer signed a different root for this checkpoint"}
    verified, tsa_count = [], 0
    for anchor in trusted:
        if anchor.get("dailyRoot") != daily_root:
            continue
        kind = anchor.get("kind")
        valid = False
        if kind == "REKOR":
            key = (external_keys or {}).get("rekor")
            evidence = parse_rekor_evidence(anchor.get("evidence"))
            valid = bool(key and evidence and verify_rekor_anchor(evidence, anchor, key)["ok"])
        elif kind == "RFC3161":
            tsa_count += 1
        elif kind in (None, "SELF"):
            key = resolve_key(anchor)
            valid = bool(key and verify_anchor_signature(anchor, key))
        if valid and anchor["issuer"] not in verified:
            verified.append(anchor["issuer"])
    present = len({a["issuer"] for a in trusted if a.get("dailyRoot") == daily_root})
    required = max(policy["requiredAnchors"], present) if policy["quorum"] == "ALL_MUST_AGREE" else policy["requiredAnchors"]
    result = {"ok": len(verified) >= required, "verifiedIssuers": verified, "divergence": False}
    if not result["ok"]:
        result["reason"] = f"anchor quorum not met ({len(verified)}/{required})"
    if tsa_count:
        result["note"] = f"{tsa_count} RFC 3161 TSA anchor(s) present but not verifiable by this tool; verify out of band"
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


@_safe_result("evidence bundle")
def verify_evidence_bundle(bundle, *, trusted_roots=None, anchors=None, anchor_policy=None,
                           resolve_anchor_key=None, external_keys=None):
    """Verify a multi-event export, including committed counters and optional anchor quorum."""
    from .ledger import AUDIT_PROFILE
    failed, notes, roots = [], [], []
    content, commitment, redacted = 0, 0, 0
    signatures = {"verified": 0, "invalid": [], "notCheckable": 0}
    entries, checkpoints = bundle["entries"], bundle["checkpoints"]
    if not isinstance(entries, list) or not isinstance(checkpoints, list):
        raise ValueError("entries/checkpoints must be arrays")
    if bundle.get("kind") != EVIDENCE_BUNDLE_KIND:
        failed.append({"seq": "-", "reason": "refusing bundle kind"})
    unknown = "profile" in bundle and bundle["profile"] != AUDIT_PROFILE
    if unknown:
        notes.append("Unknown canonical profile; content cannot be bound to its leaf")
    trusted = set(trusted_roots) if trusted_roots is not None else None
    if trusted is None:
        notes.append("No independent roots supplied; only internal consistency can be checked")
    known = {cp["root"]: cp.get("anchorRef") for cp in checkpoints}
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
    for entry in entries:
        event, proof = entry["event"], entry["proof"]
        seq, root, canonical = event["seq"], proof.get("checkpointRoot"), event.get("canonical")
        reason = None
        if not root:
            reason = "no checkpoint root"
        elif root not in known:
            reason = "proof's checkpoint root is not in the bundle's checkpoint list"
        elif trusted is not None and root not in trusted:
            reason = "proof's checkpoint root is not among supplied trusted roots"
        elif not verify_inclusion_proof(proof, root):
            reason = "inclusion proof does not recompute to the daily root"
        if reason:
            failed.append({"seq": seq, "reason": reason})
            continue
        redaction = event.get("redaction")
        is_redacted = redaction.get("mode") == "COMMITMENT_ONLY" if redaction else event.get("redacted") is True
        if is_redacted and canonical is None:
            retained = (redaction.get("commitment") or {}).get("leaf") if redaction else None
            if retained is not None and retained != proof["leaf"]:
                failed.append({"seq": seq, "reason": "redaction commitment leaf does not match the proof leaf"})
                continue
            redacted += 1
            commitment += 1
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
            tenant = (bundle.get("tenant") or {}).get("id")
            if canonical.get("tenantId") is not None and tenant is not None and canonical["tenantId"] != tenant:
                failed.append({"seq": seq, "reason": "entry belongs to another tenant"})
                continue
            if canonical.get("sigAlg") == "ES256" and canonical.get("signature") and canonical.get("signerPublicKey"):
                if verify_embedded_signature(canonical):
                    signatures["verified"] += 1
                else:
                    signatures["invalid"].append({"seq": seq})
            else:
                signatures["notCheckable"] += 1
            content += 1
        else:
            failed.append({"seq": seq, "reason": "unredacted entry is missing its canonical preimage"})
    first, last, uncounted, unbound = None, None, False, False
    for entry in entries:
        event = entry["event"]
        bound = (event.get("canonical") or {}).get("tenantSeq")
        value = bound
        if value is None:
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
        notes.append("Some tenantSeq counters are NOT covered by the Merkle leaf; gaplessness rests on redaction records")
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
            if declared.get("tenantId") != (bundle.get("tenant") or {}).get("id"):
                notes.append("tenantSequenceCommitment names a different tenant")
    can_check = bool(anchor_policy and callable(resolve_anchor_key))
    for root, reference in known.items():
        if not can_check:
            roots.append({"root": root, "anchorRef": reference, "anchorVerified": None, "verifiedIssuers": []})
            continue
        candidates = caller if caller else bundle_anchors.get(root, [])
        divergence = attributed.get(root, []) if keyed else [a for a in caller if a.get("dailyRoot") == root or a.get("dailyRoot") not in known]
        verdict = verify_anchor_quorum(candidates, root, anchor_policy, resolve_anchor_key,
            divergence_anchors=divergence, external_keys=external_keys)
        if verdict["divergence"]:
            failed.append({"seq": "-", "reason": "ANCHOR DIVERGENCE: " + verdict["reason"]})
        elif not verdict["ok"]:
            notes.append(verdict.get("reason", "anchor quorum not met"))
        if verdict.get("note"):
            notes.append(verdict["note"])
        roots.append({"root": root, "anchorRef": reference, "anchorVerified": verdict["ok"], "verifiedIssuers": verdict["verifiedIssuers"]})
    if can_check and not caller and bundle_anchors:
        notes.append("Anchors carried in the bundle were checked under caller keys; divergence requires caller-fetched anchors")
    if can_check and caller and not keyed and len(known) > 1:
        notes.append("Flat caller anchor list spans multiple checkpoints; key anchors by checkpoint for exact divergence attribution")
    if unattributed:
        notes.append("Some caller anchor keys name unknown checkpoints; they cannot establish divergence")
    if not can_check:
        notes.append("No complete anchor policy/resolver supplied; no anchor quorum evaluated")
    if signatures["invalid"]:
        notes.append("Committed ES256 signature material does not verify; this is not bundle tampering")
    all_anchored = anchor_policy is None or (can_check and all(r["anchorVerified"] is True for r in roots))
    return {"ok": not failed and bool(entries) and trusted is not None and all_anchored,
            "total": len(entries), "contentVerified": content, "commitmentOnly": commitment,
            "failed": failed, "roots": roots, "signatures": signatures, "notes": notes}
