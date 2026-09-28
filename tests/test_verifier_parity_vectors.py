"""Consume the same executable verifier fixtures as TS, Go, Rust, and Java."""
import json
import unittest
from datetime import datetime
from pathlib import Path

import intyga_verify


VECTORS = Path(__file__).parents[1] / "vectors" / "verifier-parity-vectors.json"
CANONICAL_VECTORS = Path(__file__).parents[1] / "vectors" / "canonical-vectors.json"


def _load():
    return json.loads(VECTORS.read_text(encoding="utf-8"))


def _at(raw):
    return datetime.fromisoformat(raw.replace("Z", "+00:00"))


def _keys(vectors):
    return {item["id"]: item for item in vectors["keys"]}


def _approvers(ids, keys):
    return {"publicKeys": [keys[key_id].get("coseB64", keys[key_id]["spkiB64"]) for key_id in ids]}


def _did_approvers(table, keys):
    return {
        "dids": list(table),
        "resolveKey": lambda did: [keys[key_id]["spkiB64"] for key_id in table.get(did, [])],
    }


def _external_keys(options, keys):
    if not options.get("rekorKeyId"):
        return None
    return {
        "rekor": keys[options["rekorKeyId"]]["spkiB64"],
        **({"rekor_issuer": options["rekorIssuer"]} if options.get("rekorIssuer") else {}),
        **({"rekorSubmitterKeys": [keys[k]["spkiB64"] for k in options["rekorSubmitterKeyIds"]]}
           if options.get("rekorSubmitterKeyIds") else {}),
    }


def _run_bundle_cases(cases, keys, default_policy):
    """``default_policy`` is the `bundles` section's; the hardening section applies a policy only when a
    case carries one."""
    for case in cases:
        options = case.get("options", {})
        result = intyga_verify.ledger.verify_bundle(
            case["bundle"], trusted_root=options.get("trustedRoot"),
            anchors=options.get("divergenceAnchors"), anchor_policy=case.get("policy", default_policy),
            resolve_anchor_key=lambda anchor: keys.get(anchor.get("keyId"), {}).get("spkiB64"),
            external_keys=_external_keys(options, keys),
            trusted_checkpoint=options.get("trustedCheckpoint"),
        )
        assert result["ok"] is case["ok"], f'{case["name"]}: {result.get("notes")}'
        if "verificationLevel" in case:
            assert result["verificationLevel"] == case["verificationLevel"], case["name"]
        if "witnessTimes" in case:
            assert result["witnessTimes"] == case["witnessTimes"], case["name"]
        for prop, expected in case.get("properties", {}).items():
            assert result["properties"][prop] is expected, f'{case["name"]}:{prop}'


def _run_evidence_cases(cases, keys):
    for case in cases:
        options = case.get("options", {})
        result = intyga_verify.ledger.verify_evidence_bundle(
            case["bundle"], trusted_roots=options.get("trustedRoots"),
            trusted_checkpoints=options.get("trustedCheckpoints"),
            anchors=options.get("anchors"), anchor_policy=case.get("policy"),
            resolve_anchor_key=(lambda anchor: keys.get(anchor.get("keyId"), {}).get("spkiB64")) if case.get("policy") else None,
            external_keys=_external_keys(options, keys),
        )
        assert result["ok"] is case["ok"], f'{case["name"]}: {result.get("failed")} {result.get("notes")}'
        for prop in ("total", "contentVerified", "commitmentOnly"):
            if prop in case:
                assert result[prop] == case[prop], case["name"]


def _run_approval_cases(section, keys):
    for case in section["cases"]:
        raw = {**section["expected"], **case.get("expected", {})}
        # A WEBAUTHN witness verifies under the credential's COSE_Key; such cases say so explicitly.
        encoding = "coseB64" if case.get("approverKeyEncoding") == "cose" else "spkiB64"
        expected = {**raw, "approvers": {
            "publicKeys": [keys[key_id][encoding] for key_id in raw["approverKeyIds"]]
        }}
        options = {**section["options"], **case.get("options", {})}
        result = intyga_verify.verify_approval_receipt(
            case["receipt"], expected, as_of=_at(options["asOf"]),
            clock_skew_seconds=options.get("clockSkewSeconds", 30),
            allow_offline=options.get("allowOffline", False),
            expected_origin=options.get("expectedOrigin"),
            expected_rp_id=options.get("expectedRpId"),
            require_user_verification=options.get("requireUserVerification", True),
        )
        assert result["ok"] is case["ok"], f'{case["name"]}: {result.get("reason")}'
        if "signers" in case:
            assert result.get("signers") == case["signers"], case["name"]
        if "reasonIncludes" in case:
            assert case["reasonIncludes"] in result.get("reason", ""), f'{case["name"]}: {result.get("reason")}'


def _run_platform_cases(section, keys):
    for case in section["cases"]:
        raw = {**section["expected"], **case.get("expected", {})}
        expected = {**raw, "approvers": _approvers(raw["approverKeyIds"], keys)}
        options = {**section["options"], **case.get("options", {})}
        result = intyga_verify.verify_platform_receipt(
            case["receipt"], expected,
            expected_origin=options["expectedOrigin"], as_of=_at(options["asOf"]),
            clock_skew_seconds=options.get("clockSkewSeconds", 30),
            require_user_verification=options.get("requireUserVerification", True),
        )
        assert result["ok"] is case["ok"], f'{case["name"]}: {result.get("reason")}'
        if "signers" in case:
            assert result.get("signers") == case["signers"], case["name"]
        if "reasonIncludes" in case:
            assert case["reasonIncludes"] in result.get("reason", ""), f'{case["name"]}: {result.get("reason")}'


def _run_authority_cases(section, keys):
    for case in section["cases"]:
        raw = {**section["expected"], **case.get("expected", {})}
        expected = {**raw, "approvers": _approvers(raw["approverKeyIds"], keys) if "approverKeyIds" in raw else _did_approvers(raw["approverDids"], keys)}
        options = {**section["options"], **case.get("options", {})}
        result = intyga_verify.verify_agent_authority(
            case["receipt"], expected, as_of=_at(options["asOf"]),
            clock_skew_seconds=options.get("clockSkewSeconds", 30),
        )
        assert result["ok"] is case["ok"], f'{case["name"]}: {result.get("reason")}'
        if "signers" in case:
            assert result["authority"]["signers"] == case["signers"], case["name"]
        if "actionPatterns" in case:
            assert result["authority"]["actionPatterns"] == case["actionPatterns"], case["name"]
        if "reasonIncludes" in case:
            assert case["reasonIncludes"] in result.get("reason", ""), f'{case["name"]}: {result.get("reason")}'


class TestVerifierParityVectors(unittest.TestCase):
  def test_approval_signature_algorithm_and_four_eyes_vectors(self):
    vectors = _load()
    _run_approval_cases(vectors["approvals"], _keys(vectors))

  def test_agent_authority_and_platform_canonical_vectors(self):
    vectors = json.loads(CANONICAL_VECTORS.read_text(encoding="utf-8"))
    for item in vectors["agentAuthorityPayloads"]:
        raw = item["input"]
        self.assertEqual(
            intyga_verify.canonical_agent_authority_payload(
                target=raw["target"], action_patterns=raw["actionPatterns"],
                display=raw["actionDescription"], agent={"did": raw["agentDid"]},
                requester=raw["requester"], requirement=raw["requirement"],
                nonce=raw["nonce"], sealed_at=raw["sealedAt"], expires_at=raw["expiresAt"],
                parent_receipt_hash=raw["parentReceiptHash"]
            ), item["expected"]
        )
    for item in vectors["platformIntentPayloads"]["cases"]:
        raw = item["input"]
        self.assertEqual(intyga_verify.canonical_platform_intent_payload(
            payload_hash=raw["payloadHash"], rp_id=raw["rpId"],
            subject_external_id=raw["subjectExternalId"], signed_at=raw["signedAt"],
            expires_at=raw["expiresAt"], nonce=raw["nonce"]
        ), item["expected"])

  def test_platform_and_agent_authority_vectors(self):
    vectors = _load()
    keys = _keys(vectors)
    _run_platform_cases(vectors["platform"], keys)
    _run_authority_cases(vectors["agentAuthority"], keys)

  def test_verifier_input_hardening_vectors(self):
    # 2026-09-27 review L15-L18, I7, I8. Its own keys; the same harness as the sections of the same
    # names, except that a bundle case's policy applies only when present.
    section = _load()["verifierInputHardening"]
    for part in ("approvals", "platform", "agentAuthority", "bundles"):
        assert section[part]["cases"], part
    keys = {item["id"]: item for item in section["keys"]}
    _run_approval_cases(section["approvals"], keys)
    _run_platform_cases(section["platform"], keys)
    _run_authority_cases(section["agentAuthority"], keys)
    _run_bundle_cases(section["bundles"]["cases"], keys, None)

  def test_bundle_anchor_rekor_and_evidence_vectors(self):
    vectors = _load()
    keys = _keys(vectors)
    _run_bundle_cases(vectors["bundles"]["cases"], keys, vectors["bundles"]["anchorPolicy"])
    _run_evidence_cases(vectors["evidence"]["cases"], keys)

  def test_dewp_evidence_hardening_vectors(self):
    # Its own keys; a policy applies only when a case carries one.
    section = _load()["dewpEvidenceHardening"]
    assert section["bundles"]["cases"] and section["evidence"]["cases"]
    keys = {item["id"]: item for item in section["keys"]}
    _run_bundle_cases(section["bundles"]["cases"], keys, None)
    _run_evidence_cases(section["evidence"]["cases"], keys)


  def test_checkpoint_continuity_vectors(self):
    vectors = _load()
    for case in vectors["rootsChain"]["cases"]:
        result = intyga_verify.ledger.verify_roots_chain(case["entries"])
        assert result["ok"] is case["ok"], case["name"]
        assert result["brokenAt"] == case["brokenAt"]
        assert result["unchained"] is case["unchained"]
        if "verifiedCount" in case:
            assert result["verifiedCount"] == case["verifiedCount"]


if __name__ == "__main__":
    unittest.main()
