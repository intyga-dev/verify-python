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


class TestVerifierParityVectors(unittest.TestCase):
  def test_approval_signature_algorithm_and_four_eyes_vectors(self):
    vectors = _load()
    keys = _keys(vectors)
    section = vectors["approvals"]
    for case in section["cases"]:
        raw = {**section["expected"], **case.get("expected", {})}
        expected = {**raw, "approvers": {
            "publicKeys": [keys[key_id]["spkiB64"] for key_id in raw["approverKeyIds"]]
        }}
        options = {**section["options"], **case.get("options", {})}
        result = intyga_verify.verify_approval_receipt(
            case["receipt"], expected, as_of=_at(options["asOf"]),
            clock_skew_seconds=options.get("clockSkewSeconds", 30),
        )
        assert result["ok"] is case["ok"], f'{case["name"]}: {result.get("reason")}'
        if "signers" in case:
            assert result.get("signers") == case["signers"]
        if "reasonIncludes" in case:
            assert case["reasonIncludes"] in result.get("reason", ""), case["name"]

  def test_agent_authority_and_platform_canonical_vectors(self):
    vectors = json.loads(CANONICAL_VECTORS.read_text(encoding="utf-8"))
    for item in vectors["agentAuthorityPayloads"]:
        raw = item["input"]
        self.assertEqual(
            intyga_verify.canonical_agent_authority_payload(
                target=raw["target"], action_patterns=raw["actionPatterns"],
                display=raw["actionDescription"], agent={"did": raw["agentDid"]},
                requester=raw["requester"], requirement=raw["requirement"],
                nonce=raw["nonce"], sealed_at=raw["sealedAt"], expires_at=raw["expiresAt"]
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
    section = vectors["platform"]
    for case in section["cases"]:
        raw = {**section["expected"], **case.get("expected", {})}
        expected = {**raw, "approvers": _approvers(raw["approverKeyIds"], keys)}
        options = {**section["options"], **case.get("options", {})}
        result = intyga_verify.verify_platform_receipt(
            case["receipt"], expected,
            expected_origin=options["expectedOrigin"], as_of=_at(options["asOf"]),
            clock_skew_seconds=options.get("clockSkewSeconds", 30),
        )
        assert result["ok"] is case["ok"], f'{case["name"]}: {result.get("reason")}'
        if "signers" in case:
            assert result.get("signers") == case["signers"]

    section = vectors["agentAuthority"]
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
            assert result["authority"]["signers"] == case["signers"]
        if "actionPatterns" in case:
            assert result["authority"]["actionPatterns"] == case["actionPatterns"]


  def test_bundle_anchor_rekor_and_evidence_vectors(self):
    vectors = _load()
    keys = _keys(vectors)
    section = vectors["bundles"]
    for case in section["cases"]:
        options = case.get("options", {})
        policy = case.get("policy", section["anchorPolicy"])
        result = intyga_verify.ledger.verify_bundle(
            case["bundle"], trusted_root=options.get("trustedRoot"),
            anchors=options.get("divergenceAnchors"), anchor_policy=policy,
            resolve_anchor_key=lambda anchor: keys.get(anchor.get("keyId"), {}).get("spkiB64"),
            external_keys={"rekor": keys[options["rekorKeyId"]]["spkiB64"]} if options.get("rekorKeyId") else None,
        )
        assert result["ok"] is case["ok"], f'{case["name"]}: {result.get("notes")}'
        if "verificationLevel" in case:
            assert result["verificationLevel"] == case["verificationLevel"]
        for prop, expected in case.get("properties", {}).items():
            assert result["properties"][prop] is expected, f'{case["name"]}:{prop}'

    for case in vectors["evidence"]["cases"]:
        result = intyga_verify.ledger.verify_evidence_bundle(
            case["bundle"], trusted_roots=case.get("options", {}).get("trustedRoots"),
            anchors=case.get("options", {}).get("anchors"), anchor_policy=case.get("policy"),
            resolve_anchor_key=(lambda anchor: keys.get(anchor.get("keyId"), {}).get("spkiB64")) if case.get("policy") else None
        )
        assert result["ok"] is case["ok"], f'{case["name"]}: {result.get("failed")}'
        for prop in ("total", "contentVerified", "commitmentOnly"):
            if prop in case:
                assert result[prop] == case[prop]


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
