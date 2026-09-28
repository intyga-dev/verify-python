import json
import unittest
from pathlib import Path

from intyga_verify.ledger import BUNDLE_KIND, verify_anchor_quorum, verify_bundle, verify_rfc3161_anchor


# unittest.TestCase, not bare pytest-style functions: CI runs `python -m unittest discover`, which
# silently collects zero tests from module-level `def test_*` — this file shipped that way and its
# RFC 3161 checks never ran in CI.
class Rfc3161Tests(unittest.TestCase):
    def test_shared_rfc3161_vectors(self):
        vectors = json.loads((Path(__file__).parents[1] / "vectors/rfc3161-vectors.json").read_text())
        for case in vectors["cases"]:
            assert verify_rfc3161_anchor(case["anchor"], case.get("trust"))["ok"] is case["expected"], case["name"]

    def test_missing_executable_fails_closed(self):
        vectors = json.loads((Path(__file__).parents[1] / "vectors/rfc3161-vectors.json").read_text())
        case = next(c for c in vectors["cases"] if c["name"] == "valid-unchecked")
        trust = {**case["trust"], "opensslPath": "/does/not/exist/openssl"}
        assert verify_rfc3161_anchor(case["anchor"], trust)["ok"] is False

    def test_rfc3161_counts_for_quorum_and_caller_attributed_divergence(self):
        vectors = json.loads((Path(__file__).parents[1] / "vectors/rfc3161-vectors.json").read_text())
        valid = next(c for c in vectors["cases"] if c["name"] == "valid-unchecked")
        divergent = next(c for c in vectors["cases"] if c["name"] == "valid-different-root-for-divergence")
        policy = {"requiredAnchors": 1, "trustedIssuers": [valid["anchor"]["issuer"]], "quorum": "N_OF_M"}
        external = {"rfc3161": {valid["anchor"]["issuer"]: valid["trust"]}}
        assert verify_anchor_quorum([valid["anchor"]], valid["anchor"]["dailyRoot"], policy, lambda _: None,
                                    external_keys=external)["ok"] is True
        result = verify_anchor_quorum([valid["anchor"]], valid["anchor"]["dailyRoot"], policy, lambda _: None,
                                      divergence_anchors=[divergent["anchor"]], external_keys=external)
        assert result["divergence"] is True

        wrong = {**valid["trust"], "signerCertificateSha256": "00" * 32}
        failed = verify_anchor_quorum([valid["anchor"]], valid["anchor"]["dailyRoot"], policy, lambda _: None,
                                      external_keys={"rfc3161": {valid["anchor"]["issuer"]: wrong}})
        assert failed["ok"] is False
        assert "not verified" in failed["note"]

        # Unknown and WEBHOOK anchors never reach SELF key resolution, including divergence evidence.
        def unexpected_resolver(_):
            raise AssertionError("unsupported anchor kind reached SELF resolver")
        for kind in ("WEBHOOK", "FUTURE_KIND"):
            relabeled = {**divergent["anchor"], "kind": kind}
            verdict = verify_anchor_quorum([valid["anchor"]], valid["anchor"]["dailyRoot"], policy,
                                           unexpected_resolver, divergence_anchors=[relabeled], external_keys=external)
            assert verdict["divergence"] is False

        bundle = {
            "version": 1,
            "kind": BUNDLE_KIND,
            "event": {},
            "proof": {"leaf": valid["anchor"]["dailyRoot"], "checkpointRoot": valid["anchor"]["dailyRoot"]},
        }
        # A single proof carries no checkpoint: the TSA time is bounded against the caller's record (§5.3).
        a = valid["anchor"]
        record = {"root": a["dailyRoot"], "seqStart": a["seqStart"], "seqEnd": a["seqEnd"],
                  "chainHash": a["chainHash"], "anchoredAt": a["timestamp"]}
        integrated = verify_bundle(bundle, trusted_root=a["dailyRoot"], anchors=[a],
                                   anchor_policy=policy, external_keys=external, trusted_checkpoint=record)
        assert any("Anchor quorum met" in note for note in integrated["notes"])
        assert not any("could not be evaluated" in note for note in integrated["notes"])
        # Without that record the external witness cannot be time-bounded, so it does not count.
        unbounded = verify_bundle(bundle, trusted_root=a["dailyRoot"], anchors=[a],
                                  anchor_policy=policy, external_keys=external)
        assert any("no trusted checkpoint time" in note for note in unbounded["notes"])
