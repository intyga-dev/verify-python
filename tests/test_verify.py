import json
import unittest
from pathlib import Path

import intyga_verify


class TestVerify(unittest.TestCase):
    """Drives the standalone verifier from the shared cross-language golden vectors, vendored into
    ./vectors at publish time. Proves this split-out package stays byte-identical to the others."""

    @classmethod
    def setUpClass(cls):
        vectors_dir = Path(__file__).parent.parent / "vectors"
        with open(vectors_dir / "canonical-vectors.json", encoding="utf-8") as f:
            cls.vectors = json.load(f)
        with open(vectors_dir / "webauthn-vector.json", encoding="utf-8") as f:
            cls.webauthn = json.load(f)

    def test_stable_stringify(self):
        for case in self.vectors.get("stableStringify", []):
            with self.subTest(name=case["name"]):
                self.assertEqual(intyga_verify.stable_stringify(case["value"]), case["expected"])

    def test_intent_payloads(self):
        cases = self.vectors.get("intentPayloads", [])
        self.assertTrue(cases, "no DIV intent vectors present")
        for i, case in enumerate(cases):
            inp = case["input"]
            with self.subTest(index=i):
                result = intyga_verify.canonical_intent_payload(
                    target=inp["target"],
                    action_type=inp["actionType"],
                    display=inp["actionDescription"],
                    params=inp["params"],
                    requester=inp["requester"],
                    # REQUIRED and signed (DIV §4.3.2): without it a 3-of-3 hardware-pinned receipt
                    # would be byte-identical to a 1-of-1 one.
                    requirement=inp["requirement"],
                    nonce=inp["nonce"],
                    expires_at=inp["expiresAt"],
                )
                self.assertEqual(result, case["expected"])

    def test_receipts(self):
        for entry in self.vectors.get("receipts", []):
            receipt = entry["receipt"]
            nonce = json.loads(receipt["canonicalPayload"]).get("nonce")
            # The approver trust anchor is REQUIRED (DIV Invariant 3): the key must come from the
            # caller's own policy, never from the receipt. For a golden vector the committed file IS
            # the enrollment record, so pinning its key is the legitimate resolution step.
            expected = {
                "target": receipt.get("target"),
                "actionType": receipt.get("actionType"),
                "params": receipt.get("params"),
                "nonce": nonce,
                "approvers": {"publicKeys": [receipt.get("signerPublicKey")]}
                if receipt.get("signerPublicKey")
                else {"publicKeys": ["unused-for-auto-approved"]},
            }
            with self.subTest(name=entry["name"]):
                result = intyga_verify.verify_approval_receipt(receipt, expected)
                self.assertEqual(result["ok"], entry["expectOk"], result.get("reason"))

    def test_webauthn_vector(self):
        r = self.webauthn["receipt"]
        e = self.webauthn["expected"]
        expected = {
            "target": e["target"],
            "actionType": e["actionType"],
            "params": e["params"],
            "nonce": e["nonce"],
            "approvers": {"publicKeys": [r["signerPublicKey"]]},
        }

        ok = intyga_verify.verify_approval_receipt(
            r, expected, expected_origin=self.webauthn["origin"], expected_rp_id=self.webauthn["rpId"]
        )
        self.assertTrue(ok["ok"], ok.get("reason"))

        # Fails closed without origin/RP-ID pinning.
        unpinned = intyga_verify.verify_approval_receipt(r, expected)
        self.assertFalse(unpinned["ok"])

        # Rejects an assertion presented for a different origin.
        wrong = intyga_verify.verify_approval_receipt(
            r, expected, expected_origin="https://evil.example.com", expected_rp_id=self.webauthn["rpId"]
        )
        self.assertFalse(wrong["ok"])


if __name__ == "__main__":
    unittest.main()
