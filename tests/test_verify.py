import json
import unittest
from pathlib import Path

import sakra_verify


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
                self.assertEqual(sakra_verify.stable_stringify(case["value"]), case["expected"])

    def test_authorization_payloads_v3(self):
        cases = self.vectors.get("authorizationPayloadsV3", [])
        self.assertTrue(cases, "no v3 authorization vectors present")
        for i, case in enumerate(cases):
            inp = case["input"]
            with self.subTest(index=i):
                result = sakra_verify.canonical_authorization_payload_v3(
                    nonce=inp["nonce"],
                    action_type=inp["actionType"],
                    action_description=inp["actionDescription"],
                    params=inp["params"],
                    requester=inp["requester"],
                )
                self.assertEqual(result, case["expected"])

    def test_receipts(self):
        for entry in self.vectors.get("receipts", []):
            receipt = entry["receipt"]
            nonce = json.loads(receipt["canonicalPayload"]).get("nonce")
            expected = {
                "actionType": receipt.get("actionType"),
                "params": receipt.get("params"),
                "nonce": nonce,
            }
            with self.subTest(name=entry["name"]):
                result = sakra_verify.verify_approval_receipt(receipt, expected)
                self.assertEqual(result["ok"], entry["expectOk"], result.get("reason"))

    def test_webauthn_vector(self):
        r = self.webauthn["receipt"]
        e = self.webauthn["expected"]
        expected = {"actionType": e["actionType"], "params": e["params"], "nonce": e["nonce"]}

        ok = sakra_verify.verify_approval_receipt(
            r, expected, expected_origin=self.webauthn["origin"], expected_rp_id=self.webauthn["rpId"]
        )
        self.assertTrue(ok["ok"], ok.get("reason"))

        # Fails closed without origin/RP-ID pinning.
        unpinned = sakra_verify.verify_approval_receipt(r, expected)
        self.assertFalse(unpinned["ok"])

        # Rejects an assertion presented for a different origin.
        wrong = sakra_verify.verify_approval_receipt(
            r, expected, expected_origin="https://evil.example.com", expected_rp_id=self.webauthn["rpId"]
        )
        self.assertFalse(wrong["ok"])


if __name__ == "__main__":
    unittest.main()
