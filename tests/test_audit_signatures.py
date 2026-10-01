import json
import unittest
from pathlib import Path
from intyga_verify.ledger import verify_bundle, verify_evidence_bundle
VECTORS=json.loads((Path(__file__).parents[1] / "vectors" / "audit-signature-vectors.json").read_text())["cases"]

class AuditSignatureParityTests(unittest.TestCase):
    def test_audit_signature_parity(self):
        for v in VECTORS:
            opts=dict(trusted_root=v["root"],signature_policy=v["policy"])
            got=verify_bundle(v["bundle"],**opts)
            assert got["ok"], (v["name"],got)
            assert got["signature"]["status"]==v["status"], v["name"]
            assert got["signature"]["trusted"]==v["trusted"], v["name"]
            assert verify_bundle(v["bundle"],**opts,require_signatures=True)["ok"]==v["strictOk"], v["name"]
            b=v["bundle"]
            evidence=dict(kind="dewp.audit.evidence-bundle",version="1.0",tenant={"id":"test-tenant"},entries=[dict(event=b["event"],proof=b["proof"])],checkpoints=[dict(id="cp",root=v["root"],seqStart="1",seqEnd="1",anchorRef=None,anchoredAt=None)])
            bulk=verify_evidence_bundle(evidence,trusted_roots=[v["root"]],signature_policy=v["policy"])
            assert bulk["ok"], (v["name"],bulk)
            assert bulk["signatures"]["checks"][0]["status"]==v["status"]
            assert verify_evidence_bundle(evidence,trusted_roots=[v["root"]],signature_policy=v["policy"],require_signatures=True)["ok"]==v["strictOk"],v["name"]
