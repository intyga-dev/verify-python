"""Opt-in RFC 3161 TimeStampToken verification through a caller-selected OpenSSL 3 binary."""
import base64
import binascii
import datetime as dt
import hashlib
import os
import re
import subprocess
import tempfile
import time
import math

_MAX = 1024 * 1024
_QUERY_PREFIX = bytes.fromhex("30360201013031300d060960864801650304020105000420")


def _fail():
    return {"ok": False, "reason": "RFC 3161 evidence could not be verified"}


def _strict_b64(value):
    if not isinstance(value, str) or len(value) > ((_MAX + 2) // 3) * 4 or len(value) % 4 or not re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", value):
        raise ValueError()
    raw = base64.b64decode(value, validate=True)
    if len(raw) > _MAX or base64.b64encode(raw).decode() != value:
        raise ValueError()
    return raw


def _tlv(data, offset, expected=None):
    if offset + 2 > len(data):
        raise ValueError()
    tag, first = data[offset], data[offset + 1]
    offset += 2
    if first < 128:
        length = first
    else:
        count = first & 127
        if count == 0 or count > 4 or offset + count > len(data) or data[offset] == 0:
            raise ValueError()
        length = int.from_bytes(data[offset:offset + count], "big")
        if length < 128:
            raise ValueError()
        offset += count
    end = offset + length
    if end > len(data) or expected is not None and tag != expected:
        raise ValueError()
    return tag, offset, end


def _whole_sequence(data):
    _, start, end = _tlv(data, 0, 0x30)
    if end != len(data):
        raise ValueError()
    return start, end


_SIGNED_DATA_OID = bytes.fromhex("2a864886f70d010702")
_DIGEST_OIDS = {
    bytes.fromhex("608648016503040201"),  # SHA-256
    bytes.fromhex("608648016503040202"),  # SHA-384
    bytes.fromhex("608648016503040203"),  # SHA-512
}


def _algorithm(data, pos):
    _, start, end = _tlv(data, pos, 0x30)
    _, oid_start, oid_end = _tlv(data, start, 0x06)
    oid = data[oid_start:oid_end]
    cursor = oid_end
    if cursor < end:
        _, null_start, cursor = _tlv(data, cursor, 0x05)
        if null_start != cursor:
            raise ValueError()
    if cursor != end or oid not in _DIGEST_OIDS:
        raise ValueError()
    return oid, end


def _cms_digest_algorithm(token):
    """Require one signer using SHA-256/384/512; OpenSSL auth_level does not reject SHA-1/MD5 CMS."""
    pos, outer_end = _whole_sequence(token)
    _, a, b = _tlv(token, pos, 0x06)
    if token[a:b] != _SIGNED_DATA_OID:
        raise ValueError()
    _, explicit_start, explicit_end = _tlv(token, b, 0xA0)
    if explicit_end != outer_end:
        raise ValueError()
    _, signed_start, signed_end = _tlv(token, explicit_start, 0x30)
    if signed_end != explicit_end:
        raise ValueError()
    pos = signed_start
    _, _, pos = _tlv(token, pos, 0x02)
    _, set_start, set_end = _tlv(token, pos, 0x31)
    digest_oid, cursor = _algorithm(token, set_start)
    if cursor != set_end:
        raise ValueError()
    pos = set_end
    _, _, pos = _tlv(token, pos, 0x30)  # encapContentInfo
    while pos < signed_end and token[pos] in (0xA0, 0xA1):
        _, _, pos = _tlv(token, pos, token[pos])
    _, signers_start, signers_end = _tlv(token, pos, 0x31)
    if signers_end != signed_end:
        raise ValueError()
    _, signer_start, signer_end = _tlv(token, signers_start, 0x30)
    if signer_end != signers_end:
        raise ValueError()
    pos = signer_start
    _, _, pos = _tlv(token, pos, 0x02)
    if pos >= signer_end or token[pos] not in (0x30, 0x80):
        raise ValueError()
    _, _, pos = _tlv(token, pos, token[pos])
    signer_oid, _ = _algorithm(token, pos)
    if signer_oid != digest_oid:
        raise ValueError()


def _gen_time(info):
    pos, end = _whole_sequence(info)
    _, a, b = _tlv(info, pos, 0x02)
    if info[a:b] != b"\x01":
        raise ValueError()
    pos = b
    _, _, pos = _tlv(info, pos, 0x06)
    _, _, pos = _tlv(info, pos, 0x30)
    _, _, pos = _tlv(info, pos, 0x02)
    _, a, b = _tlv(info, pos, 0x18)
    text = info[a:b].decode("ascii")
    match = re.fullmatch(r"(\d{14})(?:\.(\d*[1-9]))?Z", text)
    if not match:
        raise ValueError()
    stamp = dt.datetime.strptime(match.group(1), "%Y%m%d%H%M%S").replace(tzinfo=dt.timezone.utc)
    if stamp.strftime("%Y%m%d%H%M%S") != match.group(1):
        raise ValueError()
    return int(stamp.timestamp()), match.group(2) is not None


def _one_signer_der(pem):
    matches = re.findall(rb"-----BEGIN CERTIFICATE-----\s*([A-Za-z0-9+/=\r\n]+?)\s*-----END CERTIFICATE-----", pem)
    if len(matches) != 1:
        raise ValueError()
    compact = re.sub(rb"\s", b"", matches[0])
    der = _strict_b64(compact.decode())
    _whole_sequence(der)
    return der


def _run(argv, directory, env):
    try:
        return subprocess.run(argv, cwd=directory, env=env, stdin=subprocess.DEVNULL,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              timeout=5, check=False).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def verify_rfc3161_anchor(anchor, trust):
    """Verify one DEWP RFC3161 anchor. All trust and evaluation time come from the caller."""
    try:
        # Local import avoids the ledger -> ledger_advanced -> rfc3161 initialization cycle while
        # keeping this module relocatable in the standalone intyga-verify distribution.
        from .ledger import anchor_digest_hex
        if (not isinstance(anchor, dict) or not isinstance(trust, dict) or anchor.get("kind") != "RFC3161"
                or not isinstance(anchor.get("dailyRoot"), str) or not re.fullmatch(r"[0-9a-f]{64}", anchor["dailyRoot"])
                or anchor.get("algorithm") not in ("ES256", "Ed25519", "RSA-PSS")
                or not isinstance(anchor.get("issuer"), str) or not isinstance(anchor.get("timestamp"), str)):
            return _fail()
        token = _strict_b64(anchor.get("evidence"))
        _whole_sequence(token)
        _cms_digest_algorithm(token)
        digest = bytes.fromhex(anchor_digest_hex(anchor))
        if len(digest) != 32:
            return _fail()
        ca = trust.get("ca_pem", trust.get("caPem"))
        pin = trust.get("signer_certificate_sha256", trust.get("signerCertificateSha256"))
        revocation = trust.get("revocation")
        crl = trust.get("crl_pem", trust.get("crlPem"))
        untrusted = trust.get("untrusted_pem", trust.get("untrustedPem"))
        when = trust.get("verification_time", trust.get("verificationTime", math.ceil(time.time())))
        openssl = trust.get("openssl_path", trust.get("opensslPath", "openssl"))
        values = [ca, crl, untrusted]
        if (not isinstance(ca, str) or not ca or any(v is not None and (not isinstance(v, str) or len(v.encode()) > _MAX) for v in values)
                or not isinstance(pin, str) or not re.fullmatch(r"[0-9a-f]{64}", pin)
                or revocation not in ("crl", "unchecked") or revocation == "crl" and not crl
                or type(when) is not int or when < 0 or when > 253402300799
                or not isinstance(openssl, str) or not openssl or "\0" in openssl):
            return _fail()
        # Process cwd changes to the private directory below. Preserve caller-relative executable
        # paths while leaving a bare command name to normal PATH lookup.
        if "/" in openssl or "\\" in openssl:
            openssl = os.path.abspath(openssl)
        with tempfile.TemporaryDirectory(prefix="intyga-rfc3161-") as directory:
            # Owner-only on purpose: this directory briefly holds the caller's trust material. The
            # rule's suggested 0o644 would be WIDER (and non-traversable); 0o700 is the tight mode.
            # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
            os.chmod(directory, 0o700)
            empty = os.path.join(directory, "empty"); os.mkdir(empty, 0o700)
            files = {"token.der": token, "query.tsq": _QUERY_PREFIX + digest,
                     "trust.pem": (ca + ("\n" + crl if crl else "")).encode(), "openssl.cnf": b""}
            if untrusted:
                files["intermediates.pem"] = untrusted.encode()
            for name, content in files.items():
                path = os.path.join(directory, name)
                with open(path, "xb") as handle:
                    os.chmod(path, 0o600); handle.write(content)
            env = {**os.environ, "OPENSSL_CONF": os.path.join(directory, "openssl.cnf"),
                   "SSL_CERT_FILE": os.path.join(directory, "none.pem"), "SSL_CERT_DIR": empty}
            cms = [openssl, "cms", "-verify", "-binary", "-inform", "DER", "-in", "token.der",
                   "-noverify", "-signer", "signer.pem", "-out", "info.der"]
            if not _run(cms, directory, env): return _fail()
            signer = open(os.path.join(directory, "signer.pem"), "rb").read()
            info = open(os.path.join(directory, "info.der"), "rb").read()
            if len(signer) > _MAX or len(info) > _MAX or hashlib.sha256(_one_signer_der(signer)).hexdigest() != pin:
                return _fail()
            gen_time, fractional = _gen_time(info)
            if gen_time < 0 or gen_time > when or fractional and when <= gen_time:
                return _fail()
            # `ts -verify` never loads OpenSSL's default trust locations; it trusts only what is passed. No
            # `-CAstore`: OpenSSL 3.0 loads a store URI eagerly and fails on an empty one (3.5 is lazy), which
            # made every valid token fail closed on Ubuntu 24.04's 3.0.13.
            base = [openssl, "ts", "-verify", "-token_in", "-in", "token.der", "-queryfile", "query.tsq",
                    "-CAfile", "trust.pem", "-CApath", "empty"]
            if untrusted: base += ["-untrusted", "intermediates.pem"]
            common = ["-auth_level", "2", "-x509_strict"]
            current = base + ["-attime", str(when)] + common + (["-crl_check_all"] if revocation == "crl" else [])
            issued = base + ["-attime", str(gen_time)] + common
            if not _run(current, directory, env) or not _run(issued, directory, env): return _fail()
            return {"ok": True, "genTime": gen_time}
    except Exception:
        return _fail()
