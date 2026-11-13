"""Static verification of the Authenticode signature.

It checks: (1) that the Authenticode hash of the file matches the signed one (otherwise the file was
modified after signing or the signature was copied from another file); (2) the signer's signature over the
signed attributes; (3) the certificate chain up to a root of the Microsoft store (mscerts package);
(4) validity dates and the countersignature timestamp. Neither Windows nor the network is needed (no revocation check).
"""
from __future__ import annotations

import datetime as dt
import hashlib
import struct
from functools import lru_cache

_HASHES = {"md5": hashlib.md5, "sha1": hashlib.sha1, "sha256": hashlib.sha256, "sha384": hashlib.sha384,
           "sha512": hashlib.sha512}


def _strip_tlv(der: bytes) -> bytes:
    """Content of a DER element (without tag and length)."""
    n = der[1]
    if n < 0x80:
        return der[2:2 + n]
    k = n & 0x7F
    ln = int.from_bytes(der[2:2 + k], "big")
    return der[2 + k:2 + k + ln]


def authenticode_hash(data: bytes, algo: str) -> bytes | None:
    """Authenticode hash: the whole file except the CheckSum field, the Certificate Table entry and the signature."""
    try:
        lf = struct.unpack_from("<I", data, 0x3C)[0]
        opt = lf + 24
        magic = struct.unpack_from("<H", data, opt)[0]
        checksum_off = opt + 64
        dd = opt + (112 if magic == 0x20B else 96)
        cert_entry = dd + 4 * 8
        cert_off, cert_size = struct.unpack_from("<II", data, cert_entry)
    except struct.error:
        return None
    h = _HASHES[algo]()
    h.update(data[:checksum_off])
    h.update(data[checksum_off + 4:cert_entry])
    end = cert_off if cert_off and cert_off + cert_size <= len(data) else len(data)
    h.update(data[cert_entry + 8:end])
    # after the signature (rare): those bytes are part of the hash too
    if cert_off and cert_off + cert_size < len(data):
        h.update(data[cert_off + cert_size:])
    return h.digest()


# --- public-key signatures in pure Python (no OpenSSL: the executable stays small) ------------------

# DigestInfo OIDs of the hashes (PKCS#1 v1.5)
_HASH_OIDS = {"1.2.840.113549.2.5": "md5", "1.3.14.3.2.26": "sha1", "2.16.840.1.101.3.4.2.1": "sha256",
              "2.16.840.1.101.3.4.2.2": "sha384", "2.16.840.1.101.3.4.2.3": "sha512"}

# NIST curves used by code signing certificates: p, b, Gx, Gy, n (a = -3)
_CURVES = {
    "secp256r1": (
        0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
        0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
        0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
        0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
        0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551),
    "secp384r1": (
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF,
        0xB3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF,
        0xAA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7,
        0x3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F,
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973),
}


def _rsa_verify(n: int, e: int, signature: bytes, data: bytes, hash_name: str) -> bool:
    """RSA PKCS#1 v1.5: signature^e mod n must be 00 01 FF..FF 00 DigestInfo(hash of data)."""
    from asn1crypto.algos import DigestInfo
    k = (n.bit_length() + 7) // 8
    if len(signature) > k:
        return False
    em = pow(int.from_bytes(signature, "big"), e, n).to_bytes(k, "big")
    if em[:2] != b"\x00\x01":
        return False
    sep = em.find(b"\x00", 2)
    if sep < 10 or em[2:sep].strip(b"\xff"):
        return False
    try:
        di = DigestInfo.load(em[sep + 1:])
        algo = _HASH_OIDS.get(di["digest_algorithm"]["algorithm"].dotted)
        digest = di["digest"].native
    except Exception:
        return False
    return algo == hash_name and digest == _HASHES[hash_name](data).digest()


def _ec_add(P, Q, p):
    """Sum of two points in affine coordinates (None = point at infinity), curve with a = -3."""
    if P is None:
        return Q
    if Q is None:
        return P
    if P[0] == Q[0]:
        if (P[1] + Q[1]) % p == 0:
            return None
        lam = (3 * P[0] * P[0] - 3) * pow(2 * P[1], -1, p) % p
    else:
        lam = (Q[1] - P[1]) * pow(Q[0] - P[0], -1, p) % p
    x = (lam * lam - P[0] - Q[0]) % p
    return x, (lam * (P[0] - x) - P[1]) % p


def _ec_mul2(k1, P, k2, Q, p):
    """k1*P + k2*Q (Shamir's trick)."""
    R, PQ = None, _ec_add(P, Q, p)
    for i in range(max(k1.bit_length(), k2.bit_length()) - 1, -1, -1):
        R = _ec_add(R, R, p)
        b1, b2 = (k1 >> i) & 1, (k2 >> i) & 1
        if b1 or b2:
            R = _ec_add(R, PQ if b1 and b2 else (P if b1 else Q), p)
    return R


def _ecdsa_verify(curve: str, point: bytes, signature: bytes, data: bytes, hash_name: str) -> bool:
    from asn1crypto.algos import DSASignature
    if curve not in _CURVES:
        return False
    p, b, gx, gy, n = _CURVES[curve]
    size = (p.bit_length() + 7) // 8
    if point[:1] == b"\x04" and len(point) == 1 + 2 * size:
        Q = (int.from_bytes(point[1:1 + size], "big"), int.from_bytes(point[1 + size:], "big"))
    elif point[:1] in (b"\x02", b"\x03") and len(point) == 1 + size:
        x = int.from_bytes(point[1:], "big")
        y = pow((x ** 3 - 3 * x + b) % p, (p + 1) // 4, p)      # p = 3 mod 4 for both curves
        if (y & 1) != (point[0] & 1):
            y = p - y
        Q = (x, y)
    else:
        return False
    if (Q[1] ** 2 - (Q[0] ** 3 - 3 * Q[0] + b)) % p:
        return False                                            # not on the curve
    try:
        rs = DSASignature.load(signature).native
        r, s = rs["r"], rs["s"]
    except Exception:
        return False
    if not (0 < r < n and 0 < s < n):
        return False
    h = _HASHES[hash_name](data).digest()
    e = int.from_bytes(h, "big")
    if len(h) * 8 > n.bit_length():
        e >>= len(h) * 8 - n.bit_length()
    w = pow(s, -1, n)
    R = _ec_mul2(e * w % n, (gx, gy), r * w % n, Q, p)
    return R is not None and R[0] % n == r


def _verify_sig(cert, signature: bytes, data: bytes, hash_name: str) -> bool:
    """Signature made with the key of cert (asn1crypto Certificate)."""
    try:
        pk = cert.public_key
        if pk.algorithm == "rsa":
            key = pk["public_key"].parsed
            return _rsa_verify(key["modulus"].native, key["public_exponent"].native, signature, data, hash_name)
        if pk.algorithm == "ec":
            kind, curve = pk.curve
            return kind == "named" and _ecdsa_verify(curve, pk["public_key"].native, signature, data, hash_name)
    except Exception:
        return False
    return False


# --- certificates -----------------------------------------------------------------------------------

def _load_pem(text: bytes) -> list:
    import base64

    from asn1crypto import x509
    out = []
    for block in text.split(b"-----BEGIN CERTIFICATE-----")[1:]:
        body = block.split(b"-----END CERTIFICATE-----")[0]
        try:
            out.append(x509.Certificate.load(base64.b64decode(b"".join(body.split()))))
        except Exception:
            pass
    return out


@lru_cache(maxsize=1)
def _trusted_roots():
    """Trusted Microsoft root certificates (from the mscerts package), by subject name."""
    try:
        import mscerts
        with open(mscerts.where(), "rb") as f:
            certs = _load_pem(f.read())
    except Exception:
        return {}
    out: dict = {}
    for c in certs:
        try:
            out.setdefault(c.subject.sha256, []).append(c)
        except Exception:
            pass
    return out


def _cn(name) -> str:
    try:
        nat = name.native
        return str(nat.get("common_name") or nat.get("organization_name") or name.human_friendly)
    except Exception:
        return str(name)


def _issued_by(child, parent) -> bool:
    """child is signed by parent (direct signature check: accepts SHA-1 too, common in old signatures)."""
    try:
        if child.issuer != parent.subject:
            return False
        name = child["signature_algorithm"].hash_algo
    except Exception:
        return False
    if name not in _HASHES:
        return False
    return _verify_sig(parent, child["signature_value"].native, child["tbs_certificate"].dump(), name)


def _signing_time(signer) -> str | None:
    """Countersignature date (timestamp): RFC 3161 or PKCS#9 countersignature."""
    from asn1crypto import cms, tsp
    try:
        for attr in signer["unsigned_attrs"] or []:
            t = attr["type"].dotted
            for v in attr["values"]:
                if t == "1.3.6.1.4.1.311.3.3.1":        # RFC 3161 timestamp (Microsoft)
                    ci = cms.ContentInfo.load(v.dump()) if not isinstance(v, cms.ContentInfo) else v
                    tst = ci["content"]["encap_content_info"]["content"].parsed
                    if isinstance(tst, tsp.TSTInfo):
                        return tst["gen_time"].native.isoformat()
                elif t == "1.2.840.113549.1.9.6":        # PKCS#9 countersignature
                    for a in v["signed_attrs"]:
                        if a["type"].native == "signing_time":
                            return a["values"][0].native.isoformat()
    except Exception:
        return None
    return None


def verify(data: bytes, offset: int, size: int) -> dict:
    """Verifies the signature in the Certificate Table (offset/size in the file)."""
    import warnings
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")   # historical root certificates with non-standard fields
        try:
            return _verify(data, offset, size)
        except Exception as e:
            return {"verified": False, "problems": [f"cannot verify the signature: {e}"]}


def _verify(data: bytes, offset: int, size: int) -> dict:
    from asn1crypto import cms

    out: dict = {"verified": False, "problems": []}
    blob = data[offset:offset + size]
    if len(blob) < 8:
        out["problems"].append("certificate table is truncated")
        return out
    length, _rev, ctype = struct.unpack_from("<IHH", blob, 0)
    if ctype != 2:   # WIN_CERT_TYPE_PKCS_SIGNED_DATA
        out["problems"].append(f"unsupported certificate type {ctype}")
        return out
    try:
        ci = cms.ContentInfo.load(blob[8:length])
        sd = ci["content"]
        spc = sd["encap_content_info"]
        # SpcIndirectDataContent: SEQUENCE { data, messageDigest DigestInfo }, inside the explicit tag [0]
        from asn1crypto.core import Sequence
        raw = spc["content"].dump()
        spc_seq = Sequence.load(_strip_tlv(raw) if raw[0] == 0xA0 else raw)
        digest_info = Sequence.load(spc_seq[1].dump())
        algo_oid = Sequence.load(digest_info[0].dump())[0].dotted
        signed_digest = digest_info[1].native
    except Exception as e:
        out["problems"].append(f"cannot parse the signature: {e}")
        return out
    algo = {"1.2.840.113549.2.5": "md5", "1.3.14.3.2.26": "sha1", "2.16.840.1.101.3.4.2.1": "sha256",
            "2.16.840.1.101.3.4.2.2": "sha384", "2.16.840.1.101.3.4.2.3": "sha512"}.get(algo_oid)
    out["digest_algorithm"] = algo or algo_oid
    if algo:
        actual = authenticode_hash(data, algo)
        out["digest_ok"] = actual == signed_digest
        if not out["digest_ok"]:
            out["problems"].append("the file was modified after signing, or the signature was copied from "
                                   "another file (Authenticode hash mismatch)")

    certs = []
    for c in sd["certificates"] or []:
        if c.name == "certificate":
            certs.append(c.chosen)
    signer = sd["signer_infos"][0]
    sid = signer["sid"].chosen
    signer_cert = None
    try:
        serial = sid["serial_number"].native
        signer_cert = next((c for c in certs if c.serial_number == serial), None)
    except Exception:
        pass
    if signer_cert is None:
        out["problems"].append("the signer certificate is missing")
        return out

    # signature over the signed attributes + messageDigest == hash of the SpcIndirectData content
    hname = signer["digest_algorithm"]["algorithm"].native
    hname = {"sha256": "sha256", "sha1": "sha1", "md5": "md5", "sha384": "sha384", "sha512": "sha512"}.get(hname)
    sig_ok = False
    if hname and signer["signed_attrs"]:
        attrs = signer["signed_attrs"]
        md = next((a["values"][0].native for a in attrs if a["type"].native == "message_digest"), None)
        content_hash = _HASHES[hname](spc_seq.contents).digest()
        der = attrs.dump()
        der = b"\x31" + der[1:]   # attributes are signed as a SET (tag 0x31), not with the implicit tag [0]
        sig_ok = md == content_hash and _verify_sig(signer_cert, signer["signature"].native, der, hname)
    out["signature_ok"] = sig_ok
    if not sig_ok:
        out["problems"].append("the signer's signature is not valid")

    # chain up to a Microsoft root
    chain = [signer_cert]
    pool = [c for c in certs if c is not signer_cert]
    while True:
        cur = chain[-1]
        if cur.issuer == cur.subject:
            break
        nxt = next((c for c in pool if c.subject == cur.issuer and c not in chain and _issued_by(cur, c)), None)
        if nxt is None:
            break
        chain.append(nxt)
    top = chain[-1]
    roots = _trusted_roots()
    trusted = any(r.sha256 == top.sha256 for r in roots.get(top.subject.sha256, [])) or \
        any(_issued_by(top, r) for r in roots.get(top.issuer.sha256, []))
    self_signed = len(chain) == 1 and signer_cert.issuer == signer_cert.subject
    out.update({
        "signer": _cn(signer_cert.subject),
        "issuer": _cn(signer_cert.issuer),
        "serial": format(signer_cert.serial_number, "x"),
        "valid_from": signer_cert.not_valid_before.isoformat(),
        "valid_to": signer_cert.not_valid_after.isoformat(),
        "chain": [_cn(c.subject) for c in chain],
        "trusted_root": bool(trusted),
        "self_signed": self_signed,
        "signing_time": _signing_time(signer),
        "thumbprint": signer_cert.sha1.hex(),
    })
    if self_signed:
        out["problems"].append("self-signed certificate")
    elif not trusted:
        out["problems"].append("the certificate chain does not lead to a trusted Microsoft root")
    when = out["signing_time"]
    ref = dt.datetime.fromisoformat(when) if when else dt.datetime.now(dt.timezone.utc)
    if not (signer_cert.not_valid_before <= ref <= signer_cert.not_valid_after):
        out["expired"] = True
        out["problems"].append("signed outside the certificate's validity period" if when
                               else "certificate expired and the signature has no timestamp")
    out["verified"] = bool(out.get("digest_ok") and sig_ok and trusted and not out.get("expired"))
    return out
