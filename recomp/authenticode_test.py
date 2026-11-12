"""Offline proof of authenticode.py: a complete Authenticode signature built from scratch; no game files, stdlib only.

    python3 -I recomp/authenticode_test.py

An RSA key (two 512-bit primes, deterministic) signs a synthetic PE (pe_report_test.build_pe) the Authenticode way:
certificate, SpcIndirectDataContent with the file's SHA-1, signed attributes (contentType, messageDigest), PKCS#7
SignedData, WIN_CERTIFICATE appended and pointed to by the certificate-table directory. Cases:
(a) the signed file verifies: all three checks, the signer's names, and the SHA-256 of the signing certificate;
(b) one flipped code byte: the file digest fails;
(c) a messageDigest that doesn't match the content: the attribute check fails;
(d) the same signature block made with another key (same certificate): the RSA check fails;
(e) an unsigned file: "no signature"; (f) garbage in the certificate table: "unreadable signature", no exception.
Last run: 6 checks PASS -> exit 0.
"""
import hashlib
import os
import random
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import authenticode  # noqa: E402
import pe_report_test  # noqa: E402


# ---- a tiny DER encoder ----
def der(tag, body):
    n = len(body)
    ln = bytes([n]) if n < 0x80 else bytes([0x80 | ((n.bit_length() + 7) // 8)]) + n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag]) + ln + body


def seq(*xs): return der(0x30, b"".join(xs))
def set_(*xs): return der(0x31, b"".join(xs))
def ctx(n, *xs): return der(0xA0 + n, b"".join(xs))
def octet(b): return der(0x04, b)
def null(): return b"\x05\x00"
def integer(v): return der(0x02, v.to_bytes(v.bit_length() // 8 + 1, "big"))
def printable(s): return der(0x13, s.encode())


def oid(s):
    p = [int(x) for x in s.split(".")]
    out = bytearray([40 * p[0] + p[1]])
    for v in p[2:]:
        enc = [v & 0x7F]
        v >>= 7
        while v:
            enc.append(0x80 | (v & 0x7F))
            v >>= 7
        out += bytes(reversed(enc))
    return der(0x06, bytes(out))


def prime(rnd, bits):
    def probable(n):
        if n % 2 == 0:
            return False
        d, s = n - 1, 0
        while d % 2 == 0:
            d, s = d // 2, s + 1
        for _ in range(20):
            x = pow(rnd.randrange(2, n - 1), d, n)
            if x in (1, n - 1):
                continue
            for _ in range(s - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True
    while True:
        c = rnd.getrandbits(bits) | (1 << (bits - 1)) | 1
        if all(c % q for q in (3, 5, 7, 11, 13, 17, 19, 23, 29, 31)) and probable(c):
            return c


def key(seed):
    rnd = random.Random(seed)
    e = 65537
    while True:
        p, q = prime(rnd, 512), prime(rnd, 512)
        phi = (p - 1) * (q - 1)
        if p != q and phi % e:
            return p * q, e, pow(e, -1, phi)


SHA1_ALG = seq(oid(authenticode.OID_SHA1), null())
SPC = "1.3.6.1.4.1.311.2.1.4"
NAME = seq(set_(seq(oid("2.5.4.10"), printable("Test Signer"))), set_(seq(oid("2.5.4.3"), printable("Test CN"))))
SERIAL = 0x1234567


def certificate(n, e):
    spki = seq(seq(oid("1.2.840.113549.1.1.1"), null()), der(0x03, b"\x00" + seq(integer(n), integer(e))))
    tbs = seq(ctx(0, integer(2)), integer(SERIAL), seq(oid("1.2.840.113549.1.1.5"), null()), NAME,
              seq(der(0x17, b"070101000000Z"), der(0x17, b"370101000000Z")), NAME, spki)
    return seq(tbs, seq(oid("1.2.840.113549.1.1.5"), null()), der(0x03, b"\x00" + b"\x55" * 16))


def sign_pe(pe, cert_key, sign_key, bad_attr=False):
    """The PE with an Authenticode signature: cert_key's certificate, signed with sign_key."""
    data = bytearray(pe + bytes((-len(pe)) % 8))
    off = struct.unpack_from("<I", data, 0x3C)[0] + 24 + 96 + 32
    struct.pack_into("<II", data, off, len(data), 0)                   # the table will start here (excluded anyway)
    digest = authenticode.authenticode_hash(bytes(data), "sha1")
    content = seq(seq(oid("1.3.6.1.4.1.311.2.1.15"), seq()), seq(SHA1_ALG, octet(digest)))
    content_value = content[2:] if content[1] < 0x80 else content[2 + (content[1] & 0x7F):]
    md = hashlib.sha1(content_value).digest()
    if bad_attr:
        md = bytes(20)
    attrs = [seq(oid("1.2.840.113549.1.9.3"), set_(oid(SPC))), seq(oid(authenticode.OID_MESSAGE_DIGEST), set_(octet(md)))]
    n, e, d = sign_key
    em_len = (n.bit_length() + 7) // 8
    t = bytes.fromhex("3021300906052b0e03021a05000414") + hashlib.sha1(set_(*attrs)).digest()
    em = b"\x00\x01" + b"\xff" * (em_len - len(t) - 3) + b"\x00" + t
    sig = pow(int.from_bytes(em, "big"), d, n).to_bytes(em_len, "big")
    signer_info = seq(integer(1), seq(NAME, integer(SERIAL)), SHA1_ALG, ctx(0, *attrs),
                      seq(oid("1.2.840.113549.1.1.1"), null()), octet(sig))
    cert = certificate(cert_key[0], cert_key[1])
    signed = seq(integer(1), set_(SHA1_ALG), seq(oid(SPC), ctx(0, content)), ctx(0, cert), set_(signer_info))
    p7 = seq(oid("1.2.840.113549.1.7.2"), ctx(0, signed))
    blob = struct.pack("<IHH", 8 + len(p7), 0x200, 2) + p7
    blob += bytes((-len(blob)) % 8)
    struct.pack_into("<II", data, off, len(data), len(blob))
    return bytes(data + blob), hashlib.sha256(cert).hexdigest()


def main():
    fails = []

    def check(label, ok, detail=""):
        print(f"{'PASS' if ok else 'FAIL'} {label}" + (f": {detail}" if detail and not ok else ""))
        if not ok:
            fails.append(label)

    k1, k2 = key(1), key(2)
    pe = pe_report_test.build_pe()
    signed, cert_fp = sign_pe(pe, k1, k1)
    r = authenticode.verify(signed)
    check("(a) a signed file verifies", r["ok"] and r["why"] == "valid" and r["signer"] == "Test Signer / Test CN"
          and r["signer_sha256"] == cert_fp, r)
    t = bytearray(signed)
    t[0x400 + 0x20] ^= 1                                               # a byte of .text
    r = authenticode.verify(bytes(t))
    check("(b) a changed code byte breaks the file digest", not r["ok"] and not r["file_digest_ok"] and r["signature_ok"]
          and r["why"] == "file changed after signing", r)
    r = authenticode.verify(sign_pe(pe, k1, k1, bad_attr=True)[0])
    check("(c) a wrong messageDigest fails the attribute check", not r["ok"] and r["file_digest_ok"] and not r["attrs_ok"], r)
    r = authenticode.verify(sign_pe(pe, k1, k2)[0])
    check("(d) another key's signature fails the RSA check", not r["ok"] and r["file_digest_ok"] and r["attrs_ok"]
          and not r["signature_ok"] and r["why"] == "signature doesn't verify", r)
    r = authenticode.verify(pe)
    check("(e) an unsigned file", not r["signed"] and r["why"] == "no signature", r)
    g = bytearray(signed)
    off = struct.unpack_from("<I", g, 0x3C)[0] + 24 + 96 + 32
    sec_off = struct.unpack_from("<I", g, off)[0]
    g[sec_off + 8:sec_off + 40] = b"\xff" * 32
    r = authenticode.verify(bytes(g))
    check("(f) garbage in the certificate table is reported, not raised", not r["ok"] and r["why"].startswith("unreadable"), r)
    print(f"{'FAIL' if fails else 'ok'}: {len(fails)} failing")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
