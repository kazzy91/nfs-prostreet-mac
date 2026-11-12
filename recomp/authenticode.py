"""Authenticode check of a 32-bit PE, stdlib only: is this file exactly what its signer signed, and who signed it?

    python3 -I recomp/authenticode.py <file>...

verify(data) -> {"signed", "file_digest_ok", "attrs_ok", "signature_ok", "signer", "signer_sha256", "ok", "why"}
  1. the Authenticode hash of the file (everything except the checksum field, the certificate-table directory entry
     and the certificate table) equals the digest in the signed SpcIndirectDataContent;
  2. the signed attributes' messageDigest equals the hash of that content (its DER value without tag and length);
  3. the RSA PKCS#1 v1.5 signature over the attributes (DER, re-tagged as a SET) verifies with the signing
     certificate's public key: pow(signature, e, n), then the padding and DigestInfo compared byte for byte.
ok = all three. The certificate chain and timestamp are not validated (the 2007 chains have long expired): callers pin
the signer instead, comparing signer_sha256 (the SHA-256 of the signing certificate's DER) with a known value, e.g.
EA_2007 below, taken from the retail disc's untouched nfs.exe and server.dll.
"""
import hashlib
import struct
import sys

# EA's code-signing certificate on the ProStreet retail disc's nfs.exe and server.dll (and the demo's nfs.exe).
EA_2007 = "b829b0a1f42d54ae703ed5864eafc1b50e12ec9ebd7e4cbd28ee031c789e0a0d"
KNOWN_SIGNERS = {EA_2007: "Electronic Arts, 2007 code-signing certificate"}

OID_SHA1 = "1.3.14.3.2.26"
OID_SHA256 = "2.16.840.1.101.3.4.2.1"
OID_MD5 = "1.2.840.113549.2.5"
OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
HASHES = {OID_SHA1: "sha1", OID_SHA256: "sha256", OID_MD5: "md5"}


class DerError(ValueError):
    pass


def tlv(b, i):
    """(tag, header length, value start, value end) of the DER element at b[i]."""
    if i + 2 > len(b):
        raise DerError("truncated")
    tag, n = b[i], b[i + 1]
    j = i + 2
    if n & 0x80:
        k = n & 0x7F
        if k == 0 or k > 4 or j + k > len(b):
            raise DerError("bad length")
        n = int.from_bytes(b[j:j + k], "big")
        j += k
    if j + n > len(b):
        raise DerError("element past the end")
    return tag, j - i, j, j + n


def children(b, start, end):
    out, i = [], start
    while i < end:
        t, _, s, e = tlv(b, i)
        out.append((t, i, s, e))
        i = e
    return out


def oid(b):
    first = b[0]
    parts, v = [first // 40, first % 40], 0
    for x in b[1:]:
        v = v << 7 | (x & 0x7F)
        if not x & 0x80:
            parts.append(v)
            v = 0
    return ".".join(map(str, parts))


def authenticode_hash(data, name):
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    opt = pe + 24
    magic = struct.unpack_from("<H", data, opt)[0]
    dirs = opt + (96 if magic == 0x10B else 112)
    sec_off, sec_len = struct.unpack_from("<II", data, dirs + 4 * 8)
    h = hashlib.new(name)
    h.update(data[:opt + 64])                                  # up to the checksum field
    h.update(data[opt + 68:dirs + 32])                         # to the certificate-table entry
    h.update(data[dirs + 40:sec_off])                          # the rest, up to the certificate table
    h.update(data[sec_off + sec_len:])                         # anything after it
    return h.digest()


def cert_info(b, s, e):
    """(issuer DER, serial bytes, subject text, RSA n, e) of the Certificate element starting at b[s] (ending at e)."""
    cert = children(b, *tlv(b, s)[2:4])                         # tbsCertificate, signatureAlgorithm, signature
    tbs = children(b, cert[0][2], cert[0][3])
    k = 1 if tbs[0][0] == 0xA0 else 0                          # optional [0] version
    serial = b[tbs[k][2]:tbs[k][3]]
    issuer = b[tbs[k + 2][1]:tbs[k + 2][3]]
    subject_el = tbs[k + 4]
    names = []
    for _, _, rs, re_ in children(b, subject_el[2], subject_el[3]):         # RDN SETs
        for _, _, as_, ae in children(b, rs, re_):                          # AttributeTypeAndValue
            o, v = children(b, as_, ae)
            if oid(b[o[2]:o[3]]) in ("2.5.4.3", "2.5.4.10"):                 # CN, O
                names.append(b[v[2]:v[3]].decode("latin-1"))
    spki = children(b, tbs[k + 5][2], tbs[k + 5][3])
    bits = b[spki[1][2] + 1:spki[1][3]]                                      # BIT STRING without the unused-bits byte
    rsa = children(bits, *tlv(bits, 0)[2:4])
    n = int.from_bytes(bits[rsa[0][2]:rsa[0][3]], "big")
    ex = int.from_bytes(bits[rsa[1][2]:rsa[1][3]], "big")
    return issuer, serial, " / ".join(names), n, ex


def verify(data):
    r = {"signed": False, "file_digest_ok": False, "attrs_ok": False, "signature_ok": False, "signer": "",
         "signer_sha256": "", "ok": False, "why": ""}
    try:
        pe = struct.unpack_from("<I", data, 0x3C)[0]
        opt = pe + 24
        dirs = opt + (96 if struct.unpack_from("<H", data, opt)[0] == 0x10B else 112)
        sec_off, sec_len = struct.unpack_from("<II", data, dirs + 32)
        if not sec_off or sec_off + 8 > len(data):
            r["why"] = "no signature"
            return r
        length, _, typ = struct.unpack_from("<IHH", data, sec_off)
        if typ != 2:
            r["why"] = "not a PKCS#7 certificate"
            return r
        r["signed"] = True
        b = data[sec_off + 8:sec_off + length]
        ci = children(b, *tlv(b, 0)[2:4])                                      # ContentInfo
        sd = children(b, *tlv(b, ci[1][2])[2:4])                               # [0] -> SignedData
        k = 1
        enc_ci = children(b, sd[2][2], sd[2][3])                               # contentInfo: type, [0] content
        content = tlv(b, enc_ci[1][2])                                         # SpcIndirectDataContent
        spc = children(b, content[2], content[3])
        dig_info = children(b, spc[1][2], spc[1][3])                           # DigestInfo
        alg = oid(b[children(b, dig_info[0][2], dig_info[0][3])[0][2]:children(b, dig_info[0][2], dig_info[0][3])[0][3]])
        want = b[dig_info[1][2]:dig_info[1][3]]
        name = HASHES.get(alg)
        if not name:
            r["why"] = f"digest algorithm {alg}"
            return r
        r["file_digest_ok"] = authenticode_hash(data, name) == want
        certs = [c for c in sd[3:] if c[0] == 0xA0][0] if any(c[0] == 0xA0 for c in sd[3:]) else None
        signer_infos = children(b, sd[-1][2], sd[-1][3])
        si = children(b, signer_infos[0][2], signer_infos[0][3])
        ias = children(b, si[1][2], si[1][3])
        want_issuer, want_serial = b[ias[0][1]:ias[0][3]], b[ias[1][2]:ias[1][3]]
        si_alg = HASHES.get(oid(b[children(b, si[2][2], si[2][3])[0][2]:children(b, si[2][2], si[2][3])[0][3]]))
        attrs = si[3]
        if attrs[0] != 0xA0 or not si_alg:
            r["why"] = "no signed attributes"
            return r
        content_hash = hashlib.new(si_alg, b[content[2]:content[3]]).digest()
        for _, _, as_, ae in children(b, attrs[2], attrs[3]):
            o, vals = children(b, as_, ae)
            if oid(b[o[2]:o[3]]) == OID_MESSAGE_DIGEST:
                md = children(b, vals[2], vals[3])[0]
                r["attrs_ok"] = b[md[2]:md[3]] == content_hash
        sig = int.from_bytes(b[si[5][2]:si[5][3]], "big")
        signed_attrs = b"\x31" + b[attrs[1] + 1:attrs[3]]                    # [0] IMPLICIT -> SET OF
        for _, cs, _, ce in children(b, certs[2], certs[3]) if certs else []:
            issuer, serial, subject, n, ex = cert_info(b, cs, ce)
            if issuer != want_issuer or serial != want_serial:
                continue
            r["signer"] = subject
            r["signer_sha256"] = hashlib.sha256(b[cs:ce]).hexdigest()
            em = pow(sig, ex, n).to_bytes((n.bit_length() + 7) // 8, "big")
            h = hashlib.new(si_alg, signed_attrs).digest()
            prefix = {"sha1": bytes.fromhex("3021300906052b0e03021a05000414"),
                      "sha256": bytes.fromhex("3031300d060960864801650304020105000420"),
                      "md5": bytes.fromhex("3020300c06082a864886f70d020505000410")}[si_alg]
            t = prefix + h
            r["signature_ok"] = em == b"\x00\x01" + b"\xff" * (len(em) - len(t) - 3) + b"\x00" + t
        if not r["signer"]:
            r["why"] = "signing certificate not found"
    except (DerError, IndexError, ValueError, struct.error) as e:
        r["why"] = f"unreadable signature ({e})"
        return r
    r["ok"] = r["file_digest_ok"] and r["attrs_ok"] and r["signature_ok"]
    if not r["why"]:
        r["why"] = "valid" if r["ok"] else "file changed after signing" if not r["file_digest_ok"] else "signature doesn't verify"
    return r


def main(argv):
    for p in argv:
        r = verify(open(p, "rb").read())
        known = KNOWN_SIGNERS.get(r["signer_sha256"], "")
        print(f"{p}: {r['why']}; signer {r['signer'] or '-'} {r['signer_sha256'][:16]}{' (' + known + ')' if known else ''}; "
              f"file digest {r['file_digest_ok']}, attributes {r['attrs_ok']}, signature {r['signature_ok']}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
