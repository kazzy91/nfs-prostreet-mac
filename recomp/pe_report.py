"""PE report and Phase 0 gate: is this 32-bit Windows exe plain code we can translate, or is it packed/protected?

    python3 -I recomp/pe_report.py path/to/nfs.exe [--json] [--imports]

Reads the file only (stdlib, no third-party modules, nothing executed). Prints the header facts the port depends on
(image base, entry point, relocations, sections with entropy, TLS, exports, version resource) and a verdict:

  exit 0  plain: entry point in the first code section, no wrapper sections, code entropy in the normal x86 range
  exit 2  protected or packed: at least one strong finding below. Static recompilation needs the plain code bytes,
          and this project never unpacks or strips copy protection (CLAUDE.md, rule 2)
  exit 1  not a 32-bit PE, or unreadable

Strong findings: a section name known from DRM wrappers or packers; the entry point outside the first executable
section; an executable section with entropy above CODE_ENTROPY_MAX. Weak findings (reported, not decisive): a
writable code section; the import directory outside the usual import sections.

Offline test: recomp/pe_report_test.py (synthetic PEs, no game files).
"""
import collections
import hashlib
import json
import math
import struct
import sys
import time

# Plain compiled x86 code sits around 6.0-6.7 bits/byte; encrypted or compressed data is close to 8.
CODE_ENTROPY_MAX = 7.2
# Section names left by copy-protection wrappers and executable packers (lower-case comparison).
WRAPPER_SECTIONS = {
    ".securom": "SecuROM", ".sforce": "StarForce", ".sforce3": "StarForce", ".tages": "TAGES",
    ".stxt371": "SafeDisc", ".stxt774": "SafeDisc", "stxt371": "SafeDisc", "stxt774": "SafeDisc",
    ".dsstext": "LaserLock", ".laserlo": "LaserLock", ".vmp0": "VMProtect", ".vmp1": "VMProtect",
    ".themida": "Themida", ".winlice": "WinLicense", "upx0": "UPX", "upx1": "UPX", ".aspack": "ASPack",
    ".adata": "ASPack", ".petite": "Petite", ".nsp0": "NsPack", ".nsp1": "NsPack", ".mpress1": "MPRESS",
    ".mpress2": "MPRESS", ".enigma1": "Enigma", ".enigma2": "Enigma", ".arm": "Armadillo", ".pec1": "PECompact",
    ".pec2": "PECompact", ".boom": "The Boomerang", ".bind": "Steam DRM", ".ccg": "CrackProof",
}
IMPORT_SECTIONS = {".rdata", ".idata"}
DIR_NAMES = ("export", "import", "resource", "exception", "security", "basereloc", "debug", "architecture",
             "globalptr", "tls", "loadconfig", "boundimport", "iat", "delayimport", "clr", "reserved")
SCN_CODE, SCN_EXEC, SCN_WRITE = 0x20, 0x20000000, 0x80000000


class NotPE(ValueError):
    pass


def entropy(b):
    if not b:
        return 0.0
    n = len(b)
    return -sum(v / n * math.log2(v / n) for v in collections.Counter(b).values())


def parse(data):
    """Everything the report needs from a 32-bit PE image, as a dict. Raises NotPE."""
    try:
        if data[:2] != b"MZ":
            raise NotPE("no MZ header")
        pe = struct.unpack_from("<I", data, 0x3C)[0]
        if data[pe:pe + 4] != b"PE\0\0":
            raise NotPE("no PE signature")
        machine, nsec, stamp, _, _, optsz, chars = struct.unpack_from("<HHIIIHH", data, pe + 4)
        opt = pe + 24
        if machine != 0x14C or struct.unpack_from("<H", data, opt)[0] != 0x10B:
            raise NotPE("not a 32-bit x86 image")
        if not 0 < nsec <= 96:
            raise NotPE(f"implausible section count {nsec}")
        entry, = struct.unpack_from("<I", data, opt + 16)
        base, = struct.unpack_from("<I", data, opt + 28)
        size_of_image, = struct.unpack_from("<I", data, opt + 56)
        subsystem, dllchars = struct.unpack_from("<HH", data, opt + 68)
        ndirs = min(struct.unpack_from("<I", data, opt + 92)[0], 16)
        dirs = {DIR_NAMES[i]: struct.unpack_from("<II", data, opt + 96 + 8 * i) for i in range(ndirs)}
        sections = []
        for i in range(nsec):
            o = opt + optsz + 40 * i
            name = data[o:o + 8].rstrip(b"\0").decode("latin-1")
            vsize, va, rsize, roff = struct.unpack_from("<IIII", data, o + 8)
            sc, = struct.unpack_from("<I", data, o + 36)
            raw = data[roff:roff + rsize]
            sections.append({"name": name, "va": va, "vsize": vsize, "raw_off": roff, "raw_size": rsize,
                             "chars": sc, "entropy": round(entropy(raw), 3)})
    except struct.error:
        raise NotPE("truncated header") from None
    info = {"size": len(data), "sha1": hashlib.sha1(data).hexdigest(), "sha256": hashlib.sha256(data).hexdigest(),
            "timestamp": stamp, "characteristics": chars, "relocs_stripped": bool(chars & 1),
            "image_base": base, "entry_rva": entry, "size_of_image": size_of_image, "subsystem": subsystem,
            "dll_characteristics": dllchars, "dirs": {k: v for k, v in dirs.items() if v[0]},
            "sections": sections}
    end = max((s["raw_off"] + s["raw_size"] for s in sections), default=0)
    info["overlay"] = max(0, len(data) - end)
    info["entry_section"] = section_of(sections, entry)
    info["imports"] = imports(data, sections, base, dirs.get("import", (0, 0))[0])
    info["exports"] = exports(data, sections, dirs.get("export", (0, 0))[0])
    info["version"] = version(data)
    return info


def section_of(sections, rva):
    for s in sections:
        if s["va"] <= rva < s["va"] + max(s["vsize"], s["raw_size"]):
            return s["name"]
    return None


def _off(sections, rva):
    for s in sections:
        if s["va"] <= rva < s["va"] + max(s["vsize"], s["raw_size"]):
            o = rva - s["va"]
            return s["raw_off"] + o if o < s["raw_size"] else None
    return None


def _cstr(data, off, limit=512):
    return data[off:off + limit].split(b"\0")[0].decode("latin-1")


def imports(data, sections, base, rva):
    """{dll: [(iat slot VA, name or '#ordinal')]} in table order."""
    out = {}
    o = _off(sections, rva) if rva else None
    for _ in range(256):
        if o is None or o + 20 > len(data):
            break
        ilt, _, _, name, iat = struct.unpack_from("<IIIII", data, o)
        if not (ilt or name or iat):
            break
        no = _off(sections, name)
        dll = _cstr(data, no) if no is not None else f"?{name:#x}"
        t, slot, fns = _off(sections, ilt or iat), iat, []
        while t is not None and t + 4 <= len(data) and len(fns) < 4096:
            v, = struct.unpack_from("<I", data, t)
            if not v:
                break
            if v & 0x80000000:
                fns.append((base + slot, f"#{v & 0xFFFF}"))
            else:
                ho = _off(sections, v)
                fns.append((base + slot, _cstr(data, ho + 2) if ho is not None else f"?{v:#x}"))
            t += 4
            slot += 4
        out.setdefault(dll, []).extend(fns)
        o += 20
    return out


def exports(data, sections, rva):
    o = _off(sections, rva) if rva else None
    if o is None:
        return {}
    name, _, nfun, nnames, _, names, _ = struct.unpack_from("<IIIIIII", data, o + 12)
    no, out = _off(sections, names), []
    for i in range(min(nnames, 4096)):
        if no is None:
            break
        so = _off(sections, struct.unpack_from("<I", data, no + 4 * i)[0])
        if so is not None:
            out.append(_cstr(data, so))
    dn = _off(sections, name)
    return {"dll_name": _cstr(data, dn) if dn is not None else "", "functions": nfun, "names": out}


def version(data):
    """FileVersion/ProductVersion and the common string values of VS_VERSION_INFO, or {}."""
    i = data.find(b"\xbd\x04\xef\xfe")      # VS_FIXEDFILEINFO signature
    if i < 0:
        return {}
    u = lambda k: struct.unpack_from("<I", data, i + k)[0]
    out = {"file_version": "%d.%d.%d.%d" % (u(8) >> 16, u(8) & 0xFFFF, u(12) >> 16, u(12) & 0xFFFF),
           "product_version": "%d.%d.%d.%d" % (u(16) >> 16, u(16) & 0xFFFF, u(20) >> 16, u(20) & 0xFFFF)}
    blob = data[i:i + 4096].decode("utf-16le", "ignore")
    for key in ("CompanyName", "FileDescription", "InternalName", "OriginalFilename", "ProductName"):
        k = blob.find(key + "\0")
        if k >= 0:
            out[key] = blob[k + len(key):k + len(key) + 80].lstrip("\0").split("\0")[0]
    return out


def findings(info):
    """[(strength 'strong'|'weak', text)] for protection/packing evidence."""
    out, secs = [], info["sections"]
    for s in secs:
        tool = WRAPPER_SECTIONS.get(s["name"].lower())
        if tool:
            out.append(("strong", f"section {s['name']!r} is a {tool} wrapper/packer section"))
    code = [s for s in secs if s["chars"] & (SCN_CODE | SCN_EXEC)]
    if not code:
        out.append(("strong", "no executable section"))
    elif info["entry_section"] != code[0]["name"]:
        out.append(("strong", f"entry point is in {info['entry_section']!r}, not in the first code section "
                              f"{code[0]['name']!r}"))
    for s in code:
        if s["raw_size"] and s["entropy"] > CODE_ENTROPY_MAX:
            out.append(("strong", f"executable section {s['name']!r} has entropy {s['entropy']:.2f} "
                                  f"(> {CODE_ENTROPY_MAX}): encrypted or compressed"))
        if s["chars"] & SCN_WRITE:
            out.append(("weak", f"executable section {s['name']!r} is also writable"))
    imp = info["dirs"].get("import")
    if imp:
        where = section_of(secs, imp[0])
        if where not in IMPORT_SECTIONS:
            out.append(("weak", f"import directory lives in {where!r}, not .rdata/.idata (rebuilt by a wrapper?)"))
    return out


def report(info, show_imports=False):
    L = []
    base = info["image_base"]
    L.append(f"size {info['size']:,} bytes  SHA-1 {info['sha1']}")
    L.append(f"SHA-256 {info['sha256']}")
    L.append(f"linked {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(info['timestamp']))} UTC  "
             f"subsystem {info['subsystem']}  DllCharacteristics {info['dll_characteristics']:#06x}  "
             f"relocations {'stripped' if info['relocs_stripped'] else 'present'}")
    L.append(f"image base {base:#010x}  SizeOfImage {info['size_of_image']:#x}  "
             f"entry RVA {info['entry_rva']:#x} -> VA {base + info['entry_rva']:#010x} in {info['entry_section']!r}")
    L.append("directories: " + ", ".join(f"{k} {v[0]:#x}+{v[1]:#x}" for k, v in info["dirs"].items()))
    L.append(f"{'section':10}{'VA':>10}{'VSize':>10}{'RawSize':>10}  chars     entropy")
    for s in info["sections"]:
        L.append(f"{s['name']:10}{base + s['va']:>10x}{s['vsize']:>10x}{s['raw_size']:>10x}  {s['chars']:08x}  "
                 f"{s['entropy']:.3f}")
    L.append(f"overlay {info['overlay']:,} bytes")
    if info["exports"]:
        e = info["exports"]
        L.append(f"exports ({e['dll_name']}): {', '.join(e['names']) or '(by ordinal only)'}")
    if info["version"]:
        L.append("version: " + ", ".join(f"{k} {v}" for k, v in info["version"].items()))
    imps = info["imports"]
    L.append(f"imports: {sum(map(len, imps.values()))} functions in {len(imps)} DLLs: " +
             ", ".join(f"{k} {len(v)}" for k, v in imps.items()))
    if show_imports:
        for dll, fns in imps.items():
            L.append(f"  {dll}: " + " ".join(f for _, f in fns))
    F = findings(info)
    for strength, text in F:
        L.append(f"[{strength}] {text}")
    L.append("verdict: " + ("PROTECTED/PACKED (not translatable as is)" if any(s == "strong" for s, _ in F)
                            else "plain"))
    return "\n".join(L)


def main(argv):
    args = [a for a in argv if not a.startswith("--")]
    if len(args) != 1:
        print(__doc__.strip().splitlines()[2].strip(), file=sys.stderr)
        return 1
    try:
        data = open(args[0], "rb").read()
        info = parse(data)
    except (OSError, NotPE) as e:
        print(f"{args[0]}: {e}", file=sys.stderr)
        return 1
    F = findings(info)
    if "--json" in argv:
        info = dict(info, findings=F, imports={k: [[f"{a:#010x}", n] for a, n in v] for k, v in info["imports"].items()})
        print(json.dumps(info, indent=1))
    else:
        print(report(info, "--imports" in argv))
    return 2 if any(s == "strong" for s, _ in F) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
