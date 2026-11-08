"""Offline proof of pe_report.py (the Phase 0 gate) on synthetic PEs; no game files.

    python3 -I recomp/pe_report_test.py

build_pe() writes a minimal i386 PE: .text (plain-looking code), .rdata (import directory, names, export table,
version info), .data, optional extra sections, entry point and import list as given. Cases:
(a) plain image: verdict plain, exit 0, imports/exports/version read back exactly;
(b) + a '.securom' section: refused, names SecuROM;
(c) entry point moved into a later executable section: refused, names the section;
(d) .text filled with random bytes: refused for entropy;
(e) a writable code section alone: weak finding only, still plain;
(f) not a PE / truncated header: NotPE, exit 1.
Check of the check: with each detector disabled in turn (monkey-patched), its case must stop being refused; the run
fails if a disabled detector still "catches" its case (the test would not be testing that detector).
Last run: 6 cases PASS, 3 detector mutants seen -> exit 0.
"""
import os
import random
import struct
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pe_report  # noqa: E402

FILE_ALIGN, SECT_ALIGN, BASE = 0x200, 0x1000, 0x400000
CODE, RDATA, DATA = 0x60000020, 0x40000040, 0xC0000040


def plain_code(n):
    """Bytes that look like MSVC x86: prologues, calls, movs, int3 padding (entropy well under 7)."""
    rnd, out = random.Random(1), bytearray()
    while len(out) < n:
        out += b"\x55\x8b\xec\x83\xec" + bytes([rnd.randrange(4, 64, 4)])
        out += b"\x8b\x45" + bytes([rnd.randrange(8, 32, 4)]) + b"\xe8" + struct.pack("<i", rnd.randrange(-9999, 9999))
        out += b"\x89\x45\xfc\x8b\xe5\x5d\xc3" + b"\xcc" * rnd.randrange(1, 9)
    return bytes(out[:n])


def version_blob():
    fixed = struct.pack("<13I", 0xFEEF04BD, 0x10000, (1 << 16) | 1, (0 << 16) | 2, (1 << 16) | 1, 0, 0x3F, 0, 4, 1, 0, 0, 0)
    # Real layout: the VS_VERSION_INFO key, VS_FIXEDFILEINFO, then StringFileInfo with the key/value strings.
    strings = "\0".join(["StringFileInfo", "040904b0", "ProductName", "Synthetic Test", "InternalName", "synth.exe", ""])
    return "VS_VERSION_INFO\0".encode("utf-16le") + fixed + strings.encode("utf-16le")


def build_pe(imports=None, extra=(), entry_section=".text", text=None, text_chars=CODE, export_name="synth.exe",
             export_fns=("ExportedThing",)):
    """bytes of a PE. imports: {dll: [name or '#ordinal']}. extra: [(name, bytes, chars)] appended sections."""
    imports = imports if imports is not None else {"KERNEL32.dll": ["GetTickCount", "Sleep"], "WS2_32.dll": ["#3"]}
    text = text if text is not None else plain_code(0x3000)
    sections = [(".text", text, text_chars), (".rdata", None, RDATA), (".data", b"\x01\x02" * 0x200, DATA)]
    sections += list(extra)
    rva = {}
    v = SECT_ALIGN
    for name, blob, _ in sections:          # .rdata size is fixed below before layout matters
        rva[name] = v
        v += SECT_ALIGN * 4
    # .rdata: import descriptors, ILTs, IATs, hint/names, export directory, version info
    r0 = rva[".rdata"]
    rd = bytearray(0x2000)
    dlls = list(imports)
    desc_off, p = 0, 20 * (len(dlls) + 1)
    layout = []
    for dll in dlls:
        n = len(imports[dll])
        ilt, iat = p, p + 4 * (n + 1)
        p = iat + 4 * (n + 1)
        layout.append((dll, ilt, iat))
    for i, (dll, ilt, iat) in enumerate(layout):
        name_off = p
        rd[p:p + len(dll) + 1] = dll.encode() + b"\0"
        p += len(dll) + 2
        for k, fn in enumerate(imports[dll]):
            if fn.startswith("#"):
                val = 0x80000000 | int(fn[1:])
            else:
                val = r0 + p
                rd[p:p + 2 + len(fn) + 1] = b"\0\0" + fn.encode() + b"\0"
                p += 2 + len(fn) + 2
            struct.pack_into("<I", rd, ilt + 4 * k, val)
            struct.pack_into("<I", rd, iat + 4 * k, val)
        struct.pack_into("<IIIII", rd, desc_off + 20 * i, r0 + ilt, 0, 0, r0 + name_off, r0 + iat)
    exp = p = (p + 15) & ~15
    names_rva = []
    p += 40
    dn = p
    rd[p:p + len(export_name) + 1] = export_name.encode() + b"\0"
    p += len(export_name) + 1
    for fn in export_fns:
        names_rva.append(r0 + p)
        rd[p:p + len(fn) + 1] = fn.encode() + b"\0"
        p += len(fn) + 1
    p = (p + 3) & ~3
    nt = p
    for k, a in enumerate(names_rva):
        struct.pack_into("<I", rd, nt + 4 * k, a)
    p += 4 * len(names_rva)
    struct.pack_into("<IIHHIIIIIII", rd, exp, 0, 0, 0, 0, r0 + dn, 1, len(export_fns), len(export_fns), 0, r0 + nt, 0)
    p = (p + 3) & ~3
    vb = version_blob()
    rd[p:p + len(vb)] = vb
    sections[1] = (".rdata", bytes(rd), RDATA)
    # headers
    nsec = len(sections)
    hdr = bytearray(0x400)
    hdr[0:2] = b"MZ"
    struct.pack_into("<I", hdr, 0x3C, 0x80)
    hdr[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", hdr, 0x84, 0x14C, nsec, 0x4722CE66, 0, 0, 224, 0x103)
    opt = 0x98
    entry = rva[entry_section] + 0x10
    size_img = v
    struct.pack_into("<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII", hdr, opt, 0x10B, 8, 0, 0, 0, 0, entry, 0, 0, BASE, SECT_ALIGN,
                     FILE_ALIGN, 4, 0, 0, 0, 4, 0, 0, size_img, 0x400, 0, 2, 0, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    struct.pack_into("<II", hdr, opt + 96, r0 + exp, 40)                         # export
    struct.pack_into("<II", hdr, opt + 104, r0, 20 * (len(dlls) + 1))            # import
    body, raw = bytearray(), 0x400
    for i, (name, blob, chars) in enumerate(sections):
        size = (len(blob) + FILE_ALIGN - 1) & ~(FILE_ALIGN - 1)
        struct.pack_into("<8sIIIIIIHHI", hdr, opt + 224 + 40 * i, name.encode(), len(blob), rva[name], size,
                         raw + len(body), 0, 0, 0, 0, chars)
        body += blob + bytes(size - len(blob))
    return bytes(hdr) + bytes(body)


def verdict(data):
    return any(s == "strong" for s, _ in pe_report.findings(pe_report.parse(data)))


def run_main(data):
    with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
        f.write(data)
    try:
        import contextlib
        import io
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return pe_report.main([f.name])
    finally:
        os.unlink(f.name)


def main():
    fails = []

    def check(label, ok, detail=""):
        print(f"{'PASS' if ok else 'FAIL'} {label}" + (f": {detail}" if detail and not ok else ""))
        if not ok:
            fails.append(label)

    plain = build_pe()
    info = pe_report.parse(plain)
    imps = {k: [f for _, f in v] for k, v in info["imports"].items()}
    check("(a) plain image accepted", not verdict(plain) and run_main(plain) == 0, pe_report.findings(info))
    check("(a) imports read back", imps == {"KERNEL32.dll": ["GetTickCount", "Sleep"], "WS2_32.dll": ["#3"]}, imps)
    check("(a) IAT slots are VAs", info["imports"]["KERNEL32.dll"][0][0] > BASE, info["imports"])
    check("(a) exports and version read back", info["exports"]["names"] == ["ExportedThing"] and
          info["version"].get("file_version") == "1.1.0.2" and info["version"].get("ProductName") == "Synthetic Test",
          (info["exports"], info["version"]))

    securom = build_pe(extra=[(".securom", plain_code(0x800), 0xE0000020)])
    F = pe_report.findings(pe_report.parse(securom))
    check("(b) .securom section refused", verdict(securom) and run_main(securom) == 2 and
          any("SecuROM" in t for _, t in F), F)

    stub = build_pe(extra=[("est", plain_code(0x800), CODE)], entry_section="est")
    F = pe_report.findings(pe_report.parse(stub))
    check("(c) entry point outside first code section refused", verdict(stub) and any("'est'" in t for _, t in F), F)

    noise = build_pe(text=random.Random(7).randbytes(0x3000))
    F = pe_report.findings(pe_report.parse(noise))
    check("(d) encrypted .text refused", verdict(noise) and any("entropy" in t for _, t in F), F)

    rwx = build_pe(text_chars=0xE0000020)
    F = pe_report.findings(pe_report.parse(rwx))
    check("(e) writable code is a weak finding only", not verdict(rwx) and any(s == "weak" for s, _ in F), F)

    bad = [b"", b"MZ" + bytes(10), plain[:0x90], b"\x7fELF" + bytes(100)]
    nope = all(_raises(lambda d=d: pe_report.parse(d)) for d in bad)
    check("(f) non-PE and truncated inputs raise NotPE", nope and run_main(b"not a pe") == 1)

    # check of the check: disable each detector, its case must slip through
    seen = 0
    for label, data, patch in (
            ("wrapper names", securom, lambda: setattr(pe_report, "WRAPPER_SECTIONS", {})),
            ("entry section", stub, lambda: setattr(pe_report, "section_of", lambda s, r: ".text")),
            ("entropy", noise, lambda: setattr(pe_report, "CODE_ENTROPY_MAX", 8.1))):
        saved = dict(WRAPPER_SECTIONS=pe_report.WRAPPER_SECTIONS, section_of=pe_report.section_of,
                     CODE_ENTROPY_MAX=pe_report.CODE_ENTROPY_MAX)
        patch()
        try:
            slipped = not verdict(data)
        finally:
            for k, val in saved.items():
                setattr(pe_report, k, val)
        print(f"  mutant '{label}' disabled: case {'ACCEPTED (test sees the break)' if slipped else 'still refused'}")
        seen += slipped
    check("detector mutants all visible", seen == 3, f"{seen}/3")
    print(f"{'FAIL' if fails else 'ok'}: {len(fails)} failing")
    return 1 if fails else 0


def _raises(f):
    try:
        f()
    except pe_report.NotPE:
        return True
    return False


if __name__ == "__main__":
    sys.exit(main())
