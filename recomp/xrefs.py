"""Who calls an import, or uses a string? Code cross-references by byte pattern, mapped to manifest functions.

    python3 -I recomp/xrefs.py <exe> <manifest.tsv> --import Direct3DCreate9 [--import ...] [--string ".vp6" ...]
                                                    [--calls 006E4280 ...]

--import NAME: references to the import's IAT slot from the code section (call/jmp [slot], mov reg, [slot], push [slot]):
  each site with the manifest function containing it. A site that is a jump thunk (jmp [slot]) is followed one level:
  its direct callers are listed under it.
--calls VA: direct callers of VA, i.e. call/jmp rel32 (E8/E9) whose target is VA, with their functions.
--string TEXT: every occurrence of TEXT (ASCII, NUL-terminated) in the image's data sections, then every 4-byte
  little-endian use of its address in the code section (push offset, mov reg, offset, operands), with the function.
A byte-pattern scan, not a disassembly: a hit can be a coincidence inside an instruction, so read it as a lead. Stdlib
only; the file is only read.
"""
import argparse
import bisect
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pe_image  # noqa: E402

# opcode prefixes followed by a 32-bit absolute memory operand: call/jmp/push [m32] (FF 15/25/35), mov eax, [m32] (A1),
# mov r32, [m32] (8B 05/0D/15/1D/25/2D/35/3D)
SLOT_REFS = [b"\xff\x15", b"\xff\x25", b"\xff\x35", b"\xa1"] + [bytes([0x8B, m]) for m in (0x05, 0x0D, 0x15, 0x1D, 0x25, 0x2D, 0x35, 0x3D)]


def load_starts(manifest):
    starts, names = [], {}
    for line in open(manifest):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        a, _, n = line.partition("\t")
        starts.append(int(a, 16))
        names[int(a, 16)] = n or f"FUN_{int(a, 16):08x}"
    starts.sort()
    return starts, names


def owner(starts, names, va):
    k = bisect.bisect_right(starts, va) - 1
    return (starts[k], names[starts[k]]) if k >= 0 else (0, "?")


def find_all(blob, needle):
    i = blob.find(needle)
    while i >= 0:
        yield i
        i = blob.find(needle, i + 1)


def import_refs(img, name):
    slots = [s for s, n in img.imports.items() if n.split("!", 1)[1] == name]
    lo, hi = img.code()
    code = img.read(lo, hi - lo)
    out = []
    for slot in slots:
        for pre in SLOT_REFS:
            for i in find_all(code, pre + struct.pack("<I", slot)):
                out.append((lo + i, f"{pre.hex()} [{slot:08X}]"))
    return slots, sorted(out)


def rel32_index(img):
    """target VA -> [(site VA, 'call'|'jmp')] for every E8/E9 rel32 in the code section whose target lands in it."""
    lo, hi = img.code()
    code = img.read(lo, hi - lo)
    idx = {}
    for op, kind in ((0xE8, "call"), (0xE9, "jmp")):
        i = code.find(op)
        while 0 <= i <= len(code) - 5:
            t = (lo + i + 5 + struct.unpack_from("<i", code, i + 1)[0]) & 0xFFFFFFFF
            if lo <= t < hi:
                idx.setdefault(t, []).append((lo + i, kind))
            i = code.find(op, i + 1)
    return idx


def string_refs(img, text):
    lo, hi = img.code()
    code = img.read(lo, hi - lo)
    addrs = []
    for name, vs, rva, rs, _, chars in img.sections:
        if chars & 0x20000000:
            continue
        sec = img.read(img.base + rva, min(vs or rs, rs) if rs else 0) or b""
        for i in find_all(sec, text.encode("latin-1") + b"\0"):
            addrs.append(img.base + rva + i)
    out = []
    for a in addrs:
        for i in find_all(code, struct.pack("<I", a)):
            out.append((lo + i, a))
    return addrs, sorted(out)


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    ap.add_argument("exe")
    ap.add_argument("manifest")
    ap.add_argument("--import", dest="imports", action="append", default=[])
    ap.add_argument("--string", dest="strings", action="append", default=[])
    ap.add_argument("--calls", action="append", default=[], type=lambda v: int(v, 16))
    a = ap.parse_args(argv)
    img = pe_image.Image(a.exe)
    starts, names = load_starts(a.manifest)
    idx = rel32_index(img) if a.imports or a.calls else {}

    def callers(target, indent):
        for site, kind in sorted(idx.get(target, [])):
            f, n = owner(starts, names, site)
            print(f"{indent}{site:08X}  {kind:16}  in {f:08X} {n}")

    for name in a.imports:
        slots, refs = import_refs(img, name)
        print(f"import {name}: slot(s) {', '.join(f'{s:08X}' for s in slots) or 'none'}; {len(refs)} reference(s)")
        for site, how in refs:
            f, n = owner(starts, names, site)
            print(f"  {site:08X}  {how:16}  in {f:08X} {n}")
            if how.startswith("ff25"):
                callers(site, "    <- ")
    for t in a.calls:
        print(f"calls to {t:08X} {names.get(t, '')}: {len(idx.get(t, []))}")
        callers(t, "  ")
    for text in a.strings:
        addrs, refs = string_refs(img, text)
        print(f"string {text!r}: at {', '.join(f'{x:08X}' for x in addrs) or 'nowhere'}; {len(refs)} code reference(s)")
        for site, target in refs:
            f, n = owner(starts, names, site)
            print(f"  {site:08X}  -> {target:08X}  in {f:08X} {n}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
