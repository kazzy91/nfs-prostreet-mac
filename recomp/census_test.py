"""Offline proof of census.py (and pe_image.py) on a synthetic PE; no Ghidra, no game files.

    tools/.venv/bin/python -I recomp/census_test.py      (needs capstone; exit 3 = skipped without it)

The code section holds one function per instruction class, each 16 bytes apart from 0x401000:
  f0 fld dword [esp+4]; fstp st(0); fnstsw ax; ret      x87 3 (capstone's FPU group misses the last two)
  f1 paddb mm0, mm1; pmovmskb eax, mm0; emms; ret        MMX 3
  f2 movaps xmm0, xmm1; ret                              SSE1 1
  f3 paddq xmm0, xmm1; movapd xmm0, xmm1; ret            SSE2 2
  f4 rep movsd; stosb; ret                               string 2
  f5 ff ff                                               undecodable: a stub
  f6 haddps xmm0, xmm1; ret                              SSE3+ 1
  f7 call [GetTickCount's IAT slot]; ret                 an import call
Checked: function/stub counts, every class count, the eight "other" instructions (seven rets and the call), that the
SSE2/SSE3 instructions the translator lacks (paddq, haddps) are trapped while x87/MMX/SSE moves/string code is not,
the stub reason, imports by DLL, the Markdown table, and
pe_image's mapping (code range, IAT slots, refusing to move an image without relocations).
The main run uses two worker processes; the mutant runs in-process (jobs=1), where a patched classify() applies.
Check of the check: with classify() replaced by one that calls everything "other", the class checks must fail.
(A pool's workers start fresh on macOS, so a patch made here would never reach them.)
Last run: 12 checks PASS, mutant seen -> exit 0.
"""
import os
import struct
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
try:
    import capstone  # noqa: F401
except ImportError:
    print("SKIP: capstone not available (run with tools/.venv/bin/python)")
    sys.exit(3)
import census  # noqa: E402
import pe_image  # noqa: E402
import pe_report  # noqa: E402
import pe_report_test  # noqa: E402

FUNCS = [b"\xd9\x44\x24\x04\xdd\xd8\xdf\xe0\xc3", b"\x0f\xfc\xc1\x0f\xd7\xc0\x0f\x77\xc3", b"\x0f\x28\xc1\xc3",
         b"\x66\x0f\xd4\xc1\x66\x0f\x28\xc1\xc3", b"\xf3\xa5\xaa\xc3", b"\xff\xff", b"\xf2\x0f\x7c\xc1\xc3", None]


def code(slot):
    t = bytearray(b"\xcc" * 0x2000)
    for k, f in enumerate(FUNCS):
        f = f if f is not None else b"\xff\x15" + struct.pack("<I", slot) + b"\xc3"
        t[16 * k:16 * k + len(f)] = f
    return bytes(t)


def main():
    fails = []

    def check(label, ok, detail=""):
        print(f"{'PASS' if ok else 'FAIL'} {label}" + (f": {detail}" if detail and not ok else ""))
        if not ok:
            fails.append(label)

    slot = pe_report.parse(pe_report_test.build_pe(text=code(0)))["imports"]["KERNEL32.dll"][0][0]   # IAT layout is independent of .text
    pe = pe_report_test.build_pe(text=code(slot))
    tmp = tempfile.mkdtemp()
    exe, man = os.path.join(tmp, "synth.exe"), os.path.join(tmp, "functions.tsv")
    with open(exe, "wb") as f:
        f.write(pe)
    with open(man, "w") as f:
        f.write("# synthetic\n" + "".join(f"{0x401000 + 16 * k:08X}\tf{k}\n" for k in range(len(FUNCS))))
    try:
        img = pe_image.Image(exe)
        check("pe_image maps the code range and IAT slots", img.code()[0] == 0x401000 and img.imports.get(slot) == "KERNEL32.dll!GetTickCount"
              and img.read(0x401000, 3) == FUNCS[0][:3], (img.code(), img.imports))
        try:
            pe_image.Image(exe, base=0x02000000)
            moved = True
        except ValueError:
            moved = False
        check("an image without relocations isn't moved", not moved)
        r = census.census(exe, man, jobs=2)
        want = {"x87": 3, "MMX": 3, "SSE1": 1, "SSE2": 2, "SSE3+": 1, "string": 2, "other": 8}
        check("functions and stubs", r["functions"] == 8 and r["stubs"] == 1 and r["translated"] == 7, (r["functions"], r["stubs"]))
        check("the stub is the undecodable function", r["stub_list"] == [["00401050", "undecodable"]], r["stub_list"])
        check("instructions by class", r["by_class"] == want, r["by_class"])
        check("instruction total", r["instructions"] == sum(want.values()), r["instructions"])
        traps = {a for a, _ in r["trap_list"]}
        # paddq (64-bit lanes) and SSE3 haddps aren't translated; movaps (SSE) and movapd (SSE2 move) are
        check("untranslated SSE2/SSE3 instructions are trapped", traps == {"00401030", "00401060"}, r["trap_list"])
        check("x87, MMX, SSE moves and string code are not trapped", not traps & {"00401000", "00401004", "00401010", "00401013", "00401016", "00401020", "00401034", "00401040", "00401042"},
              r["trap_list"])
        check("trap reasons name the instruction", all(any(m in why for m in ("sse", "movaps", "movapd", "haddps", "paddq")) for _, why in r["trap_list"]),
              r["trap_reasons"])
        check("imports by DLL", dict(r["imports_by_dll"]) == {"KERNEL32.dll": 2, "WS2_32.dll": 1}, r["imports_by_dll"])
        md = census.markdown(r)
        check("Markdown table", "| x87 FPU | 3 (" in md and "| SSE2 | 2 (" in md and "undecodable 1" in md, md)
        saved = census.classify
        census.classify = lambda insn, X: "other"
        try:
            broken = census.census(exe, man, jobs=1)["by_class"] != want   # in-process, so the patch applies
        finally:
            census.classify = saved
        print(f"  mutant 'classify -> other': class counts {'DIFFER (test sees the break)' if broken else 'unchanged'}")
        check("classifier mutant visible", broken)
    finally:
        for p in (exe, man):
            os.unlink(p)
        os.rmdir(tmp)
    print(f"{'FAIL' if fails else 'ok'}: {len(fails)} failing")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
