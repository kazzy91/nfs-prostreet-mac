"""Offline proof of ghidra_functions.py's --data-refs pass on a synthetic PE; no Ghidra, no game files.

    tools/.venv/bin/python -I recomp/ghidra_functions_test.py      (needs capstone; exit 3 = skipped without it)

The code section (0x401000) holds, with Ghidra's view being only f0, f3, f5, f6 and f8:
  f0 0x401000  push 0x401040; add esp, 4; ret     -> f4 reached only as a code immediate
  f1 0x401010  call f2; ret                       -> reached only through a pointer in a data section
  f2 0x401020  mov eax, 1; ret                    -> reached only from f1: the call closure must add it
  f3 0x401030  push ebp; mov ebp, esp; xor eax, eax; inc eax (0x401035); pop ebp; ret
  f4 0x401040  ret
  f5 0x401050  three mov eax, imm32; inc eax; inc eax (0x401060, 16-byte aligned); ret
  f6 0x401070  call $+5; pop eax; call f7; ret     -> a Ghidra function: f7 joins by the closure, $+5 doesn't
  f7 0x401080  ret                                 -> reached only by a direct call Ghidra didn't follow
  f8 0x401090  jmp eax; call f9; ret              -> a Ghidra function whose call sits past an indirect jump
  f9 0x4010A0  ret                                 -> found by the linear sweep's call targets
Data pointers: f1, 0x401035 (inside f3, not a plausible start), 0x401060 (aligned, but code falls into it) and
0x401041 (int3 padding right after f4's ret).
Expected additions: exactly f1 and f4 (data_ref_), f2, f7 and f9 (called_).
Check of the check: with the plausible-start test disabled, 0x401060 must get in (the test sees the rule).
Last run: 6 checks PASS, mutant seen -> exit 0.
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
import ghidra_functions as gf  # noqa: E402
import pe_report_test  # noqa: E402


def code():
    t = bytearray(b"\xcc" * 0x3000)
    def put(at, b): t[at - 0x401000:at - 0x401000 + len(b)] = b
    put(0x401000, b"\x68" + struct.pack("<I", 0x401040) + b"\x83\xc4\x04\xc3")
    put(0x401010, b"\xe8" + struct.pack("<i", 0x401020 - (0x401010 + 5)) + b"\xc3")
    put(0x401020, b"\xb8\x01\x00\x00\x00\xc3")
    put(0x401030, b"\x55\x89\xe5\x31\xc0\x40\x5d\xc3")
    put(0x401040, b"\xc3")
    put(0x401050, b"\xb8\x01\x00\x00\x00" * 3 + b"\x40\x40\xc3")
    put(0x401070, b"\xe8\x00\x00\x00\x00\x58\xe8" + struct.pack("<i", 0x401080 - (0x401076 + 5)) + b"\xc3")
    put(0x401080, b"\xc3")
    put(0x401090, b"\xff\xe0\xe8" + struct.pack("<i", 0x4010A0 - (0x401092 + 5)) + b"\xc3")
    put(0x4010A0, b"\xc3")
    return bytes(t)


def main():
    fails = []

    def check(label, ok, detail=""):
        print(f"{'PASS' if ok else 'FAIL'} {label}" + (f": {detail}" if detail and not ok else ""))
        if not ok:
            fails.append(label)

    ptrs = struct.pack("<IIII", 0x401010, 0x401035, 0x401060, 0x401041) + bytes(0x100)
    pe = pe_report_test.build_pe(text=code(), extra=[(".ptrs", ptrs, 0xC0000040)])
    with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
        f.write(pe)
    try:
        rows = [(0x401000, "f0"), (0x401030, "f3"), (0x401050, "f5"), (0x401070, "f6"), (0x401090, "f8")]
        got = gf.data_referenced(f.name, rows, rva=False)
        want = [(0x401010, "data_ref_00401010"), (0x401020, "called_00401020"), (0x401040, "data_ref_00401040"),
                (0x401080, "called_00401080"), (0x4010A0, "called_004010A0")]
        check("pointer-only, immediate-only and call-closure starts are added", got == want, got)
        check("a pointer into the middle of a function is refused", 0x401035 not in {a for a, _ in got})
        check("an aligned address that code falls into is refused", 0x401060 not in {a for a, _ in got})
        check("call $+5 (get EIP) is not a function start", 0x401075 not in {a for a, _ in got})
        check("int3 padding after a ret is not a function start", 0x401041 not in {a for a, _ in got})
        rva = gf.data_referenced(f.name, [(a - 0x400000, n) for a, n in rows], rva=True)
        check("--rva gives the same starts relative to the image base", rva == [(a - 0x400000, n) for a, n in want], rva)
        saved = gf._plausible
        gf._plausible = lambda t, s, e: t in s
        try:
            slipped = 0x401060 in {a for a, _ in gf.data_referenced(f.name, rows, rva=False)}
        finally:
            gf._plausible = saved
        print(f"  mutant 'plausible-start test disabled': 0x401060 {'ADDED (test sees the rule)' if slipped else 'still refused'}")
        check("plausible-start mutant visible", slipped)
    finally:
        os.unlink(f.name)
    print(f"{'FAIL' if fails else 'ok'}: {len(fails)} failing")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
