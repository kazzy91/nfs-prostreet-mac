#!/usr/bin/env python3
"""recomp/xrefs.py on a synthetic PE (offline; temp dir).

Run: python3 -I recomp/xrefs_test.py          (stdlib only)

The code section holds an import thunk (jmp [GetTickCount slot]), two functions that call it with E8 rel32, one tail
jump (E9) to a function, a push of a string's address, a call [Sleep slot] and a constructor storing a vtable. A data
section holds the string and MSVC RTTI for class ns::Foo (type descriptor, complete object locator, a two-slot vtable).
The test checks that every reference is found and mapped to its manifest function, that the thunk's callers are listed
under it, that a rel32 whose target falls outside the code section is not indexed, and that --class finds the vtable,
its slots and the constructor.
"""
import contextlib
import io
import os
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pe_image  # noqa: E402
import pe_report_test  # noqa: E402
import xrefs  # noqa: E402

STR = b"MOVIES\\%s_test.vp6\0"


def build(slot_tick=0, slot_sleep=0, str_va=0):
    t = bytearray(b"\xcc" * 0x3000)
    t[0x000:0x006] = b"\xff\x25" + struct.pack("<I", slot_tick)                 # 401000 thunk: jmp [GetTickCount]
    def rel(at, op, target):                                                      # E8/E9 at 0x401000 + at
        t[at:at + 5] = bytes([op]) + struct.pack("<i", target - (0x401000 + at + 5))
    t[0x010] = 0x55; rel(0x011, 0xE8, 0x401000); t[0x016] = 0xC3                # 401010 calls the thunk
    t[0x020] = 0x55; rel(0x021, 0xE8, 0x401000)                                  # 401020 calls it too,
    t[0x026:0x02B] = b"\x68" + struct.pack("<I", str_va)                          #   pushes the string,
    t[0x02B:0x031] = b"\xff\x15" + struct.pack("<I", slot_sleep)                  #   calls [Sleep],
    rel(0x031, 0xE9, 0x401040)                                                    #   tail-jumps to 401040
    t[0x040] = 0xC3                                                               # 401040
    rel(0x050, 0xE8, 0x00100000)                                                  # 401050: target outside the code
    t[0x060:0x067] = b"\xc7\x01" + struct.pack("<I", str_va + 0x64) + b"\xc3"     # 401060 ctor: mov [ecx], vtable
    d = bytearray(STR.ljust(0x20, b"\0"))
    d += b"\0" * 8 + b".?AVFoo@ns@@\0".ljust(0x18, b"\0")                         # +20 type descriptor
    d += struct.pack("<5I", 0, 0, 0, str_va + 0x20, 0).ljust(0x20, b"\0")         # +40 complete object locator
    d += struct.pack("<4I", str_va + 0x40, 0x401010, 0x401020, 0)                 # +60 locator, then vtable at +64
    return pe_report_test.build_pe(text=bytes(t), extra=[(".str", bytes(d) + b"\0" * 0x20, pe_report_test.DATA)])


class Xrefs(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="xrefs_test.")
        exe = os.path.join(cls.tmp, "a.exe")
        with open(exe, "wb") as f:
            f.write(build())
        img = pe_image.Image(exe)
        slots = {n.split("!")[1]: s for s, n in img.imports.items()}
        str_va = next(img.base + rva for name, _, rva, *_ in img.sections if name == ".str")
        with open(exe, "wb") as f:                                                # same layout, real addresses
            f.write(build(slots["GetTickCount"], slots["Sleep"], str_va))
        cls.exe, cls.slots, cls.str_va = exe, slots, str_va
        cls.img = pe_image.Image(exe)
        cls.man = os.path.join(cls.tmp, "functions.tsv")
        with open(cls.man, "w") as f:
            f.write("# test\n00401000\tGetTickCount_thunk\n00401010\tA\n00401020\tB\n00401040\tC\n00401050\tD\n00401060\tFoo_ctor\n00401070\tE\n")

    def run_main(self, *args):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(xrefs.main([self.exe, self.man, *args]), 0)
        return out.getvalue()

    def test_import_refs_and_thunk_callers(self):
        out = self.run_main("--import", "GetTickCount", "--import", "Sleep")
        self.assertIn(f"00401000  ff25 [{self.slots['GetTickCount']:08X}]   in 00401000 GetTickCount_thunk", out)
        self.assertIn("    <- 00401011  call              in 00401010 A", out)
        self.assertIn("    <- 00401021  call              in 00401020 B", out)
        self.assertIn(f"0040102B  ff15 [{self.slots['Sleep']:08X}]   in 00401020 B", out)

    def test_calls(self):
        idx = xrefs.rel32_index(self.img)
        self.assertEqual(sorted(idx[0x401000]), [(0x401011, "call"), (0x401021, "call")])
        self.assertEqual(idx[0x401040], [(0x401031, "jmp")])
        self.assertNotIn(0x00100000, idx)
        self.assertIn("calls to 00401040 C: 1\n  00401031  jmp               in 00401020 B", self.run_main("--calls", "401040"))

    def test_string(self):
        out = self.run_main("--string", "MOVIES\\%s_test.vp6")
        self.assertIn(f"at {self.str_va:08X}; 1 code reference(s)", out)
        self.assertIn(f"00401027  -> {self.str_va:08X}  in 00401020 B", out)

    def test_class(self):
        self.assertEqual(xrefs.mangle("ns::Foo"), ".?AVFoo@ns@@")
        self.assertEqual(xrefs.class_vtables(self.img, "ns::Foo"), [(self.str_va + 0x64, (0x401010, 0x401020), self.str_va + 0x40)])
        self.assertEqual(xrefs.class_vtables(self.img, "Foo"), [])
        out = self.run_main("--class", "ns::Foo")
        self.assertIn(f"vtable {self.str_va + 0x64:08X} (locator {self.str_va + 0x40:08X}): 2 slot(s)", out)
        self.assertIn("[1] 00401020 B", out)
        self.assertIn("stored by 00401060 Foo_ctor", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
