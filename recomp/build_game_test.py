#!/usr/bin/env python3
"""recomp/build_game.py on a synthetic exe under a temporary game profile (offline; temp dirs).

Run: tools/.venv/bin/python -I recomp/build_game_test.py        (capstone; the compile case needs clang)

The exe's code holds four functions: a leaf, a caller of it, one with an instruction the translator traps (a segment register read), and
one whose bytes don't decode (a stub). A temporary profile pins its code fingerprint and points at a manifest and a
hooks file naming the leaf. Checked: an exe with other code is refused before anything is written; funcs.h declares
every function plus the hooked one's _orig; the hooked body is f_X_orig with a weak f_X; table.c lists every start and
the fingerprint; the report counts translated functions, the stub and the trap by reason; the C compiles to the
library. Broken control: with the hook removed from the hooks file the _orig split disappears.
"""
import os
import shutil
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import build_game  # noqa: E402
import exe_fingerprint  # noqa: E402
import pe_report_test  # noqa: E402
import profiles  # noqa: E402

LEAF, CALLER, TRAP, BAD = 0x401000, 0x401010, 0x401020, 0x401030


def exe(flip=False):
    t = bytearray(b"\xcc" * 0x3000)
    t[0x00:0x06] = b"\xb8\x01\x00\x00\x00\xc3"                                   # mov eax, 1; ret
    t[0x10:0x16] = b"\xe8" + struct.pack("<i", LEAF - (CALLER + 5)) + b"\xc3"    # call leaf; ret
    t[0x20:0x23] = b"\x8c\xd0\xc3"                                               # mov eax, ss (a trap); ret
    t[0x30:0x33] = b"\x0f\x04\xc3"                                               # undecodable: a stub
    if flip:
        t[0x01] = 2
    return pe_report_test.build_pe(text=bytes(t))


class BuildGame(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="build_game_test.")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.exe = os.path.join(self.tmp, "game.exe")
        with open(self.exe, "wb") as f:
            f.write(exe())
        man, self.hooks = os.path.join(self.tmp, "functions.tsv"), os.path.join(self.tmp, "hooks.txt")
        with open(man, "w") as f:
            f.write("# synthetic\n00401000\tleaf\n00401010\tcaller\n00401020\ttrap\n00401030\tbad\n")
        self.set_hooks(True)
        regions = ((".text", 0x1000, 0x3000),)
        tag = b"synth-exe-fp-v1\n"
        exe_fingerprint.PROFILES["synth"] = {"regions": regions, "tag": tag, "name": "synthetic game",
                                             "fingerprint": exe_fingerprint.describe_regions(exe(), regions, tag)[1]}
        profiles.PROFILES["synth"] = profiles.Profile("synth", "synthetic game", "synth", "SYNTH_EXE", man, self.hooks,
                                                      "game", "build_game.py")
        self.addCleanup(exe_fingerprint.PROFILES.pop, "synth")
        self.addCleanup(profiles.PROFILES.pop, "synth")

    def set_hooks(self, on):
        with open(self.hooks, "w") as f:
            f.write("# address owner\n" + ("00401000    test.c: the leaf\n" if on else ""))

    def run_build(self, generate_only=True):
        return build_game.build("synth", self.exe, os.path.join(self.tmp, "out"), jobs=1, generate_only=generate_only,
                                log=lambda *_: None)

    def read(self, name):
        with open(os.path.join(self.tmp, "out", name)) as f:
            return f.read()

    def test_refuses_other_code(self):
        other = os.path.join(self.tmp, "other.exe")
        with open(other, "wb") as f:
            f.write(exe(flip=True))
        with self.assertRaisesRegex(SystemExit, "not the synthetic game"):
            build_game.build("synth", other, os.path.join(self.tmp, "out"), jobs=1, generate_only=True)
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "out", "funcs.h")))

    def test_generate(self):
        r = self.run_build()
        self.assertEqual((r["functions"], r["translated"]), (4, 3))
        self.assertEqual(sum(r["stubs"].values()), 1)
        self.assertEqual(sum(r["traps"].values()), 1, r["traps"])
        self.assertEqual(list(r["traps"]), ["reg ss"])
        h = self.read("funcs.h")
        for a in (LEAF, CALLER, TRAP, BAD):
            self.assertIn(f"void f_{a:08X}(Cpu *c);", h)
        self.assertIn(f"void f_{LEAF:08X}_orig(Cpu *c);   /* hooked: test.c: the leaf */", h)
        c = self.read("game_00.c")
        self.assertIn(f"void f_{LEAF:08X}_orig(Cpu *restrict c) {{", c)
        self.assertIn(f"__attribute__((weak)) void f_{LEAF:08X}(Cpu *c) {{ f_{LEAF:08X}_orig(c); }}", c)
        self.assertIn(f"untranslated(c, 0x{BAD:08X}u); }}", c)
        t = self.read("table.c")
        self.assertIn("const unsigned guest_func_count = 4;", t)
        self.assertIn(f'const char game_exe_fingerprint[] = "{exe_fingerprint.PROFILES["synth"]["fingerprint"]}";', t)
        self.assertIn("traps (instructions trapping at run time): 1", self.read("report.txt"))

    def test_broken_control(self):
        self.set_hooks(False)
        self.run_build()
        self.assertNotIn("_orig", self.read("game_00.c"), "without the hook the body must not be split")

    def test_unknown_hook_refused(self):
        with open(self.hooks, "a") as f:
            f.write("00401005    test.c: not a start\n")
        with self.assertRaisesRegex(SystemExit, "00401005"):
            self.run_build()

    @unittest.skipUnless(shutil.which("clang"), "needs clang")
    def test_compiles(self):
        r = self.run_build(generate_only=False)
        self.assertEqual(r["errors"], [])
        self.assertTrue(r["lib"] and os.path.getsize(r["lib"]) > 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
