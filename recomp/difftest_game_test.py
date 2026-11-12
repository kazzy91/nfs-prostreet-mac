#!/usr/bin/env python3
"""difftest.py --game on a synthetic exe under a temporary game profile (offline; temp dirs; no game files).

    tools/.venv/bin/python -I recomp/difftest_game_test.py      (needs capstone and unicorn; exit 3 = skipped)

The exe's code holds three leaf functions, run as C and under Unicorn (recomp/synth_emu.py, whole image mapped):
  f0 0x401000  movss xmm0, [ecx]; addss xmm0, [ecx+4]; movss [ecx+8], xmm0; ret      SSE, results in memory and xmm0
  f1 0x401020  or edx, 0x80000000 (SF set); fld [ecx]; fld [ecx+4]; fucomip st(1); fstp st(0); lahf; ret
               (lahf exposes SF after the compare: the reference hook must clear it as the translation does)
  f2 0x401040  rdtsc; mov [ecx], eax; ret                                          left out: not comparable
Checked: the exe is refused without the profile's fingerprint; with it, f0 and f1 pass and f2 is counted as an rdtsc
function. Broken control: without the fcomi reference hook (FCOMI emptied), f1 fails.
"""
import contextlib
import io
import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
try:
    import capstone  # noqa: F401
    import unicorn  # noqa: F401
except ImportError:
    print("SKIP: needs capstone and unicorn (run with tools/.venv/bin/python)")
    sys.exit(3)
import difftest  # noqa: E402
import exe_fingerprint  # noqa: E402
import pe_report_test  # noqa: E402
import profiles  # noqa: E402


def exe(flip=False):
    t = bytearray(b"\xcc" * 0x3000)
    t[0x00:0x10] = bytes.fromhex("f30f1001 f30f584104 f30f114108 c3".replace(" ", ""))
    t[0x20:0x31] = bytes.fromhex("81ca00000080 d901 d94104 dfe9 ddd8 9f c3".replace(" ", ""))
    t[0x40:0x45] = bytes.fromhex("0f31 8901 c3".replace(" ", ""))
    if flip:
        t[0x0F] = 0xC2
    return pe_report_test.build_pe(text=bytes(t))


class GameDifftest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="difftest_game_test.")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.exe = os.path.join(self.tmp, "game.exe")
        with open(self.exe, "wb") as f:
            f.write(exe())
        man, hooks = os.path.join(self.tmp, "functions.tsv"), os.path.join(self.tmp, "hooks.txt")
        with open(man, "w") as f:
            f.write("00401000\tf0\n00401020\tf1\n00401040\tf2\n")
        with open(hooks, "w") as f:
            f.write("# none\n")
        regions = ((".text", 0x1000, 0x3000),)
        tag = b"synth-difftest-fp-v1\n"
        exe_fingerprint.PROFILES["synth"] = {"regions": regions, "tag": tag, "name": "synthetic game",
                                             "fingerprint": exe_fingerprint.describe_regions(exe(), regions, tag)[1]}
        profiles.PROFILES["synth"] = profiles.Profile("synth", "synthetic game", "synth", "SYNTH_EXE", man, hooks,
                                                      "game", "build_game.py")
        self.addCleanup(exe_fingerprint.PROFILES.pop, "synth")
        self.addCleanup(profiles.PROFILES.pop, "synth")

    def run_difftest(self, path):
        out = io.StringIO()
        argv = sys.argv
        sys.argv = ["difftest.py", "--game", "synth", "--exe", path, "--tests", "16", "--seed", "3"]
        try:
            with contextlib.redirect_stdout(out):
                difftest.main()
        finally:
            sys.argv = argv
        return out.getvalue()

    def test_refuses_other_code(self):
        other = os.path.join(self.tmp, "other.exe")
        with open(other, "wb") as f:
            f.write(exe(flip=True))
        with self.assertRaisesRegex(SystemExit, "not the synthetic game"):
            self.run_difftest(other)

    def test_pass_and_rdtsc(self):
        out = self.run_difftest(self.exe)
        self.assertIn("translatable now: 3 of 3 functions (1 read the time-stamp counter (rdtsc) and aren't compared)", out)
        self.assertIn("differential test: 2 functions sampled, 2 pass, 0 fail", out)

    def test_broken_control(self):
        saved = difftest.FCOMI
        difftest.FCOMI = set()
        try:
            out = self.run_difftest(self.exe)
        finally:
            difftest.FCOMI = saved
        self.assertIn("1 pass, 1 fail", out, "without the fcomi reference hook, lahf after fucomip must differ")
        self.assertIn("FAIL 00401020 f1", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
