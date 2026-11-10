"""Runs the translator's synthetic differential tests (difftest.py --synth) and checks the verdict; no game files.

    tools/.venv/bin/python -I recomp/difftest_synth_test.py      (needs capstone and unicorn; exit 3 = skipped)

Every synthetic case (one or a few instructions each, assembled with clang) is translated, compiled, and run as C and
under Unicorn on random states. Pass: all cases translate, and none fails, crashes, times out or ends without a verdict
(the documented AUDIT_XFAIL entries are reported, not counted). Without MW's speed.exe and developer emulator the run
uses difftest's stand-in image and recomp/synth_emu.py.
Check of the check (by hand, 2026-11-10): with runtime.h's parity8 inverted in a scratch copy, 48 of 375 cases fail.
Last run: 375 of 375 translate; 374 pass, 1 expected-fail, 0 fail -> exit 0 (about a minute).
"""
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def main():
    try:
        import capstone  # noqa: F401
        import unicorn  # noqa: F401
    except ImportError:
        print("SKIP: needs capstone and unicorn (run with tools/.venv/bin/python)")
        return 3
    r = subprocess.run([sys.executable, "-I", os.path.join(HERE, "difftest.py"), "--synth"], capture_output=True, text=True, timeout=900)
    out = r.stdout + r.stderr
    t = re.search(r"translatable now: (\d+) of (\d+) functions", out)
    v = re.search(r"differential test: (\d+) functions sampled, (\d+) pass, (\d+) fail \((\d+) crash/timeout\), (\d+) expected-fail, (\d+) no-verdict", out)
    if r.returncode not in (0, 1) or not t or not v:
        print(out[-3000:])
        print("FAIL: difftest --synth did not report a verdict")
        return 1
    ok_t = t.group(1) == t.group(2)
    sampled, passed, failed, crashed, xfail, nov = map(int, v.groups())
    print(f"translatable {t.group(1)}/{t.group(2)}; {passed} pass, {failed} fail, {crashed} crash/timeout, {xfail} expected-fail, {nov} no-verdict")
    if not ok_t or failed or crashed or nov or passed + xfail != sampled:
        print("\n".join(line for line in out.splitlines() if line.startswith(("  FAIL", "  not translated")))[:3000])
        print("FAIL: synthetic differential tests")
        return 1
    print("ok: 0 failing")
    return 0


if __name__ == "__main__":
    sys.exit(main())
