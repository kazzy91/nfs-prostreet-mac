"""Builds and runs runtime/msvcr_test.c (the MSVCR80 shim, runtime/msvcr.c) with sanitizers; no game files.

    python3 -I runtime/msvcr_test.py

Pass: the test exits 0. Check of the check: a second run with MSVCR_TEST_SELFCHECK=1 adds one deliberately wrong
expectation and must report exactly one failure. Build, sanitizer choice and the libgmalloc fallback: c_test_driver.py.
Last run: ok (721 checks); self-check reports 1 failing; libgmalloc run ok -> exit 0.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import c_test_driver  # noqa: E402

if __name__ == "__main__":
    sys.exit(c_test_driver.run("msvcr_test", ["msvcr_test.c", "msvcr.c"], "MSVCR_TEST_SELFCHECK"))
