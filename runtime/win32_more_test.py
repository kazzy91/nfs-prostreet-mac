"""Builds and runs runtime/win32_more_test.c (runtime/win32_more.c) with sanitizers; no game files.

    python3 -I runtime/win32_more_test.py

Pass: the test exits 0. Check of the check: a second run with WIN32_MORE_TEST_SELFCHECK=1 adds one deliberately wrong
expectation and must report exactly one failure. Build, sanitizer choice and the libgmalloc fallback: c_test_driver.py.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import c_test_driver  # noqa: E402

if __name__ == "__main__":
    sys.exit(c_test_driver.run("win32_more_test", ["win32_more_test.c", "win32_more.c"], "WIN32_MORE_TEST_SELFCHECK"))
