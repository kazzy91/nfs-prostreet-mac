"""Builds and runs runtime/readback_test.c (runtime/readback.c, GetRenderTargetData's format store); no GPU, no game files.

    python3 -I runtime/readback_test.py

Pass: the test exits 0. Check of the check: a run with READBACK_TEST_SELFCHECK=1 must report exactly one failure.
The GPU half (render.m's render_readback) needs the full runtime and a frame to read; it is not covered here.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import c_test_driver  # noqa: E402

if __name__ == "__main__":
    sys.exit(c_test_driver.run("readback_test", ["readback_test.c", "readback.c"], "READBACK_TEST_SELFCHECK"))
