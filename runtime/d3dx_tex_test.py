"""Builds and runs runtime/d3dx_tex_test.c (runtime/d3dx_tex.c) against a fake IDirect3DDevice9; no game files.

    python3 -I runtime/d3dx_tex_test.py

Pass: the test exits 0. Check of the check: a run with D3DX_TEX_TEST_SELFCHECK=1 must report exactly one failure.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import c_test_driver  # noqa: E402

FRAMEWORKS = ["-framework", "ImageIO", "-framework", "CoreGraphics", "-framework", "CoreFoundation"]

if __name__ == "__main__":
    sys.exit(c_test_driver.run("d3dx_tex_test", ["d3dx_tex_test.c", "d3dx_tex.c"], "D3DX_TEX_TEST_SELFCHECK", FRAMEWORKS))
