"""Builds and runs runtime/registry_test.c (runtime/registry.c) with sanitizers; no game files.

    python3 -I runtime/registry_test.py

Pass: the test exits 0. It pins MW's registry behaviour from before the code moved out of boot.c, then the calls added
for ProStreet. Check of the check: a run with REGISTRY_TEST_SELFCHECK=1 must report exactly one failure.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import c_test_driver  # noqa: E402

if __name__ == "__main__":
    sys.exit(c_test_driver.run("registry_test", ["registry_test.c", "registry.c"], "REGISTRY_TEST_SELFCHECK"))
