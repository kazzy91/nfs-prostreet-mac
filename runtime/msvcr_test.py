"""Builds and runs runtime/msvcr_test.c (the MSVCR80 shim, runtime/msvcr.c) with sanitizers; no game files.

    python3 -I runtime/msvcr_test.py

Pass: the test exits 0. Check of the check: the same binary with MSVCR_TEST_SELFCHECK=1 adds one deliberately wrong
expectation and must exit 1 with exactly one failure, so a broken shim cannot pass silently.
ASan is probed first. Where it hangs at start-up, the test runs with UBSan only, plus a second run under libgmalloc
(guard pages around every host allocation) for the memory checks ASan would have done.
Last run: ok (all checks pass); self-check run fails with 1 failing -> exit 0.
"""
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
GMALLOC = "/usr/lib/libgmalloc.dylib"
CF = ["-std=c11", "-Wall", "-Wextra", "-Werror", "-g", "-fno-sanitize-recover=undefined"]


def asan_works(tmp):
    """Some toolchain/OS pairs hang in ASan's own start-up (seen: Apple clang 17.0.0 on macOS 26.5.1). Probe first."""
    src, exe = os.path.join(tmp, "probe.c"), os.path.join(tmp, "probe")
    with open(src, "w") as f:
        f.write("int main(void) { return 0; }\n")
    if subprocess.run(["clang", "-fsanitize=address", src, "-o", exe], capture_output=True).returncode:
        return False
    try:
        return subprocess.run([exe], capture_output=True, timeout=20).returncode == 0
    except subprocess.TimeoutExpired:
        return False


def main():
    with tempfile.TemporaryDirectory() as tmp:
        exe = os.path.join(tmp, "msvcr_test")
        san = "address,undefined" if asan_works(tmp) else "undefined"
        if san == "undefined":
            print("note: AddressSanitizer hangs at start-up with this toolchain; running with UBSan only")
        cmd = ["clang", *CF, f"-fsanitize={san}", "-I", os.path.join(HERE, "..", "recomp"), os.path.join(HERE, "msvcr_test.c"),
               os.path.join(HERE, "msvcr.c"), "-o", exe]
        b = subprocess.run(cmd, capture_output=True, text=True)
        if b.returncode:
            print(b.stdout + b.stderr)
            print("FAIL: build")
            return 1
        env = dict(os.environ, ASAN_OPTIONS="detect_leaks=0")
        r = subprocess.run([exe], capture_output=True, text=True, env=env, timeout=120)
        print(r.stdout.strip())
        if r.returncode:
            print(r.stderr[-4000:])
            print("FAIL: msvcr_test")
            return 1
        env["MSVCR_TEST_SELFCHECK"] = "1"
        s = subprocess.run([exe], capture_output=True, text=True, env=env, timeout=120)
        m = re.search(r"(\d+) failing", s.stdout)
        if s.returncode != 1 or not m or m.group(1) != "1":
            print(s.stdout[-2000:])
            print("FAIL: self-check run did not report exactly one failure")
            return 1
        print("self-check: the deliberately wrong expectation was reported (1 failing)")
        if san == "undefined" and os.path.exists(GMALLOC):
            # Without ASan, guard pages around every host allocation (libgmalloc) catch the formatter's buffer overruns.
            plain = os.path.join(tmp, "msvcr_plain")
            b = subprocess.run(["clang", *CF[:-1], "-O1", "-I", os.path.join(HERE, "..", "recomp"),
                                os.path.join(HERE, "msvcr_test.c"), os.path.join(HERE, "msvcr.c"), "-o", plain],
                               capture_output=True, text=True)
            genv = dict(os.environ, DYLD_INSERT_LIBRARIES=GMALLOC, MALLOC_PROTECT_BEFORE="1")
            g = subprocess.run([plain], capture_output=True, text=True, env=genv, timeout=300) if not b.returncode else b
            if g.returncode:
                print((g.stdout + g.stderr)[-3000:])
                print("FAIL: libgmalloc run")
                return 1
            print("libgmalloc run (guard pages before and after host allocations): " + g.stdout.strip().splitlines()[-1])
    return 0


if __name__ == "__main__":
    sys.exit(main())
