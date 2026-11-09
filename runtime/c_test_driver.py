"""Shared driver for the standalone C tests of the ProStreet host additions (msvcr_test.c, win32_more_test.c).

run(name, sources, selfcheck_env) builds the test with -Wall -Wextra -Werror and sanitizers, runs it, then runs it again
with `selfcheck_env`=1, where the test adds one deliberately wrong expectation and must report exactly one failure.
AddressSanitizer is probed first: where it hangs at start-up (seen with Apple clang 17.0.0 on macOS 26.5.1) the test
runs with UBSan only, plus a run under libgmalloc (guard pages before and after every host allocation).
Scratch files go to a private temporary directory passed as C_TEST_TMP.
"""
import os
import re
import subprocess
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
GMALLOC = "/usr/lib/libgmalloc.dylib"
CF = ["-std=c11", "-Wall", "-Wextra", "-Werror", "-g", "-fno-sanitize-recover=undefined"]


def asan_works(tmp):
    src, exe = os.path.join(tmp, "probe.c"), os.path.join(tmp, "probe")
    with open(src, "w") as f:
        f.write("int main(void) { return 0; }\n")
    if subprocess.run(["clang", "-fsanitize=address", src, "-o", exe], capture_output=True).returncode:
        return False
    try:
        return subprocess.run([exe], capture_output=True, timeout=20).returncode == 0
    except subprocess.TimeoutExpired:
        return False


def run(name, sources, selfcheck_env):
    srcs = [os.path.join(HERE, s) for s in sources]
    inc = ["-I", os.path.join(HERE, "..", "recomp"), "-I", HERE]
    with tempfile.TemporaryDirectory() as tmp:
        exe = os.path.join(tmp, name)
        san = "address,undefined" if asan_works(tmp) else "undefined"
        if san == "undefined":
            print("note: AddressSanitizer hangs at start-up with this toolchain; running with UBSan only")
        b = subprocess.run(["clang", *CF, f"-fsanitize={san}", *inc, *srcs, "-o", exe], capture_output=True, text=True)
        if b.returncode:
            print(b.stdout + b.stderr)
            print("FAIL: build")
            return 1
        env = dict(os.environ, ASAN_OPTIONS="detect_leaks=0", C_TEST_TMP=tmp)
        r = subprocess.run([exe], capture_output=True, text=True, env=env, timeout=120)
        print(r.stdout.strip().splitlines()[-1] if r.stdout.strip() else "(no output)")
        if r.returncode:
            print(r.stdout[-4000:] + r.stderr[-4000:])
            print(f"FAIL: {name}")
            return 1
        s = subprocess.run([exe], capture_output=True, text=True, env=dict(env, **{selfcheck_env: "1"}), timeout=120)
        m = re.search(r"(\d+) failing", s.stdout)
        if s.returncode != 1 or not m or m.group(1) != "1":
            print(s.stdout[-2000:])
            print("FAIL: self-check run did not report exactly one failure")
            return 1
        print("self-check: the deliberately wrong expectation was reported (1 failing)")
        if san == "undefined" and os.path.exists(GMALLOC):
            plain = os.path.join(tmp, name + "_plain")
            b = subprocess.run(["clang", *CF[:-1], "-O1", *inc, *srcs, "-o", plain], capture_output=True, text=True)
            genv = dict(env, DYLD_INSERT_LIBRARIES=GMALLOC, MALLOC_PROTECT_BEFORE="1")
            g = subprocess.run([plain], capture_output=True, text=True, env=genv, timeout=300) if not b.returncode else b
            if g.returncode:
                print((g.stdout + g.stderr)[-3000:])
                print("FAIL: libgmalloc run")
                return 1
            print("libgmalloc run (guard pages before and after host allocations): " + g.stdout.strip().splitlines()[-1])
    return 0
