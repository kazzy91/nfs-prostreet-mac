"""Offline proof of tools/asan_off (the clang/clang++ wrapper offline_tests.sh uses when AddressSanitizer can't start).

    python3 -I runtime/asan_off_test.py

Through the wrapper:
(a) -fsanitize=address,undefined reaches the compiler as UBSan only (no "address" in the driver's cc1 arguments, the
    undefined-behaviour checks present), and -fsanitize=address alone disappears;
(b) other arguments pass through unchanged (the -D below reaches cc1);
(c) a program built with -fsanitize=address,undefined runs to the end (no ASan start-up hang) and UBSan still reports
    a signed overflow;
(d) clang++ (a link to the same script) builds C++;
(e) with no real compiler on PATH outside the wrapper's folder, it says so and exits 127.
Last run: 6 checks PASS -> exit 0.
"""
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
WRAP = os.path.normpath(os.path.join(HERE, "..", "tools", "asan_off"))


def main():
    if not shutil.which("clang"):
        print("SKIP: no clang")
        return 3
    fails = []

    def check(label, ok, detail=""):
        print(f"{'PASS' if ok else 'FAIL'} {label}" + (f": {str(detail)[-600:]}" if detail and not ok else ""))
        if not ok:
            fails.append(label)

    env = dict(os.environ, PATH=WRAP + os.pathsep + os.environ.get("PATH", ""))
    with tempfile.TemporaryDirectory() as tmp:
        src = os.path.join(tmp, "t.c")
        with open(src, "w") as f:
            f.write("#include <limits.h>\n#include <stdio.h>\nint main(int argc, char **argv) { (void)argv; int x = INT_MAX; x += argc; "
                    "printf(\"done %d\\n\", x != 0); return 0; }\n")
        cc1 = subprocess.run(["clang", "-###", "-fsanitize=address,undefined", "-DMARK_PASSED=1", "-c", src, "-o", os.path.join(tmp, "t.o")],
                             capture_output=True, text=True, env=env).stderr
        san = [t for t in cc1.replace('"', " ").split() if t.startswith("-fsanitize=")]
        check("(a) address is taken out, UBSan stays", san and not any("address" in t for t in san) and any("signed-integer-overflow" in t for t in san), san)
        only = subprocess.run(["clang", "-###", "-fsanitize=address", "-c", src, "-o", os.path.join(tmp, "t.o")],
                              capture_output=True, text=True, env=env).stderr
        check("(a) an ASan-only list disappears", "-fsanitize=" not in only, only)
        check("(b) other arguments pass through", "MARK_PASSED=1" in cc1, cc1)
        exe = os.path.join(tmp, "t")
        b = subprocess.run(["clang", "-fsanitize=address,undefined", "-g", src, "-o", exe], capture_output=True, text=True, env=env)
        try:
            r = subprocess.run([exe, "x"], capture_output=True, text=True, timeout=30) if not b.returncode else b
            ran = r.returncode == 0 and "done 1" in r.stdout
            check("(c) the program runs and UBSan reports the overflow", ran and "runtime error" in r.stderr, (b.stderr, r.stdout, r.stderr))
        except subprocess.TimeoutExpired:
            check("(c) the program runs and UBSan reports the overflow", False, "timed out: ASan still in the build?")
        cpp = os.path.join(tmp, "t.cpp")
        with open(cpp, "w") as f:
            f.write("#include <string>\nint main() { std::string s(\"ok\"); return s.size() == 2 ? 0 : 1; }\n")
        b = subprocess.run(["clang++", "-std=c++17", "-fsanitize=address,undefined", cpp, "-o", exe + "pp"], capture_output=True, text=True, env=env)
        r = subprocess.run([exe + "pp"], capture_output=True, text=True, timeout=30) if not b.returncode else b
        check("(d) clang++ through the link", r.returncode == 0, (b.stderr, getattr(r, "stderr", "")))
        lone = subprocess.run([os.path.join(WRAP, "clang"), "--version"], capture_output=True, text=True, env=dict(os.environ, PATH=WRAP))
        check("(e) no real compiler: exit 127 with a message", lone.returncode == 127 and "no clang on PATH" in lone.stderr, (lone.returncode, lone.stderr))
    print(f"{'FAIL' if fails else 'ok'}: {len(fails)} failing")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
