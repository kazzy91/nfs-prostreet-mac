#!/usr/bin/env python3
"""runtime/app.m's game-folder fingerprint (C) agrees with recomp/exe_fingerprint.py, for MW and for ProStreet.

    python3 -I runtime/app_fingerprint_test.py        (needs clang; offline; temp dir)

The macro block and exe_digests() are cut out of app.m and compiled twice: as MW's build and with -DNFS_GAME_PS=1.
Each prints the code fingerprint of a file; it must equal exe_fingerprint.describe_regions() with the matching
profile (mw13, ps_demo). Inputs: synthetic PEs (pe_report_test.build_pe; their sections don't cover every region,
which both sides hash as zeros), a copy with one code byte changed (the fingerprint must change), and, when
NFS_PS_EXE names it or ~/Games/ProStreet/nfs.exe exists, the real demo exe (read only), which must be ps_demo's
pinned fingerprint. Broken control: compiled with the other game's tag, the ProStreet build must disagree.
"""
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "recomp"))
import exe_fingerprint  # noqa: E402
import pe_report_test  # noqa: E402

MAIN = r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <CommonCrypto/CommonDigest.h>
%s
int main(int argc, char **argv) {
    FILE *f = fopen(argv[1], "rb"); fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
    uint8_t *d = malloc((size_t)n); if (fread(d, 1, (size_t)n, f) != (size_t)n) return 2; fclose(f);
    char parts[4][65], fp[65];
    if (!exe_digests(d, (size_t)n, parts, fp)) { puts("not a PE"); return 0; }
    puts(fp);
    return 0;
}
'''


def extract():
    src = (ROOT / "runtime/app.m").read_text()
    macros = re.search(r"#ifdef NFS_GAME_PS\n#define GAME_EXE.*?\n#endif\n", src, re.S).group(0)
    i = src.index("extern const char EXE_FINGERPRINT[]")
    j = src.index("    return 1;\n}\n", src.index("static int exe_digests(", i)) + len("    return 1;\n}\n")
    body = src[i:j].replace("extern const char EXE_FINGERPRINT[], EXE_REGION_SHA256[4][65];", "")
    return macros + body


def build(tmp, defines, code):
    c = tmp / f"fp{len(defines)}{abs(hash(code)) % 1000}.c"
    c.write_text(MAIN % code)
    exe = c.with_suffix("")
    subprocess.run(["clang", "-O1", "-w", *defines, str(c), "-o", str(exe)], check=True)
    return exe


def fingerprint(exe, path):
    return subprocess.run([str(exe), str(path)], capture_output=True, text=True, check=True).stdout.strip()


def main():
    fails = []

    def check(label, ok, detail=""):
        print(f"{'PASS' if ok else 'FAIL'} {label}" + (f": {detail}" if detail and not ok else ""))
        if not ok:
            fails.append(label)

    code = extract()
    with tempfile.TemporaryDirectory(prefix="app_fp_test.") as td:
        tmp = Path(td)
        mw, ps = build(tmp, [], code), build(tmp, ["-DNFS_GAME_PS=1"], code)
        big = pe_report_test.build_pe(text=pe_report_test.plain_code(0x520000))   # covers both games' .text regions
        changed = bytearray(big)
        changed[0x400 + 0x100] ^= 1
        for label, data in (("small PE", pe_report_test.build_pe()), ("large PE", big), ("one byte changed", bytes(changed))):
            p = tmp / "x.exe"
            p.write_bytes(data)
            for game, exe in (("mw13", mw), ("ps_demo", ps)):
                prof = exe_fingerprint.PROFILES[game]
                want = exe_fingerprint.describe_regions(data, prof["regions"], prof["tag"])[1]
                got = fingerprint(exe, p)
                check(f"{label}: app.m ({game}) == exe_fingerprint.py", got == want, f"{got} != {want}")
        p.write_bytes(big)
        a = fingerprint(ps, p)
        p.write_bytes(bytes(changed))
        check("a changed code byte changes the ProStreet fingerprint", fingerprint(ps, p) != a)
        real = Path(os.environ.get("NFS_PS_EXE") or Path.home() / "Games/ProStreet/nfs.exe")
        if real.is_file():
            check("the real demo exe gives ps_demo's pinned fingerprint",
                  fingerprint(ps, real) == exe_fingerprint.PROFILES["ps_demo"]["fingerprint"])
        else:
            print("skip: no local demo exe (NFS_PS_EXE)")
        broken = build(tmp, ["-DNFS_GAME_PS=1"], code.replace('"nfsps-exe-fp-v1\\n"', '"nfsmw-exe-fp-v1\\n"'))
        p.write_bytes(big)
        prof = exe_fingerprint.PROFILES["ps_demo"]
        check("broken control: MW's tag in the ProStreet build disagrees",
              fingerprint(broken, p) != exe_fingerprint.describe_regions(big, prof["regions"], prof["tag"])[1])
    print(f"{'FAIL' if fails else 'ok'}: {len(fails)} failing")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
