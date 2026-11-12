"""Writes a game's import-slot table for the runtime (runtime/imports.c is MW's, generated from speed.exe the same way).

    python3 -I recomp/gen_imports.py --game ps_demo --exe <nfs.exe> --out runtime/imports_ps.c

The exe must carry the profile's code fingerprint. Output: the entry point and every IAT slot with "DLL!function"
(or "DLL!#ordinal"), sorted by slot, under the symbol names boot.c reads (speed_entry, speed_imports,
speed_import_count; boot.c's binary search needs the order). Addresses and names only, no code: committable like
MW's imports.c (CLAUDE.md rule 1). Stdlib only; the exe is only read.
"""
import argparse
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import exe_fingerprint  # noqa: E402
import pe_image  # noqa: E402
import profiles  # noqa: E402


def generate(exe, game):
    profile = profiles.PROFILES[game]
    with open(exe, "rb") as f:
        data = f.read()
    if exe_fingerprint.identify(data) != profile.fingerprint:
        raise SystemExit(f"{exe}: not the {exe_fingerprint.PROFILES[profile.fingerprint]['name']}")
    img = pe_image.Image(data)
    rows = sorted(img.imports.items())
    out = [f"// generated from {os.path.basename(exe)} ({profile.title}) by recomp/gen_imports.py: IAT slot -> \"DLL!function\"",
           "// (symbol names as MW's runtime/imports.c, which boot.c reads)",
           "#include <stdint.h>",
           f"const uint32_t speed_entry = 0x{img.entry:08X}u;",
           "const struct ImportSlot { uint32_t slot; const char *name; } speed_imports[] = {"]
    out += [f'    {{0x{slot:08X}u, "{name}"}},' for slot, name in rows]
    out += ["};", f"const unsigned speed_import_count = {len(rows)};", ""]
    return "\n".join(out)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    ap.add_argument("--game", default="ps_demo", choices=sorted(profiles.PROFILES))
    ap.add_argument("--exe", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    text = generate(a.exe, a.game)
    with open(a.out, "w", newline="\n") as f:
        f.write(text)
    print(f"{a.out}: {text.count('{0x')} imports")
    return 0


if __name__ == "__main__":
    sys.exit(main())
