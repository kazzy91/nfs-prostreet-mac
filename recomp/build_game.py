"""Translate every function of a game profile's exe to C and compile it for arm64 (one static library).

    tools/.venv/bin/python -I recomp/build_game.py --game ps_demo --exe <nfs.exe> [--jobs N] [--generate-only] [--out DIR]

The exe must carry the profile's code fingerprint (exe_fingerprint.PROFILES); anything else is refused before a byte
is translated. Function starts come from the profile's committed manifest, each bounded by the next start (or the end
of the code section). The translator runs with calls on, as for MW (build_all.py), and the profile's passes run on
each function. Hooked functions (the profile's hooks file) become f_X_orig plus a weak f_X.

Output in recomp/out/<game>/ (gitignored; derived from the game, never committed): <stem>_NN.c, funcs.h, table.c
(guest address -> function, and the code fingerprint), <stem>.a, report.txt (functions, stubs and traps by reason,
compile errors). A function the translator can't handle becomes a stub calling untranslated(c, address), and a single
instruction it can't do becomes a trap at that instruction, so the library always links completely.

MW still builds with build_all.py; see profiles.py.
"""
import argparse
import collections
import concurrent.futures
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import exe_fingerprint  # noqa: E402
import profiles  # noqa: E402

CHUNK = 800
TRAP = re.compile(r"untranslated\(c, 0x([0-9A-F]{8})u\); return; /\* (.*?) \*/")

_W = {}


def open_image(exe, profile):
    """The exe as the translator reads it, after the fingerprint check. SystemExit naming the problem otherwise."""
    import pe_image
    with open(exe, "rb") as f:
        data = f.read()
    want = exe_fingerprint.PROFILES[profile.fingerprint]
    got = exe_fingerprint.identify(data)
    if got != profile.fingerprint:
        raise SystemExit(f"{exe}: not the {want['name']} (code fingerprint "
                         f"{'of profile ' + got if got else 'unknown'}); this build needs exactly that executable.")
    img = pe_image.Image(data)
    img.fingerprint = want["fingerprint"]             # the translator's profile-specific rules key on this
    return img


def functions(img, profile):
    """[(start, limit, name)] for the manifest's starts inside the code section."""
    lo, hi = img.code()
    starts = [(a, n) for a, n in profiles.load_manifest(profile.path(profile.manifest)) if lo <= a < hi]
    return [(a, starts[k + 1][0] if k + 1 < len(starts) else hi, n) for k, (a, n) in enumerate(starts)]


def _init(exe, game, limits):
    import recomp
    profile = profiles.PROFILES[game]
    _W["profile"] = profile
    _W["hooks"] = profiles.load_hooks(profile.path(profile.hooks))
    _W["rc"] = recomp.Recompiler(pe=open_image(exe, profile), functions=limits)
    _W["rc"].calls = True


def _chunk(job):
    """Translate one chunk and write its C file. Returns (path, stub reasons, trap reasons, instructions)."""
    path, items = job
    rc, profile, hooks = _W["rc"], _W["profile"], _W["hooks"]
    stubs, traps, insns, bodies = collections.Counter(), collections.Counter(), 0, []
    for a, limit, name in items:
        code, why = rc.translate(a, limit)
        if code is None:
            stubs[why] += 1
            code = f"void f_{a:08X}(Cpu *c) {{ untranslated(c, 0x{a:08X}u); }} /* {name}: {why} */"
        else:
            if isinstance(code, list):
                code = "\n".join(code)
            insns += code.count("\n    /* ")
            traps.update(r for _, r in TRAP.findall(code))
            for p in profile.passes:
                code = p(a, code)
        if a in hooks:
            # The runtime replaces this function: the body becomes f_X_orig, f_X a weak wrapper (never inlined, so
            # a strong f_X in the runtime takes every call).
            code = code.replace(f"void f_{a:08X}(Cpu *restrict c) {{", f"void f_{a:08X}_orig(Cpu *restrict c) {{", 1)
            code = code.replace(f"void f_{a:08X}(Cpu *c) {{", f"void f_{a:08X}_orig(Cpu *c) {{", 1)
            code += f"\n__attribute__((weak)) void f_{a:08X}(Cpu *c) {{ f_{a:08X}_orig(c); }}"
        bodies.append(code)
    tmp = path + ".new"
    with open(tmp, "w", newline="\n", encoding="utf-8") as f:
        f.write('#include "funcs.h"\n\n' + "\n\n".join(bodies) + "\n")
    os.replace(tmp, path)
    return path, stubs, traps, insns


def compile_one(path, out):
    import recomp
    obj = path[:-2] + ".o"
    r = subprocess.run(["clang", "-c", "-target", "arm64-apple-macos14.5"] + recomp.CFLAGS +
                       os.environ.get("RECOMP_CFLAGS", "").split() + ["-I", HERE, "-I", out, path, "-o", obj],
                       capture_output=True, text=True)
    return path, obj, r.returncode, r.stderr[-3000:]


def build(game, exe, out=None, jobs=None, generate_only=False, log=print):
    profile = profiles.PROFILES[game]
    if profile.builder != "build_game.py":
        raise SystemExit(f"{game} builds with {profile.builder} (see profiles.py)")
    out = os.path.abspath(out or os.path.join(HERE, "out", game))
    os.makedirs(out, exist_ok=True)
    lib = os.path.join(out, profile.stem + ".a")
    if os.path.exists(lib):
        os.remove(lib)                                # a failed build must never leave an older library behind
    t0 = time.time()
    img = open_image(exe, profile)
    funcs = functions(img, profile)
    hooks = profiles.load_hooks(profile.path(profile.hooks))
    unknown = sorted(set(hooks) - {a for a, _, _ in funcs})
    if unknown:
        raise SystemExit(f"{profile.hooks}: not function starts in {profile.manifest}: " + ", ".join(f"{a:08X}" for a in unknown))
    limits = {a: l for a, l, _ in funcs}
    jobs_list = [(os.path.join(out, f"{profile.stem}_{k // CHUNK:02d}.c"), funcs[k:k + CHUNK]) for k in range(0, len(funcs), CHUNK)]
    stale = {f for f in os.listdir(out) if re.fullmatch(rf"{profile.stem}_\d+\.[co]", f)} - \
            {os.path.basename(p) for p, _ in jobs_list} - {os.path.basename(p)[:-2] + ".o" for p, _ in jobs_list}
    for f in stale:
        os.remove(os.path.join(out, f))
    stubs, traps, insns, files = collections.Counter(), collections.Counter(), 0, []
    jobs = jobs or os.cpu_count() or 4
    if jobs == 1:
        _init(exe, game, limits)
        results = map(_chunk, jobs_list)
    else:
        ex = concurrent.futures.ProcessPoolExecutor(jobs, initializer=_init, initargs=(exe, game, limits))
        results = ex.map(_chunk, jobs_list)
    for path, s, t, n in results:
        files.append(path)
        stubs += s
        traps += t
        insns += n
    if jobs != 1:
        ex.shutdown()
    log(f"translated {len(funcs)} functions in {time.time() - t0:.0f} s")

    with open(os.path.join(out, "funcs.h"), "w", newline="\n", encoding="utf-8") as h:
        h.write(f'#pragma once\n/* {profile.title}: generated by build_game.py */\n#include "runtime.h"\n'
                'void untranslated(Cpu *c, uint32_t addr);\n')
        h.writelines(f"void f_{a:08X}(Cpu *c);\n" for a, _, _ in funcs)
        h.writelines(f"void f_{a:08X}_orig(Cpu *c);   /* hooked: {hooks[a]} */\n" for a, _, _ in funcs if a in hooks)
    with open(os.path.join(out, "table.c"), "w", newline="\n", encoding="utf-8") as t:
        t.write('#include "funcs.h"\n')
        t.write("const uint32_t guest_func_addr[] = {" + ",".join(f"0x{a:08X}u" for a, _, _ in funcs) + "};\n")
        t.write("void (*const guest_func_ptr[])(Cpu *) = {" + ",".join(f"f_{a:08X}" for a, _, _ in funcs) + "};\n")
        t.write(f"const unsigned guest_func_count = {len(funcs)};\n")
        t.write(f'const char game_profile[] = "{profile.name}";\n')
        t.write(f'const char game_exe_fingerprint[] = "{img.fingerprint}";\n')
        # what runtime/app.m checks the player's exe against: per-region digests (layout first) and the whole file
        fp = exe_fingerprint.PROFILES[profile.fingerprint]
        with open(exe, "rb") as f:
            parts = exe_fingerprint.describe_regions(f.read(), fp["regions"], fp["tag"])[0]
        names = ["layout"] + [n for n, _, _ in fp["regions"]]
        t.write("const char game_exe_region_sha256[4][65] = {" + ",".join(f'"{parts[k] or "0" * 64}"' for k in names[:4]) + "};\n")
        t.write(f'const char game_exe_sha256[] = "{fp.get("file_sha256", "")}";\n')
    files.append(os.path.join(out, "table.c"))

    errors = []
    if not generate_only:
        t1 = time.time()
        objs = []
        with concurrent.futures.ThreadPoolExecutor(jobs) as ex2:
            for path, obj, rc_, err in ex2.map(lambda p: compile_one(p, out), files):
                (objs if rc_ == 0 else errors).append(obj if rc_ == 0 else (path, err))
        log(f"compiled {len(files)} C files in {time.time() - t1:.0f} s, {len(errors)} with errors")
        if not errors:
            pending = lib + ".new"
            subprocess.run(["ar", "rcs", pending] + sorted(objs), check=True)
            os.replace(pending, lib)

    translated = len(funcs) - sum(stubs.values())
    rep = [f"game: {profile.name} ({profile.title})",
           f"functions: {len(funcs)}, translated: {translated} ({100 * translated / len(funcs):.2f} %), stubbed: {sum(stubs.values())}",
           f"instructions translated: {insns}",
           f"traps (instructions trapping at run time): {sum(traps.values())}",
           f"C files: {len(files)}, compile errors: {len(errors)}" + ("" if not generate_only else " (not compiled)"),
           f"library: {lib if os.path.exists(lib) else 'not built'}",
           "stub reasons:"] + [f"  {n:6d}  {w}" for w, n in stubs.most_common()] + \
          ["trap reasons:"] + [f"  {n:6d}  {w}" for w, n in traps.most_common()]
    for path, err in errors[:3]:
        rep.append(f"ERROR {path}:\n{err}")
    with open(os.path.join(out, "report.txt"), "w", newline="\n", encoding="utf-8") as r:
        r.write("\n".join(rep) + "\n")
    log("\n".join(rep[:6]))
    return {"functions": len(funcs), "translated": translated, "stubs": dict(stubs), "traps": dict(traps),
            "instructions": insns, "errors": errors, "lib": lib if os.path.exists(lib) else None, "out": out}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    ap.add_argument("--game", default="ps_demo", choices=sorted(profiles.PROFILES))
    ap.add_argument("--exe", help="the game's executable (default: the profile's environment variable)")
    ap.add_argument("--out", help="output directory (default recomp/out/<game>)")
    ap.add_argument("--jobs", type=int)
    ap.add_argument("--generate-only", action="store_true", help="write the C sources and report; don't compile")
    a = ap.parse_args(argv)
    profile = profiles.PROFILES[a.game]
    exe = a.exe or os.environ.get(profile.exe_env)
    if not exe:
        ap.error(f"--exe or ${profile.exe_env} must name the executable")
    r = build(a.game, exe, a.out, a.jobs, a.generate_only)
    return 1 if r["errors"] else 0


if __name__ == "__main__":
    sys.exit(main())
