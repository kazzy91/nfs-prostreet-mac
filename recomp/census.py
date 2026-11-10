"""Phase 2 instruction census: what a function manifest covers, by instruction class, and what the translator can't do.

    tools/.venv/bin/python -I recomp/census.py <exe or dll> <manifest.tsv> [--rva] [--json out.json] [--md out.md] [--jobs N]

The manifest is ghidra_functions.py's output (or MW's functions_v13.tsv / server_functions.tsv): one hex start per
line, VAs (default) or RVAs (--rva), optional names after a tab, '#' comments. Each function runs through the real
translator (recomp.Recompiler with calls on, as build_all.py and server_module.py use it) on a pe_image.Image, so the
verdicts are the translator's own:
  stubs   functions it can't translate at all, by reason (undecodable, falls into next function, ...)
  traps   single instructions it replaces with a run-time trap, by reason (e.g. "sse2 movapd")
Every instruction the translation reaches is counted once (functions can share code), by class: x87, MMX, SSE1, SSE2,
SSE3+ (SSE3/SSSE3/SSE4), string ops (movs/stos/cmps/scas/lods, rep or not), other. Imports are counted by DLL.
The input is only read. Output: a summary on stdout, --json for the full numbers, --md for a table like ARCHITECTURE.md's.
"""
import argparse
import collections
import concurrent.futures
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

CLASSES = ("x87", "MMX", "SSE1", "SSE2", "SSE3+", "string", "other")
STRING = re.compile(r"^(rep\w* )?(movs|stos|cmps|scas|lods)[bwdq]?$")
TRAP = re.compile(r"untranslated\(c, 0x([0-9A-F]{8})u\); return; /\* (.*?) \*/")


def load_manifest(path, base, rva):
    starts = []
    for line in open(path):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        a = int(line.split("\t")[0].split()[0], 16)
        starts.append(a + base if rva else a)
    return sorted(set(starts))


def classify(insn, X):
    m = insn.mnemonic
    if STRING.match(m):
        return "string"
    # x87 by mnemonic: capstone's FPU group misses some (fstp st(0), fnstsw ax, fnstcw), which MSVC float code uses
    # constantly. Every x87 mnemonic starts with f; fxsave/fxrstor (FXSR) and femms (3DNow) are not x87 arithmetic.
    if (m.startswith("f") and m not in ("fxsave", "fxrstor", "femms")) or m in ("wait", "fwait") or insn.group(X.X86_GRP_FPU):
        return "x87"
    regs = []
    for op in insn.operands:
        if op.type == 1:                                  # CS_OP_REG
            regs.append(insn.reg_name(op.reg))
    xmm = any(r.startswith("xmm") for r in regs)
    if any(insn.group(g) for g in (X.X86_GRP_SSE3, X.X86_GRP_SSSE3, X.X86_GRP_SSE41, X.X86_GRP_SSE42, X.X86_GRP_SSE4A)):
        return "SSE3+"
    if insn.group(X.X86_GRP_SSE2) and (xmm or not any(r.startswith("mm") for r in regs)):
        return "SSE2"
    if insn.group(X.X86_GRP_SSE1) and not insn.group(X.X86_GRP_MMX):
        return "SSE1"
    if insn.group(X.X86_GRP_MMX) or any(r.startswith("mm") for r in regs) or insn.group(X.X86_GRP_SSE2) or insn.group(X.X86_GRP_SSE1):
        return "MMX"
    return "other"


_W = {}


def _worker_init(path, base, functions):
    import recomp
    import pe_image
    _W["rc"] = recomp.Recompiler(pe=pe_image.Image(path, base=base), functions=functions)
    _W["rc"].calls = True


def _run(chunk):
    """Translate a chunk of (start, limit): stubs, traps and the instructions reached (address -> mnemonic, class)."""
    import capstone.x86 as X
    rc = _W["rc"]
    stubs, traps, insns = [], [], {}
    for a, limit in chunk:
        code, why = rc.translate(a, limit)
        if code is None:
            stubs.append((a, why))
            continue
        traps.extend((int(t, 16), r) for t, r in TRAP.findall(code))
        for addr, i in rc.seen.items():
            if addr not in insns:
                insns[addr] = (i.mnemonic, classify(i, X))
    return stubs, traps, insns


def census(path, manifest, rva=False, jobs=None, base=None):
    import pe_image
    img = pe_image.Image(path, base=base)
    lo, hi = img.code()
    starts = [a for a in load_manifest(manifest, img.base, rva) if lo <= a < hi]
    functions = dict(zip(starts, starts[1:] + [hi]))
    items = list(functions.items())
    jobs = jobs or os.cpu_count() or 4
    chunks = [items[k::jobs] for k in range(jobs)] if len(items) >= jobs else [items]
    stubs, traps, insns = [], [], {}
    if jobs == 1:                                         # in this process (debugging; tests patch classify here)
        _worker_init(path, img.base, functions)
        results = [_run(items)]
    else:                                                 # worker processes start fresh (spawn on macOS)
        with concurrent.futures.ProcessPoolExecutor(len(chunks), initializer=_worker_init, initargs=(path, img.base, functions)) as ex:
            results = list(ex.map(_run, chunks))
    for s, t, i in results:
        stubs += s
        traps += t
        for k, v in i.items():
            insns.setdefault(k, v)
    by_class = collections.Counter(c for _, c in insns.values())
    mnem = collections.Counter(m for m, _ in insns.values())
    per_class_top = {c: collections.Counter(m for m, k in insns.values() if k == c).most_common(8) for c in CLASSES}
    imports = collections.Counter(n.split("!")[0] for n in img.imports.values())
    stub_reasons = collections.Counter(r for _, r in stubs)
    trap_reasons = collections.Counter(r for _, r in traps)
    return {
        "input": os.path.basename(path), "image_base": img.base, "code": [lo, hi],
        "functions": len(functions), "translated": len(functions) - len(stubs), "stubs": len(stubs),
        "stub_reasons": stub_reasons.most_common(), "stub_list": [[f"{a:08X}", r] for a, r in sorted(stubs)],
        "traps": len(traps), "trap_reasons": trap_reasons.most_common(),
        "trap_list": [[f"{a:08X}", r] for a, r in sorted(set(traps))],
        "instructions": len(insns), "mnemonics": len(mnem),
        "by_class": {c: by_class.get(c, 0) for c in CLASSES}, "top_by_class": per_class_top,
        "imports": sum(imports.values()), "imports_by_dll": imports.most_common(),
    }


def markdown(r):
    n = r["instructions"] or 1
    pct = lambda k: f"{r['by_class'][k]:,} ({100.0 * r['by_class'][k] / n:.1f} %)"
    L = [f"Census of `{r['input']}` (recomp/census.py)", "", "| | |", "|---|---|",
         f"| Functions | {r['functions']:,} ({r['translated']:,} translate, {r['stubs']} stubs) |",
         f"| Instructions | {r['instructions']:,}, {r['mnemonics']} distinct mnemonics |",
         f"| x87 FPU | {pct('x87')} |", f"| MMX | {pct('MMX')} |", f"| SSE (float) | {pct('SSE1')} |",
         f"| SSE2 | {pct('SSE2')} |", f"| SSE3 and later | {pct('SSE3+')} |", f"| String ops | {pct('string')} |",
         f"| Traps (instructions the translator can't do) | {r['traps']:,} |",
         f"| Imports | {r['imports']} functions in {len(r['imports_by_dll'])} DLLs ("
         + ", ".join(f"{d.split('.')[0]} {k}" for d, k in r["imports_by_dll"]) + ") |"]
    if r["stub_reasons"]:
        L += ["", "Stubs by reason: " + ", ".join(f"{why} {k}" for why, k in r["stub_reasons"])]
    if r["trap_reasons"]:
        L += ["", "Traps by reason: " + ", ".join(f"{why} {k}" for why, k in r["trap_reasons"])]
    return "\n".join(L) + "\n"


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    ap.add_argument("input")
    ap.add_argument("manifest")
    ap.add_argument("--rva", action="store_true")
    ap.add_argument("--base", type=lambda s: int(s, 0), help="map the image here instead of its preferred base")
    ap.add_argument("--jobs", type=int)
    ap.add_argument("--json")
    ap.add_argument("--md")
    a = ap.parse_args(argv)
    r = census(a.input, a.manifest, a.rva, a.jobs, a.base)
    if a.json:
        with open(a.json, "w") as f:
            json.dump(r, f, indent=1)
    md = markdown(r)
    if a.md:
        with open(a.md, "w") as f:
            f.write(md)
    print(md)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
