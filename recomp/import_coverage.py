"""Which of an exe's imports the host layer already handles, per DLL.

    python3 -I recomp/import_coverage.py path/to/nfs.exe [--json] [--all]
    python3 -I recomp/import_coverage.py --mw            # MW's own import list (runtime/imports.c), parser check

Stdlib only; reads files, runs nothing. The DLL -> handler routing is read from host_import's dispatch statement
in runtime/boot.c (`!strncmp(name, "DLL", n) ? handler(c, fn) || ...`, then the fallback chain), and each handler's
file is found by its definition `int handler(Cpu *c, const char *fn)`. An import counts as handled when one of its
handlers' files compares `fn` with its exact name (`strcmp(fn, "Name")`), or, for WS2_32 ordinals, when the ordinal
is a `case` of ws2_32.c's `fn[0] == '#'` switch. Prefix tests are not counted: in this code base they are negative
gates or tracing, not handlers.

"Handled" means a handler exists for the name. Whether it does what this game needs is a separate question.

WSOCK32 imports are reported with the WS2_32 ordinal of the same function: for the ordinals listed in WSOCK32_AS_WS2
the two DLLs export the same function under the same number, so routing WSOCK32 to win32_ws2 covers them.

Offline test: recomp/import_coverage_test.py.
"""
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
RUNTIME = os.path.join(HERE, "..", "runtime")
sys.path.insert(0, HERE)
import pe_report  # noqa: E402

# WSOCK32 ordinal -> the WS2_32 ordinal of the same function (identical numbers for the socket core).
WSOCK32_AS_WS2 = {n: n for n in (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                                 51, 52, 53, 54, 55, 56, 57, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111,
                                 112, 113, 114, 115, 116, 151)}


def _read(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        return f.read()


def source_files(runtime=RUNTIME):
    return [os.path.join(runtime, f) for f in sorted(os.listdir(runtime))
            if f.endswith((".c", ".m")) and "_test" not in f]


def routing(runtime=RUNTIME):
    """([(dll prefixes, [handler names])], [fallback handler names]) from host_import's dispatch in boot.c."""
    src = _read(os.path.join(runtime, "boot.c"))
    m = re.search(r"int ok = (!strncmp\(name,.*?);\n", src, re.S)
    if not m:
        raise SystemExit("runtime/boot.c: host_import's dispatch statement (int ok = ...;) not found")
    routes, fallback = [], None
    for arm in re.split(r"\n\s*:\s*", m.group(1)):
        handlers = re.findall(r"(\w+)\(c, fn\)", arm)
        prefixes = re.findall(r'!strncmp\(name, "([^"]+)", \d+\)', arm)
        if prefixes:
            routes.append((prefixes, handlers))
        else:
            fallback = handlers
    if not routes or not fallback:
        raise SystemExit("runtime/boot.c: could not read the DLL routing of host_import")
    return routes, fallback


def handler_files(names, runtime=RUNTIME):
    """{handler name: file path} for `int name(Cpu *c, const char *fn)` definitions."""
    out = {}
    for path in source_files(runtime):
        src = _read(path)
        for n in names:
            if re.search(r"^\s*(?:static\s+)?int\s+%s\s*\(\s*Cpu\s*\*\s*c\s*,\s*const char\s*\*\s*fn\s*\)" % re.escape(n),
                         src, re.M):
                out[n] = path
    missing = [n for n in names if n not in out]
    if missing:
        raise SystemExit(f"handler definitions not found in runtime/: {', '.join(missing)}")
    return out


def handled_names(path):
    """(exact names, WS2 ordinal set) a handler file recognises."""
    src = _read(path)
    names = set(re.findall(r'strcmp\(fn,\s*"([^"]+)"\)', src))
    ords = set()
    m = re.search(r"if \(fn\[0\] == '#'\) \{(.*?)unimplemented WS2_32 ordinal", src, re.S)
    if m:
        ords = {int(n) for n in re.findall(r"\bcase (\d+):", m.group(1))}
    return names, ords


class Host:
    """The host layer's import coverage, read from runtime/."""

    def __init__(self, runtime=RUNTIME):
        self.routes, self.fallback = routing(runtime)
        allh = sorted({h for _, hs in self.routes for h in hs} | set(self.fallback))
        files = handler_files(allh, runtime)
        self.by_handler = {h: handled_names(files[h]) for h in allh}
        self.files = {h: os.path.relpath(p, os.path.join(runtime, "..")) for h, p in files.items()}

    def handlers_for(self, dll):
        for prefixes, hs in self.routes:
            if any(dll.startswith(p) for p in prefixes):
                return hs
        return self.fallback

    def covers(self, dll, fn):
        hs = self.handlers_for(dll)
        if fn.startswith("#") and fn[1:].isdigit():
            n = int(fn[1:])
            if any(n in self.by_handler[h][1] for h in hs):
                return True
        return any(fn in self.by_handler[h][0] for h in hs)

    def note(self, dll, fn):
        """A hint for an unhandled import, or ''."""
        if dll.upper().startswith("WSOCK32") and fn.startswith("#") and fn[1:].isdigit():
            n = WSOCK32_AS_WS2.get(int(fn[1:]))
            if n is not None and self.covers("WS2_32.dll", f"#{n}"):
                return f"= WS2_32 #{n} (handled there: route WSOCK32 to win32_ws2)"
        return ""


def coverage(imports, host):
    """[{dll, total, handled, missing: [(name, note)]}] in import-table order."""
    rows = []
    for dll, fns in imports.items():
        names = [f for _, f in fns]
        miss = [(f, host.note(dll, f)) for f in names if not host.covers(dll, f)]
        rows.append({"dll": dll, "total": len(names), "handled": len(names) - len(miss), "missing": miss,
                     "handlers": host.handlers_for(dll)})
    return rows


def mw_imports(runtime=RUNTIME):
    """MW's speed.exe import list from the generated runtime/imports.c, as {dll: [(slot, name)]}."""
    out = {}
    for slot, dll, fn in re.findall(r'\{0x([0-9A-Fa-f]+)u, "([^"!]+)!([^"]+)"\}', _read(os.path.join(runtime, "imports.c"))):
        out.setdefault(dll, []).append((int(slot, 16), fn))
    return out


def render(rows, show_all=False):
    L = ["| DLL | Imports | Handled | Missing | Handler(s) |", "|---|---|---|---|---|"]
    for r in rows:
        L.append(f"| {r['dll']} | {r['total']} | {r['handled']} | {len(r['missing'])} | {', '.join(r['handlers'])} |")
    tot, hand = sum(r["total"] for r in rows), sum(r["handled"] for r in rows)
    aliases = sum(1 for r in rows for _, n in r["missing"] if n)
    L.append(f"\nTotal: {tot} imports in {len(rows)} DLLs, {hand} handled, {tot - hand} missing"
             + (f" ({aliases} of them covered by routing WSOCK32 to the WS2_32 handler)" if aliases else "") + ".")
    for r in rows:
        if r["missing"] and (show_all or len(r["missing"]) <= 200):
            L.append(f"\n**{r['dll']}** missing: " + " ".join(f"{f} ({n})" if n else f for f, n in r["missing"]))
    return "\n".join(L)


def main(argv):
    args = [a for a in argv if not a.startswith("--")]
    if "--mw" in argv:
        imports = mw_imports()
    elif len(args) == 1:
        try:
            imports = pe_report.parse(open(args[0], "rb").read())["imports"]
        except (OSError, pe_report.NotPE) as e:
            print(f"{args[0]}: {e}", file=sys.stderr)
            return 1
    else:
        print(__doc__.strip().splitlines()[2].strip(), file=sys.stderr)
        return 1
    rows = coverage(imports, Host())
    if "--json" in argv:
        print(json.dumps(rows, indent=1))
    else:
        print(render(rows, "--all" in argv))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
