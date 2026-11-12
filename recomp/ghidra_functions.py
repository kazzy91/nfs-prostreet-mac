"""Phase 2: function boundaries from a Ghidra headless analysis, written as a recompiler manifest.

    python3 -I recomp/ghidra_functions.py <exe or dll> --out <manifest.tsv> [--rva] [--names] [--jobs N]

Runs Ghidra's analyzeHeadless on the file in a temporary project (outside the repository, deleted afterwards) with
recomp/ghidra/ExportFunctions.java, then writes the function starts:
  default  virtual addresses with a comment header naming the input's SHA-256, like recomp/functions_v13.tsv
  --rva    image-relative addresses, bare (like recomp/server_functions.tsv)
  --names  keep Ghidra's names as a second column (FUN_xxxxxxxx, thunk and export names)
  --data-refs  add the starts Ghidra's auto-analysis misses because only pointers reach them (vtables, callbacks,
           static initializers), with MW's build_all.add_data_referenced rules on any 32-bit PE: code pointers in the
           data sections and code immediates (push/mov) at a 16-byte boundary or after padding/ret/jmp, every entry
           of a `push end; push start; call _initterm` table, each checked with listing.py's plausible-start test on a
           capstone sweep of the code section. Then a call closure: every function (Ghidra's and the new ones) is
           walked by recursive descent and every direct call target it reaches becomes a start too, until nothing new
           turns up. Code reached only through a pointer was never explored by Ghidra, so neither were its callees,
           and Ghidra also leaves some direct call targets inside a neighbour's body (ProStreet: small constructors
           after a jmp-only function, an import thunk). Direct calls seen anywhere in the linear sweep count too (switch
           cases reached only through a jump table), when the target passes the same plausible-start test. A
           `call $+5` (the get-EIP idiom) is not a start, and neither is an address holding int3 (padding). A
           16-byte-aligned target right after int3 padding is accepted even when the bytes before the padding decode
           as junk (MSVC's switch tables, of case addresses or byte indexes, sit between a function's ret and it), and
           so is one right after a table of nearby case addresses, padded or not.
           Needs capstone (tools/.venv/bin/python).
The input is only read (Ghidra imports a copy into its project); nothing is executed. The manifest holds addresses and
names only, no code bytes, so it is committable metadata (CLAUDE.md rule 1).

analyzeHeadless is found through $GHIDRA_HEADLESS, then `brew --prefix ghidra`, then PATH. Ghidra 12 needs JDK 25: the
subprocess gets JAVA_HOME from $GHIDRA_JAVA_HOME, else Homebrew's openjdk@25 (the formula's own dependency), else the
inherited JAVA_HOME. A JAVA_HOME pointing at an older JDK otherwise stops analyzeHeadless, which can't prompt without a TTY.
"""
import argparse
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.join(HERE, "ghidra")


def find_headless():
    env = os.environ.get("GHIDRA_HEADLESS")
    if env and os.access(env, os.X_OK):
        return env
    try:
        prefix = subprocess.run(["brew", "--prefix", "ghidra"], capture_output=True, text=True, timeout=60).stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        prefix = ""
    cand = os.path.join(prefix, "libexec", "support", "analyzeHeadless") if prefix else ""
    if cand and os.access(cand, os.X_OK):
        return cand
    return shutil.which("analyzeHeadless")


def java_home():
    if os.environ.get("GHIDRA_JAVA_HOME"):
        return os.environ["GHIDRA_JAVA_HOME"]
    try:
        prefix = subprocess.run(["brew", "--prefix", "openjdk@25"], capture_output=True, text=True, timeout=60).stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        prefix = ""
    home = os.path.join(prefix, "libexec", "openjdk.jdk", "Contents", "Home") if prefix else ""
    return home if home and os.access(os.path.join(home, "bin", "java"), os.X_OK) else os.environ.get("JAVA_HOME")


def analyze(path, rva, jobs, log=None):
    """[(address, name)] from Ghidra's auto-analysis of path."""
    headless = find_headless()
    if not headless:
        raise SystemExit("analyzeHeadless not found: install Ghidra (brew install ghidra) or set GHIDRA_HEADLESS")
    with tempfile.TemporaryDirectory(prefix="ghidra_functions.") as tmp:
        out = os.path.join(tmp, "functions.tsv")
        cmd = [headless, tmp, "proj", "-import", os.path.abspath(path), "-scriptPath", SCRIPTS,
               "-postScript", "ExportFunctions.java", out] + (["rva"] if rva else []) + \
              ["-deleteProject", "-max-cpu", str(jobs)]
        env = dict(os.environ)
        if java_home():
            env["JAVA_HOME"] = java_home()
        r = subprocess.run(cmd, capture_output=True, text=True, env=env)
        if log:
            with open(log, "w") as f:
                f.write(r.stdout + r.stderr)
        if r.returncode or not os.path.exists(out):
            tail = (r.stdout + r.stderr)[-3000:]
            raise SystemExit(f"analyzeHeadless failed (exit {r.returncode}):\n{tail}")
        rows = []
        with open(out) as f:
            for line in f:
                addr, _, name = line.rstrip("\n").partition("\t")
                rows.append((int(addr, 16), name))
        return rows


def _plausible(t, starts, ends):
    """build_all.plausible_start, for any image: an instruction boundary that ordinary code doesn't fall into (walking
    back over padding, the previous real instruction must end control flow)."""
    if t not in starts:
        return False
    at = t
    for _ in range(32):
        prev = ends.get(at)
        if prev is None:
            return True
        a, kind = prev
        if kind != "pad":
            return kind == "end"
        at = a
    return True


def data_referenced(path, rows, rva):
    """Extra (address, name) rows for code reached only through pointers; addresses in the same form as rows."""
    import struct
    from capstone import CS_ARCH_X86, CS_MODE_32, Cs
    sys.path.insert(0, HERE)
    import listing
    import pe_report
    data = open(path, "rb").read()
    info = pe_report.parse(data)
    base = info["image_base"]
    secs = info["sections"]
    code = [s for s in secs if s["chars"] & 0x20000000]
    if not code:
        return []
    text = code[0]
    lo, hi = base + text["va"], base + text["va"] + min(text["vsize"] or text["raw_size"], text["raw_size"])
    blob = data[text["raw_off"]:text["raw_off"] + (hi - lo)]

    def read(va, n):
        for s in secs:
            o = va - base - s["va"]
            if 0 <= o and o + n <= s["raw_size"]:
                return data[s["raw_off"] + o:s["raw_off"] + o + n]
        return None
    # a linear sweep of the code section, as listing.py does for speed.exe
    starts, ends, imms, calls = set(), {}, set(), set()
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    pos = 0
    while pos < len(blob):
        insn = next(md.disasm_lite(blob[pos:pos + 16], lo + pos), None)
        if insn is None:
            pos += 1
            continue
        a, n, mn, ops = insn
        starts.add(a)
        ends[a + n] = (a, listing.kind(mn, ops))
        if mn == "call" and n == 5 and blob[pos] == 0xE8:
            t = (a + 5 + int.from_bytes(blob[pos + 1:pos + 5], "little", signed=True)) & 0xFFFFFFFF
            if lo <= t < hi and t != a + 5:
                calls.add(t)
        if mn in ("push", "mov") and n >= 5:
            imm = int.from_bytes(blob[pos + n - 4:pos + n], "little")
            if lo <= imm < hi:
                imms.add(imm)
        pos += n
    known = {a + (base if rva else 0) for a, _ in rows}
    names = {a + (base if rva else 0): nm for a, nm in rows}

    def aligned_after_padding(t):
        """MSVC puts a switch's tables (case addresses, or byte indexes) between a function's ret and the padding: the
        sweep decodes them as junk, so the plausible-start test fails. A pointer target at a 16-byte boundary right
        after int3 padding is a function start all the same (MSVC aligns functions so, padding with int3)."""
        return t % 16 == 0 and read(t - 1, 1) == b"\xcc" and read(t, 1) != b"\xcc"

    def after_case_table(t):
        """A switch's table of case addresses right before t (after optional int3 padding): its last two dwords are
        code addresses within 64 KiB of t. MSVC also places such a table with no padding before the next function."""
        k = t
        while k > lo and read(k - 1, 1) == b"\xcc":
            k -= 1
        words = read(k - 8, 8) if k % 4 == 0 else None
        return words is not None and all(lo <= w < hi and abs(w - t) < 0x10000 for w in struct.unpack("<II", words))

    def start_ok(t):
        if _plausible(t, starts, ends):
            return True
        # a switch's byte-index table can follow its case-address table: it starts with index 0, and no MSVC
        # function starts with 00 (add r/m8, r8)
        return read(t, 1) != b"\x00" and (aligned_after_padding(t) or after_case_table(t))

    def boundary_ok(t):
        if read(t, 1) == b"\xcc":                    # int3 padding between functions, never a start
            return False
        prev, before = read(t - 1, 1), read(t - 5, 5)
        after = before is not None and (before[0] == 0xE9 or before[3] == 0xEB or before[2] == 0xC2)
        return t % 16 == 0 or prev in (b"\xcc", b"\xc3", b"\x90") or after
    extra = set()
    for s in secs:
        if s["chars"] & 0x20000000 or not s["raw_size"] or s["name"] in (".rsrc", ".reloc"):
            continue
        sb = data[s["raw_off"]:s["raw_off"] + s["raw_size"]]
        for k in range(0, len(sb) - 3, 4):
            t = struct.unpack_from("<I", sb, k)[0]
            if lo <= t < hi and t not in known and boundary_ok(t) and start_ok(t):
                extra.add(t)
    for t in imms:
        if t not in known and t not in extra and boundary_ok(t) and start_ok(t):
            extra.add(t)
    initterm = {a for a, nm in names.items() if "initterm" in nm}
    for k in range(len(blob) - 15):
        if blob[k] == 0x68 and blob[k + 5] == 0x68 and blob[k + 10] == 0xE8:
            call_at = lo + k + 10
            tgt = (call_at + 5 + int.from_bytes(blob[k + 11:k + 15], "little", signed=True)) & 0xFFFFFFFF
            if tgt not in initterm:
                continue
            end, start = int.from_bytes(blob[k + 1:k + 5], "little"), int.from_bytes(blob[k + 6:k + 10], "little")
            for a in range(start, end, 4):
                t = int.from_bytes(read(a, 4) or b"\0\0\0\0", "little")
                if lo <= t < hi and t not in known:
                    extra.add(t)
    # direct calls the sweep sees anywhere, e.g. in switch cases reached only through a jump table, which recursive
    # descent from a start doesn't follow: the same plausible-start rules as data pointers
    swept = {t for t in calls if t not in known and t not in extra and boundary_ok(t) and _plausible(t, starts, ends)}
    called = call_closure(extra | swept, known, read, lo, hi, md, roots=known) | swept
    return sorted([(t - (base if rva else 0), f"data_ref_{t:08X}") for t in extra] +
                  [(t - (base if rva else 0), f"called_{t:08X}") for t in called])


def call_closure(new, known, read, lo, hi, md, roots=()):
    """Direct call targets that aren't starts yet, reachable from the functions at `new` and `roots` (recursive
    descent inside each function, stopping at returns, indirect jumps and other functions' starts), repeated over the
    targets themselves."""
    stop = set(known) | set(new)                      # every start; `found` grows beside it
    found, queue = set(), sorted(set(roots) | set(new))
    while queue:
        start = queue.pop()
        work, seen = [start], set()
        while work and len(seen) < 50000:
            at = work.pop()
            while lo <= at < hi and at not in seen and (at == start or (at not in stop and at not in found)):
                seen.add(at)
                code = read(at, 16)
                insn = next(md.disasm(code, at), None) if code else None
                if insn is None:
                    break
                mn, nxt = insn.mnemonic, at + insn.size
                target = int(insn.op_str, 16) if insn.op_str.startswith("0x") else None
                if mn == "call":
                    if (target is not None and lo <= target < hi and target != nxt and target not in stop
                            and target not in found):
                        found.add(target)
                        queue.append(target)
                elif mn.startswith("ret") or mn in ("hlt", "ud2", "int3"):
                    break
                elif mn == "jmp":
                    if target is not None:
                        work.append(target)
                    break
                elif mn.startswith("j") or mn.startswith("loop") or mn == "jecxz":
                    if target is not None:
                        work.append(target)
                at = nxt
    return found


def write_manifest(rows, out, path, rva, names):
    digest = hashlib.sha256(open(path, "rb").read()).hexdigest()
    with open(out, "w") as f:
        if not rva:
            f.write(f"# Function starts of {os.path.basename(path)} (Ghidra headless analysis, recomp/ghidra_functions.py):\n"
                    f"# addresses{' and Ghidra names' if names else ' only'}. No code or bytes.\n# sha256 {digest}\n")
        for a, n in rows:
            f.write(f"{a:08X}\t{n}\n" if names else f"{a:08X}\n")


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    ap.add_argument("input")
    ap.add_argument("--out", required=True)
    ap.add_argument("--rva", action="store_true")
    ap.add_argument("--names", action="store_true")
    ap.add_argument("--jobs", type=int, default=os.cpu_count() or 4)
    ap.add_argument("--log", help="write analyzeHeadless's output here")
    ap.add_argument("--data-refs", action="store_true")
    a = ap.parse_args(argv)
    rows = analyze(a.input, a.rva, a.jobs, a.log)
    if a.data_refs:
        extra = data_referenced(a.input, rows, a.rva)
        print(f"data-referenced starts added: {len(extra)}")
        rows = sorted(rows + extra)
    write_manifest(rows, a.out, a.input, a.rva, a.names)
    print(f"{len(rows)} functions -> {a.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
