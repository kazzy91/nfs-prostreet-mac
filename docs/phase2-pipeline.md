# Phase 2 pipeline: function boundaries with Ghidra

`recomp/ghidra_functions.py` turns a 32-bit PE into a recompiler function manifest:

```bash
tools/.venv/bin/python -I recomp/ghidra_functions.py <nfs.exe> --data-refs --names --out <manifest.tsv>
```

1. **Ghidra headless auto-analysis** (`analyzeHeadless` with `recomp/ghidra/ExportFunctions.java`) in a temporary
   project outside the repository, deleted afterwards. It exports every function entry in executable memory, including
   thunks and C++ `Catch`/`Unwind` funclets (code reached only through exception tables, which the recompiler must be
   able to enter), and Ghidra's names: its function-ID database recognises the MSVC runtime (`_malloc`,
   `___CxxFrameHandler`, ...).
2. **`--data-refs`**: MW's `build_all.add_data_referenced` rules, generalised to any image. It adds code pointers in the
   data sections and code immediates at a 16-byte boundary or after padding/ret/jmp, plus the entries of
   `push end; push start; call _initterm` tables. Each candidate must be a plausible start on a capstone sweep (the
   previous real instruction ends control flow).
3. **Call closure** (also `--data-refs`): code reached only through a pointer was never explored by Ghidra, so neither
   were its callees. The new functions are walked by recursive descent, and every direct call target becomes a start,
   until nothing new turns up.

Setup: `brew install ghidra` (12.2, about 500 MB with its JDK). Ghidra 12 needs JDK 25: the tool passes Homebrew's
`openjdk@25` to the subprocess (`GHIDRA_JAVA_HOME` overrides), because a `JAVA_HOME` pointing at an older JDK stops
`analyzeHeadless`, which can't prompt without a TTY. The tool only reads the input; the manifest holds addresses and
names, so it is committable metadata (CLAUDE.md rule 1).

Test: `recomp/ghidra_functions_test.py` checks the data-reference and closure rules on a synthetic PE (capstone, no
Ghidra), including a mutant run with the plausible-start rule disabled.

## Proof on ProStreet's `server.dll` (2026-11-10)

The disc's LAN server DLL is plain code (`pe_report.py`: "plain"), so it could run through the whole pipeline before
`nfs.exe` can. The DLL was copied from the read-only disc image into a scratch folder outside the repository.

| Step | Result |
|---|---|
| Ghidra auto-analysis | 1,101 functions in 43 s |
| `--data-refs` (data pointers, immediates, initializer tables) | +208 |
| call closure | +36, **1,345 functions** in total |
| translation with the unchanged MW recompiler | **1,345/1,345 translated**, 0 stubs, 0 traps, 0 calls to unknown targets, 102,233 instructions |
| clang `-O2` for arm64 | 7/7 C files compile |

Without step 3 the translation had 30 traps ("call to unknown target"): every one was a call from a pointer-reached
function into code Ghidra had never seen. Without step 2, translation is just as clean (direct calls only reach known
functions), but the 244 pointer-reached functions would fail at run time as indirect calls to unknown code. A clean
translation report alone doesn't prove a complete manifest.

**Against MW's manifest.** ProStreet's `server.dll` is MW's LAN server relinked: the first 77 starts (below 0x5000)
are identical, and from about 0x5A10 the code sits 0x70 bytes earlier. Aligned that way, MW's hand-checked
`server_functions.tsv` (1,413 starts) is a reference answer for this binary:
- Ghidra alone covers 1,069 of MW's starts; with `--data-refs` and the closure, **1,326**.
- Of the 87 left, 71 are not even 16-byte aligned: interior entry points MW added by a rule of its own, not ordinary
  function starts. The other 16 are mostly in the C runtime, where the two builds' library code differs.
- 19 of ProStreet's starts are not in MW's manifest: C++ `Catch` funclets and CRT functions.

The scratch driver used for the translation (a copy of `server_module.ServerPE`'s loading without MW's pins: hash,
entry point, relocation counts) was not committed. Giving the recompiler per-game profiles is Phase 3.

## Instruction census (`recomp/census.py`)

```bash
tools/.venv/bin/python -I recomp/census.py <nfs.exe> <manifest.tsv> --json census.json --md census.md
```

Every function in the manifest goes through the real translator (`recomp.Recompiler`, calls on, as `build_all.py`
uses it) on a `recomp/pe_image.py` image, the generic stand-in for `recomp.PE`, which is pinned to MW's `speed.exe`.
So the verdicts are the translator's own:
- **stubs:** functions it can't translate at all, by reason.
- **traps:** single instructions replaced by a run-time trap, by reason (`sse2 movapd`, `haddps`, ...). That is
  Phase 3's to-do list.

Every instruction the translation reaches is counted once, by class: x87, MMX, SSE1, SSE2, SSE3 and later, and string
ops. x87 is recognised by mnemonic: capstone's FPU group misses `fstp st(0)`, `fnstsw ax` and `fnstcw`, which MSVC
float code uses all the time. On `server.dll` the group alone counted 97 x87 instructions; the real number is 106.
`--jobs 1` runs in-process; otherwise worker processes share the work, with identical results.

`server.dll` (ProStreet's, 1,345-function manifest from above):

| | |
|---|---|
| Functions | 1,345 (1,345 translate, 0 stubs) |
| Instructions | 102,233, 98 distinct mnemonics |
| x87 FPU | 106 (0.1 %) |
| MMX | 0 (0.0 %) |
| SSE (float) | 0 (0.0 %) |
| SSE2 | 0 (0.0 %) |
| SSE3 and later | 0 (0.0 %) |
| String ops | 319 (0.3 %) |
| Traps (instructions the translator can't do) | 0 |
| Imports | 129 functions in 3 DLLs (KERNEL32 93, WS2_32 35, NETAPI32 1) |

So the LAN server needs nothing the translator lacks. The numbers that matter come from `nfs.exe`: MW's `speed.exe`
had 85,875 x87, 10,391 MMX/SSE2-integer and 231 SSE float instructions, and VS2005 code may use more SSE.

Test: `recomp/census_test.py` builds a PE with one function per class (x87, MMX, SSE1, SSE2, SSE3, string ops, an
import call, an undecodable function). It checks exact class counts and the translator's verdicts (SSE2 trapped;
x87/MMX/string not), `pe_image`'s mapping, and a mutant run with a broken classifier.

## For `nfs.exe`

The same command, once an `nfs.exe` passes Phase 0. Things to check then:
- `nfs.exe` has no relocations, so data pointers are found by scanning (as here), not from a relocation table.
- Jump tables are handled by the translator itself (`jmp [table + reg*4]` becomes a `switch`), not by the manifest.
- Run the census on the manifest: its trap list is what Phase 3 has to add to the translator.
