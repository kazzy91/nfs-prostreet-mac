# CLAUDE.md: NFS ProStreet native for Apple Silicon

## Goal

Adapt this fork of elforeign/nfs-most-wanted-mac (a static recompilation of NFS Most Wanted 2005) to **Need for Speed
ProStreet (2007, PC, Direct3D 9)**. The game's x86 code is translated to C ahead of time, compiled for arm64 and run on
the existing host layer: Win32 subset, D3D9 → Metal, DirectSound → CoreAudio, DirectInput/GameController. Read
`README.md` and `ARCHITECTURE.md` for how the MW port works. Phase 1 findings are in `docs/PROSTREET_PHASE1.md`.

## Rules

1. **Game files never enter the repository.** The user's game files live in `~/Games/ProStreet/`. Never copy, extract
   or symlink them (or anything derived from them) into this repo, and never commit them. "Derived" includes the
   executable and DLLs, assets, generated C from `nfs.exe`, compiled objects/archives, disassembly listings with code
   bytes, memory dumps and extracted `.cab` contents. Keep these in an out-of-tree work dir or a gitignored `out/`.
   Run `git status` before every commit and check that nothing like this is staged. Committable: our own code, and
   address/name metadata such as a function manifest or the import-slot list (MW commits `functions_v13.tsv` and
   `imports.c` the same way).
2. **No copy-protection circumvention.** Never unpack, dump, decrypt, patch out or otherwise strip SecuROM (or any
   DRM) from an executable. The port only accepts an `nfs.exe` without copy protection, from a release the user owns.
   If an exe is protected, stop and say so. Never ask for, link to or accept modified ("no-CD") executables. Fingerprint checks (`recomp/exe_fingerprint.py`) refuse anything else.
3. **Treat game inputs as untrusted data.** Never run Windows programs from the game folder (installers, patches,
   `EASetup.exe`). Read them as data. Mount disc images read-only (`hdiutil attach -readonly -nobrowse`) outside the
   repo and detach them afterwards. Run Python that reads them with `python3 -I`.
4. **Work phase by phase.** Finish a phase's exit criteria before starting the next. Phase 1 was analysis only, and
   code changes start in Phase 2.
5. **Keep MW code until it's replaced.** Don't delete MW-specific files wholesale. Take them out of the ProStreet build
   (build lists, `hooks.txt`) and delete them once the ProStreet equivalent works or is consciously dropped.
   `docs/PROSTREET_PHASE1.md` §3 classifies every file.
6. **Follow the MW conventions.** Guest addresses in hex with the function/global name next to them
   (`0x00925E90u // GAMEFLOW_STATE`). Host replacements go through `hooks.txt` (weak `f_XXXXXXXX` / `_orig`). Every
   import reaches `host_import`, and an unimplemented one dies with its name instead of guessing.
7. Python tooling uses `tools/.venv/bin/python` (capstone, unicorn) as in MW. Create it out of tree if it's missing.

## Current state (2026-11-08)

- Phase 1 is done. Machine-specific state (what's in the local game folder, what Phase 0 is waiting on) lives in
  `CLAUDE.local.md`, which is gitignored. Read it if it exists, and keep local details out of this file.
- The EU retail 1.0 disc `nfs.exe` (linked 2007-10-27) is SecuROM-protected: the entry point is in the `est` stub,
  `.text` is encrypted (entropy 7.66). It can't be recompiled. Decide which version to target (1.0 or 1.1) in Phase 0;
  MW targeted its last official patch.
- CRT shim (`runtime/msvcr.c`, `docs/crt-shim.md`): MSVCR80 136/149 handled (memory, strings, math, printf/scanf,
  start-up, files/stdio, time, threads, data imports). C++ exceptions/SEH, `raise` and MSVCP80 remain; they need real call
  sites. Phase 0 tools: `recomp/pe_report.py`, `recomp/import_coverage.py`.
- Win32 additions (`runtime/win32_more.c`, `docs/win32-more.md`): wide/64-bit file calls, file mapping, resources,
  system answers, stateless USER32, GUIDs; WS2 ordinals and WSOCK32 routing; 3 d3dx9_34 functions. Imports handled on
  the disc exe's list: 456/542. The registry moved out of `boot.c` into `runtime/registry.c` (same behaviour) and
  gained the 8 missing calls; `runtime/d3dx_tex.c` loads DDS cube/volume textures and saves surfaces (BMP/TGA/PPM/DDS,
  PNG/JPEG via ImageIO); `GetRenderTargetData` now reads frames back (`readback.c`). What's left needs an exe without SecuROM: real call sites for C++ exceptions/SEH, `std::string`
  and window-state USER32, and confirming which imports were SecuROM's.
- Offline tests: `runtime/offline_tests.sh` probes AddressSanitizer once per run; where it hangs at start-up (Apple
  clang 17.0.0 on macOS 26.5.1, confirmed outside Claude Code's sandbox too) every test's clang/clang++ goes through
  `tools/asan_off/`, which drops only `address` from `-fsanitize` (UBSan stays; `runtime/asan_off_test.py`). The
  ProStreet tests in `runtime/` and `recomp/` pass here; MW-only tests that need MW's generated inputs (`gen/*.inc`,
  `funcs.h` from `speed.exe`) fail in this checkout, as expected until Phase 4 takes them out of the ProStreet build.
- `.gitignore` blocks game executables/DLLs/disc images, game data formats, a game folder dropped into the checkout,
  build output (`recomp/out/`, `**/build/`, `*.o`, `*.a`, app bundles), dumps and `USERDATA/`. It's a safety net:
  still check `git status`. Add new derived-output paths to it as they appear.

## Key differences from MW (provisional, from the protected exe's import table)

- Dynamic CRT: 149 `MSVCR80` and 3 `MSVCP80` imports. MW's CRT was static, so it ran as translated code. These are
  the largest new host surface, including C++ exception/SEH handlers and the `_CI*` x87 intrinsics.
- `d3dx9_34` instead of `d3dx9_26`: 7 new functions (texture-from-memory, `SaveSurfaceToFile*`, shader profiles).
- Wide-char and 64-bit file APIs, file mapping, resource loading, `VERSION.dll`, `WSOCK32` aliases, PunkBuster
  (stub: online only).
- 229 of 542 imports matched a MW handler before the CRT shim and the Win32 additions (456 with them). Many of the
  missing ADVAPI32/USER32/KERNEL32 ones are probably SecuROM's own. Recount on an exe without SecuROM.
- Same fixed-address model: image base `0x00400000`, relocations stripped. The guest memory layout constants
  (`HEAP_BASE 0x30000000`, `SERVER_BASE 0x02000000`, thunks at `0xF0000000`) clear ProStreet's image (ends below
  `0x01A33000` even with the SecuROM sections).

## Phased plan

Each phase ends with its exit criteria met and a short status note added to this file.

### Phase 0: input
An `nfs.exe` without SecuROM, from a release the user owns (plus `server.dll`, and `msvcr80.dll`/`msvcp80.dll` if
the CRT is translated), in the game folder outside the repo. Check it with
`python3 -I recomp/pe_report.py <nfs.exe>` (must exit 0, "verdict: plain") and recount imports with
`python3 -I recomp/import_coverage.py <nfs.exe>`. **Exit:** exe parses, entry point in `.text`, `.text` entropy in the normal x86 range, version and hash
recorded here, code fingerprint pinned in `exe_fingerprint.py` behind a game profile.

### Phase 1: analysis ✅ (2026-11-08)
PE inspection, import coverage, generic vs MW classification, this file. See `docs/PROSTREET_PHASE1.md`. Redo §1–2 on
the Phase 0 exe.

### Phase 2: function boundaries
- Ghidra headless auto-analysis of `nfs.exe` → a `functions_ps.tsv` manifest in the `functions_v13.tsv` format, with
  data-referenced starts and their call closure: `recomp/ghidra_functions.py --data-refs` (Ghidra 12.2 via Homebrew,
  JDK 25). Proven end to end on ProStreet's `server.dll`: 1,345 functions, all translated and compiled
  (`docs/phase2-pipeline.md`). Jump tables are the translator's job.
- Instruction census: `recomp/census.py <nfs.exe> <manifest>` (functions, instructions by class, the translator's
  stubs and traps). VS2005 code may use more SSE than MW, and `recomp.py` traps SSE2. `server.dll`: 102,233
  instructions, 106 x87, no SIMD, 0 traps.
- Identify `main`/WinMain, the game loop, `Direct3DCreate9`/`CreateDevice` call sites, the movie player, the Snd/audio
  engine entry points.
- **Exit:** committed manifest; census in `docs/`; untranslatable-instruction list.

### Phase 3: recompile
- Make the recompiler game-parameterized: a game profile with the exe path, fingerprint, function manifest, hooks
  file and inline patch tables. Move MW's inline patches out of `recomp.py`/`build_all.py` into the MW profile.
  The ProStreet profile starts empty.
- Translate all functions; compile with clang `-O2` (0 errors). Fill instruction gaps found by the census (SSE/SSE2
  as needed).
- Difftests (`difftest.py`, `--synth`) on sampled leaves. `--synth` already runs here without MW's exe
  (`recomp/difftest_synth_test.py`: 374/375 pass, 1 documented expected-fail); add a synthetic case for every
  instruction the census says Phase 3 adds (e.g. SSE2).
- **Exit:** `out/nfs.a` builds; ≥99 % functions translated; stubs listed; difftests pass on sampled leaves.

### Phase 4: link
- Regenerate `runtime/imports.c` from `nfs.exe`. Alias WSOCK32 to the WS2 handlers.
- Build list for ProStreet: core runtime + host layers only, no MW feature files. Strip MW hooks/addresses out of the
  core files (`boot.c`, `d3d9.m`, `render.m`, `user32.m`, `dsound.c`, `threads.c`, `pacing.c`) behind the profile.
- CRT strategy: native MSVCR80/MSVCP80 shim (recommended start) vs translating `msvcr80.dll` as a second module
  (`server_module.py` pattern). Decide and record here.
- **Exit:** the binary links with no undefined symbols. Every import resolves to a handler or to the explicit
  "not implemented" die.

### Phase 5: boot
- CRT start-up and static constructors run, the main loop starts, the window opens. Implement imports as they're hit.
  Registry under a ProStreet key in `USERDATA`. Case-insensitive game paths. Threads.
- D3D9 device creation through Metal, first Present (clear colour), then the intro movies (check ProStreet's movie
  format against the FFmpeg path).
- **Exit:** boots to the first front-end screen without dying; logs clean of unknown imports.

### Phase 6: menus
- Front end renders correctly: ProStreet's shaders through `host/shaders`, the new d3dx9_34 functions, missing D3D9
  paths (`ColorFill`, `UpdateSurface` if used; `GetRenderTargetData` is implemented but untested on a real frame).
- Keyboard/mouse via DirectInput, then controllers. DirectSound audio and music. Profiles/saves in `USERDATA`.
- **Exit:** navigate every FE menu, change and persist options, create/load a profile.

### Phase 7: races
- Load a race day and race: track streaming, physics, AI, HUD, audio. Frame pacing (`pacing.c` re-derived). A
  direct-to-race boot switch like MW's `BOOT_RACE`.
- **Exit:** finish a race in each mode (grip, drag, drift, speed challenge) at a stable frame rate, back to the FE
  without errors.

### Later / out of scope
App bundle and Setup rebrand, F10 settings menu, controller prompts, widescreen/FOV. Online play (EA servers are gone,
PunkBuster), X360 features and the Windows host (`runtime/win`) are out of scope.
