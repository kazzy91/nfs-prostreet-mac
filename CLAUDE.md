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
- **Phase 0 is done (2026-11-12): the target is EA's ProStreet demo release executable** (`nfs.exe`,
  `ProStreet08DemoRelease.exe`, 7,943,432 bytes, SHA-256 `a43bf6be…`), built by EA without SecuROM. Authenticode-signed
  by Electronic Arts and verified unchanged (`recomp/authenticode.py`); code fingerprint pinned as the `ps_demo` profile
  (`recomp/exe_fingerprint.py`). Players get it from EA's ProStreet demo. The retail discs' `nfs.exe` (1.0 and 1.1)
  are SecuROM-protected and can't be used. Imports: 332 in 13 DLLs, 311 handled, 21 missing (exceptions, `std::string`,
  `GetWindowLongA`, an admin check; `docs/PROSTREET_PHASE1.md` §4).
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
- Setup DMG (`tools/ps_setup/`, `docs/ps-setup.md`): `tools/ps_setup/build_dmg.sh [--worktree]` makes an ~18 MB Setup
  app that checks the player's exe and, for EA's demo install, builds the game on their Mac like MW's Setup
  (recompile, FFmpeg, host libraries, runtime, signed `NFS ProStreet Native.app` in Applications, Play). It carries
  the source (git archive), capstone and FFmpeg's tarball, and runs on the Command Line Tools' Python: no downloads.
  MW's Setup (`tools/installer/`) is untouched.
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

### Phase 0: input ✅ (2026-11-12: EA's demo release executable, see Current state)
An `nfs.exe` without SecuROM, from a release the user owns (plus `server.dll`, and `msvcr80.dll`/`msvcp80.dll` if
the CRT is translated), in the game folder outside the repo. Check it with
`python3 -I recomp/pe_report.py <nfs.exe>` (must exit 0, "verdict: plain") and recount imports with
`python3 -I recomp/import_coverage.py <nfs.exe>`. **Exit:** exe parses, entry point in `.text`, `.text` entropy in the normal x86 range, version and hash
recorded here, code fingerprint pinned in `exe_fingerprint.py` behind a game profile.

### Phase 1: analysis ✅ (2026-11-08)
PE inspection, import coverage, generic vs MW classification, this file. See `docs/PROSTREET_PHASE1.md`. Redo §1–2 on
the Phase 0 exe.

### Phase 2: function boundaries ✅ (2026-11-12)
Status: manifest `recomp/functions_ps.tsv` (35,288 starts of the demo exe); census, untranslatable list and entry
points in `docs/ps-census.md`. 51,078 traps in 3,257 functions, nearly all SSE scalar/packed float and
`fcomip`/`fucomip`; 12 functions trap on something else. WinMain `004AF9A0`; window, D3D9 and the message pump on a
thread of their own (`004AFBC0`); game init `006BE380`, main loop in `006BF2D0`, frame function `006BE730`. Audio is
`EAXSound` over RenderWare Audio (DAC thread `00877CA0`, one DirectSound buffer); movies are VP6. MW's inline
translator patches apply only to MW's fingerprinted exe (`Recompiler.mw_patches`).
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

### Phase 3: recompile ✅ (2026-11-12)
Status: game profiles in `recomp/profiles.py` (`mw13` still builds with `build_all.py`; `ps_demo` with
`recomp/build_game.py`). **The whole demo exe translates with no run-time traps**: 35,245 of 35,247 functions (the 2
stubs are data tables in `.text` that a data pointer made look like starts), compiled to `recomp/out/ps_demo/nfs.a`
(arm64, 0 errors, ~55 s). New in the translator: SSE single precision, SSE2 integer and conversions,
`fcomi`/`fucomi`, `bswap`, `bsr`/`bsf`, `jcxz`, `rep ret`, `cmpxchg8b`, segment-register reads (669 synthetic
difftests). Manifest: the call closure walks every function and the linear sweep's calls; int3 padding is never a
start. **Real difftests** (`difftest.py --game ps_demo`, Unicorn via `synth_emu.py`, whole image mapped): 2,000
sampled leaves, 1,575 pass, 0 fail, 425 without a verdict (the original faulted on every random state); with
`--calls`, 991 non-leaf roots, 199 pass, 0 fail. Not done here, deferred: moving MW's build_all.py passes and
translator patches into `mw13` and building MW with build_game.py, which needs speed.exe to check.
- Make the recompiler game-parameterized: a game profile with the exe path, fingerprint, function manifest, hooks
  file and inline patch tables. Move MW's inline patches out of `recomp.py`/`build_all.py` into the MW profile.
  The ProStreet profile starts empty.
- Translate all functions; compile with clang `-O2` (0 errors). Fill instruction gaps found by the census (SSE/SSE2
  as needed).
- Difftests (`difftest.py`, `--synth`) on sampled leaves. `--synth` already runs here without MW's exe
  (`recomp/difftest_synth_test.py`: 374/375 pass, 1 documented expected-fail); add a synthetic case for every
  instruction the census says Phase 3 adds (e.g. SSE2).
- **Exit:** `out/nfs.a` builds; ≥99 % functions translated; stubs listed; difftests pass on sampled leaves.

### Phase 4: link ✅ (2026-11-12)
Status: `runtime/build_ps.sh` links `recomp/out/ps_demo/boot_ps` (arm64) with no undefined symbols, from `nfs.a`, the
core runtime, the app-shell files without MW addresses, `runtime/imports_ps.c` (`recomp/gen_imports.py`) and 226
generated "feature off" stubs (`runtime/ps_stubs.m`, `runtime/gen_ps_stubs.py`). `-DNFS_GAME_PS=1` compiles the MW
hooks and the MW guest-address reads/writes out of the core files; the game-folder check takes `nfs.exe` and the
`ps_demo` fingerprint (`runtime/app_fingerprint_test.py`); CPUID reports SSE/SSE2. All 332 imports reach
`host_import`: 311 handled, 21 stop by name. **CRT decision: the native MSVCR80/MSVCP80 shim** (`runtime/msvcr.c`),
not a translated second module. The demo imports no WSOCK32. Details: `docs/ps-link.md`. MW's `build.sh` unchanged.
- Regenerate `runtime/imports.c` from `nfs.exe`. Alias WSOCK32 to the WS2 handlers.
- Build list for ProStreet: core runtime + host layers only, no MW feature files. Strip MW hooks/addresses out of the
  core files (`boot.c`, `d3d9.m`, `render.m`, `user32.m`, `dsound.c`, `threads.c`, `pacing.c`) behind the profile.
- CRT strategy: native MSVCR80/MSVCP80 shim (recommended start) vs translating `msvcr80.dll` as a second module
  (`server_module.py` pattern). Decide and record here.
- **Exit:** the binary links with no undefined symbols. Every import resolves to a handler or to the explicit
  "not implemented" die.

### Phase 5: boot ✅ (2026-11-12)
Status: the demo exe, on an installed game's data (the exe from `NFS_PS_EXE`), boots through EA's start screens and
the Attract movie (VP6, played by the game's own translated player) to the title screen and, after a click or
Return, to the demo's front end (the Nitrocide / Nevada Highway Speed Challenge event screen), rendered through
Metal, with no unknown imports. `BOOT_SKIPINTRO=1` goes straight to the title. What it took, beyond Phase 4:
- threading: the guest's main thread on a pthread, the host main thread serving AppKit (`app_main_loop`); USER32 and
  DirectInput's pump run there for the calling guest thread (`threads_on_main`); host-only main-thread work lets go
  of the GIL (`threads_main_sync`);
- `RaiseException` (MSVC thread naming), `GetWindowLongA`, d3dx9_34's `ID3DXEffect` (`DeleteParameterBlock`,
  `SetRawValue`), the demo's registry key (`Install Dir` must end in `\`: the game appends file names to it), a
  read-only game folder (writes go to `USERDATA/game-overlay`), `NFSPS-port` folders;
- shader length by parsing (a `0x0000FFFF` dword inside a shader cut it short); stub return values (NULL for owned
  strings, -1 where -1 means none);
- function starts Ghidra missed behind MSVC switch tables (manifest: 35,267 starts);
- the boot flow (`runtime/ps_boot.c`, hook `007B81A0`): DEMO_MUSIC_LEGAL never asks for the next screen, so its
  step goes straight to the Attract movie (why it doesn't end is open).
Open for Phase 6: frame pacing (several hundred fps), keys the game turns into screenshots, DEMO_MUSIC_LEGAL.
- CRT start-up and static constructors run, the main loop starts, the window opens. Implement imports as they're hit.
  Registry under a ProStreet key in `USERDATA`. Case-insensitive game paths. Threads.
- D3D9 device creation through Metal, first Present (clear colour), then the intro movies (check ProStreet's movie
  format against the FFmpeg path).
- **Exit:** boots to the first front-end screen without dying; logs clean of unknown imports.

### Phase 6: menus (in progress)
Status (2026-11-12): frame pacing for ProStreet (`runtime/ps_pacing.c`): Present waits for the next frame slot,
60 fps by default (`NFS_PS_FPS`, 0 = uncapped; the game asks for immediate presents and steps its sim by measured
time); measured 300 frames per 5.0 s. The stub list is committed (`runtime/ps_stubs.txt`, regenerate with
`runtime/gen_ps_stubs.py`). Return on the demo's event screen starts the race load: `_setjmp3`/`longjmp` are in the
CRT shim (`runtime/msvcr.c`), and the translator's Lua protected-frame patch is per game (`Recompiler.lua_protected_frame`:
MW `006069C0`/`006069E8`, ProStreet `006C3E60`/`006C3EAB`, same guest code), resumed by `boot.c` `host_lua_resume`.
**The race load completes** (2026-11-12) and the in-race START RACE menu shows over the track at 60 fps, with two fixes:
- **Data must be the demo's own** (the demo exe hard-codes offsets into its NIS sound bank `SOUND/NIs/ps_nis_pc_en.*`,
  which differs from retail's). On retail data the race-intro NIS (`HubCrowd08HD`) re-requested its audio stream every
  frame and the load stayed on LOADING (game flow `WaitForSimulation`, sim load stage 10, NIS phase 2). The demo's
  installer data works; `sound\NISRevData\*.bin` is missing in both and is optional.
- The render thread's command replay loop (004AFBC0 -> `006B5000`) waits for the main thread without making an import,
  so it held the GIL forever: hook `006B5000` (`runtime/ps_render_sync.c`) offers the GIL when its batch is empty.
- **3D renders** (pre-race hub: cars, crowd, banners, sky): `ID3DXEffect::SetRawValue` is a memcpy of shader
  constants, and ProStreet passes its matrices through it already laid out for the registers (WorldViewProj,
  cmWorldMat, bone palettes). They were taken as matrices in the parameter's layout and transposed on upload into the
  shaders' column-class constants, so every draw exploded towards the screen centre. A matrix written raw is now
  uploaded as its register image (`raw_regs` in `runtime/d3dx_effect.c`) until a typed setter replaces it.
Diagnostics: `BOOT_FILES=1` logs every file open (game path -> host path or the error); `BOOT_D3DLOG=1` logs vertex
declarations, instancing, raw effect writes and matrix upload classes; the draw dump (`BOOT_DIAG` +
`BOOT_DIAG_DRAWS=<frame>`) lists each draw's first fetched vertex positions; `BOOT_KEYS=frame:KEY:N` holds a key N
frames.
- **The race runs** (2026-11-12): Start Race -> driver aids (Racer) -> Race Match Up -> Nevada Highway Speed Challenge
  with AI opponents, HUD, checkpoints; holding the throttle drives the car (it left the road and was TOTALED).
- **Resolution**: a fresh profile asks for 640x480. Hook `006E40A0` SelectMode (`runtime/ps_video.c`) replaces that
  default with the largest mode in the game's own list closest to the display's shape (1920x1200 on a 16:10 MacBook),
  in the call and in the video settings (+0x6C/+0x70); `NFS_PS_RES=WxH` forces one; a choice made in the game's
  options is kept. The game's list holds only standard modes (1920x1200 .. 640x480).
- **Playtest app**: `tools/ps_setup/build_playtest.sh` -> `dist/NFS ProStreet Playtest.app` and
  `dist/NFS-ProStreet-Playtest.dmg` (gitignored; it contains translated game code: this Mac only, never shared). It
  asks for the game folder once: EA's demo install, whose `nfsdemo.exe` is now accepted beside `nfs.exe`.
- **Memory**: the game reserves ~460 MB of its process heap at start-up and passes 500 MB in a race; MW's 512 MB heap
  ran out on the results screen after a won race ("guest process heap full"). The demo exe isn't
  large-address-aware (2 GB on Windows). ProStreet's process heap is now 0x02200000-0x48000000 (1,118 MB), the bump
  region (galloc, VirtualAlloc) 0x48000000-0x50000000, with a bounds check in VirtualAlloc too.
Open: roadside bushes (`IDI_GRASSCARD_FX`) and part of the crowd render overexposed/tinted: the grass vertex shader
reads `c12` (sun colour), which isn't in its CTAB, so it keeps a stale value (255 from another effect's upload);
DEMO_MUSIC_LEGAL never ends; menus and options; the race itself (Phase 7). Scripted runs (`BOOT_KEYS`) ignore the
physical keyboard and mouse on purpose.
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
Setup polish (an app icon, notarization, a build cache keyed like MW's), F10 settings menu, controller prompts, widescreen/FOV. Online play (EA servers are gone,
PunkBuster), X360 features and the Windows host (`runtime/win`) are out of scope.
