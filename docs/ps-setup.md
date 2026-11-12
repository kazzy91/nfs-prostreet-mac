# Early ProStreet Setup (`tools/ps_setup/`)

MW's release is a **Setup app** in a disk image: it builds the game on the player's Mac from their own files, so
nothing from the game is ever distributed. ProStreet can't be built yet (Phases 2-5 need an `nfs.exe` without
SecuROM), so this early Setup does the first step only: it checks the player's copy and says whether the port can use
it. MW's Setup (`tools/installer/`, `tools/setup.py`, `tools/setup_kit/`) is untouched.

```bash
tools/ps_setup/build_dmg.sh [version]      # dist/NFS-ProStreet-Native-Setup-early-v0.1.0.dmg (+ .sha256), ~0.5 MB, ~10 s
```

| Piece | What it is |
|---|---|
| `SetupApp.swift` | SwiftUI window: choose (or drop) `nfs.exe`, the game folder or a disc image; shows the verdict, details (size, SHA-256, link date, entry point, sections with entropy, imports, findings), how many imports already have a Mac implementation, and that building isn't available yet. Offers Apple's Command Line Tools if missing. `Setup --check <path>` runs the same check headless |
| `check.py` | The backend (stdlib only, macOS's own Python): `recomp/pe_report.py` + `recomp/import_coverage.py`, worded for players. Verdicts: plain, protected (SecuROM and the like), packed (modified), not_pe, not_found. A folder is searched three levels deep; a disc image is attached read-only, hidden, and detached after the check |
| `build_dmg.sh` | Compiles the app, bundles the backend and the 14 runtime handler files the import count reads, signs ad hoc, smoke-tests the built app's check path, makes the DMG and its checksum. No downloads |
| `ReadMe.txt` | The disk image's "Read Me First" |

Test: `tests/setup/test_ps_check.py` (8 tests: each verdict on synthetic executables, folder search, a real disc image
made with `hdiutil makehybrid`, the compiled app's headless check, and a broken control without the DRM list).

On this Mac (2026-11-12), run from the mounted DMG: the retail disc image gives "copy-protected (SecuROM)" with 456 of
542 imports already implemented.

When building becomes possible, this grows into the real Setup: the same check first, then `ghidra_functions.py`,
`census.py`, the recompiler and the runtime build, the way MW's Setup runs its stages.
