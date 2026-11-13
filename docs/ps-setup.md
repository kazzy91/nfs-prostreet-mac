# ProStreet Setup (`tools/ps_setup/`)

Like MW's release, ProStreet's is a **Setup app** in a disk image that builds the game on the player's Mac from their
own files, so nothing from the game is ever distributed. It checks the player's copy, then for the supported build
(EA's ProStreet demo release, as EA's demo installer leaves it: `nfsdemo.exe` and the demo's data) recompiles the code,
builds the host libraries and the runtime, signs `NFS ProStreet Native.app`, installs it in Applications and offers
Play. MW's Setup (`tools/installer/`, `tools/setup.py`, `tools/setup_kit/`) is untouched.

```bash
tools/ps_setup/build_dmg.sh [--worktree] [version]   # dist/NFS-ProStreet-Native-Setup-v0.2.0.dmg (+ .sha256), ~18 MB
```
`--worktree` puts uncommitted changes to tracked files into the source payload (local testing); a release is built
from HEAD.

| Piece | What it is |
|---|---|
| `SetupApp.swift` | SwiftUI window: choose (or drop) the game folder, `nfs.exe` or a disc image; shows the verdict and details. For the supported build: Build and Install (live stages, last log line), then Play / Show in Finder, or the error, its fix and Open Log. Offers Apple's Command Line Tools if missing. `Setup --check <path>` and `Setup --build <folder>` run headless |
| `check.py` | The check backend (stdlib only, macOS's own Python): `recomp/pe_report.py` + `recomp/import_coverage.py`, worded for players. Verdicts: supported, plain, unverified, protected (SecuROM and the like), packed (modified), not_pe, not_found. A folder is searched three levels deep for `nfs.exe` or `nfsdemo.exe`; a disc image is attached read-only, hidden, and detached after the check |
| `build.py` | The build backend (stdlib, the Command Line Tools' Python 3.9). Stages: developer tools and 4 GB free; the game folder (the exe's code fingerprint must be `ps_demo`, and the demo's own NIS sound bank must be there, since the demo exe hard-codes its offsets); unpack the bundled source into `~/Library/Application Support/NFSPS-Setup/work` (links and paths leaving the tree refused; FFmpeg's build kept across source updates); `recomp/build_game.py` (with the bundled capstone in the work copy's `recomp/`, so `python3 -I` finds it); `media/build_ffmpeg.sh` (once); `host/shaders` and `host/audio` libraries; `runtime/build_ps.sh`; the app bundle, signed ad hoc; install into `/Applications` (`~/Applications` when that isn't writable), replacing an earlier one, and the game folder written to the app's preferences (`NFSPS-port/app.txt`). JSON events on stdout; full log `~/Library/Logs/NFSPS-Setup/build.log` |
| `build_dmg.sh` | Compiles the app; bundles both backends, the 14 runtime handler files the import count reads, the source (`git archive`: tracked files only), capstone from the developer venv (5.0.x, version and library hash in `capstone.lock`) and FFmpeg's source tarball (checked against its SHA-256); signs ad hoc; smoke-tests the check path; makes the DMG and its checksum. No downloads |
| `ReadMe.txt` | The disk image's "Read Me First" |

The translator on the Command Line Tools' Python 3.9 produces the same C as the developer build's Python 3.13 (all 47
generated files byte for byte, 2026-11-13).

Test: `tests/setup/test_ps_check.py` (11 tests: each verdict on synthetic executables, folder search, a real disc
image made with `hdiutil makehybrid`, the compiled app's headless check, and a broken control without the DRM list).

## Playtest app (local only)

`tools/ps_setup/build_playtest.sh` wraps the built `recomp/out/ps_demo/boot_ps` in `dist/NFS ProStreet Playtest.app`
and `dist/NFS-ProStreet-Playtest.dmg` for testing on the Mac that built it. The binary contains code translated from
the player's `nfs.exe`, so these stay in the gitignored `dist/` and are never shared: the release remains the Setup
that builds on each player's Mac. The app asks once for the game folder (EA's demo install; `nfsdemo.exe` is
accepted), Option at launch asks again; saves and logs go to `~/Library/Application Support/NFSPS-port`.
