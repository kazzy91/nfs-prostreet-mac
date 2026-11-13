#!/bin/sh
# Builds the NFS ProStreet Native Setup app and its disk image from this checkout:
#   dist/NFS-ProStreet-Native-Setup-v<version>.dmg  and  .dmg.sha256
# No game files are involved. Like MW's Setup, it builds the game on the player's Mac from their own files. The app
# carries its Swift front end; the check backend (tools/ps_setup/check.py with recomp/pe_report.py, authenticode.py,
# exe_fingerprint.py and import_coverage.py, plus the runtime sources the import count reads); the build backend
# (tools/ps_setup/build.py); this project's source (git archive: tracked files only); capstone (from the developer
# venv, version and library hash recorded in capstone.lock); and the FFmpeg source tarball (third_party/dl, checked
# against its SHA-256). Both backends run on the Python of Apple's Command Line Tools, so nothing is downloaded,
# here or on the player's Mac. MW's Setup (tools/installer/) is untouched.
#
# Usage: tools/ps_setup/build_dmg.sh [--worktree] [version]        (default 0.2.0)
#   --worktree  the source payload includes uncommitted changes to tracked files (local testing; release from HEAD)
set -eu
SOURCE=HEAD
if [ "${1:-}" = "--worktree" ]; then SOURCE=worktree; shift; fi

MIN_MACOS=14.5
PRODUCT="NFS-ProStreet-Native-Setup"
NAME="NFS ProStreet Native Setup"
VERSION="${1:-0.2.0}"
VERSION="${VERSION#v}"
printf '%s\n' "$VERSION" | grep -Eq '^[0-9]+(\.[0-9]+){1,3}$' || { echo "build_dmg: version must look like 0.1.0" >&2; exit 1; }

cd "$(dirname "$0")/../.."
ROOT="$(pwd -P)"
OUT="$ROOT/build/ps_setup"
rm -rf "$OUT"; mkdir -p "$OUT/dmg"
APP="$OUT/dmg/$NAME.app"
RES="$APP/Contents/Resources"
mkdir -p "$APP/Contents/MacOS" "$RES/check/runtime"

# --- the app ---
swiftc -O -parse-as-library -target "arm64-apple-macos$MIN_MACOS" -o "$APP/Contents/MacOS/Setup" tools/ps_setup/SetupApp.swift

# --- the backend: check.py and the two recomp tools, flat; the runtime handler files the import count reads ---
cp tools/ps_setup/check.py recomp/pe_report.py recomp/import_coverage.py recomp/authenticode.py recomp/exe_fingerprint.py "$RES/check/"
/usr/bin/python3 -I - "$ROOT" "$RES/check/runtime" <<'PY'
import os, shutil, sys
root, dest = sys.argv[1:3]
sys.path.insert(0, os.path.join(root, "recomp"))
import import_coverage
host = import_coverage.Host(os.path.join(root, "runtime"))
files = sorted(set(host.files.values()) | {"runtime/boot.c"})
for f in files:
    shutil.copy(os.path.join(root, f), dest)
print("backend: runtime handler files:", len(files))
PY
sed "s/@MIN_MACOS@/$MIN_MACOS/g" tools/ps_setup/ReadMe.txt > "$RES/ReadMe.txt"
printf '%s\n' "$VERSION" > "$RES/version.txt"

# --- the build backend and what it builds from ---
cp tools/ps_setup/build.py "$RES/build.py"
# The source: tracked files only (never game files or build output: CLAUDE.md rule 1). --worktree: with uncommitted
# changes to tracked files (git stash create makes a commit of them without touching the checkout or the stash list).
TREE=HEAD
if [ "$SOURCE" = worktree ]; then TREE="$(git stash create)"; [ -n "$TREE" ] || TREE=HEAD; fi
[ -z "$(git status --porcelain --untracked-files=no)" ] || [ "$SOURCE" = worktree ] || \
    echo "Note: uncommitted changes are not included (the payload is HEAD; --worktree includes them)." >&2
git archive --format=tar "$TREE" | gzip -9 > "$RES/source.tar.gz"
printf '%s\n' "$(git rev-parse --short "$TREE")" > "$RES/source-commit.txt"
# capstone, the translator's disassembler (pure Python and its own library through ctypes: runs on the Command Line
# Tools' Python 3.9 too, and translates byte for byte like the developer build)
CAP="$(tools/.venv/bin/python -I -c 'import capstone, os; print(os.path.dirname(capstone.__file__))')"
CAPV="$(tools/.venv/bin/python -I -c 'import capstone; print(capstone.__version__)')"
case "$CAPV" in 5.*) ;; *) echo "build_dmg: capstone $CAPV in tools/.venv; Setup was tested with 5.0.x" >&2; exit 1 ;; esac
mkdir -p "$RES/capstone"
(cd "$CAP" && find . -name __pycache__ -prune -o -type f -print | while read -r f; do mkdir -p "$RES/capstone/$(dirname "$f")"; cp "$f" "$RES/capstone/$f"; done)
printf 'capstone %s\nlibcapstone.dylib sha256 %s\n' "$CAPV" "$(shasum -a 256 "$RES/capstone/lib/libcapstone.dylib" | cut -d' ' -f1)" > "$RES/capstone.lock"
# FFmpeg's source, as media/build_ffmpeg.sh pins it
FFMPEG_SHA=733984395e0dbbe5c046abda2dc49a5544e7e0e1e2366bba849222ae9e3a03b1
FF=third_party/dl/ffmpeg-7.1.1.tar.xz
[ -f "$FF" ] || { echo "build_dmg: $FF is missing (FFmpeg's release tarball, SHA-256 $FFMPEG_SHA)" >&2; exit 1; }
echo "$FFMPEG_SHA  $FF" | shasum -a 256 -c - >/dev/null || { echo "build_dmg: $FF has the wrong SHA-256" >&2; exit 1; }
cp "$FF" "$RES/ffmpeg-7.1.1.tar.xz"

cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleExecutable</key><string>Setup</string>
  <key>CFBundleIdentifier</key><string>io.github.nfsps-native.setup</string>
  <key>CFBundleName</key><string>NFSPS Setup</string>
  <key>CFBundleDisplayName</key><string>$NAME</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>$VERSION</string>
  <key>CFBundleVersion</key><string>$VERSION</string>
  <key>LSMinimumSystemVersion</key><string>$MIN_MACOS</string>
  <key>LSApplicationCategoryType</key><string>public.app-category.utilities</string>
  <key>NSHighResolutionCapable</key><true/>
</dict></plist>
PLIST

# --- ad hoc signature, then a smoke test of the built app's own check path (headless) ---
codesign --force --sign - "$RES/capstone/lib/libcapstone.dylib"
codesign --force --sign - "$APP"
codesign --verify --strict "$APP"
SMOKE="$OUT/smoke"; mkdir -p "$SMOKE"
printf 'MZ' > "$SMOKE/nfs.exe"
"$APP/Contents/MacOS/Setup" --check "$SMOKE" | grep -q "^not_pe" || { echo "build_dmg: smoke test failed (expected not_pe)" >&2; exit 1; }
"$APP/Contents/MacOS/Setup" --check "$SMOKE/none" | grep -q "^not_found" || { echo "build_dmg: smoke test failed (expected not_found)" >&2; exit 1; }
echo "smoke test: the built app's check path works"

# --- the disk image and its checksum ---
sed "s/@MIN_MACOS@/$MIN_MACOS/g" tools/ps_setup/ReadMe.txt > "$OUT/dmg/Read Me First.txt"
chmod 644 "$OUT/dmg/Read Me First.txt"; xattr -c "$OUT/dmg/Read Me First.txt" 2>/dev/null || true
mkdir -p "$ROOT/dist"
DMGNAME="$PRODUCT-v$VERSION.dmg"
DMG="$ROOT/dist/$DMGNAME"
rm -f "$DMG"
hdiutil create -quiet -volname "$NAME" -srcfolder "$OUT/dmg" -ov -format UDZO "$DMG"
echo "$DMG ($(du -h "$DMG" | cut -f1))"
(cd "$ROOT/dist" && shasum -a 256 "$DMGNAME" | tee "$DMGNAME.sha256")
