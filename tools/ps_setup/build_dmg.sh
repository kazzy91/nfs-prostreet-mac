#!/bin/sh
# Builds the early NFS ProStreet Native Setup app and its disk image from this checkout:
#   dist/NFS-ProStreet-Native-Setup-early-v<version>.dmg  and  .dmg.sha256
# No game files are involved. The app carries its Swift front end, the check backend (tools/ps_setup/check.py with
# recomp/pe_report.py, authenticode.py, exe_fingerprint.py and import_coverage.py) and the runtime sources the import count reads; it runs on macOS's
# own Python (Command Line Tools), so nothing is downloaded. MW's Setup (tools/installer/) is untouched.
#
# Usage: tools/ps_setup/build_dmg.sh [version]        (default 0.1.0)
set -eu

MIN_MACOS=14.5
PRODUCT="NFS-ProStreet-Native-Setup-early"
NAME="NFS ProStreet Native Setup"
VERSION="${1:-0.1.0}"
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
