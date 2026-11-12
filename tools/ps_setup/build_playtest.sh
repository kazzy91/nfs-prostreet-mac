#!/bin/bash
# build_playtest.sh - a playtest app and disk image of the ProStreet port, FOR THIS MAC ONLY.
#
#   tools/ps_setup/build_playtest.sh          # dist/NFS ProStreet Playtest.app and dist/NFS-ProStreet-Playtest.dmg
#
# The app is recomp/out/ps_demo/boot_ps (build it first: recomp/build_game.py, then runtime/build_ps.sh) in a bundle.
# That binary contains code translated from the player's nfs.exe, so the app and the disk image are derived from game
# files: they stay in the gitignored dist/ and are never committed, uploaded or shared (CLAUDE.md rule 1). The real
# release is the Setup that builds the game on each player's Mac (docs/ps-setup.md).
#
# On first launch the app asks for the game folder: EA's ProStreet demo install (its nfsdemo.exe is the supported
# exe and its data match it). Hold Option while launching to choose again. Saves and logs go to
# ~/Library/Application Support/NFSPS-port.
set -euo pipefail
cd "$(dirname "$0")/../.."
BIN=recomp/out/ps_demo/boot_ps
[ -x "$BIN" ] || { echo "build_playtest: $BIN is missing (recomp/build_game.py, then runtime/build_ps.sh)" >&2; exit 1; }
APP="dist/NFS ProStreet Playtest.app"
DMG=dist/NFS-ProStreet-Playtest.dmg
rm -rf "$APP" "$DMG"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BIN" "$APP/Contents/MacOS/nfsps"
cat > "$APP/Contents/Info.plist" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key><string>local.nfsps.playtest</string>
    <key>CFBundleName</key><string>NFS ProStreet Playtest</string>
    <key>CFBundleDisplayName</key><string>NFS ProStreet Playtest</string>
    <key>CFBundleExecutable</key><string>nfsps</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleShortVersionString</key><string>0.1</string>
    <key>CFBundleVersion</key><string>1</string>
    <key>LSMinimumSystemVersion</key><string>13.0</string>
    <key>LSApplicationCategoryType</key><string>public.app-category.racing-games</string>
    <key>NSHighResolutionCapable</key><true/>
    <key>GCSupportsControllerUserInteraction</key><true/>
</dict>
</plist>
EOF
codesign --force --sign - "$APP" >/dev/null
codesign --verify --strict "$APP"
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
cp -R "$APP" "$STAGE/"
ln -s /Applications "$STAGE/Applications"
cat > "$STAGE/Read Me.txt" <<'EOF'
NFS ProStreet Playtest (built on this Mac, for this Mac only: it contains code translated from your nfs.exe, so don't
share it). Drag the app to Applications, open it, and choose your ProStreet demo folder when it asks (hold Option at
launch to choose again). Saves and logs: ~/Library/Application Support/NFSPS-port.
EOF
hdiutil create -quiet -volname "NFS ProStreet Playtest" -srcfolder "$STAGE" -format UDZO -ov "$DMG"
echo "build_playtest: $APP"
echo "build_playtest: $DMG ($(du -h "$DMG" | cut -f1)), personal use only"
