#!/bin/sh
# Links the ProStreet runtime (profile ps_demo) against the recompiled demo exe. MW's build is runtime/build.sh.
#   1. tools/.venv/bin/python -I recomp/build_game.py --game ps_demo --exe <nfs.exe>   -> recomp/out/ps_demo/nfs.a
#   2. host/shaders/build.sh lib; media/build_ffmpeg.sh; host/audio/build.sh lib       -> the host libraries
#   3. runtime/build_ps.sh                                                            -> recomp/out/ps_demo/boot_ps
# Only the core runtime (docs/PROSTREET_PHASE1.md §3 "core"): loader and host_import, Win32/CRT/registry, threads,
# heap, D3D9 -> Metal, D3DX, DirectSound -> CoreAudio, DirectInput, Winsock, diagnostics. No MW feature files.
# NFS_GAME_PS=1 compiles out the MW-specific hooks and guest addresses inside those core files.
# Output lands in recomp/out/ps_demo/ (gitignored, derived from the game).
set -e
cd "$(dirname "$0")"
O=../recomp/out/ps_demo
[ -f "$O/nfs.a" ] || { echo "build_ps: $O/nfs.a missing; run recomp/build_game.py --game ps_demo first" >&2; exit 1; }
SM=../host/shaders/build/libsmtranslate.a
[ -f "$SM" ] || { echo "build_ps: $SM missing; run host/shaders/build.sh lib first" >&2; exit 1; }
AU=../host/audio/build
FF=../third_party/ffmpeg/lib
[ -f "$AU/libhostaudio.a" ] && [ -f "$AU/libmedia.a" ] || { echo "build_ps: run host/audio/build.sh lib first" >&2; exit 1; }
[ -f "$FF/libavcodec.a" ] || { echo "build_ps: FFmpeg missing; run media/build_ffmpeg.sh first" >&2; exit 1; }
# MW's generated tables (runtime/gen/, tools/gen_tables.py, from MW's files) aren't part of this build: the two headers
# the core files include get their "no X360" versions (zeros, the X360 features off), made here from the generators'
# own stubs, so a fresh checkout (or Setup's work copy) builds without MW's files. A checkout that has runtime/gen/
# keeps using it (quoted includes look next to the including file first); its no-X360 copies are the same.
PY="${TOOLS_PY:-/usr/bin/python3}"
mkdir -p "$O/inc/gen"
"$PY" -I ../tools_snapshot/x360_shader_lits.py --stub --out "$O/inc/gen/x360_shader_lits.inc" >/dev/null
(cd ../tools_snapshot && "$PY" -I -c "import sys; sys.path.insert(0, '.'); import pubtables_gen as g
open(sys.argv[1], 'w').write(g.ENGINE_STUB)" "$OLDPWD/$O/inc/gen/x360_engine.inc")
CORE="boot.c app.m heap.c d3dx.c d3dx_effect.c d3dx_tex.c readback.c threads.c user32.m d3d9.m render.m
      render_target.m render_query.m render_present.m render_thread.m render_post.m pipeline_cache.m dsound.c dinput.c
      ws2_32.c msvcr.c win32_more.c registry.c interp.c diag.c imports_ps.c
      ps_boot.c ps_pacing.c ps_render_sync.c ps_video.c"
# app shell and render infrastructure without MW addresses (settings store, second-module loader, upscaling, GPU
# timing, controller rumble/haptics, overlay, probe)
SHELL_FILES="settings.c server_loader.c render_upscale_route.m render_metalfx_spatial.m alpha_to_coverage.c gpupass.m
      gpuclients.m rumble.m padfx.m overlay.m probe.m"
# "feature off" definitions for the MW feature code the files above still call (runtime/gen_ps_stubs.py)
STUBS="ps_stubs.m"
# shellcheck disable=SC2086
clang -O1 -g -w -DNFS_GAME_PS=1 -I "$O" -I "$O/inc" -I ../recomp -fobjc-arc $CORE $SHELL_FILES $STUBS "$O/nfs.a" \
    "$AU/libhostaudio.a" "$AU/libmedia.a" "$SM" \
    "$FF/libavformat.a" "$FF/libavcodec.a" "$FF/libswscale.a" "$FF/libswresample.a" "$FF/libavutil.a" \
    -lc++ -lz -framework AudioToolbox -framework CoreAudio -framework CoreFoundation -framework Cocoa \
    -framework QuartzCore -framework Metal -weak_framework MetalFX -framework ImageIO -framework CoreGraphics \
    -framework CoreText -framework GameController -framework IOKit -framework Security -framework SystemConfiguration \
    -framework AVFoundation -framework VideoToolbox -framework CoreVideo -framework CoreMedia -o "$O/boot_ps"
echo "build_ps: $O/boot_ps"
