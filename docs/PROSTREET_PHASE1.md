# ProStreet port, Phase 1: analysis (2026-11-08)

Read-only analysis of the EU retail 1.0 disc. No code was changed, no game file was copied into this repository, the
disc image was mounted read-only outside the repo, and no Windows program was run.

The retail disc root holds `nfs.exe`, `server.dll`, `Group*.cab` (game data), the MSVC 7.1/8.0 runtime DLLs
(`msvcr80.dll`, `msvcp80.dll`), `PB/` (PunkBuster), `DirectX/JUN2007_XACT_x86.cab`, `EASetup.exe` and `AutoRun.exe`.
The official patches are RTPatch self-applying patches (7.00 for the EN/EU/DE-FR-IT DLC patches, 6.50 for the Taiwan
1.1 patch), and each one replaces `nfs.exe`. They weren't applied here. MW's official update shipped a copy-protected
exe, so assume ProStreet's patched exe is protected too until checked.

## 1. The disc `nfs.exe`

| | |
|---|---|
| Size / SHA-1 | 12,739,848 bytes / `37e35df337bbe2ca16a10eef48bacc552b0d4e88` |
| Build | EU retail 1.0, internal name `ProStreet08EuropeRelease.exe`, linked 2007-10-27 05:36:38 UTC |
| Toolchain | MSVC 8.0 linker (VS2005), dynamic CRT `Microsoft.VC80.CRT` 8.0.50727.762 (SP1) |
| PE | i386, GUI, image base `0x00400000`, SizeOfImage `0x1633000`, **relocations stripped** (fixed addresses, like MW), DllCharacteristics 0 (no ASLR/DEP), no version resource |
| Entry point | RVA `0x124EA80` → VA `0x0164EA80`, in section **`est`** (the SecuROM stub), not in `.text` |
| Other | TLS directory, Authenticode signature (5,384 bytes), one export `PB_SendUdpPacket` (PunkBuster) |

| Section | VA | VSize | Raw size | Entropy | |
|---|---|---|---|---|---|
| `.text` | 00401000 | 53753B | 538000 | **7.66** | game code, encrypted |
| `.rdata` | 00939000 | 0D9F80 | 0DA000 | 5.57 | |
| `.data` | 00A13000 | 5BF79C | 05E000 | 3.77 | |
| `.tls` | 00FD3000 | 9 | 1000 | 0 | |
| `.rsrc` | 00FD4000 | 0D8424 | 0D9000 | 3.74 | |
| `ars` | 010AD000 | 59D470 | 2FA000 | **8.00** | SecuROM |
| `est` | 0164B000 | 6E90 | 7000 | 6.64 | SecuROM stub (entry point) |
| `artem` | 01652000 | 2E25BA | 0DB000 | **8.00** | SecuROM |
| `celare` | 01935000 | 53B8 | 6000 | 5.63 | SecuROM |
| `.securom` | 0193B000 | 0F708B | 0F8000 | 6.18 | SecuROM, holds the import directory |

**Verdict: packed/encrypted, not translatable.** `.text` entropy is 7.66 (plain x86 is typically about 6.0–6.7), its
first bytes are noise (`f8 73 ad f3 eb c7 …`), and there are only 1,124 `push ebp; mov ebp, esp` prologues in 5.5 MB.
Static recompilation needs the plain code bytes at their final addresses. This project will not unpack, dump or strip
SecuROM. Phase 2 needs an `nfs.exe` without copy protection, from a release the user owns.

`server.dll` (LAN server, 386,312 bytes, linked 2005-10-20, MSVC 7.1, base `0x10000000`, SizeOfImage `0x6F000`, plain
code) has MW's `server.dll` image size and era plus a 5,384-byte signature. Its hash doesn't match MW's pinned one,
even with the signature stripped, so treat it as a different build until compared.

## 2. Imports vs the MW host layer

The import table below comes from the **protected** exe. SecuROM rebuilds it in `.securom`, so it is the game's
imports **plus the wrapper's own**. Re-run this on an exe without SecuROM before acting on it. "Handled" means a handler
in `runtime/` (boot.c, threads.c, heap.c, user32.m, d3d9.m, d3dx*.c, dsound.c, dinput.c, ws2_32.c) matches the name.
It does not mean the behaviour fits ProStreet's use of it.

The counts come from `recomp/import_coverage.py`, which reads the DLL routing from `host_import` and counts exact
names only. The first hand count (234 handled) wrongly credited prefix tests: `Global*` (`GlobalLock`, `GlobalUnlock`,
`GlobalMemoryStatus`) and `*KeyEx` (`RegCreateKeyExA`, `RegEnumKeyExA`), which in `runtime/` are a negative gate and a
branch inside the `RegOpenKeyExA` handler.

MW: 300 functions in 13 DLLs (287 handled; the 13 others are never called). ProStreet disc exe: **542 functions in
18 DLLs, 229 handled** (234 counting the 5 WSOCK32 imports covered by aliasing to WS2_32).

| DLL | Imports | Handled | Missing | Notes |
|---|---|---|---|---|
| KERNEL32 | 194 | 134 | 60 | wide-char file API, 64-bit file pointers, file mapping, resources, `lstr*`, `Local*`/`Global*` locks; many probably SecuROM's |
| USER32 | 80 | 40 | 40 | display/system metrics, cursors, `LoadStringA`, `GetWindowLongA`; dialogs, menus and window enumeration probably SecuROM's |
| ADVAPI32 | 41 | 6 | 35 | services, SIDs/tokens, event log, crypto: almost certainly SecuROM's; `RegCreateKeyExA`, `RegEnumKeyExA`, `RegEnumValueA`, `RegDeleteKeyA`/`ValueA`, `RegQueryInfoKeyA` probably the game's |
| **MSVCR80** | 149 | 0 | **149** | **new: dynamic CRT** (MW linked its CRT statically, so it ran as translated code) |
| MSVCP80 | 3 | 0 | 3 | `std::string` ctor/dtor |
| d3dx9_34 | 14 | 7 | 7 | MW used d3dx9_26 |
| WS2_32 | 39 | 34 | 5 | `#11` inet_addr, `#12` inet_ntoa, `#51` gethostbyaddr, `#55` getservbyname, `#56` getservbyport |
| WSOCK32 | 6 | 0 | 6 | ordinals 3/16/19/22/111/112 = closesocket/recv/send/shutdown/WSAGetLastError/WSASetLastError. The WS2 shim already handles the first five by the same ordinal, so alias them; `#112` WSASetLastError is new |
| VERSION | 3 | 0 | 3 | `GetFileVersionInfo*`, `VerQueryValueA` |
| SHELL32 | 2 | 0 | 2 | `ShellExecuteA`/`ExA` (stub) |
| RPCRT4 | 2 | 0 | 2 | `UuidToStringA`, `RpcStringFreeA` |
| ole32 | 1 | 0 | 1 | `CoCreateGuid` (no `CoCreateInstance`, so no XACT/COM audio despite the XACT cab on the disc) |
| d3d9, DINPUT8, DSOUND (`#1`), WINMM (3), SHFOLDER, NETAPI32 | 1 / 1 / 1 / 3 / 1 / 1 | all | 0 | same entry points as MW |

Gone compared with MW: GDI32 (MW 12), TAPI32 (MW 9).

The COM side matters more than the flat imports. MW's `d3d9.m` implements full vtables for IDirect3D9,
IDirect3DDevice9 (119 methods), textures, cube/volume textures, surfaces, VB/IB, declarations, shaders, state blocks
and queries. MW leaves `UpdateSurface`, `GetRenderTargetData` and `ColorFill` as no-ops (`GetRenderTargetData` has since been implemented, see `docs/win32-more.md`); ProStreet may call them
(`D3DXSaveSurfaceToFile*` implies render-target readback). The SM1–3 → MSL translator (`host/shaders`) is proven only
on MW's 108 shaders.

### Missing, full list

- **KERNEL32:** UnhandledExceptionFilter GetSystemDirectoryA RemoveDirectoryW CreateDirectoryW FindNextFileW
  FindFirstFileW MoveFileW DeleteFileW CreateFileW GetFileSizeEx SetFilePointerEx RaiseException
  SetThreadIdealProcessor GetVolumeInformationA MapViewOfFile OpenMutexA QueryDosDeviceA UnmapViewOfFile lstrlenA
  lstrcmpiA lstrcmpA GetComputerNameA FormatMessageA lstrlenW OpenProcess FlushInstructionCache GetTempPathA
  GetShortPathNameA WaitNamedPipeA SetNamedPipeHandleState SetFileAttributesA CopyFileA DeviceIoControl
  CreateFileMappingA GetFileAttributesA OpenEventA ReadConsoleInputA SetConsoleMode GetConsoleMode GetWindowsDirectoryA
  GetExitCodeProcess GetVersion GetEnvironmentVariableA LocalFree LocalAlloc LoadLibraryW LoadLibraryExA LoadLibraryExW
  GetUserDefaultLangID LockResource LoadResource FindResourceA RtlUnwind FlushConsoleInputBuffer GlobalLock LocalLock
  GlobalUnlock LocalUnlock CompareFileTime GlobalMemoryStatus
- **USER32:** SystemParametersInfoA EnumDisplaySettingsA GetWindowLongA LoadCursorFromFileA SetSystemCursor LoadImageA
  CopyImage GetProcessWindowStation GetUserObjectInformationW DialogBoxIndirectParamA SetDlgItemTextW SetDlgItemTextA
  SetWindowTextW EnableWindow FlashWindow SetWindowTextA UnregisterClassA LoadStringA CheckMenuItem EnableMenuItem
  FindWindowA CharLowerBuffA FindWindowExA GetMenu GetMenuState GetSubMenu GetSysColorBrush GetSysColor
  SendDlgItemMessageA GetDlgItem EndDialog CharLowerA GetSystemMetrics GetWindowTextA GetParent GetClassNameA GetCursor
  GetWindowThreadProcessId EnumWindows SendMessageA
- **ADVAPI32:** CheckTokenMembership FreeSid CryptReleaseContext CryptGenRandom CryptAcquireContextA
  AllocateAndInitializeSid OpenServiceA QueryServiceStatus OpenSCManagerA DeleteService ControlService StartServiceA
  CreateServiceA RegQueryValueA RegSetValueA EqualSid RegDeleteValueA GetSidSubAuthorityCount GetSidSubAuthority
  GetSidIdentifierAuthority GetTokenInformation OpenProcessToken OpenThreadToken DeregisterEventSource ReportEventA
  RegisterEventSourceA RevertToSelf CloseServiceHandle IsValidSid GetUserNameA RegQueryInfoKeyA RegEnumValueA
  RegDeleteKeyA RegCreateKeyExA RegEnumKeyExA
- **d3dx9_34:** D3DXMatrixMultiplyTranspose D3DXSaveSurfaceToFileA D3DXGetVertexShaderProfile D3DXGetPixelShaderProfile
  D3DXCreateCubeTextureFromFileInMemory D3DXCreateVolumeTextureFromFileInMemory D3DXSaveSurfaceToFileInMemory
- **MSVCR80 (149):** stdio (`fopen`/`fread`-family, `printf`/`sprintf`/`sscanf`, `_vsnprintf`, `__iob_func`), low-level
  I/O (`_open`/`_read`/`_write`/`_lseek`/`_close`/`_filelength`), `_findfirst64i32`, string/ctype, `malloc`/`calloc`/
  `realloc`/`free`/`_aligned_*`, the `_CI*` x87 math intrinsics (args/results on the x87 stack), time (`_time64`,
  `_localtime64`, `_mkgmtime64`…), `qsort`/`bsearch`/`rand`, `_beginthreadex`/`_endthreadex`, start-up
  (`__getmainargs`, `_initterm`/`_initterm_e`, `_onexit`, `__dllonexit`, `_encode_pointer`, `_amsg_exit`,
  `_configthreadlocale`, `_controlfp_s`), and **exception machinery** (`__CxxFrameHandler3`, `_CxxThrowException`,
  `_except_handler3`, `_except_handler4_common`, `_setjmp3`/`longjmp`, `__RTDynamicCast`, `std::exception`)
- **MSVCP80, WS2_32, WSOCK32, VERSION, SHELL32, RPCRT4, ole32:** as in the table

**The CRT decision (Phase 4).** Either (a) implement MSVCR80/MSVCP80 natively on the host (most of it maps to libc;
the `_CI*` intrinsics, SEH/C++ exception handlers and `setjmp`/`longjmp` must work on guest stack frames), or
(b) load and recompile `msvcr80.dll`/`msvcp80.dll` from the user's own disc as extra guest modules, the way
`recomp/server_module.py` + `runtime/server_loader.c` do for `server.dll`. (b) keeps exception semantics exact. (a) is
faster and needs no extra input file. Recommendation: (a) for the flat functions plus (b)-style translation only if
exception handling proves hard.

Runtime-loaded code to expect: PunkBuster (`PB/dll`, `LoadLibrary*`) is online-only, so stub it to "not available".

## 3. MW codebase: game-agnostic vs MW-specific

Method: read the headers and the files that own imports, and counted hard-coded MW guest addresses
(`0x004xxxxx`–`0x009xxxxx`, `f_00XXXXXX`, `FUN_…`) per file. "Generic with MW hooks" means the mechanism is reusable
but the file contains MW addresses or calls that must move into a game profile or be removed.

### recomp/

| Generic | Generic with MW hooks | MW-only |
|---|---|---|
| `runtime.h` (Cpu, guest memory, flags, x87), `difftest.py` (needs Unicorn, not in public checkout), `listing.py`, `hook_coverage.py`, `build_inputs.py` | `recomp.py`: the translator is generic, but has inline MW patches: Snd 5.1 positional reads/stores, licensed-song bound assert at `004F6D65`, Lua protected resume `006069C0`, car-texture hash and car-count (`0x54`/`0x4440`) immediates, int3 assert `0045CD20`, bank-rate checks; the default `EXE` path and `SPEED_EXE_FINGERPRINT`. `build_all.py`: generic driver, but `water_reflection_gates`, `split_shadow_operands`, `split_fx_operands`, `split_capture_operands` and `breaker_diagnostic_bodies` are MW. `exe_fingerprint.py` (constant), `server_module.py` (pinned to MW's `server.dll` hash) | data: `functions_v13.tsv`, `server_functions.tsv`, `hooks.txt`. Tests/tools: `addcars_test`, `car85_test`, `carsaves*`, `car_render_diag`, `lighting_data*`, `lighting_options_test`, `traffic_detail.py`, `steer_deadzone_test`, `int3_ret_test`. Windows/D3D12 host: `build_windows.py`, `windows_*`, `win_build.bat`, `WINDOWS.md` (out of scope) |

### host/ and media/

All generic: `host/audio` (DirectSound 8 → 6-channel CoreAudio mixer, AC-3/E-AC-3/TrueHD output), `host/shaders`
(D3D9 SM1–3 bytecode → MSL, tested only on MW's shaders), `media/` (FFmpeg wrapper). `host/shaders/shadow_near_msl.h`
is MW (X360 near shadows).

### runtime/: core (keep, de-MW)

| File | State |
|---|---|
| `boot.c` | Generic loader/dispatch/`host_import`, case-insensitive files, cpuid, int3/div traps (the registry has since moved to `registry.c`; MW's key names are still in it). MW parts: Lua resume `006069E8`, career save task `f_007F4F11`, registry key "Need for Speed Most Wanted", `BOOT_RACE` SkipFE globals, split-screen car pool, X360 music handles, private-car paths |
| `imports.c` | Generated from `speed.exe`: regenerate from `nfs.exe` |
| `threads.c`, `heap.c`, `interp.c` | Generic (threads.c has two MW thread diag hooks) |
| `user32.m`, `dinput.c` | Generic; user32.m reads MW's `GAMEFLOW_STATE` (`00925E90`) and sim time for timing/pause |
| `dsound.c` | Generic COM over host/audio; MW Snd hooks (`SetOutputMode` 5.1, pause-state reads) |
| `ws2_32.c` | Generic winsock shim (DirtySock-shaped); a few MW addresses |
| `d3d9.m`, `render.m`, `render_target.m`, `render_present.m`, `render_query.m`, `render_thread.m`, `render_upscale_route.m`, `render_metalfx_spatial.m`, `pipeline_cache.m`, `render_internal.h`, `d3d9_internal.h`, `host.h` | Generic D3D9 → Metal. MW parts: d3d9.m's video-option globals (`g_FSAALevel` `00901808`, resolution index, shadow detail) and `f_006C1990` hook; render.m's checks of game state for X360 post, soft smoke, SSAO, near shadows |
| `d3dx.c`, `d3dx_effect.c` | Generic D3DX (d3dx9_26 subset + fx_2_0 effects); extend for d3dx9_34 |
| `pacing.c`, `streaming.c` | Mechanism generic, MW addresses throughout (re-derive) |
| `diag.c`, `overlay.m`, `probe.m`, `gpupass.m`, `gpuclients.m`, `report*.m`, `session_report.py` | Diagnostics infrastructure; `diag.c` embeds 271 MW addresses (symbol hints) |
| `app.m`, `app_icon.m`, `build.sh`, `bundle.sh`, `bundle_roots.h`, `roots.h`, `settings.c/.h`, `settings_port.c`, `portmenu.m`, `guide.m`, `rumble.m`, `padfx.m`, `onscreen_keyboard.c`, `cliprec.mm`, `hdr_output.h`, `hdrclip.m`, `alpha_to_coverage.c` | App shell and port features: generic, rebrand (NFSMW names, paths, log dirs) |
| `pub_update*.m`, `pub_discord.*`, `pub_settings.c`, `report_github.*` | Public-release infrastructure: generic but MW release URLs/IDs. Later |
| `server_loader.c/.h` | Generic second-module loader (pinned to MW's server.dll) |
| `win/` | Windows host (D3D12): out of scope |

### runtime/: MW-only (drop from the ProStreet build)

- **X360 features:** `x360.m`, `x360_post.m`, `x360_textures.m`, `x360_shadow_fit.cpp`, `x360abk.c`, `x360audio.c`,
  `x360copspeech.c`, `x360nisaudio.c`, `attrib_x360.c`, `vinyls.m`, `bootflow.c`, `controltype.c`, `trees.c`, the
  payloads in `materials.m`, `movies.c` (MW `MoviePlayer` hooks; the FFmpeg path is reusable), all of `tools_snapshot/`
- **Gameplay/visual mods:** `car_catalog`, `car85`, `car_audio_*`, `car_grip*`, `carsave_public`, `private_cars_public`,
  `cash_cheat`, `maxperf_career`, `underglow*`, `traffic_*`, `contact_mass`, `chasecam`, `steerresp`, `mirror`,
  `lampglow`, `lampbatch`, `auxlights`, `realworld_materials`, `roadfilm`, `shadow_near`, `particles_physical`,
  `detail`, `envcube`, `widescreen`, `lighting`, `aa_setting`, `posaudio`, `audio_limiter`, `feedback`, `padprompts`,
  `padbind`, `controlpages`, `pedals`, `fe_console`, `gameplay_opts`, `extratrax_public`, `text_fit`, `post_cuts`
- **Split screen:** `splitworld`, `splitcapture`, `padguest`, `qrsplit`
- **Online free roam / LAN:** `roam_*`, `lanserver_selftest`, `natmap`, `natpmp`, `pcp`, `upnp` (the codecs are
  generic but used only by roam), `runtime/relay/`
- **Diagnostics tied to MW scenes:** `breaker_diag`, `diag_car`, `sign_diag`, `save_timing`, `*_metric.py`

### tools/

`tools/setup.py`, `tools/setup_kit/*`, `tools/installer/*`: the MW Setup app. Mostly MW (car import, X360, disc
layout, 1.3 update). Reusable pieces: `rtpatch.py` (RTPatch 7.00 decoder. ProStreet's patches are RTPatch 7.00/6.50,
but the module refuses records that patch rather than replace, and pins MW's file list), `huff.py`, `xdvdfs.py`,
`stage.py`/`install.py` patterns. `tools/gen_tables.py`: check.
