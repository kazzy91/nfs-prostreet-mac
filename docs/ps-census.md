# ProStreet Phase 2: function manifest, census, entry points

Input: EA's ProStreet demo-release `nfs.exe` (`ps_demo` profile in `recomp/exe_fingerprint.py`, SHA-256 `a43bf6be…`,
linked 2007-10-30). Everything here is address/name metadata and counts; no code bytes.

## Manifest

`recomp/functions_ps.tsv`: **35,288 function starts**. Ghidra 12.2 found 29,378; data-referenced starts added 5,864,
and their call closure added 46 more. Ghidra names: 24,330 `FUN_`, 4,764 `Unwind@` (C++ exception unwind funclets),
92 `thunk_FUN_`, plus FID library names (`memset`, `_beginthreadex`, `___tmainCRTStartup`, …). Analysis took 186 s.

```sh
tools/.venv/bin/python -I recomp/ghidra_functions.py ~/Games/ProStreet/nfs.exe --names --data-refs --out <work>/functions_ps.tsv
```

## Census

`tools/.venv/bin/python -I recomp/census.py ~/Games/ProStreet/nfs.exe recomp/functions_ps.tsv --md <work>/census.md`

| | |
|---|---|
| Functions | 35,288 (35,286 translate, 2 stubs) |
| Instructions | 1,569,040, 216 distinct mnemonics |
| Code reached | 5,045,986 of 5,325,883 bytes (94.7 %); unreached: 239,309 padding, 40,588 other |
| x87 FPU | 148,792 (9.5 %) |
| MMX | 3,480 (0.2 %): the translator handles MMX already (MW's codecs) |
| SSE (float) | 46,679 (3.0 %) |
| SSE2 | 789 (0.1 %) |
| SSE3 and later | 0 |
| String ops | 1,182 (0.1 %) |
| Traps (instructions the translator can't do) | 51,078 in **3,257 functions (9.2 %)** |
| Imports | 332 functions in 13 DLLs |

MW's speed.exe has almost no SSE. ProStreet, built with VS2005, uses **SSE scalar float throughout** (`movss` alone
is 36,818 sites). That is the main new translator work in Phase 3. The translator check is "would `recomp.py`
translate it": a function with a trap still compiles, but it dies at run time if it reaches the trap.

### Untranslatable instructions, grouped by what Phase 3 must add

| Family | Sites | Instructions |
|---|---|---|
| SSE scalar float | 40,722 | movss 36,818, comiss 1,940, subss 1,024, ucomiss 365, cvttss2si 285, cvtsi2ss 259, mulss 18, addss 13 |
| SSE packed float | 5,961 | xorps 2,889, movaps 1,875, mulps 434, addps 320, shufps 173, movlhps 67, subps 65, andps 37, movlps 28, movups 21, orps 12, cmpltps 10, maxps 5, movntps 4, cmpneqps 4, rsqrtps 4, unpckhps 3, unpcklps 3, movhps 2, cmpleps 2, movhlps 1, sqrtps 1, cmpnltps 1 |
| x87 compare to EFLAGS (P6) | 3,485 | fcomip 3,154, fucomip 331 |
| SSE2 (integer xmm, conversions) | 789 | movdqa 279, paddsw 99, paddw 59, pmulhw 50, psubsw 46, pmullw 41, psraw 29, punpcklbw 28, movdqu 24, punpcklwd 17, pxor 16, … cvttsd2si 1, movapd 1 |
| SSE/MMX interop | 92 | movntq 37, cvtpi2ps 31, cvtps2pi 24 |
| Other | 29 | bswap 8, bsr 4, lock cmpxchg8b 4, call to an unknown target 5, segment-register reads 6 (`__report_gsfailure`, host-replaceable), repz ret 1, jcxz 1 |

Functions still trapping after each step: 3,257 now; **31** after SSE scalar/packed and fcomip/fucomip; **12** after
SSE2; the rest are the "other" sites (CRT start-up and failure reporting, two atomics, a byte-swap routine).

Stubs (undecodable starts): `007D9930` and `008D0DA0`, both inside padding/data gaps between import thunks.
The two largest unreached gaps are `008D0D98` (4,280 bytes) and `007D992E` (2,626 bytes), in the same thunk areas.

## Entry points

Found with `recomp/xrefs.py` (IAT slot references, thunks followed to their rel32 callers, `--calls`, `--string`).

| What | Where |
|---|---|
| Entry | `007DAB2F` → `___tmainCRTStartup` `007DA8D7` |
| WinMain | `004AF9A0`: called from the CRT start-up, then `exit` |
| Window/device thread | `004AFBC0`: WinMain passes it to `008B72B0` (`_beginthreadex` + `SetThreadIdealProcessor` + `ResumeThread`) |
| Window and D3D9 | `006F1450` → `006F1120`: `RegisterClassExA`, `CreateWindowExA`, `Direct3DCreate9` (thunk `007D98D4`, slot `00916520`). `CreateDevice` is a vtable call on the returned object |
| Message pump | `006E4280`: `PeekMessageA`/`GetMessageA`/`TranslateMessage`/`DispatchMessageA`, called three times from `004AFBC0` |
| Game main | `006BF2D0`, called by WinMain after the thread start. It reaches 800 functions within 4 levels, including the DirectInput set-up |
| DirectInput | `DirectInput8Create` thunk `007DA370`, called from `006F4D30` (via `006BF2D0` → … → `00689740`) and `0084E048` |
| DirectSound | `DSOUND #1` (DirectSoundCreate) thunk `008D0D92`, called from `0086CC90` (via `00877770` and `0087D9F0`) |
| Movies | VP6: `MOVIES\%s_english_ntsc.vp6` used in `0057E5F0`; player classes `MoviePlayerRW`, `rw::movie::AudioRenderer_Snd9`. MW's movies are VP6 too (FFmpeg path) |

**Difference from MW:** ProStreet runs the window, the D3D device and the message pump on a thread of its own
(`004AFBC0`), and the game on WinMain's thread (`006BF2D0`), synchronised with events (`SetEvent` /
`WaitForSingleObject`). Phase 5 has to run D3D/Metal and AppKit from that thread's work, which matters on macOS
because AppKit wants the main thread.

The game main also enumerates processes (`CreateToolhelp32Snapshot`, `Process32First/Next`). Its purpose isn't
known yet; check it in Phase 5.
