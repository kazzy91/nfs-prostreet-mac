# Win32 additions for ProStreet (`runtime/win32_more.c`)

ProStreet imports Win32 functions MW never called. The ones that clearly belong to the game, rather than to the
SecuROM wrapper, are implemented in `runtime/win32_more.c`. `host_import` reaches it **after** the existing handlers
(KERNEL32/ADVAPI32/VERSION/RPCRT4/ole32 through the fallback chain, USER32 after `win32_user32`), so nothing here
changes MW's behaviour. Small additions to existing modules sit with their neighbours: `d3dx.c`
(`D3DXMatrixMultiplyTranspose`, `D3DXGet{Vertex,Pixel}ShaderProfile`) and `ws2_32.c` (`inet_addr`, `inet_ntoa`,
`gethostbyaddr`, `getservbyname`/`getservbyport`, `WSASetLastError`). WSOCK32, which shares WS2_32's ordinals, is now
routed to `win32_ws2`.

## Decisions

- **Wide-character file calls** (`CreateFileW`, `FindFirstFileW`/`FindNextFileW`, `DeleteFileW`, `MoveFileW`,
  `CreateDirectoryW`, `RemoveDirectoryW`) convert UTF-16 names to UTF-8 for the host, because APFS refuses raw Latin-1
  bytes, and decode found names back to UTF-16. They then use `boot.c`'s file layer (`host_file_*`), with the same
  paths and save protection as the narrow calls. The narrow (A) calls still pass their bytes through unchanged, as in
  MW; non-ASCII ANSI paths remain a known limitation there.
- **File mapping** copies: `MapViewOfFile` reads the bytes into guest memory (leaving the file position alone), and
  `UnmapViewOfFile` writes them back for `FILE_MAP_WRITE` views of `PAGE_READWRITE` mappings. Page-file-backed
  mappings are zeroed memory, and names are not shared. Mapping handles live at `0x5000`, and `CloseHandle` releases
  them (a hook in `boot.c`).
- **Resources** (`FindResourceA`, `LoadResource`, `LockResource`, `SizeofResource`, `LoadStringA`) walk the exe's own
  `.rsrc` at 0x400000: integer IDs, `"#123"` and case-insensitive names, the first language entry. `LoadStringA` reads
  RT_STRING blocks and narrows to Latin-1 (`?` beyond it).
- **System answers** match `boot.c`: Windows XP SP2 (5.1.2600), en-US (0x409), the `GlobalMemoryStatusEx` sizes
  clamped to 32 bits, an empty environment, `C:\WINDOWS`, a temp folder in the user-data directory, computer "MAC",
  user "Player".
- **Stateless USER32** only: screen metrics, display mode and work area come from the Mac display
  (`user32_display_pixels`), accessibility-key settings read as "off", and the classic system colours. `FindWindowA`
  finds no other instance. Calls that need `user32.m`'s window model (window text, styles, menus, dialogs, cursors,
  `EnumWindows`, `SendMessageA`) wait for real call sites.
- **GUIDs and randomness:** `CoCreateGuid` makes version-4 GUIDs, `UuidToStringA`/`RpcStringFreeA` format and free
  them on the process heap, and `CryptGenRandom` uses `arc4random_buf`. There's no version resource, so the VERSION
  calls fail with `ERROR_RESOURCE_TYPE_NOT_FOUND`.
- `lstrcmpA`/`lstrcmpiA` compare ordinally; Windows uses the locale's word sort, so strings with hyphens or
  apostrophes can order differently.

## Coverage

`recomp/import_coverage.py` on the disc exe's import list: **456 of 542** handled (229 before the CRT shim and these
additions). MW's own list is unchanged (287 of 300). The 86 left:

| Group | Imports | Why they wait |
|---|---|---|
| Probably SecuROM's own | KERNEL32 pipes, console, `DeviceIoControl`, `QueryDosDeviceA`, `GetVolumeInformationA`, `OpenProcess`, `FlushInstructionCache`, `GetExitCodeProcess`; ADVAPI32 services, SIDs/tokens, event log | expected to vanish with an exe without SecuROM |
| Exceptions | `RaiseException`, `RtlUnwind`, `UnhandledExceptionFilter`; MSVCR80 C++/SEH (13); MSVCP80 `std::string` (3) | need real call sites |
| Window state | 30 USER32 calls | need `user32.m`'s window model and real call sites |
| SHELL32 | `ShellExecuteA`, `ShellExecuteExA` | opening web pages; a stub that fails is enough |

## d3dx texture files (`runtime/d3dx_tex.c`)

The four d3dx9_34 texture-file functions, reached through the d3dx routing arm after `d3dx.c` and `d3dx_effect.c`.
They use textures and surfaces only through their D3D9 COM vtables (`CreateCubeTexture`, `LockRect`, `LockBox`,
`GetDesc`, ...), called with `call_guest` as the game's own code would. So they don't depend on `d3d9.m`'s internals,
and MW's hooks on those methods (the env-cube sizing in `CreateCubeTexture`) apply to them like any other call.
- `D3DXCreateCubeTextureFromFileInMemory` / `D3DXCreateVolumeTextureFromFileInMemory`: DDS files (no DX10 header) in
  DXT1-5, the common 32/24/16-bit RGB layouts, L8, A8L8, L16, A8, and numeric-fourCC float formats. The texture is
  created with the file's size, levels and format in `D3DPOOL_MANAGED`, then filled level by level, face by face or
  slice by slice, honouring the locked pitch. Files that don't parse, cubes missing faces, and short or unsupported
  files give `D3DXERR_INVALIDDATA`; the device's own errors are passed on. Formats are not converted.
- `D3DXSaveSurfaceToFileA` / `D3DXSaveSurfaceToFileInMemory`: BMP and DIB (24-bit, or 32-bit with alpha), TGA, PPM
  and DDS written natively; PNG and JPEG through ImageIO (the exe's `nfsProStreet%03d.jpg` suggests the game saves
  JPEG screenshots this way); HDR and PFM are refused. An optional rectangle crops. The in-memory version returns an
  `ID3DXBuffer` (QueryInterface, AddRef, Release, GetBufferPointer, GetBufferSize) on the resource heap. Screenshots
  also need the frame in the surface's memory: MW's `GetRenderTargetData` is still a no-op, which is Phase 6 work.

`runtime/d3dx_tex_test.c` (253 checks) runs against a fake `IDirect3DDevice9` whose locked pitches are wider than the
rows, and decodes the PNG back through ImageIO.

## Registry (`runtime/registry.c`)

The registry moved out of `boot.c` unchanged into `runtime/registry.c` (`win32_registry`, routed like the other
handler modules; `registry_load()` at start-up). The model is the same: a fixed set of known keys, values in memory,
and the game's key saved to `USERDATA/registry.txt`. The known keys are still MW's; the ProStreet key comes with the
game profile. Two changes:
- `reg_open` also takes one of our key handles as the root (a relative open), and an empty subkey under a handle is that
  key. MW never did either successfully, so no existing call changes.
- Added: `RegCreateKeyExA` (opens a known key, `REG_OPENED_EXISTING_KEY`), `RegEnumKeyExA` (the distinct next path
  components of the known keys), `RegEnumValueA`, `RegQueryInfoKeyA`, `RegDeleteValueA` (the value table stays dense),
  `RegDeleteKeyA` (removes the key's values; the key itself stays known), `RegQueryValueA`/`RegSetValueA` (the
  unnamed default value, saved as `sz =text`; an unset default reads as "").

`runtime/registry_test.c` pins MW's behaviour first (known keys, `ERROR_MORE_DATA`, `registry.txt` writes and reload,
`BOOT_REG`), then the additions: 115 checks.

## Tests

`runtime/win32_more_test.c` (driver `win32_more_test.py`, shared helpers `c_test_driver.py` and `test_hostfs.h`): 220
checks through a real guest stack, with the `__stdcall` rule after every call. It uses a synthetic exe image with a
resource tree, real files in a scratch directory, and a self-check run that must fail. `msvcr_test.c` shares the same
stub file layer.
