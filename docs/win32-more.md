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

`recomp/import_coverage.py` on the disc exe's import list: **444 of 542** handled (229 before the CRT shim and these
additions). MW's own list is unchanged (287 of 300). The 98 left:

| Group | Imports | Why they wait |
|---|---|---|
| Probably SecuROM's own | KERNEL32 pipes, console, `DeviceIoControl`, `QueryDosDeviceA`, `GetVolumeInformationA`, `OpenProcess`, `FlushInstructionCache`, `GetExitCodeProcess`; ADVAPI32 services, SIDs/tokens, event log | expected to vanish with an exe without SecuROM |
| Exceptions | `RaiseException`, `RtlUnwind`, `UnhandledExceptionFilter`; MSVCR80 C++/SEH (13); MSVCP80 `std::string` (3) | need real call sites |
| Window state | 30 USER32 calls | need `user32.m`'s window model and real call sites |
| Registry | `RegCreateKeyExA`, `RegEnumKeyExA`, `RegEnumValueA`, `RegDeleteKeyA`, `RegDeleteValueA`, `RegQueryInfoKeyA`, `RegQueryValueA`, `RegSetValueA` | next: belong with `boot.c`'s registry |
| d3dx textures | `D3DXCreateCubeTextureFromFileInMemory`, `D3DXCreateVolumeTextureFromFileInMemory`, `D3DXSaveSurfaceToFileA`/`InMemory` | need DDS parsing and `d3d9.m`'s texture objects |
| SHELL32 | `ShellExecuteA`, `ShellExecuteExA` | opening web pages; a stub that fails is enough |

## Tests

`runtime/win32_more_test.c` (driver `win32_more_test.py`, shared helpers `c_test_driver.py` and `test_hostfs.h`): 220
checks through a real guest stack, with the `__stdcall` rule after every call. It uses a synthetic exe image with a
resource tree, real files in a scratch directory, and a self-check run that must fail. `msvcr_test.c` shares the same
stub file layer.
