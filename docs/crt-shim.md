# MSVCR80 / MSVCP80 host shim (ProStreet)

ProStreet links the Visual C++ 2005 runtime dynamically (149 `MSVCR80` and 3 `MSVCP80` imports). MW linked its CRT
statically, so there it ran as translated guest code. This shim implements those imports natively, in
`runtime/msvcr.c`, behind `win32_msvcr()` in `host_import`'s routing. The alternative, translating the user's own
`msvcr80.dll` as a second guest module (the `server_module.py` pattern), stays available if exception handling proves
hard to do natively.

## Conventions

- **Calling convention.** CRT functions are `__cdecl`: the caller pops the arguments. A handler sets `eax` (and `edx`
  for 64-bit results) and pops only the return address (`CRET`). Functions returning `double` push the result on the
  x87 stack (`ST(0)`), rounded by `x87_round` like translated code.
- **`_CI*` intrinsics** take their arguments on the x87 stack, not the guest stack: one-argument ones replace `ST(0)`;
  two-argument ones (`_CIpow`, `_CIfmod`, `_CIatan2`) compute `f(ST(1), ST(0))`, pop one and leave the result in
  `ST(0)`. An invalid operation on non-NaN inputs gives the x87 "indefinite" NaN (`x87_nan`).
- **Heap.** `malloc`/`free`/`realloc`/`calloc` use the same guest process heap as `HeapAlloc` (`heap.c`), through
  `crt_heap_*`. Blocks are zeroed (a superset of the CRT's behaviour). `malloc(0)` returns a unique block and
  `realloc(p, 0)` frees and returns NULL, as in MSVC. `_aligned_malloc` keeps the raw pointer in the 4 bytes below the
  aligned block, and `_aligned_free` reads it back.
- **Locale.** Only the "C" locale: ASCII `ctype`, `strcoll` = `strcmp`, `_stricmp` compares lower-cased bytes.
- **Per-thread state** (`rand` seed, `strtok` position) is thread-local, as in the multithreaded CRT. `rand` is the
  documented MSVC LCG (`seed * 214013 + 2531011`, result `(seed >> 16) & 0x7FFF`), so game randomness matches.
- **Invalid parameters.** The VC8 default handler terminates the process, so `_invalid_parameter_noinfo`,
  `_invoke_watson`, `_amsg_exit`, `_purecall` and checked functions given bad arguments (`memmove_s`) end the run with
  a message naming the function.
- **printf family.** Our own formatter reads the guest `va_list` (a pointer into guest memory). Numbers are produced
  with the host's `snprintf` per conversion, then adjusted to MSVC's output: three-digit exponents (`1.0e+000`), `%p`
  as 8 upper-case hex digits, `1.#INF` / `1.#QNAN` / `-1.#IND` for non-finite values (rounding quirks of those strings
  with small precisions are not reproduced). Size prefixes `h`, `l`, `ll`, `L`, `w`, `I`, `I32`, `I64` are accepted.
  `%n` is disabled in VC8 and ends the run. `_snprintf` returns -1 and writes no terminator on truncation.
- **qsort** is our own quicksort (median of three, insertion sort below 8 elements), calling the guest comparator
  through `call_guest`. The order of *equal* elements may differ from MSVC's; revisit if a game routine depends on it.

## Status

| Group | State |
|---|---|
| Memory (`malloc`, `calloc`, `realloc`, `free`, `_aligned_*`) | done |
| Strings and memory (`str*`, `mem*`, `memmove_s`, `_stricmp`, `_strnicmp`, `strtok`, `strcoll`) | done |
| ctype (`tolower`, `toupper`, `isspace`, `isdigit`, `isprint`) | done |
| Conversion (`atoi`, `atof`, `strtol`, `strtoul`, `_ltoa`, `abs`) | done |
| Math (`ceil`, `floor`, `cos`, `sqrt`, `ldexp`, `_isnan`, the 16 `_CI*`, `_control87`, `_controlfp_s`) | done |
| `rand`, `srand`, `qsort`, `bsearch`, `clock`, `_time64`, `_ftime64`, `getenv` | done |
| printf/scanf (`sprintf`, `_snprintf`, `vsprintf`, `_vsnprintf`, `printf`, `sscanf`) | done; `fprintf` with stdio, `_vsnwprintf` (wide) next |
| Start-up and exit (`__getmainargs`, `_initterm(_e)`, `_onexit`, `__dllonexit`, `exit`, `_exit`, `_cexit`, `_lock`/`_unlock`, `__set_app_type`, `__p__fmode`/`__p__commode`, `_encode`/`_decode_pointer`, `_configthreadlocale`, `__setusermatherr`, `_XcptFilter`, `_crt_debugger_hook`) | done |
| Data imports `_adjust_fdiv`, `__initenv` | **loader work (Phase 4)**: the IAT slot must hold the address of a guest variable, not a function thunk |
| stdio and low-level I/O (`fopen`, `fclose`, `fwrite`, `fseek`, `fflush`, `fprintf`, `__iob_func`, `_open`/`_read`/`_write`/`_lseek`/`_close`/`_filelength`) | next: needs `boot.c`'s file layer exported |
| Files and directories (`_findfirst64i32`/`_findnext64i32`/`_findclose`, `_mkdir`, `_rmdir`, `_getcwd`, `_chmod`, `rename`, `remove`, `_fullpath`, `_getdrive`, `_getdiskfree`) | next, same |
| Broken-down time (`_localtime64`, `_gmtime64`, `_localtime32`, `_mktime64`, `_mkgmtime64`, `_difftime64`, `asctime`) | next |
| Threads (`_beginthreadex`, `_endthreadex`) | next: on `threads.c`'s CreateThread |
| Exceptions (`__CxxFrameHandler3`, `_CxxThrowException`, `_except_handler3`, `_except_handler4_common`, `_setjmp3`/`longjmp`, `__RTDynamicCast`, `std::exception`, `terminate`, `type_info` dtor), `raise` | later: needs real call sites |
| MSVCP80 `std::string` (3) | later: the VC8 object layout has to be confirmed against real call sites |

Coverage (`recomp/import_coverage.py` on the disc exe's import list): **MSVCR80 99 of 149, MSVCP80 0 of 3**; the
whole exe goes from 229 to 328 of 542 handled. MW's own list is unchanged (287 of 300).

Anything not handled still reaches `host_import`'s "not implemented yet" stop with its name.

Test: `runtime/msvcr_test.c`, driven by `runtime/msvcr_test.py` (no game files): 561 checks through a real guest stack,
including the `__cdecl` stack rule after every call, plus a self-check run that must fail. The driver probes
AddressSanitizer first; where it hangs at start-up (seen with Apple clang 17.0.0 on macOS 26.5.1) it runs with UBSan
only and adds a run under `libgmalloc` (guard pages around every host allocation).
