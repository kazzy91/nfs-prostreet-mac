// win32_more.c - Win32 imports ProStreet needs beyond the MW set: KERNEL32 (wide-character and 64-bit file calls, file
// mapping, resources, strings, local/global memory, system information), stateless USER32 queries, and the small
// ADVAPI32 / VERSION / RPCRT4 / ole32 surface. host_import reaches it after the existing handlers (boot.c's routing),
// so nothing here overrides MW behaviour. Every handler is __stdcall (RET pops the arguments).
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "host.h"

// boot.c's file layer (see msvcr.c) and heap.c's process heap.
uint32_t host_file_open(const char *win, uint32_t access, uint32_t share, uint32_t disp);
int64_t host_file_read(uint32_t h, uint32_t buf, uint32_t n);
int64_t host_file_write(uint32_t h, uint32_t buf, uint32_t n);
int64_t host_file_seek(uint32_t h, int64_t distance, int method);
int64_t host_file_size(uint32_t h);
int host_file_close(uint32_t h);
int host_file_remove(const char *win, int dir);
int host_file_rename(const char *from, const char *to);
int host_mkdir(const char *win);
uint32_t host_file_attr(const char *win);
uint32_t host_find_first(const char *win, uint32_t data);
int host_find_next(uint32_t h, uint32_t data);
uint32_t crt_heap_alloc(uint32_t n);
void crt_heap_free(uint32_t a);
void user32_display_pixels(int *w, int *h);

#define IMAGE_BASE 0x400000u
static const char *gs_(uint32_t a) { return (const char *)G + a; }

// A guest UTF-16 name as a host path in UTF-8 (APFS names are UTF-8; a raw Latin-1 byte is refused). Unpaired
// surrogates become '?'. The narrow (A) calls pass their bytes through unchanged, as MW always did.
static void narrow(uint32_t w, char *out, size_t n) {
    size_t o = 0;
    for (uint32_t k = 0; w && M16(w + 2 * k); ++k) {
        uint32_t u = M16(w + 2 * k);
        if (u >= 0xD800 && u < 0xDC00 && M16(w + 2 * k + 2) >= 0xDC00 && M16(w + 2 * k + 2) < 0xE000)
            u = 0x10000 + ((u - 0xD800) << 10) + (M16(w + 2 * ++k) - 0xDC00u);
        else if (u >= 0xD800 && u < 0xE000) u = '?';
        uint8_t b[4];
        size_t len = u < 0x80 ? 1 : u < 0x800 ? 2 : u < 0x10000 ? 3 : 4;
        if (len == 1) b[0] = (uint8_t)u;
        else if (len == 2) { b[0] = (uint8_t)(0xC0 | u >> 6); b[1] = (uint8_t)(0x80 | (u & 0x3F)); }
        else if (len == 3) { b[0] = (uint8_t)(0xE0 | u >> 12); b[1] = (uint8_t)(0x80 | (u >> 6 & 0x3F)); b[2] = (uint8_t)(0x80 | (u & 0x3F)); }
        else { b[0] = (uint8_t)(0xF0 | u >> 18); b[1] = (uint8_t)(0x80 | (u >> 12 & 0x3F)); b[2] = (uint8_t)(0x80 | (u >> 6 & 0x3F)); b[3] = (uint8_t)(0x80 | (u & 0x3F)); }
        if (o + len + 1 > n) break;
        memcpy(out + o, b, len);
        o += len;
    }
    out[o] = 0;
}
// A host UTF-8 name into guest UTF-16 (at most cap units including the terminator). Bytes that aren't valid UTF-8
// are taken as Latin-1.
static void widen(const char *s, uint32_t w, uint32_t cap) {
    const uint8_t *p = (const uint8_t *)s;
    uint32_t o = 0;
    while (*p && o + 1 < cap) {
        uint32_t u = *p, len = 1;
        if (u >= 0xC2 && u < 0xE0 && (p[1] & 0xC0) == 0x80) { u = (u & 0x1F) << 6 | (p[1] & 0x3F); len = 2; }
        else if (u >= 0xE0 && u < 0xF0 && (p[1] & 0xC0) == 0x80 && (p[2] & 0xC0) == 0x80) { u = (u & 0x0F) << 12 | (p[1] & 0x3Fu) << 6 | (p[2] & 0x3F); len = 3; }
        else if (u >= 0xF0 && u < 0xF5 && (p[1] & 0xC0) == 0x80 && (p[2] & 0xC0) == 0x80 && (p[3] & 0xC0) == 0x80) {
            u = (u & 0x07) << 18 | (p[1] & 0x3Fu) << 12 | (p[2] & 0x3Fu) << 6 | (p[3] & 0x3F);
            len = 4;
        }
        if (u >= 0x10000) {
            if (o + 2 >= cap) break;
            M16(w + 2 * o++) = (uint16_t)(0xD800 + ((u - 0x10000) >> 10));
            u = 0xDC00 + ((u - 0x10000) & 0x3FF);
        }
        M16(w + 2 * o++) = (uint16_t)u;
        p += len;
    }
    M16(w + 2 * o) = 0;
}
// Copies s into a guest buffer of `cap` chars (Win32 "length or required size" convention): the length without the
// terminator when it fits, otherwise the size needed including it.
static uint32_t put_str(uint32_t buf, uint32_t cap, const char *s) {
    uint32_t len = (uint32_t)strlen(s);
    if (!buf || cap < len + 1) return len + 1;
    memcpy(G + buf, s, len + 1);
    return len;
}

// ---------------- resources in the exe's .rsrc ----------------
// A resource name or type is an integer ID (MAKEINTRESOURCE: below 0x10000), "#123", or a guest string compared
// case-insensitively with the directory's UTF-16 names. The first language entry is taken, like MW's d3dx_effect.c.
static uint32_t rsrc_base(void) {
    uint32_t pe = IMAGE_BASE + M32(IMAGE_BASE + 0x3C);
    uint32_t rva = M32(pe + 24 + 96 + 2 * 8);
    return rva ? IMAGE_BASE + rva : 0;
}
static int res_match(uint32_t rsrc, uint32_t entry_id, uint32_t key) {
    uint32_t id = 0;
    const char *name = NULL;
    if (key < 0x10000) id = key;
    else if (M8(key) == '#') id = (uint32_t)strtoul((const char *)G + key + 1, NULL, 10);
    else name = (const char *)G + key;
    if (!name) return !(entry_id & 0x80000000u) && entry_id == id;
    if (!(entry_id & 0x80000000u)) return 0;
    uint32_t s = rsrc + (entry_id & 0x7FFFFFFFu);
    uint16_t len = M16(s);
    if (strlen(name) != len) return 0;
    for (uint32_t q = 0; q < len; ++q) {
        uint16_t u = M16(s + 2 + 2 * q);
        if (u > 0x7F || tolower(u) != tolower((unsigned char)name[q])) return 0;
    }
    return 1;
}
static uint32_t res_child(uint32_t rsrc, uint32_t dir, uint32_t key) {   // the subdirectory/data offset for key, or 0
    uint32_t n = (uint32_t)M16(dir + 12) + M16(dir + 14);
    for (uint32_t k = 0; k < n; ++k)
        if (res_match(rsrc, M32(dir + 16 + 8 * k), key)) return M32(dir + 20 + 8 * k);
    return 0;
}
// FindResource: the guest address of the IMAGE_RESOURCE_DATA_ENTRY (an HRSRC), or 0.
uint32_t res_find(uint32_t type, uint32_t name) {
    uint32_t rsrc = rsrc_base();
    if (!rsrc) return 0;
    uint32_t t = res_child(rsrc, rsrc, type);
    if (!(t & 0x80000000u)) return 0;
    uint32_t nm = res_child(rsrc, rsrc + (t & 0x7FFFFFFFu), name);
    if (!nm) return 0;
    uint32_t d = rsrc + (nm & 0x7FFFFFFFu);
    if (nm & 0x80000000u) {                                       // language level: the first entry
        if (!(M16(d + 12) + M16(d + 14))) return 0;
        d = rsrc + (M32(d + 20) & 0x7FFFFFFFu);
    }
    return d;
}

// ---------------- file mapping ----------------
// A view is a copy of the file's bytes in guest memory, read at MapViewOfFile and written back at UnmapViewOfFile for
// writable views of writable mappings. Page-file-backed mappings (no file) are zeroed memory. Names are not shared.
#define MAP_BASE 0x5000u   // handle range (boot.c's: files 0x1000, kernel objects 0x2000, finds 0x2800, registry 0x3000, sockets 0x4000)
static struct { uint32_t file; uint64_t size; uint32_t prot, used; } maps[16];
static struct { uint32_t addr, size, map; uint64_t off; uint32_t write; } views[64];
static int map_index(uint32_t h) { uint32_t k = (h - MAP_BASE) / 4; return h >= MAP_BASE && k < 16 && maps[k].used ? (int)k : -1; }
int win32_more_close(uint32_t h) {
    int k = map_index(h);
    if (k < 0) return 0;
    maps[k].used = 0;
    return 1;
}

// ---------------- the handlers ----------------
static int kernel32_more(Cpu *c, const char *fn) {
    char a[1024], b[1024];
    // ---- wide-character file calls: the narrow ones' behaviour on the name made narrow ----
    if (!strcmp(fn, "CreateFileW")) {                // (name, access, share, sa, disposition, flags, template)
        narrow(arg(c, 0), a, sizeof a);
        RET(host_file_open(a, arg(c, 1), arg(c, 2), arg(c, 4)), 7);
    }
    if (!strcmp(fn, "DeleteFileW") || !strcmp(fn, "RemoveDirectoryW")) { narrow(arg(c, 0), a, sizeof a); RET(host_file_remove(a, fn[0] == 'R'), 1); }
    if (!strcmp(fn, "CreateDirectoryW")) { narrow(arg(c, 0), a, sizeof a); RET(host_mkdir(a), 2); }
    if (!strcmp(fn, "MoveFileW")) { narrow(arg(c, 0), a, sizeof a); narrow(arg(c, 1), b, sizeof b); RET(host_file_rename(a, b), 2); }
    if (!strcmp(fn, "FindFirstFileW") || !strcmp(fn, "FindNextFileW")) {
        // WIN32_FIND_DATAW: the same first 44 bytes as the A version, then cFileName[260] and cAlternateFileName[14] in UTF-16
        static uint32_t fda;
        if (!fda) fda = galloc(320);
        int first = fn[4] == 'F';
        uint32_t out = arg(c, 1), h;
        if (first) { narrow(arg(c, 0), a, sizeof a); h = host_find_first(a, fda); if (h == 0xFFFFFFFFu) RET(h, 2); }
        else { h = arg(c, 0); if (!host_find_next(h, fda)) RET(0, 2); }
        memset(G + out, 0, 592);
        memcpy(G + out, G + fda, 44);
        widen((const char *)G + fda + 44, out + 44, 260);
        RET(first ? h : 1, 2);
    }
    // ---- 64-bit file positions ----
    if (!strcmp(fn, "GetFileSizeEx")) {              // (h, LARGE_INTEGER *)
        int64_t n = host_file_size(arg(c, 0));
        if (n < 0) RET(0, 2);
        M64(arg(c, 1)) = (uint64_t)n;
        RET(1, 2);
    }
    if (!strcmp(fn, "SetFilePointerEx")) {           // (h, LARGE_INTEGER distance (2 dwords), LARGE_INTEGER *newpos, method)
        int64_t d = (int64_t)((uint64_t)arg(c, 1) | (uint64_t)arg(c, 2) << 32);
        int64_t r = host_file_seek(arg(c, 0), d, (int)arg(c, 4));
        if (r < 0) { last_error = 131; RET(0, 5); }  // ERROR_NEGATIVE_SEEK
        if (arg(c, 3)) M64(arg(c, 3)) = (uint64_t)r;
        RET(1, 5);
    }
    if (!strcmp(fn, "GetFileAttributesA")) RET(host_file_attr(gs_(arg(c, 0))), 1);
    if (!strcmp(fn, "SetFileAttributesA")) {         // attributes are not modelled; succeeds when the path exists
        uint32_t at = host_file_attr(gs_(arg(c, 0)));
        RET(at != 0xFFFFFFFFu, 2);
    }
    if (!strcmp(fn, "CopyFileA")) {                  // (from, to, failIfExists)
        uint32_t src = host_file_open(gs_(arg(c, 0)), 0x80000000u, 1, 3);
        if (src == 0xFFFFFFFFu) RET(0, 3);
        uint32_t dst = host_file_open(gs_(arg(c, 1)), 0x40000000u, 0, arg(c, 2) ? 1 : 2);   // CREATE_NEW / CREATE_ALWAYS
        if (dst == 0xFFFFFFFFu) { host_file_close(src); if (arg(c, 2)) last_error = 80; RET(0, 3); }   // ERROR_FILE_EXISTS
        uint32_t buf = crt_heap_alloc(0x10000);
        int ok = buf != 0;
        for (int64_t n; ok && (n = host_file_read(src, buf, 0x10000)) != 0;)
            ok = n > 0 && host_file_write(dst, buf, (uint32_t)n) == n;
        if (buf) crt_heap_free(buf);
        host_file_close(src);
        ok &= host_file_close(dst);
        RET(ok, 3);
    }
    if (!strcmp(fn, "CompareFileTime")) {
        uint64_t x = M64(arg(c, 0)), y = M64(arg(c, 1));
        RET(x < y ? 0xFFFFFFFFu : x > y, 2);
    }
    if (!strcmp(fn, "GetShortPathNameA")) {          // (long, short, cch): the long name is its own short name here
        const char *s = gs_(arg(c, 0));
        RET(put_str(arg(c, 1), arg(c, 2), s), 3);
    }
    // ---- file mapping ----
    if (!strcmp(fn, "CreateFileMappingA")) {         // (file, sa, protect, sizeHigh, sizeLow, name)
        uint32_t file = arg(c, 0), prot = arg(c, 2);
        uint64_t size = (uint64_t)arg(c, 3) << 32 | arg(c, 4);
        if (file != 0xFFFFFFFFu && !size) {
            int64_t n = host_file_size(file);
            if (n < 0) { last_error = 6; RET(0, 6); }  // ERROR_INVALID_HANDLE
            size = (uint64_t)n;
        }
        if (!size || size > 0x40000000u) { last_error = 87; RET(0, 6); }   // ERROR_INVALID_PARAMETER
        int k = 0;
        while (k < 16 && maps[k].used) ++k;
        if (k == 16) { last_error = 4; RET(0, 6); }  // ERROR_TOO_MANY_OPEN_FILES
        maps[k].file = file; maps[k].size = size; maps[k].prot = prot; maps[k].used = 1;
        RET(MAP_BASE + 4 * (uint32_t)k, 6);
    }
    if (!strcmp(fn, "MapViewOfFile")) {              // (map, access, offHigh, offLow, bytes)
        int k = map_index(arg(c, 0));
        uint64_t off = (uint64_t)arg(c, 2) << 32 | arg(c, 3), n = arg(c, 4);
        if (k < 0 || off > maps[k].size) { last_error = 6; RET(0, 5); }
        if (!n) n = maps[k].size - off;
        if (off + n > maps[k].size) { last_error = 8; RET(0, 5); }   // ERROR_NOT_ENOUGH_MEMORY, as Windows says
        int v = 0;
        while (v < 64 && views[v].addr) ++v;
        uint32_t addr = v < 64 ? crt_heap_alloc((uint32_t)n) : 0;
        if (!addr) { last_error = 8; RET(0, 5); }
        if (maps[k].file != 0xFFFFFFFFu) {
            uint32_t h = maps[k].file;
            int64_t pos = host_file_seek(h, 0, 1);
            host_file_seek(h, (int64_t)off, 0);
            int64_t got = host_file_read(h, addr, (uint32_t)n);
            host_file_seek(h, pos < 0 ? 0 : pos, 0);
            if (got < 0) { crt_heap_free(addr); RET(0, 5); }
        }
        views[v].addr = addr; views[v].size = (uint32_t)n; views[v].map = (uint32_t)k; views[v].off = off;
        views[v].write = (arg(c, 1) & 2) && (maps[k].prot & 0xFE) == 0x04;   // FILE_MAP_WRITE on PAGE_READWRITE
        RET(addr, 5);
    }
    if (!strcmp(fn, "UnmapViewOfFile")) {
        for (int v = 0; v < 64; ++v) {
            if (views[v].addr != arg(c, 0)) continue;
            uint32_t k = views[v].map;
            if (views[v].write && maps[k].file != 0xFFFFFFFFu) {
                int64_t pos = host_file_seek(maps[k].file, 0, 1);
                host_file_seek(maps[k].file, (int64_t)views[v].off, 0);
                host_file_write(maps[k].file, views[v].addr, views[v].size);
                host_file_seek(maps[k].file, pos < 0 ? 0 : pos, 0);
            }
            crt_heap_free(views[v].addr);
            memset(&views[v], 0, sizeof views[v]);
            RET(1, 1);
        }
        last_error = 487;                            // ERROR_INVALID_ADDRESS
        RET(0, 1);
    }
    // ---- resources ----
    if (!strcmp(fn, "FindResourceA")) {              // (module, name, type)
        if (arg(c, 0) && arg(c, 0) != IMAGE_BASE) { last_error = 1813; RET(0, 3); }
        uint32_t r = res_find(arg(c, 2), arg(c, 1));
        if (!r) last_error = 1814;                   // ERROR_RESOURCE_NAME_NOT_FOUND
        RET(r, 3);
    }
    if (!strcmp(fn, "LoadResource")) RET(arg(c, 1) ? IMAGE_BASE + M32(arg(c, 1)) : 0, 2);   // (module, hrsrc)
    if (!strcmp(fn, "LockResource")) RET(arg(c, 0), 1);
    if (!strcmp(fn, "SizeofResource")) RET(arg(c, 1) ? M32(arg(c, 1) + 4) : 0, 2);
    // ---- modules ----
    if (!strcmp(fn, "LoadLibraryW")) { narrow(arg(c, 0), a, sizeof a); RET(host_load_library(c, a), 1); }
    if (!strcmp(fn, "LoadLibraryExA")) RET(host_load_library(c, gs_(arg(c, 0))), 3);
    if (!strcmp(fn, "LoadLibraryExW")) { narrow(arg(c, 0), a, sizeof a); RET(host_load_library(c, a), 3); }
    // ---- strings ----
    if (!strcmp(fn, "lstrlenA")) RET(arg(c, 0) ? strlen(gs_(arg(c, 0))) : 0, 1);
    if (!strcmp(fn, "lstrlenW")) { uint32_t n = 0, p = arg(c, 0); if (p) while (M16(p + 2 * n)) ++n; RET(n, 1); }
    if (!strcmp(fn, "lstrcmpA") || !strcmp(fn, "lstrcmpiA")) {   // ordinal comparison (Windows uses the locale's word sort)
        const char *x = arg(c, 0) ? gs_(arg(c, 0)) : "", *y = arg(c, 1) ? gs_(arg(c, 1)) : "";
        int r = !strcmp(fn, "lstrcmpiA") ? strcasecmp(x, y) : strcmp(x, y);
        RET(r < 0 ? 0xFFFFFFFFu : r > 0, 2);
    }
    // ---- local and global memory: fixed blocks on the process heap ----
    if (!strcmp(fn, "LocalAlloc")) RET(crt_heap_alloc(arg(c, 1) ? arg(c, 1) : 1), 2);       // (flags, size): always zeroed
    if (!strcmp(fn, "LocalFree")) { if (arg(c, 0)) crt_heap_free(arg(c, 0)); RET(0, 1); }
    if (!strcmp(fn, "LocalLock") || !strcmp(fn, "GlobalLock")) RET(arg(c, 0), 1);
    if (!strcmp(fn, "LocalUnlock") || !strcmp(fn, "GlobalUnlock")) { last_error = 0; RET(0, 1); }   // no lock count: NO_ERROR
    if (!strcmp(fn, "GlobalMemoryStatus")) {         // MEMORYSTATUS: the GlobalMemoryStatusEx values, clamped to 32 bits
        uint32_t p = arg(c, 0);
        M32(p) = 32; M32(p + 4) = 20;
        M32(p + 8) = 2u << 30; M32(p + 12) = 1u << 30;               // physical: 2 GB, 1 GB free
        M32(p + 16) = 0xFFFFFFFFu; M32(p + 20) = 3u << 30;           // page file: 4 GB (clamped), 3 GB free
        M32(p + 24) = 2u << 30; M32(p + 28) = 1u << 30;              // virtual: 2 GB, 1 GB free
        RET(0, 1);
    }
    // ---- system information: Windows XP SP2 (5.1.2600), en-US, as boot.c's GetVersionExA / GetUserDefaultLCID ----
    if (!strcmp(fn, "GetVersion")) RET((2600u << 16) | 0x0105u, 0);
    if (!strcmp(fn, "GetUserDefaultLangID")) RET(0x409, 0);
    if (!strcmp(fn, "GetEnvironmentVariableA")) { last_error = 203; RET(0, 3); }   // ERROR_ENVVAR_NOT_FOUND: empty environment
    if (!strcmp(fn, "GetWindowsDirectoryA")) RET(put_str(arg(c, 0), arg(c, 1), "C:\\WINDOWS"), 2);
    if (!strcmp(fn, "GetSystemDirectoryA")) RET(put_str(arg(c, 0), arg(c, 1), "C:\\WINDOWS\\system32"), 2);
    if (!strcmp(fn, "GetTempPathA")) {               // (cch, buf): a folder in the user-data directory
        host_mkdir("C:\\USERDATA\\Temp");
        RET(put_str(arg(c, 1), arg(c, 0), "C:\\USERDATA\\Temp\\"), 2);
    }
    if (!strcmp(fn, "GetComputerNameA")) {           // (buf, size*): size in, length out
        uint32_t need = (uint32_t)strlen("MAC") + 1;
        if (M32(arg(c, 1)) < need) { M32(arg(c, 1)) = need; last_error = 111; RET(0, 2); }   // ERROR_BUFFER_OVERFLOW
        memcpy(G + arg(c, 0), "MAC", need);
        M32(arg(c, 1)) = need - 1;
        RET(1, 2);
    }
    if (!strcmp(fn, "FormatMessageA")) {             // (flags, source, id, lang, buf, size, args): a plain "Error N."
        char msg[64];
        snprintf(msg, sizeof msg, "Error %u.\r\n", arg(c, 2));
        uint32_t len = (uint32_t)strlen(msg);
        if (arg(c, 0) & 0x100) {                     // FORMAT_MESSAGE_ALLOCATE_BUFFER: buf receives a LocalAlloc pointer
            uint32_t p = crt_heap_alloc(len + 1);
            if (!p) RET(0, 7);
            memcpy(G + p, msg, len + 1);
            M32(arg(c, 4)) = p;
            RET(len, 7);
        }
        if (arg(c, 5) < len + 1) { last_error = 122; RET(0, 7); }   // ERROR_INSUFFICIENT_BUFFER
        memcpy(G + arg(c, 4), msg, len + 1);
        RET(len, 7);
    }
    if (!strcmp(fn, "OpenMutexA") || !strcmp(fn, "OpenEventA")) { last_error = 2; RET(0, 3); }   // no named object exists yet
    if (!strcmp(fn, "SetThreadIdealProcessor")) RET(0, 2);
    return 0;
}

static const uint32_t sys_colors[31] = {   // classic Windows defaults (0x00BBGGRR) for GetSysColor
    0xC8D0D4, 0x6E3A0A, 0x6A240A, 0x808080, 0xC8D0D4, 0xFFFFFF, 0x000000, 0x000000, 0x000000, 0xFFFFFF, 0xC8D0D4,
    0xC8D0D4, 0x808080, 0x6A240A, 0xFFFFFF, 0xC8D0D4, 0x808080, 0x808080, 0x000000, 0xC8D0D4, 0xFFFFFF, 0x404040,
    0xC8D0D4, 0x000000, 0xE1FFFF, 0xB5B5B5, 0x800000, 0xF0CAA6, 0xC0C0C0, 0xFF0000, 0xC8D0D4};

static int user32_more(Cpu *c, const char *fn) {
    if (!strcmp(fn, "GetSystemMetrics")) {
        int w = 0, h = 0;
        user32_display_pixels(&w, &h);
        switch (arg(c, 0)) {
        case 0: case 16: case 78: RET(w, 1);         // SM_CXSCREEN, SM_CXFULLSCREEN, SM_CXVIRTUALSCREEN
        case 1: case 17: case 79: RET(h, 1);
        case 4: RET(19, 1);                          // SM_CYCAPTION
        case 5: case 6: RET(1, 1);                   // SM_CXBORDER, SM_CYBORDER
        case 7: case 8: RET(3, 1);                   // SM_CXFIXEDFRAME
        case 13: case 14: RET(32, 1);                // SM_CXCURSOR
        case 19: case 80: RET(1, 1);                 // SM_MOUSEPRESENT, SM_CMONITORS
        case 32: case 33: RET(4, 1);                 // SM_CXSIZEFRAME
        case 36: case 37: RET(4, 1);                 // SM_CXDOUBLECLK
        default: RET(0, 1);                          // SM_SWAPBUTTON, SM_REMOTESESSION, virtual-screen origin, ...
        }
    }
    if (!strcmp(fn, "SystemParametersInfoA")) {      // (action, ui, pv, winini)
        uint32_t act = arg(c, 0), pv = arg(c, 2);
        int w = 0, h = 0;
        switch (act) {
        case 0x30:                                   // SPI_GETWORKAREA: the whole display
            user32_display_pixels(&w, &h);
            M32(pv) = 0; M32(pv + 4) = 0; M32(pv + 8) = (uint32_t)w; M32(pv + 12) = (uint32_t)h;
            RET(1, 4);
        case 0x10:                                   // SPI_GETSCREENSAVEACTIVE
            M32(pv) = 0;
            RET(1, 4);
        case 0x32: case 0x34: case 0x3A:             // SPI_GETFILTERKEYS / TOGGLEKEYS / STICKYKEYS: {cbSize, dwFlags, ...} all off
            if (M32(pv) >= 8) memset(G + pv + 4, 0, M32(pv) - 4);
            RET(1, 4);
        case 0x11: case 0x33: case 0x35: case 0x3B:  // the matching SET calls: accepted, nothing to change on a Mac
            RET(1, 4);
        }
        char m[64];
        snprintf(m, sizeof m, "SystemParametersInfoA action %X not modelled", act);
        if (boot_trace) fprintf(stderr, "      %s\n", m);
        last_error = 87;
        RET(0, 4);
    }
    if (!strcmp(fn, "EnumDisplaySettingsA")) {       // (device, mode, DEVMODEA*): the current mode only
        uint32_t mode = arg(c, 1), dm = arg(c, 2);
        if (mode != 0xFFFFFFFFu && mode != 0xFFFFFFFEu && mode != 0) RET(0, 3);
        int w = 0, h = 0;
        user32_display_pixels(&w, &h);
        uint16_t size = M16(dm + 36) ? M16(dm + 36) : 156;
        memset(G + dm, 0, 32);
        M16(dm + 32) = 0x0401;                       // dmSpecVersion (DM_SPECVERSION)
        M16(dm + 36) = size;
        if (size >= 124) {
            M32(dm + 40) = 0x40000 | 0x80000 | 0x100000 | 0x400000;   // BITSPERPEL | PELSWIDTH | PELSHEIGHT | DISPLAYFREQUENCY
            M32(dm + 104) = 32; M32(dm + 108) = (uint32_t)w; M32(dm + 112) = (uint32_t)h; M32(dm + 116) = 0; M32(dm + 120) = 60;
        }
        RET(1, 3);
    }
    if (!strcmp(fn, "LoadStringA")) {                // (instance, id, buf, cch): RT_STRING blocks of 16 counted UTF-16 strings
        uint32_t id = arg(c, 1), buf = arg(c, 2), cch = arg(c, 3);
        if (!buf || !cch) RET(0, 4);
        M8(buf) = 0;
        uint32_t e = res_find(6, (id >> 4) + 1);
        if (!e) RET(0, 4);
        uint32_t p = IMAGE_BASE + M32(e);
        for (uint32_t k = 0; k < (id & 15); ++k) p += 2 + 2u * M16(p);
        uint32_t len = M16(p), n = len < cch - 1 ? len : cch - 1;
        for (uint32_t k = 0; k < n; ++k) { uint16_t u = M16(p + 2 + 2 * k); M8(buf + k) = u > 0xFF ? '?' : (uint8_t)u; }
        M8(buf + n) = 0;
        RET(n, 4);
    }
    if (!strcmp(fn, "CharLowerA")) {                 // a string, or one character in the low word
        uint32_t s = arg(c, 0);
        if (s < 0x10000) RET(tolower(s & 0xFF), 1);
        for (uint32_t p = s; M8(p); ++p) M8(p) = (uint8_t)tolower(M8(p));
        RET(s, 1);
    }
    if (!strcmp(fn, "CharLowerBuffA")) {
        for (uint32_t k = 0; k < arg(c, 1); ++k) M8(arg(c, 0) + k) = (uint8_t)tolower(M8(arg(c, 0) + k));
        RET(arg(c, 1), 2);
    }
    if (!strcmp(fn, "GetSysColor")) RET(arg(c, 0) < 31 ? sys_colors[arg(c, 0)] : 0, 1);
    if (!strcmp(fn, "GetSysColorBrush")) RET(arg(c, 0) < 31 ? 0x00600000u + arg(c, 0) : 0, 1);   // stock brushes, never drawn with
    if (!strcmp(fn, "FindWindowA") || !strcmp(fn, "FindWindowExA")) RET(0, fn[10] == 'E' ? 4 : 2);   // no other instance's window
    return 0;
}

static int other_more(Cpu *c, const char *fn) {
    // ---- ADVAPI32 ----
    if (!strcmp(fn, "GetUserNameA")) {               // (buf, size*)
        uint32_t need = (uint32_t)strlen("Player") + 1;
        if (M32(arg(c, 1)) < need) { M32(arg(c, 1)) = need; last_error = 122; RET(0, 2); }
        memcpy(G + arg(c, 0), "Player", need);
        M32(arg(c, 1)) = need;                       // including the terminator, unlike GetComputerNameA
        RET(1, 2);
    }
    if (!strcmp(fn, "CryptAcquireContextA")) { M32(arg(c, 0)) = 0x7001; RET(1, 5); }   // (prov*, container, provider, type, flags)
    if (!strcmp(fn, "CryptGenRandom")) { arc4random_buf(G + arg(c, 2), arg(c, 1)); RET(1, 3); }   // (prov, len, buf)
    if (!strcmp(fn, "CryptReleaseContext")) RET(1, 2);
    // ---- VERSION: the exe carries no version resource ----
    if (!strcmp(fn, "GetFileVersionInfoSizeA")) { if (arg(c, 1)) M32(arg(c, 1)) = 0; last_error = 1813; RET(0, 2); }
    if (!strcmp(fn, "GetFileVersionInfoA")) { last_error = 1813; RET(0, 4); }
    if (!strcmp(fn, "VerQueryValueA")) RET(0, 4);
    // ---- RPCRT4 / ole32: GUIDs ----
    if (!strcmp(fn, "CoCreateGuid")) {               // a random (version 4) GUID
        uint32_t g = arg(c, 0);
        arc4random_buf(G + g, 16);
        M16(g + 6) = (uint16_t)((M16(g + 6) & 0x0FFF) | 0x4000);
        M8(g + 8) = (uint8_t)((M8(g + 8) & 0x3F) | 0x80);
        RET(0, 1);                                   // S_OK
    }
    if (!strcmp(fn, "UuidToStringA")) {              // (uuid*, char **out): freed by RpcStringFreeA
        uint32_t u = arg(c, 0), s = crt_heap_alloc(37);
        if (!s) RET(14, 2);                          // RPC_S_OUT_OF_MEMORY
        snprintf((char *)G + s, 37, "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x", M32(u), M16(u + 4), M16(u + 6),
                 M8(u + 8), M8(u + 9), M8(u + 10), M8(u + 11), M8(u + 12), M8(u + 13), M8(u + 14), M8(u + 15));
        M32(arg(c, 1)) = s;
        RET(0, 2);                                   // RPC_S_OK
    }
    if (!strcmp(fn, "RpcStringFreeA")) { uint32_t p = arg(c, 0); if (p && M32(p)) { crt_heap_free(M32(p)); M32(p) = 0; } RET(0, 1); }
    return 0;
}

int win32_more(Cpu *c, const char *fn) {
    return kernel32_more(c, fn) || user32_more(c, fn) || other_more(c, fn);
}
