// win32_more_test.c - standalone test of win32_more.c on a private guest address space; no game files.
// Built and run by runtime/win32_more_test.py (c_test_driver.py). Every call goes through win32_more() with a real guest
// stack, and the __stdcall rule (the callee pops its arguments) is checked after each one. A synthetic exe image at
// 0x400000 carries a resource tree (integer, named and "#id" entries, with and without a language level, a string table).
// Files are real, under a scratch directory (test_hostfs.h). WIN32_MORE_TEST_SELFCHECK=1 adds one wrong expectation.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include "host.h"
#include "test_hostfs.h"

uint8_t *G;
__thread uint32_t last_error;
int boot_trace;
static Cpu cpu;
static Cpu *const c = &cpu;
static int fails, checks;
#define CHECK(x, ...) do { ++checks; if (!(x)) { if (fails++ < 40) { printf("FAIL %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); } } } while (0)

static uint32_t bump = 0x10000000u;
uint32_t galloc(uint32_t n) { uint32_t a = (bump + 15) & ~15u; bump = a + (n ? n : 1); memset(G + a, 0, n); return a; }
uint32_t gstr(const char *s) { uint32_t a = galloc((uint32_t)strlen(s) + 1); strcpy((char *)G + a, s); return a; }
static uint32_t heap_next = 0x20000000u, live;
uint32_t crt_heap_alloc(uint32_t n) {
    uint32_t a = (heap_next + 8 + 15) & ~15u;
    M32(a - 8) = 0xB10CB10Cu;
    heap_next = a + n;
    memset(G + a, 0, n);
    ++live;
    return a;
}
void crt_heap_free(uint32_t a) { if (M32(a - 8) == 0xB10CB10Cu) { M32(a - 8) = 0; --live; } else { ++fails; printf("FAIL bad free %08X\n", a); } }
void user32_display_pixels(int *w, int *h) { *w = 1920; *h = 1080; }
static char loaded[64];
uint32_t host_load_library(Cpu *cc, const char *name) { (void)cc; snprintf(loaded, sizeof loaded, "%s", name); return !strcasecmp(name, "server.dll") ? 0x02000000u : 0; }
int win32_more_close(uint32_t h);
uint32_t res_find(uint32_t type, uint32_t name);

static int call(const char *fn, int n, const uint32_t *args) {
    uint32_t sp = 0x7F000000u;
    for (int i = n - 1; i >= 0; --i) { sp -= 4; M32(sp) = args[i]; }
    sp -= 4;
    M32(sp) = 0xDEADC0DEu;
    c->esp = sp;
    int ok = win32_more(c, fn);
    if (ok) CHECK(c->esp == sp + 4 + 4 * (uint32_t)n, "%s: esp %08X, want %08X (__stdcall pops %d arguments)", fn, c->esp, sp + 4 + 4 * (uint32_t)n, n);
    return ok;
}
static uint32_t callv(const char *fn, int n, const uint32_t *args) {
    if (call(fn, n, args)) return c->eax;
    CHECK(0, "%s not handled", fn);
    return 0;
}
#define A(...) ((const uint32_t[]){__VA_ARGS__})
#define NA(...) (int)(sizeof((const uint32_t[]){__VA_ARGS__}) / 4)
#define CALL(fn, ...) callv(fn, NA(__VA_ARGS__), A(__VA_ARGS__))
#define CALL0(fn) callv(fn, 0, NULL)
static uint32_t S(const char *s) { return gstr(s); }
static uint32_t W(const char *s) {   // a guest UTF-16 string from Latin-1 / ASCII
    uint32_t n = (uint32_t)strlen(s), a = galloc(2 * n + 2);
    for (uint32_t k = 0; k < n; ++k) M16(a + 2 * k) = (uint8_t)s[k];
    return a;
}
static const char *gs(uint32_t a) { return (const char *)G + a; }

// ---- the synthetic exe image and its resource tree ----
#define RSRC_RVA 0x10000u
#define RSRC (0x400000u + RSRC_RVA)
static uint32_t rs_at = RSRC + 0x800;   // allocator for strings/data inside .rsrc (directories live below 0x800)
static uint32_t rs_alloc(uint32_t n) { uint32_t a = (rs_at + 3) & ~3u; rs_at = a + n; return a; }
static uint32_t rs_name(const char *s) {   // a counted UTF-16 name; returns its offset with the name bit
    uint32_t n = (uint32_t)strlen(s), a = rs_alloc(2 + 2 * n);
    M16(a) = (uint16_t)n;
    for (uint32_t k = 0; k < n; ++k) M16(a + 2 + 2 * k) = (uint8_t)s[k];
    return 0x80000000u | (a - RSRC);
}
static uint32_t rs_data(const void *bytes, uint32_t n) {   // a data entry (RVA, size) and its bytes; returns its offset
    uint32_t d = rs_alloc(n), e = rs_alloc(16);
    memcpy(G + d, bytes, n);
    M32(e) = d - 0x400000u; M32(e + 4) = n;
    return e - RSRC;
}
static uint32_t dir_at = RSRC;
static uint32_t rs_dir(int named, int ids, const uint32_t *keys, const uint32_t *offs) {   // returns its offset
    uint32_t d = dir_at;
    dir_at += 16 + 8 * (uint32_t)(named + ids);
    memset(G + d, 0, 16);
    M16(d + 12) = (uint16_t)named; M16(d + 14) = (uint16_t)ids;
    for (int k = 0; k < named + ids; ++k) { M32(d + 16 + 8 * (uint32_t)k) = keys[k]; M32(d + 20 + 8 * (uint32_t)k) = offs[k]; }
    return d - RSRC;
}
static void build_image(void) {
    M16(0x400000) = 0x5A4D;
    M32(0x400000 + 0x3C) = 0x80;
    M32(0x400080) = 0x00004550;
    M32(0x400080 + 24 + 96 + 16) = RSRC_RVA;                  // data directory 2: resources
    // build children first so their offsets are known; the root must sit at RSRC, so reserve it
    dir_at = RSRC + 16 + 8 * 3;                               // root: 1 named type + 2 id types
    // RT_RCDATA (10): "FX1" with a language level, and id 101 straight to its data
    uint32_t fx1 = rs_dir(0, 1, A(0x409), A(rs_data("effect-one", 10)));
    uint32_t rc = rs_dir(1, 1, A(rs_name("FX1"), 101), A(0x80000000u | fx1, rs_data("raw-101", 7)));
    // RT_STRING (6): block 1 = ids 0..15; id 1 "Hello", id 3 "Zhe!" with a Cyrillic first letter, the rest empty
    uint16_t tab[64] = {0}, *p = tab;
    for (int k = 0; k < 16; ++k) {
        if (k == 1) { *p++ = 5; memcpy(p, (uint16_t[]){'H', 'e', 'l', 'l', 'o'}, 10); p += 5; }
        else if (k == 3) { *p++ = 2; *p++ = 0x416; *p++ = '!'; }
        else *p++ = 0;
    }
    uint32_t blk = rs_dir(0, 1, A(0x409), A(rs_data(tab, (uint32_t)((uint8_t *)p - (uint8_t *)tab))));
    uint32_t st = rs_dir(0, 1, A(1), A(0x80000000u | blk));
    // a named type "SHADERS" with id 7
    uint32_t sh7 = rs_dir(0, 1, A(0), A(rs_data("shader-7", 8)));
    uint32_t sh = rs_dir(0, 1, A(7), A(0x80000000u | sh7));
    uint32_t root_end = dir_at;
    dir_at = RSRC;
    rs_dir(1, 2, A(rs_name("SHADERS"), 6, 10), A(0x80000000u | sh, 0x80000000u | st, 0x80000000u | rc));
    dir_at = root_end;
}

static void test_resources(void) {
    uint32_t r = CALL("FindResourceA", 0, S("fx1"), 10);
    CHECK(r && !memcmp(G + CALL("LoadResource", 0, r), "effect-one", 10) && CALL("SizeofResource", 0, r) == 10, "named RCDATA through a language level");
    CHECK(CALL("LockResource", 0x401234) == 0x401234, "LockResource is the address");
    r = CALL("FindResourceA", 0x400000, S("#101"), 10);
    CHECK(r && !memcmp(G + CALL("LoadResource", 0x400000, r), "raw-101", 7), "\"#101\" names an integer id; data without a language level");
    r = CALL("FindResourceA", 0, 101, 10);
    CHECK(r && CALL("SizeofResource", 0, r) == 7, "MAKEINTRESOURCE(101)");
    r = CALL("FindResourceA", 0, 7, S("Shaders"));
    CHECK(r && !memcmp(G + CALL("LoadResource", 0, r), "shader-7", 8), "a named type, case-insensitive");
    last_error = 0;
    CHECK(CALL("FindResourceA", 0, S("nope"), 10) == 0 && last_error == 1814, "missing name");
    CHECK(CALL("FindResourceA", 0, 101, 99) == 0, "missing type");
    CHECK(CALL("FindResourceA", 0x10000000, 101, 10) == 0, "another module's resources are not ours");
    uint32_t buf = galloc(64);
    CHECK(CALL("LoadStringA", 0, 1, buf, 64) == 5 && !strcmp(gs(buf), "Hello"), "LoadStringA id 1: %s", gs(buf));
    CHECK(CALL("LoadStringA", 0, 3, buf, 64) == 2 && !strcmp(gs(buf), "?!"), "LoadStringA narrows to Latin-1: %s", gs(buf));
    CHECK(CALL("LoadStringA", 0, 2, buf, 64) == 0 && !G[buf], "an empty string");
    CHECK(CALL("LoadStringA", 0, 40, buf, 64) == 0, "a missing block");
    CHECK(CALL("LoadStringA", 0, 1, buf, 3) == 2 && !strcmp(gs(buf), "He"), "truncated to the buffer");
}

static void put_file(const char *rel, const void *data, size_t n) {
    char p[1024];
    snprintf(p, sizeof p, "%s/%s", root, rel);
    FILE *f = fopen(p, "wb");
    fwrite(data, 1, n, f);
    fclose(f);
}
static size_t get_file(const char *rel, void *buf, size_t cap) {
    char p[1024];
    snprintf(p, sizeof p, "%s/%s", root, rel);
    FILE *f = fopen(p, "rb");
    if (!f) return (size_t)-1;
    size_t n = fread(buf, 1, cap, f);
    fclose(f);
    return n;
}

static void test_files(void) {
    uint8_t pat[64];
    for (int k = 0; k < 64; ++k) pat[k] = (uint8_t)(k * 3);
    put_file("data.bin", pat, 64);
    uint32_t h = CALL("CreateFileW", W("C:\\NFSMW\\DATA.bin"), 0x80000000u, 1, 0, 3, 0, 0);
    CHECK(h != 0xFFFFFFFFu, "CreateFileW");
    uint32_t li = galloc(8);
    CHECK(CALL("GetFileSizeEx", h, li) == 1 && M64(li) == 64, "GetFileSizeEx");
    CHECK(CALL("SetFilePointerEx", h, 10, 0, li, 0) == 1 && M64(li) == 10, "SetFilePointerEx");
    // a read-only view of bytes 16..23; the file position is left where it was
    uint32_t map = CALL("CreateFileMappingA", h, 0, 2, 0, 0, 0);
    CHECK(map, "CreateFileMappingA");
    uint32_t v = CALL("MapViewOfFile", map, 4, 0, 16, 8);
    CHECK(v && !memcmp(G + v, pat + 16, 8), "MapViewOfFile reads the bytes");
    CHECK(CALL("SetFilePointerEx", h, 0, 0, li, 1) == 1 && M64(li) == 10, "the file position is unchanged (%llu)", (unsigned long long)M64(li));
    uint32_t whole = CALL("MapViewOfFile", map, 4, 0, 0, 0);
    CHECK(whole && !memcmp(G + whole, pat, 64), "bytes 0 maps the rest of the file");
    CHECK(CALL("MapViewOfFile", map, 4, 0, 60, 8) == 0, "a view past the end fails");
    uint32_t before = live;
    CHECK(CALL("UnmapViewOfFile", v) == 1 && CALL("UnmapViewOfFile", whole) == 1 && live == before - 2, "UnmapViewOfFile frees");
    last_error = 0;
    CHECK(CALL("UnmapViewOfFile", v) == 0 && last_error == 487, "unmapping twice");
    CHECK(win32_more_close(map) && !win32_more_close(map), "CloseHandle of the mapping (once)");
    host_file_close(h);
    // a writable view is written back on unmap
    h = CALL("CreateFileW", W("data.bin"), 0xC0000000u, 0, 0, 3, 0, 0);
    map = CALL("CreateFileMappingA", h, 0, 4, 0, 0, 0);
    v = CALL("MapViewOfFile", map, 2, 0, 4, 4);
    memcpy(G + v, "WXYZ", 4);
    CALL("UnmapViewOfFile", v);
    win32_more_close(map);
    host_file_close(h);
    uint8_t back[64];
    CHECK(get_file("data.bin", back, 64) == 64 && !memcmp(back + 4, "WXYZ", 4) && !memcmp(back + 8, pat + 8, 56), "write-back of a FILE_MAP_WRITE view");
    // page-file-backed: zeroed memory of the requested size
    map = CALL("CreateFileMappingA", 0xFFFFFFFFu, 0, 4, 0, 4096, S("Local\\shared"));
    v = CALL("MapViewOfFile", map, 6, 0, 0, 0);
    int zero = v != 0;
    for (uint32_t k = 0; zero && k < 4096; ++k) zero = !G[v + k];
    CHECK(zero, "a page-file view is 4096 zeroed bytes");
    CALL("UnmapViewOfFile", v);
    win32_more_close(map);
    CHECK(CALL("CreateFileMappingA", 0xFFFFFFFFu, 0, 4, 0, 0, 0) == 0, "a page-file mapping needs a size");
    // wide-character directory and file calls
    CHECK(CALL("CreateDirectoryW", W("dirw"), 0) == 1, "CreateDirectoryW");
    put_file("dirw/one.txt", "1", 1);
    put_file("dirw/two.txt", "22", 2);
    CHECK(CALL("MoveFileW", W("dirw\\two.txt"), W("dirw\\b\xe9t.txt")) == 1, "MoveFileW with a Latin-1 name");
    char hostname[1024];
    snprintf(hostname, sizeof hostname, "%s/dirw/b\xc3\xa9t.txt", root);
    CHECK(!access(hostname, F_OK), "the host file name is UTF-8");
    uint32_t fd = galloc(592), fh = CALL("FindFirstFileW", W("dirw\\*.txt"), fd);
    int seen = 0;
    if (fh != 0xFFFFFFFFu) do {
        uint16_t name[8];
        memcpy(name, G + fd + 44, sizeof name);
        if (name[0] == 'o' && name[1] == 'n' && name[2] == 'e' && name[3] == '.') seen |= 1;
        if (name[0] == 'b' && name[1] == 0xE9 && name[2] == 't') { seen |= 2; CHECK(M32(fd + 32) == 2, "size in WIN32_FIND_DATAW"); }
    } while (CALL("FindNextFileW", fh, fd) == 1);
    CHECK(seen == 3, "FindFirstFileW/FindNextFileW found both (mask %d)", seen);
    host_find_close(fh);
    CHECK(CALL("FindFirstFileW", W("dirw\\*.none"), fd) == 0xFFFFFFFFu, "no match");
    CHECK(CALL("DeleteFileW", W("dirw\\one.txt")) == 1 && CALL("DeleteFileW", W("dirw\\b\xe9t.txt")) == 1, "DeleteFileW");
    CHECK(CALL("DeleteFileW", W("dirw\\one.txt")) == 0, "DeleteFileW twice");
    CHECK(CALL("RemoveDirectoryW", W("dirw")) == 1, "RemoveDirectoryW");
    // attributes, copies, times
    CHECK(CALL("CreateDirectoryW", W("d"), 0) == 1, "a directory");
    CHECK(CALL("GetFileAttributesA", S("d")) == 0x10 && CALL("GetFileAttributesA", S("data.bin")) == 0x20 &&
          CALL("GetFileAttributesA", S("none")) == 0xFFFFFFFFu, "GetFileAttributesA");
    CHECK(CALL("SetFileAttributesA", S("data.bin"), 1) == 1 && CALL("SetFileAttributesA", S("none"), 1) == 0, "SetFileAttributesA");
    CHECK(CALL("CopyFileA", S("data.bin"), S("d\\copy.bin"), 1) == 1, "CopyFileA");
    last_error = 0;
    CHECK(CALL("CopyFileA", S("data.bin"), S("d\\copy.bin"), 1) == 0 && last_error == 80, "CopyFileA refuses to overwrite");
    CHECK(CALL("CopyFileA", S("data.bin"), S("d\\copy.bin"), 0) == 1, "CopyFileA overwrites when allowed");
    CHECK(get_file("d/copy.bin", back, 64) == 64 && !memcmp(back + 4, "WXYZ", 4), "the copy has the bytes");
    CHECK(CALL("CopyFileA", S("none"), S("d\\x"), 0) == 0, "CopyFileA of a missing file");
    host_file_remove("d\\copy.bin", 0);
    host_file_remove("d", 1);
    uint32_t t1 = galloc(8), t2 = galloc(8);
    M64(t1) = 5; M64(t2) = 9;
    CHECK(CALL("CompareFileTime", t1, t2) == 0xFFFFFFFFu && CALL("CompareFileTime", t2, t1) == 1 && CALL("CompareFileTime", t1, t1) == 0, "CompareFileTime");
    uint32_t sb = galloc(64);
    CHECK(CALL("GetShortPathNameA", S("C:\\a\\b.txt"), sb, 64) == 10 && !strcmp(gs(sb), "C:\\a\\b.txt"), "GetShortPathNameA");
    CHECK(CALL("GetShortPathNameA", S("C:\\a\\b.txt"), sb, 4) == 11, "GetShortPathNameA asks for a bigger buffer");
}

static void test_strings_memory(void) {
    CHECK(CALL("lstrlenA", S("abc")) == 3 && CALL("lstrlenA", 0) == 0 && CALL("lstrlenW", W("abcd")) == 4, "lstrlenA/W");
    CHECK(CALL("lstrcmpA", S("a"), S("b")) == 0xFFFFFFFFu && CALL("lstrcmpA", S("B"), S("a")) == 0xFFFFFFFFu, "lstrcmpA is case-sensitive");
    CHECK(CALL("lstrcmpiA", S("ABC"), S("abc")) == 0 && CALL("lstrcmpiA", S("b"), S("A")) == 1, "lstrcmpiA");
    uint32_t before = live, p = CALL("LocalAlloc", 0x40, 32);
    CHECK(p && live == before + 1 && !G[p + 31], "LocalAlloc");
    CHECK(CALL("LocalLock", p) == p && CALL("GlobalLock", p) == p, "Lock is the address");
    last_error = 5;
    CHECK(CALL("LocalUnlock", p) == 0 && last_error == 0, "LocalUnlock: unlocked, NO_ERROR");
    CHECK(CALL("LocalFree", p) == 0 && live == before, "LocalFree");
    uint32_t ms = galloc(32);
    CALL("GlobalMemoryStatus", ms);
    CHECK(M32(ms) == 32 && M32(ms + 8) == 0x80000000u && M32(ms + 12) == 0x40000000u && M32(ms + 16) == 0xFFFFFFFFu, "GlobalMemoryStatus");
}

static void test_system(void) {
    CHECK(CALL0("GetVersion") == 0x0A280105u, "GetVersion: XP 5.1.2600");
    CHECK(CALL0("GetUserDefaultLangID") == 0x409, "GetUserDefaultLangID");
    last_error = 0;
    CHECK(CALL("GetEnvironmentVariableA", S("PATH"), galloc(16), 16) == 0 && last_error == 203, "GetEnvironmentVariableA");
    uint32_t b = galloc(64);
    CHECK(CALL("GetWindowsDirectoryA", b, 64) == 10 && !strcmp(gs(b), "C:\\WINDOWS"), "GetWindowsDirectoryA");
    CHECK(CALL("GetWindowsDirectoryA", b, 4) == 11, "GetWindowsDirectoryA asks for 11");
    CHECK(CALL("GetSystemDirectoryA", b, 64) == 19 && !strcmp(gs(b), "C:\\WINDOWS\\system32"), "GetSystemDirectoryA");
    host_mkdir("USERDATA");                                   // boot.c's user-data directory always exists
    CHECK(CALL("GetTempPathA", 64, b) == 17 && !strcmp(gs(b), "C:\\USERDATA\\Temp\\") && host_file_attr("C:\\USERDATA\\Temp") == 0x10,
          "GetTempPathA creates its folder");
    host_file_remove("USERDATA\\Temp", 1);
    host_file_remove("USERDATA", 1);
    uint32_t n = galloc(4);
    M32(n) = 2;
    last_error = 0;
    CHECK(CALL("GetComputerNameA", b, n) == 0 && last_error == 111 && M32(n) == 4, "GetComputerNameA small buffer");
    M32(n) = 64;
    CHECK(CALL("GetComputerNameA", b, n) == 1 && !strcmp(gs(b), "MAC") && M32(n) == 3, "GetComputerNameA");
    uint32_t pp = galloc(4);
    CHECK(CALL("FormatMessageA", 0x1100, 0, 5, 0, pp, 0, 0) == 10 && !strcmp(gs(M32(pp)), "Error 5.\r\n"), "FormatMessageA allocating");
    crt_heap_free(M32(pp));
    CHECK(CALL("FormatMessageA", 0x1000, 0, 2, 0, b, 64, 0) == 10 && !strncmp(gs(b), "Error 2.", 8), "FormatMessageA into a buffer");
    last_error = 0;
    CHECK(CALL("FormatMessageA", 0x1000, 0, 2, 0, b, 4, 0) == 0 && last_error == 122, "FormatMessageA too small");
    last_error = 0;
    CHECK(CALL("OpenMutexA", 0x1F0001, 0, S("NFS")) == 0 && last_error == 2 && CALL("OpenEventA", 2, 0, S("x")) == 0, "Open*: no named objects");
    CHECK(CALL("SetThreadIdealProcessor", 0xFFFFFFFEu, 1) == 0, "SetThreadIdealProcessor");
    CHECK(CALL("LoadLibraryW", W("Server.dll")) == 0x02000000u && !strcmp(loaded, "Server.dll"), "LoadLibraryW forwards the name");
    CHECK(CALL("LoadLibraryExA", S("pbcl.dll"), 0, 0) == 0 && !strcmp(loaded, "pbcl.dll"), "LoadLibraryExA");
    CHECK(CALL("LoadLibraryExW", W("server.dll"), 0, 8) == 0x02000000u, "LoadLibraryExW");
}

static void test_user32(void) {
    CHECK(CALL("GetSystemMetrics", 0) == 1920 && CALL("GetSystemMetrics", 1) == 1080 && CALL("GetSystemMetrics", 80) == 1 &&
          CALL("GetSystemMetrics", 23) == 0, "GetSystemMetrics");
    uint32_t r = galloc(24);
    CHECK(CALL("SystemParametersInfoA", 0x30, 0, r, 0) == 1 && M32(r + 8) == 1920 && M32(r + 12) == 1080, "SPI_GETWORKAREA");
    M32(r) = 8; M32(r + 4) = 0x7F;
    CHECK(CALL("SystemParametersInfoA", 0x3A, 8, r, 0) == 1 && M32(r) == 8 && M32(r + 4) == 0, "SPI_GETSTICKYKEYS: off, cbSize kept");
    CHECK(CALL("SystemParametersInfoA", 0x3B, 8, r, 0) == 1, "SPI_SETSTICKYKEYS");
    last_error = 0;
    CHECK(CALL("SystemParametersInfoA", 0x1234, 0, r, 0) == 0 && last_error == 87, "an action not modelled fails");
    uint32_t dm = galloc(156);
    M16(dm + 36) = 156;
    CHECK(CALL("EnumDisplaySettingsA", 0, 0xFFFFFFFFu, dm) == 1 && M32(dm + 104) == 32 && M32(dm + 108) == 1920 && M32(dm + 112) == 1080 &&
          M32(dm + 120) == 60 && M16(dm + 36) == 156, "EnumDisplaySettingsA current mode");
    CHECK(CALL("EnumDisplaySettingsA", 0, 1, dm) == 0, "only one mode");
    uint32_t s = S("MiXeD Case");
    CHECK(CALL("CharLowerA", s) == s && !strcmp(gs(s), "mixed case"), "CharLowerA string");
    CHECK(CALL("CharLowerA", 'Q') == 'q', "CharLowerA character");
    s = S("ABCDEF");
    CHECK(CALL("CharLowerBuffA", s, 3) == 3 && !strcmp(gs(s), "abcDEF"), "CharLowerBuffA");
    CHECK(CALL("GetSysColor", 5) == 0xFFFFFF && CALL("GetSysColor", 8) == 0 && CALL("GetSysColorBrush", 5), "GetSysColor(Brush)");
    CHECK(CALL("FindWindowA", S("NFS"), 0) == 0 && CALL("FindWindowExA", 0, 0, S("NFS"), 0) == 0, "FindWindow(Ex)A: no other instance");
}

static void test_other(void) {
    uint32_t b = galloc(32), n = galloc(4);
    M32(n) = 3;
    last_error = 0;
    CHECK(CALL("GetUserNameA", b, n) == 0 && last_error == 122 && M32(n) == 7, "GetUserNameA small buffer");
    M32(n) = 32;
    CHECK(CALL("GetUserNameA", b, n) == 1 && !strcmp(gs(b), "Player") && M32(n) == 7, "GetUserNameA counts the terminator");
    uint32_t prov = galloc(4), rnd = galloc(32);
    CHECK(CALL("CryptAcquireContextA", prov, 0, 0, 1, 0xF0000000u) == 1 && M32(prov), "CryptAcquireContextA");
    CHECK(CALL("CryptGenRandom", M32(prov), 32, rnd) == 1 && (M64(rnd) | M64(rnd + 8) | M64(rnd + 16) | M64(rnd + 24)), "CryptGenRandom fills");
    CHECK(CALL("CryptReleaseContext", M32(prov), 0) == 1, "CryptReleaseContext");
    uint32_t hv = galloc(4);
    M32(hv) = 9;
    last_error = 0;
    CHECK(CALL("GetFileVersionInfoSizeA", S("nfs.exe"), hv) == 0 && M32(hv) == 0 && last_error == 1813, "no version resource");
    CHECK(CALL("GetFileVersionInfoA", S("nfs.exe"), 0, 0, 0) == 0 && CALL("VerQueryValueA", 0, 0, 0, 0) == 0, "version queries fail");
    uint32_t g1 = galloc(16), g2 = galloc(16);
    CHECK(CALL("CoCreateGuid", g1) == 0 && CALL("CoCreateGuid", g2) == 0 && memcmp(G + g1, G + g2, 16), "CoCreateGuid: two differ");
    CHECK((M16(g1 + 6) >> 12) == 4 && (M8(g1 + 8) >> 6) == 2, "version 4, RFC 4122 variant");
    uint32_t out = galloc(4);
    CHECK(CALL("UuidToStringA", g1, out) == 0 && M32(out), "UuidToStringA");
    const char *u = gs(M32(out));
    char first[9];
    snprintf(first, sizeof first, "%08x", M32(g1));
    CHECK(strlen(u) == 36 && u[8] == '-' && u[13] == '-' && u[18] == '-' && u[23] == '-' && !strncmp(u, first, 8) && u[14] == '4',
          "UuidToStringA format: %s", u);
    uint32_t before = live;
    CHECK(CALL("RpcStringFreeA", out) == 0 && M32(out) == 0 && live == before - 1, "RpcStringFreeA frees and clears");
}

int main(void) {
    G = mmap(0, 1ull << 32, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON | MAP_NORESERVE, -1, 0);
    if (G == MAP_FAILED) { printf("cannot reserve guest memory\n"); return 2; }
    const char *tmp = getenv("C_TEST_TMP") ? getenv("C_TEST_TMP") : getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp";
    snprintf(root, sizeof root, "%s/win32_more_test.XXXXXX", tmp);
    if (!mkdtemp(root)) { printf("cannot create a scratch directory\n"); return 2; }
    build_image();
    test_resources();
    test_files();
    test_strings_memory();
    test_system();
    test_user32();
    test_other();
    CHECK(!win32_more(c, "NoSuchFunction"), "unknown functions are not handled");
    host_file_remove("data.bin", 0);
    rmdir(root);
    if (getenv("WIN32_MORE_TEST_SELFCHECK")) CHECK(CALL0("GetVersion") == 0x0A280106u, "deliberately wrong");
    printf("%s: %d checks, %d failing\n", fails ? "FAIL" : "ok", checks, fails);
    return fails ? 1 : 0;
}
