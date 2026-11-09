// d3dx_tex_test.c - standalone test of d3dx_tex.c against a fake IDirect3DDevice9; no game files.
// Built and run by runtime/d3dx_tex_test.py (c_test_driver.py). The fake device, cube/volume textures, surfaces and the
// shim's ID3DXBuffer all live behind guest vtables and are reached through call_guest, as on the real runtime. Locked
// pitches are deliberately wider than the packed rows, so the copies must go row by row. Files are real
// (test_hostfs.h). D3DX_TEX_TEST_SELFCHECK=1 adds one deliberately wrong expectation.
#include <CoreFoundation/CoreFoundation.h>
#include <CoreGraphics/CoreGraphics.h>
#include <ImageIO/ImageIO.h>
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

static uint32_t bump = 0x10000000u, live;
uint32_t galloc(uint32_t n) { uint32_t a = (bump + 15) & ~15u; bump = a + (n ? n : 1); memset(G + a, 0, n); return a; }
uint32_t gmalloc(uint32_t n) { uint32_t a = galloc(n + 16) + 16; M32(a - 4) = 0xA110CA7Eu; ++live; return a; }
void gfree(uint32_t a) { if (!a) return; if (M32(a - 4) == 0xA110CA7Eu) { M32(a - 4) = 0; --live; } else { ++fails; printf("FAIL bad gfree %08X\n", a); } }

// ---- host functions and call_guest, as boot.c does them: a table of HostFn behind guest addresses ----
static HostFn fns[512];
static unsigned nfns;
uint32_t host_fn(HostFn fn, const char *name) { (void)name; fns[nfns] = fn; return HOSTFN_BASE + 4 * nfns++; }
uint32_t call_guest(Cpu *cc, uint32_t fn, int n, const uint32_t *args) {
    uint32_t sp = cc->esp;
    for (int i = n - 1; i >= 0; --i) { cc->esp -= 4; M32(cc->esp) = args[i]; }
    cc->esp -= 4;
    M32(cc->esp) = 0xFEEDF00Du;
    uint32_t want = cc->esp + 4 + 4 * (uint32_t)n, k = (fn - HOSTFN_BASE) / 4;
    if (fn < HOSTFN_BASE || k >= nfns) { printf("FAIL call to unknown %08X\n", fn); ++fails; cc->esp = sp; return 0; }
    fns[k](cc);
    CHECK(cc->esp == want, "a COM method popped the wrong number of arguments");
    cc->esp = sp;
    return cc->eax;
}

// ---- the fake device and resources ----
#define INVALIDCALL 0x8876086Cu
enum { CUBE = 1, VOLUME, SURFACE };
typedef struct { int kind; uint32_t fmt, w, h, d, levels, pool, usage, refs; uint32_t mem[6][16], pitch[16], slice[16]; int locks, unlocks, lock_flags; } Res;
static Res res[32];
static unsigned nres;
static int cube_fail;
static uint32_t vt_cube, vt_volume, vt_surface;
#define THIS (&res[M32(arg(c, 0) + 4)])
static int is_dxt(uint32_t f) { return (f & 0xFFFFFF) == 0x545844 && (f >> 24) >= '1' && (f >> 24) <= '5'; }
static uint32_t bpp(uint32_t f) { return is_dxt(f) ? (f == 0x31545844 ? 8 : 16) : f == 20 ? 3 : f == 23 || f == 24 || f == 25 || f == 26 || f == 51 ? 2 : f == 50 || f == 28 ? 1 : f == 113 ? 8 : 4; }
static uint32_t mip(uint32_t v, uint32_t l) { v >>= l; return v ? v : 1; }
static uint32_t rowb(uint32_t f, uint32_t w) { return is_dxt(f) ? (w + 3) / 4 * bpp(f) : w * bpp(f); }
static uint32_t nrows(uint32_t f, uint32_t h) { return is_dxt(f) ? (h + 3) / 4 : h; }
static uint32_t new_res(int kind, uint32_t vt, uint32_t fmt, uint32_t w, uint32_t h, uint32_t d, uint32_t levels) {
    Res *r = &res[nres];
    memset(r, 0, sizeof *r);
    r->kind = kind; r->fmt = fmt; r->w = w; r->h = h; r->d = d; r->levels = levels; r->refs = 1;
    for (uint32_t l = 0; l < levels; ++l) {
        r->pitch[l] = rowb(fmt, mip(w, l)) + 12;                 // wider than packed: copies must honour it
        r->slice[l] = r->pitch[l] * nrows(fmt, mip(h, l)) + 32;
        for (int f = 0; f < (kind == CUBE ? 6 : 1); ++f) {
            r->mem[f][l] = galloc(r->slice[l] * mip(d, l));
            memset(G + r->mem[f][l], 0xCD, r->slice[l] * mip(d, l));
        }
    }
    uint32_t o = galloc(8);
    M32(o) = vt; M32(o + 4) = nres++;
    return o;
}
static int unimplemented(Cpu *cc) { (void)cc; printf("FAIL unexpected COM method\n"); ++fails; RET(INVALIDCALL, 0); }
static int r_Release(Cpu *c) { RET(--THIS->refs, 1); }
static int cube_Lock(Cpu *c) {        // (this, face, level, locked*, rect*, flags)
    Res *r = THIS;
    uint32_t f = arg(c, 1), l = arg(c, 2);
    if (f > 5 || l >= r->levels) RET(INVALIDCALL, 6);
    M32(arg(c, 3)) = r->pitch[l]; M32(arg(c, 3) + 4) = r->mem[f][l];
    ++r->locks;
    RET(0, 6);
}
static int cube_Unlock(Cpu *c) { ++THIS->unlocks; RET(0, 3); }
static int vol_Lock(Cpu *c) {         // (this, level, D3DLOCKED_BOX*, box*, flags)
    Res *r = THIS;
    uint32_t l = arg(c, 1), b = arg(c, 2);
    if (l >= r->levels) RET(INVALIDCALL, 5);
    M32(b) = r->pitch[l]; M32(b + 4) = r->slice[l]; M32(b + 8) = r->mem[0][l];
    ++r->locks;
    RET(0, 5);
}
static int vol_Unlock(Cpu *c) { ++THIS->unlocks; RET(0, 2); }
static int surf_Desc(Cpu *c) {
    Res *r = THIS;
    uint32_t d = arg(c, 1);
    memset(G + d, 0, 32);
    M32(d) = r->fmt; M32(d + 4) = 1; M32(d + 24) = r->w; M32(d + 28) = r->h;
    RET(0, 2);
}
static int surf_Lock(Cpu *c) { Res *r = THIS; M32(arg(c, 1)) = r->pitch[0]; M32(arg(c, 1) + 4) = r->mem[0][0]; r->lock_flags = (int)arg(c, 3); ++r->locks; RET(0, 4); }
static int surf_Unlock(Cpu *c) { ++THIS->unlocks; RET(0, 1); }
static uint32_t cube_args[7], vol_args[9];
static int dev_CreateCube(Cpu *c) {   // (this, edge, levels, usage, fmt, pool, pp, shared)
    for (int i = 0; i < 7; ++i) cube_args[i] = arg(c, 1 + i);
    if (cube_fail) RET(INVALIDCALL, 8);
    M32(arg(c, 6)) = new_res(CUBE, vt_cube, arg(c, 4), arg(c, 1), arg(c, 1), 1, arg(c, 2));
    RET(0, 8);
}
static int dev_CreateVolume(Cpu *c) { // (this, w, h, d, levels, usage, fmt, pool, pp, shared)
    for (int i = 0; i < 9; ++i) vol_args[i] = arg(c, 1 + i);
    M32(arg(c, 8)) = new_res(VOLUME, vt_volume, arg(c, 6), arg(c, 1), arg(c, 2), arg(c, 3), arg(c, 4));
    RET(0, 10);
}
static uint32_t make_vt(int n, const int *slots, const HostFn *impl, int m) {
    uint32_t vt = galloc(4 * (uint32_t)n);
    for (int i = 0; i < n; ++i) M32(vt + 4 * (uint32_t)i) = host_fn(unimplemented, "?");
    for (int k = 0; k < m; ++k) M32(vt + 4 * (uint32_t)slots[k]) = host_fn(impl[k], "impl");
    return vt;
}
static uint32_t device;
static void build_fakes(void) {
    uint32_t dvt = make_vt(119, (int[]){24, 25}, (HostFn[]){dev_CreateVolume, dev_CreateCube}, 2);
    device = galloc(8);
    M32(device) = dvt;
    vt_cube = make_vt(22, (int[]){2, 19, 20}, (HostFn[]){r_Release, cube_Lock, cube_Unlock}, 3);
    vt_volume = make_vt(22, (int[]){2, 19, 20}, (HostFn[]){r_Release, vol_Lock, vol_Unlock}, 3);
    vt_surface = make_vt(17, (int[]){2, 12, 13, 14}, (HostFn[]){r_Release, surf_Desc, surf_Lock, surf_Unlock}, 4);
}

// ---- calling the shim ----
static int call(const char *fn, int n, const uint32_t *args) {
    uint32_t sp = 0x7F000000u;
    for (int i = n - 1; i >= 0; --i) { sp -= 4; M32(sp) = args[i]; }
    sp -= 4;
    M32(sp) = 0xDEADC0DEu;
    c->esp = sp;
    int ok = d3dx_tex(c, fn);
    if (ok) CHECK(c->esp == sp + 4 + 4 * (uint32_t)n, "%s: __stdcall pops %d arguments", fn, n);
    return ok;
}
static uint32_t callv(const char *fn, int n, const uint32_t *args) { if (call(fn, n, args)) return c->eax; CHECK(0, "%s not handled", fn); return 0xBAD; }
#define A(...) ((const uint32_t[]){__VA_ARGS__})
#define NA(...) (int)(sizeof((const uint32_t[]){__VA_ARGS__}) / 4)
#define CALL(fn, ...) callv(fn, NA(__VA_ARGS__), A(__VA_ARGS__))
static uint32_t S(const char *s) { uint32_t a = galloc((uint32_t)strlen(s) + 1); strcpy((char *)G + a, s); return a; }

// ---- DDS files in guest memory ----
#define FOURCC(a, b, c, d) ((uint32_t)(a) | (uint32_t)(b) << 8 | (uint32_t)(c) << 16 | (uint32_t)(d) << 24)
typedef struct { uint32_t flags, cc, bits, r, g, b, a; } PF;
static const PF PF_DXT1 = {0x4, FOURCC('D', 'X', 'T', '1'), 0, 0, 0, 0, 0}, PF_ARGB = {0x41, 0, 32, 0xFF0000, 0xFF00, 0xFF, 0xFF000000},
                PF_XRGB = {0x40, 0, 32, 0xFF0000, 0xFF00, 0xFF, 0};
// A DDS with every byte of the payload numbered (k * 7 + 1) so misplaced copies show. Returns the guest address.
static uint32_t dds(uint32_t w, uint32_t h, uint32_t d, uint32_t levels, PF pf, uint32_t caps2, uint32_t payload, uint32_t *size) {
    uint32_t p = galloc(128 + payload);
    M32(p) = FOURCC('D', 'D', 'S', ' '); M32(p + 4) = 124;
    M32(p + 8) = 0x1007 | (levels > 1 ? 0x20000 : 0) | (d > 1 ? 0x800000 : 0);
    M32(p + 12) = h; M32(p + 16) = w; M32(p + 24) = d; M32(p + 28) = levels;
    M32(p + 76) = 32; M32(p + 80) = pf.flags; M32(p + 84) = pf.cc; M32(p + 88) = pf.bits;
    M32(p + 92) = pf.r; M32(p + 96) = pf.g; M32(p + 100) = pf.b; M32(p + 104) = pf.a;
    M32(p + 108) = 0x1000; M32(p + 112) = caps2;
    for (uint32_t k = 0; k < payload; ++k) M8(p + 128 + k) = (uint8_t)(k * 7 + 1);
    *size = 128 + payload;
    return p;
}

static void test_cube(void) {
    // DXT1 16x16, 3 levels (16, 8, 4): 128 + 32 + 8 bytes per face
    uint32_t n, per_face = 128 + 32 + 8, f = dds(16, 16, 1, 3, PF_DXT1, 0xFE00, 6 * per_face, &n), out = galloc(4);
    CHECK(CALL("D3DXCreateCubeTextureFromFileInMemory", device, f, n, out) == 0 && M32(out), "a DXT1 cube loads");
    CHECK(cube_args[0] == 16 && cube_args[1] == 3 && cube_args[2] == 0 && cube_args[3] == FOURCC('D', 'X', 'T', '1') && cube_args[4] == 1 && cube_args[5] == out,
          "CreateCubeTexture(16, 3 levels, usage 0, DXT1, MANAGED)");
    Res *r = &res[M32(M32(out) + 4)];
    int same = 1;
    uint32_t src = f + 128;
    for (uint32_t fc = 0; fc < 6; ++fc)
        for (uint32_t l = 0; l < 3; ++l) {
            uint32_t rb = rowb(r->fmt, mip(16, l)), nr = nrows(r->fmt, mip(16, l));
            for (uint32_t y = 0; y < nr; ++y) {
                same &= !memcmp(G + r->mem[fc][l] + y * r->pitch[l], G + src, rb);
                same &= M8(r->mem[fc][l] + y * r->pitch[l] + rb) == 0xCD;   // the padding is left alone
                src += rb;
            }
        }
    CHECK(same, "every face and level copied row by row into the locked pitch");
    CHECK(r->locks == 18 && r->unlocks == 18, "18 locks, 18 unlocks (%d, %d)", r->locks, r->unlocks);
    // 32-bit ARGB and XRGB masks map to A8R8G8B8 / X8R8G8B8
    f = dds(4, 4, 1, 1, PF_ARGB, 0xFE00, 6 * 64, &n);
    CHECK(CALL("D3DXCreateCubeTextureFromFileInMemory", device, f, n, out) == 0 && cube_args[3] == 21, "ARGB -> A8R8G8B8");
    f = dds(4, 4, 1, 1, PF_XRGB, 0xFE00, 6 * 64, &n);
    CHECK(CALL("D3DXCreateCubeTextureFromFileInMemory", device, f, n, out) == 0 && cube_args[3] == 22, "XRGB -> X8R8G8B8");
    static const struct { PF pf; uint32_t bytes, want; const char *what; } more[] = {
        {{0x40, 0, 16, 0xF800, 0x7E0, 0x1F, 0}, 2, 23, "R5G6B5"}, {{0x41, 0, 16, 0x7C00, 0x3E0, 0x1F, 0x8000}, 2, 25, "A1R5G5B5"},
        {{0x20000, 0, 8, 0xFF, 0, 0, 0}, 1, 50, "L8"}, {{0x2, 0, 8, 0, 0, 0, 0xFF}, 1, 28, "A8"}, {{0x4, 113, 0, 0, 0, 0, 0}, 8, 113, "fourCC 113 (A16B16G16R16F)"}};
    for (unsigned k = 0; k < sizeof more / sizeof *more; ++k) {
        f = dds(2, 2, 1, 1, more[k].pf, 0xFE00, 6 * 4 * more[k].bytes, &n);
        CHECK(CALL("D3DXCreateCubeTextureFromFileInMemory", device, f, n, out) == 0 && cube_args[3] == more[k].want, "%s", more[k].what);
    }
    // bad files
    f = dds(4, 4, 1, 1, PF_ARGB, 0x200 | 0x400, 6 * 64, &n);
    CHECK(CALL("D3DXCreateCubeTextureFromFileInMemory", device, f, n, out) == 0x88760B59u, "a cube missing faces is invalid data");
    f = dds(4, 4, 1, 1, PF_ARGB, 0xFE00, 6 * 64 - 1, &n);
    CHECK(CALL("D3DXCreateCubeTextureFromFileInMemory", device, f, n, out) == 0x88760B59u, "a truncated cube is invalid data");
    f = dds(4, 4, 1, 1, PF_ARGB, 0, 64, &n);
    CHECK(CALL("D3DXCreateCubeTextureFromFileInMemory", device, f, n, out) == 0x88760B59u, "a 2D file is not a cube");
    f = dds(4, 4, 1, 1, (PF){0x40, 0, 32, 0x3FF, 0xFFC00, 0x3FF00000, 0}, 0xFE00, 6 * 64, &n);
    CHECK(CALL("D3DXCreateCubeTextureFromFileInMemory", device, f, n, out) == 0x88760B59u, "an unsupported pixel format");
    M32(f) = 0;
    CHECK(CALL("D3DXCreateCubeTextureFromFileInMemory", device, f, n, out) == 0x88760B59u, "no DDS magic");
    CHECK(CALL("D3DXCreateCubeTextureFromFileInMemory", device, f, n, 0) == INVALIDCALL, "no output pointer");
    f = dds(4, 4, 1, 1, PF_ARGB, 0xFE00, 6 * 64, &n);
    cube_fail = 1;
    CHECK(CALL("D3DXCreateCubeTextureFromFileInMemory", device, f, n, out) == INVALIDCALL, "the device's error is passed on");
    cube_fail = 0;
}

static void test_volume(void) {
    // X8R8G8B8 4x4x4, 3 levels: 4x4x4 (256 bytes), 2x2x2 (32), 1x1x1 (4)
    uint32_t n, f = dds(4, 4, 4, 3, PF_XRGB, 0x200000, 256 + 32 + 4, &n), out = galloc(4);
    CHECK(CALL("D3DXCreateVolumeTextureFromFileInMemory", device, f, n, out) == 0 && M32(out), "a volume loads");
    CHECK(vol_args[0] == 4 && vol_args[1] == 4 && vol_args[2] == 4 && vol_args[3] == 3 && vol_args[5] == 22 && vol_args[6] == 1, "CreateVolumeTexture(4x4x4, 3 levels, X8R8G8B8, MANAGED)");
    Res *r = &res[M32(M32(out) + 4)];
    int same = 1;
    uint32_t src = f + 128;
    for (uint32_t l = 0; l < 3; ++l) {
        uint32_t rb = 4 * mip(4, l);
        for (uint32_t z = 0; z < mip(4, l); ++z)
            for (uint32_t y = 0; y < mip(4, l); ++y) { same &= !memcmp(G + r->mem[0][l] + z * r->slice[l] + y * r->pitch[l], G + src, rb); src += rb; }
    }
    CHECK(same, "slices and rows land at the locked slice and row pitches");
    CHECK(r->locks == 3 && r->unlocks == 3, "one LockBox/UnlockBox per level");
    f = dds(4, 4, 4, 1, PF_XRGB, 0xFE00, 6 * 256, &n);
    CHECK(CALL("D3DXCreateVolumeTextureFromFileInMemory", device, f, n, out) == 0x88760B59u, "a cube is not a volume");
}

// A surface with known pixels: (x, y) -> R = 40x+1, G = 50y+2, B = 77, A = 128 (A8R8G8B8 memory order B, G, R, A).
static uint32_t make_surface(uint32_t fmt, uint32_t w, uint32_t h) {
    uint32_t s = new_res(SURFACE, vt_surface, fmt, w, h, 1, 1);
    Res *r = &res[M32(s + 4)];
    uint32_t units_x = is_dxt(fmt) ? (w + 3) / 4 : w, units_y = nrows(fmt, h);   // DXT: bpp() bytes per 4x4 block
    for (uint32_t y = 0; y < units_y; ++y)
        for (uint32_t x = 0; x < units_x; ++x) {
            uint32_t a = r->mem[0][0] + y * r->pitch[0] + x * bpp(fmt);
            if (fmt == 21 || fmt == 22) { M8(a) = 77; M8(a + 1) = (uint8_t)(50 * y + 2); M8(a + 2) = (uint8_t)(40 * x + 1); M8(a + 3) = 128; }
            else for (uint32_t k = 0; k < bpp(fmt); ++k) M8(a + k) = (uint8_t)(x * 16 + y * 4 + k);
        }
    return s;
}
static size_t read_file(const char *rel, uint8_t *buf, size_t cap) {
    char p[1024];
    snprintf(p, sizeof p, "%s/%s", root, rel);
    FILE *f = fopen(p, "rb");
    if (!f) return 0;
    size_t n = fread(buf, 1, cap, f);
    fclose(f);
    return n;
}
static uint32_t le32(const uint8_t *p) { return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }

static void test_save(void) {
    static uint8_t b[1 << 16];
    uint32_t argb = make_surface(21, 3, 2), xrgb = make_surface(22, 3, 2);
    Res *ra = &res[M32(argb + 4)];
    // BMP, 32-bit for a surface with alpha: bottom-up rows, BGRA
    CHECK(CALL("D3DXSaveSurfaceToFileA", S("shot.bmp"), 0, argb, 0, 0) == 0, "save BMP");
    size_t n = read_file("shot.bmp", b, sizeof b);
    CHECK(n == 54 + 3 * 2 * 4 && b[0] == 'B' && b[1] == 'M' && le32(b + 2) == n && le32(b + 18) == 3 && le32(b + 22) == 2 && b[28] == 32, "BMP header (%zu bytes)", n);
    CHECK(b[54] == 77 && b[55] == 52 && b[56] == 1 && b[57] == 128, "the first BMP pixel is the bottom-left one (y = 1)");
    CHECK(ra->locks == 1 && ra->unlocks == 1 && ra->lock_flags == 0x10, "locked once, read-only, and unlocked");
    // 24-bit BMP without alpha, rows padded to 4 bytes (3 * 3 = 9 -> 12)
    CHECK(CALL("D3DXSaveSurfaceToFileA", S("shot24.bmp"), 0, xrgb, 0, 0) == 0, "save BMP 24");
    n = read_file("shot24.bmp", b, sizeof b);
    CHECK(n == 54 + 12 * 2 && b[28] == 24 && b[54 + 3] == 77 && b[54 + 5] == 41, "24-bit BMP, padded rows");
    // a rectangle: x 1..3, y 0..1 -> 2x1
    uint32_t rect = galloc(16);
    M32(rect) = 1; M32(rect + 4) = 0; M32(rect + 8) = 3; M32(rect + 12) = 1;
    CHECK(CALL("D3DXSaveSurfaceToFileA", S("rect.ppm"), 5, xrgb, 0, rect) == 0, "save a PPM of a rectangle");
    n = read_file("rect.ppm", b, sizeof b);
    CHECK(n == 11 + 6 && !memcmp(b, "P6\n2 1\n255\n", 11) && b[11] == 41 && b[12] == 2 && b[13] == 77 && b[14] == 81, "PPM pixels from x = 1");
    M32(rect + 8) = 4;
    CHECK(CALL("D3DXSaveSurfaceToFileA", S("bad.ppm"), 5, xrgb, 0, rect) == INVALIDCALL, "a rectangle outside the surface");
    // TGA: top-left origin, BGRA
    CHECK(CALL("D3DXSaveSurfaceToFileA", S("shot.tga"), 2, argb, 0, 0) == 0, "save TGA");
    n = read_file("shot.tga", b, sizeof b);
    CHECK(n == 18 + 24 && b[2] == 2 && b[12] == 3 && b[14] == 2 && b[16] == 32 && b[17] == 0x28 && b[18] == 77 && b[20] == 1 && b[21] == 128, "TGA");
    // DDS: header + the surface's own bytes
    CHECK(CALL("D3DXSaveSurfaceToFileA", S("shot.dds"), 4, argb, 0, 0) == 0, "save DDS");
    n = read_file("shot.dds", b, sizeof b);
    CHECK(n == 128 + 24 && le32(b) == FOURCC('D', 'D', 'S', ' ') && le32(b + 12) == 2 && le32(b + 16) == 3 && le32(b + 80) == 0x41 &&
          le32(b + 104) == 0xFF000000u && !memcmp(b + 128, G + ra->mem[0][0], 12) && !memcmp(b + 140, G + ra->mem[0][0] + ra->pitch[0], 12), "DDS");
    uint32_t dxt = make_surface(FOURCC('D', 'X', 'T', '1'), 8, 8);
    CHECK(CALL("D3DXSaveSurfaceToFileA", S("dxt.dds"), 4, dxt, 0, 0) == 0 && read_file("dxt.dds", b, sizeof b) == 128 + 32 &&
          le32(b + 84) == FOURCC('D', 'X', 'T', '1'), "a DXT1 surface saves as DDS");
    CHECK(CALL("D3DXSaveSurfaceToFileA", S("dxt.png"), 3, dxt, 0, 0) == INVALIDCALL, "but not as PNG");
    CHECK(CALL("D3DXSaveSurfaceToFileA", S("x.hdr"), 7, argb, 0, 0) == INVALIDCALL, "HDR is not written");
    // PNG round-trips through ImageIO; JPEG has its signature
    uint32_t opaque = make_surface(22, 3, 2);
    CHECK(CALL("D3DXSaveSurfaceToFileA", S("shot.png"), 3, opaque, 0, 0) == 0, "save PNG");
    n = read_file("shot.png", b, sizeof b);
    CHECK(n > 8 && !memcmp(b, "\x89PNG", 4), "PNG signature");
    CFDataRef data = CFDataCreate(NULL, b, (CFIndex)n);
    CGImageSourceRef src = CGImageSourceCreateWithData(data, NULL);
    CGImageRef img = src ? CGImageSourceCreateImageAtIndex(src, 0, NULL) : NULL;
    uint8_t px[3 * 2 * 4] = {0};
    if (img) {
        CGColorSpaceRef cs = CGColorSpaceCreateWithName(kCGColorSpaceSRGB);
        CGContextRef ctx = CGBitmapContextCreate(px, 3, 2, 8, 12, cs, (CGBitmapInfo)kCGImageAlphaNoneSkipLast);
        CGContextDrawImage(ctx, CGRectMake(0, 0, 3, 2), img);
        CGContextRelease(ctx);
        CGColorSpaceRelease(cs);
        CGImageRelease(img);
    }
    if (src) CFRelease(src);
    CFRelease(data);
    CHECK(px[0] == 1 && px[1] == 2 && px[2] == 77 && px[4 * 2] == 81 && px[12 + 1] == 52, "PNG pixels decode back (%u %u %u)", px[0], px[1], px[2]);
    CHECK(CALL("D3DXSaveSurfaceToFileA", S("shot.jpg"), 1, opaque, 0, 0) == 0, "save JPEG");
    n = read_file("shot.jpg", b, sizeof b);
    CHECK(n > 100 && b[0] == 0xFF && b[1] == 0xD8, "JPEG signature");
    // in memory: an ID3DXBuffer with the same bytes as the file
    uint32_t pbuf = galloc(4), before = live;
    CHECK(CALL("D3DXSaveSurfaceToFileInMemory", pbuf, 0, argb, 0, 0) == 0 && M32(pbuf), "save BMP in memory");
    uint32_t obj = M32(pbuf), vt = M32(obj);
    uint32_t ptr = call_guest(c, M32(vt + 12), 1, (uint32_t[]){obj}), size = call_guest(c, M32(vt + 16), 1, (uint32_t[]){obj});
    n = read_file("shot.bmp", b, sizeof b);
    CHECK(size == n && !memcmp(G + ptr, b, n), "GetBufferPointer/GetBufferSize: the BMP bytes");
    CHECK(call_guest(c, M32(vt + 4), 1, (uint32_t[]){obj}) == 2 && call_guest(c, M32(vt + 8), 1, (uint32_t[]){obj}) == 1, "AddRef/Release count");
    uint32_t ppv = galloc(4);
    CHECK(call_guest(c, M32(vt), 3, (uint32_t[]){obj, galloc(16), ppv}) == 0x80004002u && M32(ppv) == 0, "QueryInterface: E_NOINTERFACE");
    CHECK(call_guest(c, M32(vt + 8), 1, (uint32_t[]){obj}) == 0 && live == before, "the last Release frees the buffer and its data");
    CHECK(CALL("D3DXSaveSurfaceToFileInMemory", pbuf, 3, 0, 0, 0) == INVALIDCALL, "no surface");
    const char *files[] = {"shot.bmp", "shot24.bmp", "rect.ppm", "shot.tga", "shot.dds", "dxt.dds", "shot.png", "shot.jpg"};
    for (unsigned k = 0; k < sizeof files / sizeof *files; ++k) host_file_remove(files[k], 0);
}

int main(void) {
    G = mmap(0, 1ull << 32, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON | MAP_NORESERVE, -1, 0);
    if (G == MAP_FAILED) { printf("cannot reserve guest memory\n"); return 2; }
    const char *tmp = getenv("C_TEST_TMP") ? getenv("C_TEST_TMP") : getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp";
    snprintf(root, sizeof root, "%s/d3dx_tex_test.XXXXXX", tmp);
    if (!mkdtemp(root)) { printf("cannot create a scratch directory\n"); return 2; }
    build_fakes();
    test_cube();
    test_volume();
    test_save();
    CHECK(!d3dx_tex(c, "D3DXNoSuchFunction"), "unknown functions are not handled");
    if (getenv("D3DX_TEX_TEST_SELFCHECK")) CHECK(CALL("D3DXCreateVolumeTextureFromFileInMemory", device, 0, 0, galloc(4)) == 0, "deliberately wrong");
    rmdir(root);
    printf("%s: %d checks, %d failing\n", fails ? "FAIL" : "ok", checks, fails);
    return fails ? 1 : 0;
}
