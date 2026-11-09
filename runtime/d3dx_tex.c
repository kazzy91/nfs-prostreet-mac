// d3dx_tex.c - the d3dx9_34 texture file functions ProStreet imports beyond MW's d3dx9_26 set:
//   D3DXCreateCubeTextureFromFileInMemory, D3DXCreateVolumeTextureFromFileInMemory (DDS files),
//   D3DXSaveSurfaceToFileA, D3DXSaveSurfaceToFileInMemory (BMP, DIB, TGA, PPM, DDS natively; PNG and JPEG through ImageIO).
// Textures and surfaces are reached only through their D3D9 COM interfaces (the guest vtables, via call_guest), as the
// game's own code would, so this file does not depend on d3d9.m's internals and runs against any IDirect3DDevice9.
#include <CoreFoundation/CoreFoundation.h>
#include <CoreGraphics/CoreGraphics.h>
#include <ImageIO/ImageIO.h>
#include <stdlib.h>
#include <string.h>

#include "host.h"

uint32_t host_file_open(const char *win, uint32_t access, uint32_t share, uint32_t disp);
int64_t host_file_write(uint32_t h, uint32_t buf, uint32_t n);
int host_file_close(uint32_t h);

#define D3D_OK 0u
#define D3DERR_INVALIDCALL 0x8876086Cu
#define D3DXERR_INVALIDDATA 0x88760B59u
#define E_OUTOFMEMORY 0x8007000Eu
#define E_NOINTERFACE 0x80004002u
#define POOL_MANAGED 1u
// vtable slots (IUnknown 0-2, IDirect3DResource9 3-10, IDirect3DBaseTexture9 11-16)
enum { RELEASE = 2, DEV_CREATE_VOLUME = 24, DEV_CREATE_CUBE = 25, TEX_LOCK = 19, TEX_UNLOCK = 20, SURF_DESC = 12, SURF_LOCK = 13, SURF_UNLOCK = 14 };

// A COM call: this = obj, then n more arguments. Returns eax (an HRESULT for the D3D9 methods used here).
static uint32_t vcall(Cpu *c, uint32_t obj, int slot, int n, const uint32_t *args) {
    uint32_t a[12];
    a[0] = obj;
    for (int i = 0; i < n; ++i) a[1 + i] = args[i];
    return call_guest(c, M32(M32(obj) + 4 * (uint32_t)slot), n + 1, a);
}
static uint32_t scratch(void) { static uint32_t s; if (!s) s = galloc(64); return s; }   // locked rect / box / desc

// ---------------- formats ----------------
#define FOURCC(a, b, c, d) ((uint32_t)(a) | (uint32_t)(b) << 8 | (uint32_t)(c) << 16 | (uint32_t)(d) << 24)
static int is_dxt(uint32_t f) { return f >= FOURCC('D', 'X', 'T', '1') && f <= FOURCC('D', 'X', 'T', '5') && (f & 0xFFFFFF) == FOURCC('D', 'X', 'T', 0); }
static uint32_t bpp(uint32_t f) {   // bytes per pixel, or per 4x4 block for DXT; 0 = not a format these files carry
    if (is_dxt(f)) return f == FOURCC('D', 'X', 'T', '1') ? 8 : 16;
    switch (f) {
    case 20: return 3;                                            // R8G8B8
    case 21: case 22: case 32: case 33: case 31: case 35: case 34: case 114: return 4;   // A8R8G8B8 ... G16R16, R32F
    case 23: case 24: case 25: case 26: case 51: case 111: case 81: return 2;           // R5G6B5 ... A8L8, R16F, L16
    case 28: case 50: return 1;                                    // A8, L8
    case 36: case 113: case 115: return 8;                         // A16B16G16R16, A16B16G16R16F, G32R32F
    case 116: return 16;                                           // A32B32G32R32F
    }
    return 0;
}
static uint32_t mip(uint32_t v, uint32_t l) { v >>= l; return v ? v : 1; }
static uint32_t row_bytes(uint32_t f, uint32_t w) { return is_dxt(f) ? (w + 3) / 4 * bpp(f) : w * bpp(f); }
static uint32_t rows(uint32_t f, uint32_t h) { return is_dxt(f) ? (h + 3) / 4 : h; }

// ---------------- DDS ----------------
typedef struct { uint32_t w, h, d, levels, fmt, cube, volume, data, size; } Dds;
// DDS_PIXELFORMAT at p: the D3DFORMAT, or 0 when it isn't one of the formats above.
static uint32_t dds_format(uint32_t p) {
    uint32_t flags = M32(p + 4), cc = M32(p + 8), bits = M32(p + 12), r = M32(p + 16), g = M32(p + 20), b = M32(p + 24), a = M32(p + 28);
    int alpha = (flags & 0x1) && a;
    if (flags & 0x4) return bpp(cc) ? cc : 0;                    // DDPF_FOURCC: DXTn, or a numeric D3DFORMAT
    if (flags & 0x40) {                                          // DDPF_RGB
        if (bits == 32 && r == 0xFF0000 && g == 0xFF00 && b == 0xFF) return alpha ? 21 : 22;
        if (bits == 32 && r == 0xFF && g == 0xFF00 && b == 0xFF0000) return alpha ? 32 : 33;
        if (bits == 24 && r == 0xFF0000 && g == 0xFF00 && b == 0xFF) return 20;
        if (bits == 16 && r == 0xF800 && g == 0x7E0 && b == 0x1F) return 23;
        if (bits == 16 && r == 0x7C00 && g == 0x3E0 && b == 0x1F) return alpha ? 25 : 24;
        if (bits == 16 && r == 0xF00 && g == 0xF0 && b == 0xF && alpha) return 26;
        return 0;
    }
    if (flags & 0x20000) return bits == 8 ? 50 : bits == 16 && alpha ? 51 : bits == 16 ? 81 : 0;   // DDPF_LUMINANCE
    if ((flags & 0x2) && bits == 8) return 28;                   // DDPF_ALPHA
    return 0;
}
static uint64_t dds_bytes(const Dds *t) {
    uint64_t n = 0;
    for (uint32_t l = 0; l < t->levels; ++l)
        n += (uint64_t)row_bytes(t->fmt, mip(t->w, l)) * rows(t->fmt, mip(t->h, l)) * mip(t->d, l);
    return n * (t->cube ? 6 : 1);
}
static int dds_parse(uint32_t p, uint32_t n, Dds *t) {
    if (n < 128 || M32(p) != FOURCC('D', 'D', 'S', ' ') || M32(p + 4) != 124 || M32(p + 76) != 32) return 0;
    uint32_t flags = M32(p + 8), caps2 = M32(p + 112);
    memset(t, 0, sizeof *t);
    t->h = M32(p + 12); t->w = M32(p + 16);
    t->d = (flags & 0x800000) && (caps2 & 0x200000) && M32(p + 24) ? M32(p + 24) : 1;   // DDSD_DEPTH, DDSCAPS2_VOLUME
    t->levels = (flags & 0x20000) && M32(p + 28) ? M32(p + 28) : 1;                      // DDSD_MIPMAPCOUNT
    t->fmt = dds_format(p + 76);
    t->cube = (caps2 & 0x200) != 0;
    t->volume = (caps2 & 0x200000) != 0;
    t->data = p + 128; t->size = n - 128;
    if (!t->w || !t->h || !t->fmt || t->levels > 16 || t->w > 16384 || t->h > 16384 || t->d > 2048) return 0;
    if (t->cube && (caps2 & 0xFC00) != 0xFC00) return 0;         // a cube needs all six faces
    return dds_bytes(t) <= t->size;
}
// Copies `nrows` rows of `rb` bytes from packed source to a locked destination with its own pitch.
static void copy_rows(uint32_t dst, uint32_t pitch, uint32_t src, uint32_t rb, uint32_t nrows) {
    for (uint32_t y = 0; y < nrows; ++y) memmove(G + dst + y * pitch, G + src + y * rb, rb);
}

static uint32_t create_cube(Cpu *c, uint32_t dev, uint32_t data, uint32_t n, uint32_t out) {
    Dds t;
    if (!out || !dev || !data) return D3DERR_INVALIDCALL;
    if (!dds_parse(data, n, &t) || !t.cube || t.w != t.h) return D3DXERR_INVALIDDATA;
    uint32_t a[7] = {t.w, t.levels, 0, t.fmt, POOL_MANAGED, out, 0};
    uint32_t hr = vcall(c, dev, DEV_CREATE_CUBE, 7, a);
    if (hr) return hr;
    uint32_t tex = M32(out), lr = scratch(), src = t.data;
    for (uint32_t f = 0; f < 6; ++f)
        for (uint32_t l = 0; l < t.levels; ++l) {
            uint32_t rb = row_bytes(t.fmt, mip(t.w, l)), nr = rows(t.fmt, mip(t.h, l));
            if ((hr = vcall(c, tex, TEX_LOCK, 5, (uint32_t[]){f, l, lr, 0, 0}))) { vcall(c, tex, RELEASE, 0, NULL); M32(out) = 0; return hr; }
            copy_rows(M32(lr + 4), M32(lr), src, rb, nr);
            vcall(c, tex, TEX_UNLOCK, 2, (uint32_t[]){f, l});
            src += rb * nr;
        }
    return D3D_OK;
}
static uint32_t create_volume(Cpu *c, uint32_t dev, uint32_t data, uint32_t n, uint32_t out) {
    Dds t;
    if (!out || !dev || !data) return D3DERR_INVALIDCALL;
    if (!dds_parse(data, n, &t) || !t.volume || t.cube) return D3DXERR_INVALIDDATA;
    uint32_t a[9] = {t.w, t.h, t.d, t.levels, 0, t.fmt, POOL_MANAGED, out, 0};
    uint32_t hr = vcall(c, dev, DEV_CREATE_VOLUME, 9, a);
    if (hr) return hr;
    uint32_t tex = M32(out), lb = scratch(), src = t.data;
    for (uint32_t l = 0; l < t.levels; ++l) {
        uint32_t rb = row_bytes(t.fmt, mip(t.w, l)), nr = rows(t.fmt, mip(t.h, l)), nd = mip(t.d, l);
        if ((hr = vcall(c, tex, TEX_LOCK, 4, (uint32_t[]){l, lb, 0, 0}))) { vcall(c, tex, RELEASE, 0, NULL); M32(out) = 0; return hr; }
        uint32_t row_pitch = M32(lb), slice_pitch = M32(lb + 4), bits = M32(lb + 8);   // D3DLOCKED_BOX
        for (uint32_t z = 0; z < nd; ++z) { copy_rows(bits + z * slice_pitch, row_pitch, src, rb, nr); src += rb * nr; }
        vcall(c, tex, TEX_UNLOCK, 1, (uint32_t[]){l});
    }
    return D3D_OK;
}

// ---------------- saving surfaces ----------------
typedef struct { uint8_t *p; size_t n, cap; } Bytes;
static void put(Bytes *b, const void *s, size_t n) {
    if (b->n + n > b->cap) { b->cap = (b->n + n) * 2 + 256; b->p = realloc(b->p, b->cap); }
    memcpy(b->p + b->n, s, n);
    b->n += n;
}
static void put16(Bytes *b, uint32_t v) { uint8_t x[2] = {(uint8_t)v, (uint8_t)(v >> 8)}; put(b, x, 2); }
static void put32(Bytes *b, uint32_t v) { uint8_t x[4] = {(uint8_t)v, (uint8_t)(v >> 8), (uint8_t)(v >> 16), (uint8_t)(v >> 24)}; put(b, x, 4); }
// A pixel of format f at guest address a as R, G, B, A bytes; 0 if f isn't convertible.
static int to_rgba(uint32_t f, uint32_t a, uint8_t *o) {
    uint32_t v;
    switch (f) {
    case 21: case 22: o[2] = M8(a); o[1] = M8(a + 1); o[0] = M8(a + 2); o[3] = f == 21 ? M8(a + 3) : 255; return 1;
    case 32: case 33: o[0] = M8(a); o[1] = M8(a + 1); o[2] = M8(a + 2); o[3] = f == 32 ? M8(a + 3) : 255; return 1;
    case 20: o[2] = M8(a); o[1] = M8(a + 1); o[0] = M8(a + 2); o[3] = 255; return 1;
    case 23: v = M16(a); o[0] = (uint8_t)((v >> 11) * 255 / 31); o[1] = (uint8_t)((v >> 5 & 63) * 255 / 63); o[2] = (uint8_t)((v & 31) * 255 / 31); o[3] = 255; return 1;
    case 24: case 25: v = M16(a); o[0] = (uint8_t)((v >> 10 & 31) * 255 / 31); o[1] = (uint8_t)((v >> 5 & 31) * 255 / 31); o[2] = (uint8_t)((v & 31) * 255 / 31);
        o[3] = f == 25 ? (v >> 15 ? 255 : 0) : 255; return 1;
    case 26: v = M16(a); o[0] = (uint8_t)((v >> 8 & 15) * 17); o[1] = (uint8_t)((v >> 4 & 15) * 17); o[2] = (uint8_t)((v & 15) * 17); o[3] = (uint8_t)((v >> 12) * 17); return 1;
    case 50: o[0] = o[1] = o[2] = M8(a); o[3] = 255; return 1;
    }
    return 0;
}
static int has_alpha(uint32_t f) { return f == 21 || f == 32 || f == 25 || f == 26; }
// ImageIO for PNG and JPEG: RGBA rows (premultiplication doesn't matter for opaque frames; alpha is kept for PNG).
static int encode_imageio(const uint8_t *rgba, uint32_t w, uint32_t h, int png, Bytes *out) {
    CGColorSpaceRef cs = CGColorSpaceCreateWithName(kCGColorSpaceSRGB);
    CGDataProviderRef dp = CGDataProviderCreateWithData(NULL, rgba, (size_t)w * h * 4, NULL);
    CGImageRef img = CGImageCreate(w, h, 8, 32, (size_t)w * 4, cs, (CGBitmapInfo)(png ? kCGImageAlphaLast : kCGImageAlphaNoneSkipLast),
                                   dp, NULL, false, kCGRenderingIntentDefault);
    CFMutableDataRef data = CFDataCreateMutable(NULL, 0);
    CGImageDestinationRef dst = CGImageDestinationCreateWithData(data, png ? CFSTR("public.png") : CFSTR("public.jpeg"), 1, NULL);
    int ok = 0;
    if (img && dst) {
        CGImageDestinationAddImage(dst, img, NULL);
        ok = CGImageDestinationFinalize(dst);
    }
    if (ok) put(out, CFDataGetBytePtr(data), (size_t)CFDataGetLength(data));
    if (dst) CFRelease(dst);
    CFRelease(data);
    if (img) CGImageRelease(img);
    CGDataProviderRelease(dp);
    CGColorSpaceRelease(cs);
    return ok;
}
// Encodes surface `surf` (optionally the RECT at `rect`) as D3DXIMAGE_FILEFORMAT iff into out. D3D_OK or an HRESULT.
static uint32_t encode_surface(Cpu *c, uint32_t surf, uint32_t rect, uint32_t iff, Bytes *out) {
    if (!surf) return D3DERR_INVALIDCALL;
    uint32_t desc = scratch() + 16;
    uint32_t hr = vcall(c, surf, SURF_DESC, 1, (uint32_t[]){desc});
    if (hr) return hr;
    uint32_t fmt = M32(desc), sw = M32(desc + 24), sh = M32(desc + 28);
    uint32_t x0 = 0, y0 = 0, x1 = sw, y1 = sh;
    if (rect) { x0 = M32(rect); y0 = M32(rect + 4); x1 = M32(rect + 8); y1 = M32(rect + 12); }
    if (x0 >= x1 || y0 >= y1 || x1 > sw || y1 > sh) return D3DERR_INVALIDCALL;
    if (iff > 6 || !bpp(fmt) || (is_dxt(fmt) && (iff != 4 || rect))) return D3DERR_INVALIDCALL;   // HDR, PFM: not written
    uint32_t w = x1 - x0, h = y1 - y0, lr = scratch();
    if ((hr = vcall(c, surf, SURF_LOCK, 3, (uint32_t[]){lr, 0, 0x10}))) return hr;              // D3DLOCK_READONLY
    uint32_t pitch = M32(lr), bits = M32(lr + 4), px = bpp(fmt);
    hr = D3D_OK;
    if (iff == 4) {                                              // DDS: the surface's own format, rows as they are
        uint32_t rb = is_dxt(fmt) ? row_bytes(fmt, w) : w * px, nr = rows(fmt, h);
        put32(out, FOURCC('D', 'D', 'S', ' '));
        put32(out, 124); put32(out, 0x1007 | (is_dxt(fmt) ? 0x80000 : 0x8));   // CAPS|HEIGHT|WIDTH|PIXELFORMAT + LINEARSIZE/PITCH
        put32(out, h); put32(out, w); put32(out, is_dxt(fmt) ? rb * nr : rb); put32(out, 0); put32(out, 1);
        for (int k = 0; k < 11; ++k) put32(out, 0);
        put32(out, 32);
        static const struct { uint32_t f, flags, bits, r, g, b, a; } pf[] = {
            {21, 0x41, 32, 0xFF0000, 0xFF00, 0xFF, 0xFF000000}, {22, 0x40, 32, 0xFF0000, 0xFF00, 0xFF, 0}, {32, 0x41, 32, 0xFF, 0xFF00, 0xFF0000, 0xFF000000},
            {33, 0x40, 32, 0xFF, 0xFF00, 0xFF0000, 0}, {20, 0x40, 24, 0xFF0000, 0xFF00, 0xFF, 0}, {23, 0x40, 16, 0xF800, 0x7E0, 0x1F, 0},
            {25, 0x41, 16, 0x7C00, 0x3E0, 0x1F, 0x8000}, {24, 0x40, 16, 0x7C00, 0x3E0, 0x1F, 0}, {26, 0x41, 16, 0xF00, 0xF0, 0xF, 0xF000},
            {50, 0x20000, 8, 0xFF, 0, 0, 0}, {51, 0x20001, 16, 0xFF, 0, 0, 0xFF00}, {28, 0x2, 8, 0, 0, 0, 0xFF}};
        unsigned k = 0;
        while (k < sizeof pf / sizeof *pf && pf[k].f != fmt) ++k;
        if (k < sizeof pf / sizeof *pf) { put32(out, pf[k].flags); put32(out, 0); put32(out, pf[k].bits); put32(out, pf[k].r); put32(out, pf[k].g); put32(out, pf[k].b); put32(out, pf[k].a); }
        else { put32(out, 0x4); put32(out, fmt); for (int z = 0; z < 5; ++z) put32(out, 0); }   // FOURCC: DXTn or a numeric format
        put32(out, 0x1000); for (int z = 0; z < 4; ++z) put32(out, 0);                          // DDSCAPS_TEXTURE
        uint32_t first = (is_dxt(fmt) ? 0 : y0 * pitch + x0 * px);
        for (uint32_t y = 0; y < nr; ++y) put(out, G + bits + first + y * pitch, rb);
    } else {
        uint8_t *rgba = malloc((size_t)w * h * 4);
        int ok = rgba != NULL;
        for (uint32_t y = 0; ok && y < h; ++y)
            for (uint32_t x = 0; ok && x < w; ++x) ok = to_rgba(fmt, bits + (y0 + y) * pitch + (x0 + x) * px, rgba + ((size_t)y * w + x) * 4);
        int alpha = has_alpha(fmt), bpx = alpha ? 4 : 3;
        if (!ok) hr = D3DERR_INVALIDCALL;
        else if (iff == 0 || iff == 6) {                         // BMP / DIB: BI_RGB, bottom-up, BGR(A), rows padded to 4 bytes
            uint32_t stride = (w * (uint32_t)bpx + 3) & ~3u, img = stride * h;
            if (iff == 0) { put16(out, 0x4D42); put32(out, 14 + 40 + img); put32(out, 0); put32(out, 54); }
            put32(out, 40); put32(out, w); put32(out, h); put16(out, 1); put16(out, (uint32_t)bpx * 8);
            put32(out, 0); put32(out, img); put32(out, 2835); put32(out, 2835); put32(out, 0); put32(out, 0);
            uint8_t *row = calloc(stride, 1);
            for (uint32_t y = h; row && y-- > 0;) {
                for (uint32_t x = 0; x < w; ++x) {
                    const uint8_t *s = rgba + ((size_t)y * w + x) * 4;
                    row[x * bpx] = s[2]; row[x * bpx + 1] = s[1]; row[x * bpx + 2] = s[0];
                    if (alpha) row[x * bpx + 3] = s[3];
                }
                put(out, row, stride);
            }
            if (!row) hr = E_OUTOFMEMORY;
            free(row);
        } else if (iff == 2) {                                   // TGA: uncompressed true-colour, top-left origin, BGR(A)
            uint8_t hd[18] = {0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, (uint8_t)w, (uint8_t)(w >> 8), (uint8_t)h, (uint8_t)(h >> 8),
                              (uint8_t)(bpx * 8), (uint8_t)(0x20 | (alpha ? 8 : 0))};
            put(out, hd, 18);
            for (size_t k = 0; k < (size_t)w * h; ++k) { uint8_t q[4] = {rgba[k * 4 + 2], rgba[k * 4 + 1], rgba[k * 4], rgba[k * 4 + 3]}; put(out, q, (size_t)bpx); }
        } else if (iff == 5) {                                   // PPM: binary RGB
            char hd[48];
            int n = snprintf(hd, sizeof hd, "P6\n%u %u\n255\n", w, h);
            put(out, hd, (size_t)n);
            for (size_t k = 0; k < (size_t)w * h; ++k) put(out, rgba + k * 4, 3);
        } else if (!encode_imageio(rgba, w, h, iff == 3, out)) hr = D3DERR_INVALIDCALL;   // PNG (3) / JPEG (1)
        free(rgba);
    }
    vcall(c, surf, SURF_UNLOCK, 0, NULL);
    return hr;
}

// ---------------- ID3DXBuffer ----------------
// [vtable][refs][data][size] in guest memory; data is freed with the object.
static uint32_t vt_buffer;
static int buf_QueryInterface(Cpu *c) { if (arg(c, 2)) M32(arg(c, 2)) = 0; RET(E_NOINTERFACE, 3); }
static int buf_AddRef(Cpu *c) { RET(++M32(arg(c, 0) + 4), 1); }
static int buf_Release(Cpu *c) {
    uint32_t b = arg(c, 0), r = M32(b + 4) ? --M32(b + 4) : 0;
    if (!r) { gfree(M32(b + 8)); gfree(b); }
    RET(r, 1);
}
static int buf_GetBufferPointer(Cpu *c) { RET(M32(arg(c, 0) + 8), 1); }
static int buf_GetBufferSize(Cpu *c) { RET(M32(arg(c, 0) + 12), 1); }
static uint32_t make_buffer(const Bytes *b) {
    if (!vt_buffer) {
        vt_buffer = galloc(20);
        M32(vt_buffer) = host_fn(buf_QueryInterface, "ID3DXBuffer::QueryInterface");
        M32(vt_buffer + 4) = host_fn(buf_AddRef, "ID3DXBuffer::AddRef");
        M32(vt_buffer + 8) = host_fn(buf_Release, "ID3DXBuffer::Release");
        M32(vt_buffer + 12) = host_fn(buf_GetBufferPointer, "ID3DXBuffer::GetBufferPointer");
        M32(vt_buffer + 16) = host_fn(buf_GetBufferSize, "ID3DXBuffer::GetBufferSize");
    }
    uint32_t o = gmalloc(16), d = gmalloc((uint32_t)b->n ? (uint32_t)b->n : 1);
    if (!o || !d) { gfree(o); gfree(d); return 0; }
    memcpy(G + d, b->p, b->n);
    M32(o) = vt_buffer; M32(o + 4) = 1; M32(o + 8) = d; M32(o + 12) = (uint32_t)b->n;
    return o;
}

int d3dx_tex(Cpu *c, const char *fn) {
    if (!strcmp(fn, "D3DXCreateCubeTextureFromFileInMemory"))      // (device, data, size, IDirect3DCubeTexture9 **)
        RET(create_cube(c, arg(c, 0), arg(c, 1), arg(c, 2), arg(c, 3)), 4);
    if (!strcmp(fn, "D3DXCreateVolumeTextureFromFileInMemory"))    // (device, data, size, IDirect3DVolumeTexture9 **)
        RET(create_volume(c, arg(c, 0), arg(c, 1), arg(c, 2), arg(c, 3)), 4);
    if (!strcmp(fn, "D3DXSaveSurfaceToFileA") || !strcmp(fn, "D3DXSaveSurfaceToFileInMemory")) {
        // (file name | ID3DXBuffer **, D3DXIMAGE_FILEFORMAT, surface, palette, rect)
        Bytes b = {0};
        uint32_t hr = encode_surface(c, arg(c, 2), arg(c, 4), arg(c, 1), &b);
        if (!hr && !strcmp(fn, "D3DXSaveSurfaceToFileA")) {
            uint32_t h = host_file_open((const char *)G + arg(c, 0), 0x40000000u, 0, 2);   // CREATE_ALWAYS
            if (h == 0xFFFFFFFFu) hr = D3DERR_INVALIDCALL;
            else {
                uint32_t tmp = gmalloc((uint32_t)b.n ? (uint32_t)b.n : 1);
                memcpy(G + tmp, b.p, b.n);
                if (host_file_write(h, tmp, (uint32_t)b.n) != (int64_t)b.n) hr = D3DERR_INVALIDCALL;
                gfree(tmp);
                if (!host_file_close(h)) hr = D3DERR_INVALIDCALL;
            }
        } else if (!hr) {
            uint32_t o = make_buffer(&b);
            if (!o) hr = E_OUTOFMEMORY;
            else M32(arg(c, 0)) = o;
        }
        free(b.p);
        RET(hr, 5);
    }
    return 0;
}
