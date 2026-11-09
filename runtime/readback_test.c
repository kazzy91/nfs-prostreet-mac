// readback_test.c - standalone test of readback.c (GetRenderTargetData's BGRA8 -> D3D format store); no GPU, no game files.
// Built and run by runtime/readback_test.py (c_test_driver.py). Every format is checked against an independent per-pixel
// expectation, with a destination pitch wider than the rows so the padding must stay untouched.
// READBACK_TEST_SELFCHECK=1 adds one deliberately wrong expectation.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int readback_format_ok(uint32_t fmt);
int readback_store(const uint8_t *bgra, uint32_t w, uint32_t h, uint8_t *dst, uint32_t pitch, uint32_t fmt);

static int fails, checks;
#define CHECK(x, ...) do { ++checks; if (!(x)) { if (fails++ < 40) { printf("FAIL %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); } } } while (0)

enum { W = 5, H = 3, PITCH = 32 };
static uint8_t src[W * H * 4];
static uint32_t round5(uint32_t v) { return (v * 31 + 127) / 255; }
static uint32_t round6(uint32_t v) { return (v * 63 + 127) / 255; }
// The expected bytes of pixel (x, y) in format fmt, and their count.
static int expect(uint32_t fmt, const uint8_t *p, uint8_t *o) {
    uint32_t b = p[0], g = p[1], r = p[2], a = p[3], v;
    switch (fmt) {
    case 21: o[0] = (uint8_t)b; o[1] = (uint8_t)g; o[2] = (uint8_t)r; o[3] = (uint8_t)a; return 4;
    case 22: o[0] = (uint8_t)b; o[1] = (uint8_t)g; o[2] = (uint8_t)r; o[3] = 0xFF; return 4;
    case 32: o[0] = (uint8_t)r; o[1] = (uint8_t)g; o[2] = (uint8_t)b; o[3] = (uint8_t)a; return 4;
    case 33: o[0] = (uint8_t)r; o[1] = (uint8_t)g; o[2] = (uint8_t)b; o[3] = 0xFF; return 4;
    case 20: o[0] = (uint8_t)b; o[1] = (uint8_t)g; o[2] = (uint8_t)r; return 3;
    case 23: v = round5(r) << 11 | round6(g) << 5 | round5(b); break;
    case 24: v = 1u << 15 | round5(r) << 10 | round5(g) << 5 | round5(b); break;
    default: v = (a >= 128 ? 1u : 0u) << 15 | round5(r) << 10 | round5(g) << 5 | round5(b); break;   // 25
    }
    o[0] = (uint8_t)v; o[1] = (uint8_t)(v >> 8);
    return 2;
}

int main(void) {
    for (int k = 0; k < W * H * 4; ++k) src[k] = (uint8_t)(k * 37 + 11);
    src[3] = 127; src[7] = 128; src[11] = 0; src[15] = 255;   // alpha either side of A1R5G5B5's threshold
    src[16] = 255; src[17] = 255; src[18] = 255;               // white must stay white in 5/6 bits
    const uint32_t fmts[] = {21, 22, 32, 33, 20, 23, 24, 25};
    for (unsigned f = 0; f < sizeof fmts / sizeof *fmts; ++f) {
        uint32_t fmt = fmts[f];
        uint8_t dst[PITCH * H];
        memset(dst, 0xCD, sizeof dst);
        CHECK(readback_format_ok(fmt) && readback_store(src, W, H, dst, PITCH, fmt) == 1, "format %u stores", fmt);
        int same = 1, pad = 1, bytes = 0;
        for (uint32_t y = 0; y < H; ++y) {
            for (uint32_t x = 0; x < W; ++x) {
                uint8_t e[4];
                bytes = expect(fmt, src + (y * W + x) * 4, e);
                same &= !memcmp(dst + y * PITCH + x * (uint32_t)bytes, e, (size_t)bytes);
            }
            for (uint32_t k = W * (uint32_t)bytes; k < PITCH; ++k) pad &= dst[y * PITCH + k] == 0xCD;
        }
        CHECK(same, "format %u: every pixel as expected", fmt);
        CHECK(pad, "format %u: the row padding is untouched", fmt);
    }
    // spot values: white is 0xFFFF in R5G6B5; alpha 127 drops and 128 keeps A1R5G5B5's alpha bit
    uint8_t d[PITCH * H];
    readback_store(src, W, H, d, PITCH, 23);
    CHECK(d[8] == 0xFF && d[9] == 0xFF, "white -> 0xFFFF in R5G6B5 (%02X%02X)", d[9], d[8]);
    readback_store(src, W, H, d, PITCH, 25);
    CHECK(!(d[1] & 0x80) && (d[3] & 0x80), "A1R5G5B5 alpha bit: 127 -> 0, 128 -> 1");
    // formats readback can't produce
    const uint32_t bad[] = {0x31545844, 50, 113, 75, 0};
    for (unsigned k = 0; k < sizeof bad / sizeof *bad; ++k)
        CHECK(!readback_format_ok(bad[k]) && readback_store(src, W, H, d, PITCH, bad[k]) == 0, "format %X refused", bad[k]);
    if (getenv("READBACK_TEST_SELFCHECK")) CHECK(readback_format_ok(50), "deliberately wrong");
    printf("%s: %d checks, %d failing\n", fails ? "FAIL" : "ok", checks, fails);
    return fails ? 1 : 0;
}
