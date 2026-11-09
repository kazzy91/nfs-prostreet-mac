// readback.c - GetRenderTargetData's last step: pixels read back from Metal as BGRA8 (rows of w * 4 bytes) stored into a
// guest surface in its D3D format, at its own pitch. Plain C so it can be tested without a GPU (readback_test.c);
// render.m does the GPU side (render_readback).
#include <stdint.h>
#include <string.h>

// 1 if fmt is a format readback can produce: A8R8G8B8, X8R8G8B8, A8B8G8R8, X8B8G8R8, R8G8B8, R5G6B5, X1R5G5B5, A1R5G5B5.
int readback_format_ok(uint32_t fmt) {
    return fmt == 21 || fmt == 22 || fmt == 32 || fmt == 33 || fmt == 20 || fmt == 23 || fmt == 24 || fmt == 25;
}

// Stores w x h BGRA8 pixels into dst (pitch bytes per row) as fmt. Returns 0 for a format readback can't produce.
// X formats get 0xFF in the unused bits, as D3D9 drivers report them; 5/6-bit channels are rounded, not truncated.
int readback_store(const uint8_t *bgra, uint32_t w, uint32_t h, uint8_t *dst, uint32_t pitch, uint32_t fmt) {
    if (!readback_format_ok(fmt)) return 0;
    for (uint32_t y = 0; y < h; ++y) {
        const uint8_t *s = bgra + (size_t)y * w * 4;
        uint8_t *d = dst + (size_t)y * pitch;
        for (uint32_t x = 0; x < w; ++x, s += 4) {
            uint32_t b = s[0], g = s[1], r = s[2], a = s[3];
            switch (fmt) {
            case 21: d[0] = (uint8_t)b; d[1] = (uint8_t)g; d[2] = (uint8_t)r; d[3] = (uint8_t)a; d += 4; break;
            case 22: d[0] = (uint8_t)b; d[1] = (uint8_t)g; d[2] = (uint8_t)r; d[3] = 0xFF; d += 4; break;
            case 32: d[0] = (uint8_t)r; d[1] = (uint8_t)g; d[2] = (uint8_t)b; d[3] = (uint8_t)a; d += 4; break;
            case 33: d[0] = (uint8_t)r; d[1] = (uint8_t)g; d[2] = (uint8_t)b; d[3] = 0xFF; d += 4; break;
            case 20: d[0] = (uint8_t)b; d[1] = (uint8_t)g; d[2] = (uint8_t)r; d += 3; break;
            default: {
                uint32_t v;
                if (fmt == 23) v = ((r * 31 + 127) / 255) << 11 | ((g * 63 + 127) / 255) << 5 | (b * 31 + 127) / 255;
                else v = (fmt == 25 ? (a >= 128) : 1u) << 15 | ((r * 31 + 127) / 255) << 10 | ((g * 31 + 127) / 255) << 5 | (b * 31 + 127) / 255;
                d[0] = (uint8_t)v; d[1] = (uint8_t)(v >> 8);
                d += 2;
            }
            }
        }
    }
    return 1;
}
