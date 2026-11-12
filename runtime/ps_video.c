// ps_video.c - ProStreet: the screen resolution (hooks_ps.txt).
//
// The game picks its mode with SelectMode(width, height, refresh) (006E40A0, called with the profile's video settings
// from 006F1258): an exact match in its mode list, else a fallback. Its list ([this+0x14] -> +0x188 .. +0x18C, 28-byte
// entries: width, height, refresh, ...) holds only the standard modes the adapter reports, largest first: 1920x1200
// down to 640x480. A fresh profile asks for 640x480 at 60 Hz, which made everything small and blurry on a Mac display.
// That default request becomes the largest listed mode whose shape is closest to the display's (1920x1200 on a 16:10
// MacBook), or NFS_PS_RES=WxH; the size goes into the call and into the settings themselves (+0x6C width, +0x70
// height), which the game saves with the profile. A resolution chosen in the game's options (anything but 640x480)
// is kept.
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include "host.h"
#include "funcs.h"

void user32_screen_size(int *w, int *h);

static int pick_mode(uint32_t self, uint32_t *w, uint32_t *h) {
    const char *e = getenv("NFS_PS_RES");
    unsigned rw, rh;
    if (e && sscanf(e, "%ux%u", &rw, &rh) == 2 && rw >= 640 && rh >= 480) { *w = rw; *h = rh; return 1; }
    int sw = 0, sh = 0;
    user32_screen_size(&sw, &sh);
    double want = sh > 0 ? (double)sw / sh : 16.0 / 10.0, best = 1e9;
    uint32_t list = M32(self + 0x14), b = list ? M32(list + 0x188) : 0, end = list ? M32(list + 0x18C) : 0;
    int found = 0;
    for (uint32_t a = b; a && a + 28 <= end; a += 28) {
        uint32_t mw = M32(a), mh = M32(a + 4);
        if (mw < 640 || mh < 480) continue;
        double score = fabs((double)mw / mh - want) * 1e6 - (double)mw * mh;   // shape first, then size
        if (score < best) { best = score; *w = mw; *h = mh; found = 1; }
    }
    return found;
}

void f_006E40A0(Cpu *c) {                                   // SelectMode(width, height, refresh), thiscall
    uint32_t w = M32(c->esp + 4), h = M32(c->esp + 8), nw, nh;
    if (((w == 640 && h == 480) || (!w && !h) || getenv("NFS_PS_RES")) && pick_mode(c->ecx, &nw, &nh)) {
        M32(c->esp + 4) = nw; M32(c->esp + 8) = nh;
        uint32_t settings = M32(c->ecx + 0x54);            // the video settings the request came from (006F1242)
        if (settings) { M32(settings + 0x6C) = nw; M32(settings + 0x70) = nh; }
        fprintf(stderr, "boot: video mode %ux%u (the game asked for %ux%u)\n", nw, nh, w, h);
    }
    f_006E40A0_orig(c);
}
