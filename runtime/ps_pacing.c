// ps_pacing.c - ProStreet frame pacing: at most NFS_PS_FPS frames per second (default 60; 0: uncapped).
//
// ProStreet's loop steps its simulation by the real time it measures (QueryPerformanceCounter), so game speed doesn't
// depend on the frame rate; but nothing caps it here (the game asks for D3DPRESENT_INTERVAL_IMMEDIATE), and the
// front end ran at several hundred frames per second. Each Present (d3d9.m) now waits until one frame period after
// the previous one, letting other guest threads run meanwhile; a frame that comes late restarts the schedule instead
// of hurrying the next ones. (MW's pacing.c ticks MW's own scheduler at MW addresses: not for this game.)
#include <stdlib.h>
#include <time.h>
#include "host.h"

void gil_acquire(void);
void gil_release(void);

static uint64_t period_ns(void) {
    static int64_t p = -1;
    if (p < 0) {
        const char *e = getenv("NFS_PS_FPS");
        int fps = e && *e ? atoi(e) : 60;
        p = fps > 0 ? (int64_t)(1000000000LL / fps) : 0;
    }
    return (uint64_t)p;
}

void pacing_present(void) {
    static uint64_t next;
    uint64_t period = period_ns(), now = host_ticks();
    if (!period) return;
    if (!next || now > next + period) next = now;            // first frame, or a late one: start over from now
    if (next > now) {
        uint64_t wait = next - now;
        struct timespec ts = {(time_t)(wait / 1000000000ull), (long)(wait % 1000000000ull)};
        gil_release();
        nanosleep(&ts, NULL);
        gil_acquire();
    }
    next += period;
}
int pacing_sim_hz(void) { uint64_t p = period_ns(); return p ? (int)(1000000000ull / p) : 0; }   // overlay.m
int pacing_lockstep_now(void) { return 0; }                                                     // user32.m
