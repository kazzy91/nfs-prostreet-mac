// ps_boot.c - ProStreet (demo) start-up: the boot flow's screens (hooks_ps.txt).
//
// FEDemoBootFlowStateManager (vtable 0094FDFC, slot 80 = 007B81A0) shows the demo's start screens one after another:
// its state (+4) picks the next one: 25 DEMO_NOTICE, 26 DEMO_ESRB, 24 DEMO_CAR_LEGAL, 28 DEMO_MUSIC_LEGAL, then 27 the
// Attract movie (0059E750) and on into the front end. Each screen asks for the next state when it's done (~3 s each).
// DEMO_MUSIC_LEGAL never does here (why is open), so its step goes straight to the Attract movie.
// BOOT_SKIPINTRO=1 (development): no legal screens and no start-up movie: the first step is the Attract step with
// the game's own skip-movies flag (00B98AF8, read by FEngMovieStarter 005BC430) set, so the flow moves on at once.
#include <stdlib.h>
#include "host.h"
#include "funcs.h"

#define BOOT_FLOW_STATE 4u              // FEDemoBootFlowStateManager: the step to take next
#define SKIP_MOVIES 0x00B98AF8u         // nonzero: FEngMovieStarter reports a movie done without playing it

void f_007B81A0(Cpu *c) {
    static int skip = -1;
    if (skip < 0) skip = getenv("BOOT_SKIPINTRO") && atoi(getenv("BOOT_SKIPINTRO"));
    uint32_t self = c->ecx;
    int32_t state = (int32_t)M32(self + BOOT_FLOW_STATE);
    if (state == 28) M32(self + BOOT_FLOW_STATE) = 27;                        // DEMO_MUSIC_LEGAL -> Attract
    if (skip && (state == 24 || state == 25 || state == 26 || state == 28)) {
        M32(self + BOOT_FLOW_STATE) = 27;
        M32(SKIP_MOVIES) = 1;
    }
    if (boot_trace) fprintf(stderr, "      boot flow: state %d -> %d\n", state, (int32_t)M32(self + BOOT_FLOW_STATE));
    f_007B81A0_orig(c);
}
