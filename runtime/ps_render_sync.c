// ps_render_sync.c - ProStreet: the render thread's wait for the main thread's command buffer (hooks_ps.txt).
//
// The render thread (004AFBC0) replays the frame's render commands while the main thread is still writing them:
// it loops on 006B5000 (run the commands written so far, `count` = write - read) until the main thread marks the
// buffer complete (byte 00F99838) or stops it (00F9983C). On Windows the two threads run at once. Here guest threads
// share one lock (the GIL) that changes hands at imports, and that loop makes none: with nothing to run it spins
// holding the lock, the main thread can't write the rest of the frame, and the game stops (seen on the first race
// load, main thread waiting for the lock in a CRT math call). With an empty batch the loop is waiting, so it offers
// the lock the way an import does (gil_maybe_yield: after 2 ms with others waiting).
#include "host.h"
#include "funcs.h"

void f_006B5000(Cpu *c) {
    if (M32(c->esp + 4) == 0) gil_maybe_yield(c);    // stdcall (this = ecx, count); esp -> return address
    f_006B5000_orig(c);
}
