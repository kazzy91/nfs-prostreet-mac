"""Game profiles: what the recompiler needs to know about each supported executable.

A profile names the exe's code fingerprint (a profile in exe_fingerprint.PROFILES), the committed function manifest,
the hooks file (guest functions the runtime replaces), the output names and the builder that translates it. Code
that differs between games (inline patches keyed to one exe's addresses, build passes) belongs to a profile, never
to the translator's general rules.

    mw13     NFS Most Wanted PC v1.3 speed.exe. Still built by build_all.py, whose MW passes (water, split screen,
             traffic detail, car render diagnostics, breaker diagnostics) and MW's server.dll build move here when
             MW's build is switched over and checked against speed.exe. Its translator patches are gated by
             recomp.Recompiler.mw_patches.
    ps_demo  NFS ProStreet demo-release nfs.exe. Built by build_game.py.
"""
import os
from dataclasses import dataclass, field

HERE = os.path.dirname(os.path.abspath(__file__))


@dataclass(frozen=True)
class Profile:
    name: str
    title: str
    fingerprint: str            # key into exe_fingerprint.PROFILES
    exe_env: str                # environment variable naming the player's exe
    manifest: str               # function manifest (recomp/), addresses and names only
    hooks: str                  # hooks file (recomp/)
    stem: str                   # output names: <stem>_NN.c, <stem>.a
    builder: str                # the script that builds it
    passes: tuple = field(default=())   # (address, C code) -> C code, run on each translated function

    def path(self, name):
        return os.path.join(HERE, name)


PROFILES = {
    "mw13": Profile("mw13", "NFS Most Wanted PC v1.3 (speed.exe)", "mw13", "NFS_SPEED_EXE", "functions_v13.tsv",
                    "hooks.txt", "speed", "build_all.py"),
    "ps_demo": Profile("ps_demo", "NFS ProStreet demo release (nfs.exe)", "ps_demo", "NFS_PS_EXE", "functions_ps.tsv",
                       "hooks_ps.txt", "nfs", "build_game.py"),
}


def load_hooks(path):
    """A hooks file: {guest address: owner comment}. One 'ADDRESS  owner: function' per line, '#' comments."""
    hooks = {}
    with open(path, encoding="utf-8") as f:
        lines = f.read().splitlines()
    for line in lines:
        line = line.split("#", 1)[0].strip()
        if line:
            a, _, why = line.partition(" ")
            hooks[int(a, 16)] = why.strip()
    return hooks


def load_manifest(path):
    """[(address, name)] sorted, from a manifest: hex start, optional tab and name, '#' comments."""
    out = {}
    with open(path, encoding="utf-8") as f:
        lines = f.read().splitlines()
    for line in lines:
        line = line.rstrip("\n")
        if not line.strip() or line.startswith("#"):
            continue
        a, _, n = line.partition("\t")
        a = int(a.split()[0], 16)
        out[a] = n.strip() or f"FUN_{a:08x}"
    return sorted(out.items())
