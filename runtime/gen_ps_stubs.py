"""Writes runtime/ps_stubs.m: "feature off" definitions for the MW feature functions and variables the ProStreet core
runtime still references (runtime/build_ps.sh links no MW feature file).

    python3 -I runtime/gen_ps_stubs.py runtime/ps_stubs.txt     (one symbol per line; '#' comments)

runtime/ps_stubs.txt lists them (first taken from a failed link of build_ps.sh). When a ProStreet file implements one,
its symbol leaves the list and the file is regenerated.

Each symbol's declaration is taken from the runtime headers, else from a declaration inside the linked sources, and
the stub keeps that exact signature: functions return a zero value of their type (0, NULL, nil, false, an empty
struct; a `const char *` function returns "", never NULL; a `char *` one returns NULL, since its caller owns and frees
the result), variables are zero. The stub file includes the headers, so the compiler checks every stub against its
declaration. A symbol with no declaration found stops the generator (name it in MANUAL below instead).
As ProStreet features replace these, their symbols leave the list and the stubs go.
"""
import glob
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SOURCES = ("boot.c app.m heap.c d3dx.c d3dx_effect.c d3dx_tex.c readback.c threads.c user32.m d3d9.m render.m "
           "render_target.m render_query.m render_present.m render_thread.m render_post.m pipeline_cache.m dsound.c "
           "dinput.c ws2_32.c msvcr.c win32_more.c registry.c interp.c diag.c settings.c server_loader.c "
           "render_upscale_route.m render_metalfx_spatial.m alpha_to_coverage.c gpupass.m gpuclients.m rumble.m padfx.m "
           "overlay.m probe.m").split()
# headers the stubs include for their types (C and Objective-C/Metal)
INCLUDES = ["<Metal/Metal.h>", "<Foundation/Foundation.h>", '"host.h"', '"render_internal.h"', '"materials.h"']
MANUAL = {    # symbol -> full definition, for what the parser can't find (comma-joined local declarations, runtime.h)
    "car85_path": "int car85_path(const char *guest, char *host, size_t n) { return 0; }  // recomp/runtime.h",
    # "none" is -1 for these, and 0 would be a real answer (file descriptor 0 is stdin: every game file read stdin)
    "x360audio_open": "int x360audio_open(const char *win, const char *host) { return -1; }  // boot.c file_open: fd or -1",
    "widescreen_native_slot": "int widescreen_native_slot(void) { return -1; }  // d3d9.m: the native resolution's slot or -1",
    "materials_flake_force": "int materials_flake_force;  // user32.m (local extern)",
    "materials_flake_tint": "int materials_flake_tint;  // user32.m (local extern)",
    "materials_flake_test": "void materials_flake_test(int tint, int force) {}  // user32.m",
    "materials_set_car_flake": "void materials_set_car_flake(int x360) {}  // user32.m",
    "report_init": "void report_init(void) {}  // boot.c (report.m isn't linked yet)",
    # registry.c answers the game's Language value from this (settings_port.c is MW's settings page)
    "settings_game_language": 'const char *settings_game_language(void) { return "English US"; }  // registry.c',
}


def declaration(sym, texts):
    fn = re.compile(r"(?:^|[;{}]\s*|\n)\s*((?:extern\s+)?(?:__attribute__\(\([^)]*\)\)\s*)?(?:const\s+)?[A-Za-z_][\w\s\*<>,]*?[\s\*])"
                    + re.escape(sym) + r"\s*\(([^;{}()]*(?:\([^;{}()]*\)[^;{}()]*)*)\)\s*;")
    var = re.compile(r"\bextern\s+((?:const\s+)?[A-Za-z_][\w\s\*]*?[\s\*])" + re.escape(sym) + r"\s*(\[[^\]]*\])?\s*;")
    for path, text in texts:
        m = var.search(text)
        if m:
            return "var", m.group(1).strip(), m.group(2) or "", path
        m = fn.search(text)
        if m:
            ret = re.sub(r"\bextern\b|__attribute__\(\([^)]*\)\)", "", m.group(1)).strip()
            if ret in ("return", "else") or ret.startswith(("return ", "else ")):
                continue
            return "fn", ret, " ".join(m.group(2).split()), path
    return None


def code_only(text):
    """Comments removed (they hold prose that looks like declarations)."""
    return re.sub(r"//[^\n]*", "", re.sub(r"/\*.*?\*/", " ", text, flags=re.S))


def main(argv):
    syms = [l.strip() for l in open(argv[0]) if l.strip() and not l.startswith("#")]
    headers = [(h, code_only(open(os.path.join(HERE, h), errors="replace").read())) for h in sorted(os.path.basename(p) for p in glob.glob(os.path.join(HERE, "*.h")))]
    sources = [(s, code_only(open(os.path.join(HERE, s), errors="replace").read())) for s in SOURCES]
    need_headers, body, missing = set(), [], []
    for sym in syms:
        if sym in MANUAL:
            body.append(MANUAL[sym])
            continue
        d = declaration(sym, headers + sources)
        if not d:
            missing.append(sym)
            continue
        kind, typ, rest, where = d
        if where.endswith(".h"):
            need_headers.add(where)
        if kind == "var":
            body.append(f"{typ} {sym}{rest};{' ' * max(1, 40 - len(typ) - len(sym))}// {where}")
        elif typ == "void" or typ == "static void":
            body.append(f"void {sym}({rest or 'void'}) {{}}  // {where}")
        elif re.fullmatch(r"const\s+char\s*\*", typ):   # a borrowed string: callers print or compare it, never NULL
            body.append(f'{typ} {sym}({rest or "void"}) {{ return ""; }}  // {where}')
        else:
            body.append(f"{typ} {sym}({rest or 'void'}) {{ return ({typ}){{0}}; }}  // {where}")
    if missing:
        raise SystemExit("no declaration found for: " + " ".join(missing))
    inc = INCLUDES + [f'"{h}"' for h in sorted(need_headers) if f'"{h}"' not in INCLUDES]
    out = ["// ps_stubs.m: GENERATED by runtime/gen_ps_stubs.py; do not edit by hand.",
           "// \"Feature off\" definitions for the MW feature code the ProStreet core runtime still calls (runtime/build_ps.sh",
           "// links no MW feature file). Each keeps its declaration's signature and returns zero / NULL / false.",
           "#pragma clang diagnostic ignored \"-Weverything\""]
    out += [f"#include {h}" for h in inc] + [""] + body + [""]
    path = os.path.join(HERE, "ps_stubs.m")
    with open(path, "w", newline="\n") as f:
        f.write("\n".join(out))
    print(f"{path}: {len(body)} stubs")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
