"""Offline proof of import_coverage.py against this checkout's runtime/; no game files.

    python3 -I recomp/import_coverage_test.py

(a) the DLL routing read from boot.c matches host_import's dispatch (d3dx9 -> d3dx + d3dx_effect, ..., MSVCR80/MSVCP80
    -> win32_msvcr, fallback
    win32_threads/win32_heap/win32), and every handler's file is found;
(b) MW's own import list (runtime/imports.c): exactly the 13 imports MW never calls are unhandled (RtlUnwind,
    RaiseException, UnhandledExceptionFilter, ShellExecuteA, the 9 TAPI32 line* functions);
(c) a synthetic PE (pe_report_test.build_pe): GetTickCount handled, an unknown KERNEL32 name missing, WS2_32 #3
    handled through the ordinal switch, WS2_32 #53 missing, WSOCK32 #3 handled through the same routing, MSVCR80
    malloc handled by msvcr.c and _setjmp3 still missing, DSOUND #1 handled by its exact "#1" compare;
(d) prefix tests are not counted: HeapFoo (heap.c's negative "Heap" gate) and VirtualFoo (boot.c's "Virtual" trace)
    stay missing.
Check of the check: with the WS2 ordinal switch ignored, (c)'s WS2_32 #3 must turn missing.
Last run: 4 cases PASS, ordinal mutant seen -> exit 0.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import import_coverage as ic  # noqa: E402
import pe_report  # noqa: E402
import pe_report_test  # noqa: E402

MW_UNHANDLED = {("KERNEL32.dll", "RtlUnwind"), ("KERNEL32.dll", "RaiseException"),
                ("KERNEL32.dll", "UnhandledExceptionFilter"), ("SHELL32.dll", "ShellExecuteA")} | {
    ("TAPI32.dll", f) for f in ("lineGetDevCaps", "lineShutdown", "lineInitialize", "lineAnswer", "lineMakeCall",
                                "lineGetID", "lineClose", "lineNegotiateAPIVersion", "lineOpen")}


def missing_of(rows):
    return {(r["dll"], f): n for r in rows for f, n in r["missing"]}


def main():
    fails = []

    def check(label, ok, detail=""):
        print(f"{'PASS' if ok else 'FAIL'} {label}" + (f": {detail}" if detail and not ok else ""))
        if not ok:
            fails.append(label)

    host = ic.Host()
    want = [(["d3dx9"], ["d3dx", "d3dx_effect", "d3dx_tex"]), (["d3d9"], ["win32_d3d9"]), (["DSOUND"], ["win32_dsound"]),
            (["DINPUT8"], ["win32_dinput"]), (["WS2_32", "WSOCK32", "NETAPI32"], ["win32_ws2"]),
            (["USER32", "GDI32"], ["win32_user32", "win32_more"]), (["MSVCR80", "MSVCP80"], ["win32_msvcr"])]
    check("(a) routing read from boot.c", host.routes == want and host.fallback == ["win32_threads", "win32_heap", "win32_registry", "win32", "win32_more"],
          (host.routes, host.fallback))
    check("(a) handler files found", host.files.get("win32_ws2") == "runtime/ws2_32.c" and
          host.files.get("win32") == "runtime/boot.c", host.files)

    mw = ic.coverage(ic.mw_imports(), host)
    got = set(missing_of(mw))
    check("(b) MW: exactly the 13 never-called imports unhandled", got == MW_UNHANDLED and
          sum(r["total"] for r in mw) == 300, sorted(got ^ MW_UNHANDLED))

    synth = pe_report_test.build_pe(imports={
        "KERNEL32.dll": ["GetTickCount", "NoSuchFunctionAnywhere", "HeapFoo", "VirtualFoo"],
        "WS2_32.dll": ["#3", "#12", "#53"], "WSOCK32.dll": ["#3"], "MSVCR80.dll": ["malloc", "_setjmp3"], "DSOUND.dll": ["#1"]})
    rows = ic.coverage(pe_report.parse(synth)["imports"], host)
    miss = missing_of(rows)
    expect = {("KERNEL32.dll", "NoSuchFunctionAnywhere"), ("KERNEL32.dll", "HeapFoo"), ("KERNEL32.dll", "VirtualFoo"),
              ("WS2_32.dll", "#53"), ("MSVCR80.dll", "_setjmp3")}
    check("(c) synthetic PE: handled/missing split", set(miss) == expect, sorted(set(miss) ^ expect))
    check("(c) WSOCK32 #3 is handled by the WS2_32 handler", ("WSOCK32.dll", "#3") not in miss, miss)
    check("(d) prefix gates/traces not counted", ("KERNEL32.dll", "HeapFoo") in miss and ("KERNEL32.dll", "VirtualFoo") in miss)

    saved = host.by_handler["win32_ws2"]
    host.by_handler["win32_ws2"] = (saved[0], set())
    try:
        slipped = ("WS2_32.dll", "#3") in missing_of(ic.coverage(pe_report.parse(synth)["imports"], host))
    finally:
        host.by_handler["win32_ws2"] = saved
    print(f"  mutant 'ordinal switch ignored': WS2_32 #3 {'MISSING (test sees the break)' if slipped else 'still handled'}")
    check("ordinal mutant visible", slipped)
    print(f"{'FAIL' if fails else 'ok'}: {len(fails)} failing")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
