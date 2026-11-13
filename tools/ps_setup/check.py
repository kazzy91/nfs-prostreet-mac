"""The early ProStreet Setup's backend: checks the player's nfs.exe and prints one JSON result.

    python3 -I tools/ps_setup/check.py <nfs.exe | game folder | disc image .iso>

Stdlib only (it runs on macOS's own Python from the Command Line Tools). Nothing from the game is executed, copied or
changed: an exe is read; a folder is searched (up to 3 levels) for nfs.exe; a disc image is attached read-only and
hidden from Finder, its nfs.exe read, and detached again.

The verdict uses recomp/pe_report.py (the Phase 0 gate), recomp/authenticode.py (is this exactly what Electronic Arts
signed?), recomp/exe_fingerprint.py (the builds the port supports) and recomp/import_coverage.py:
  supported   plain code, EA's signature valid, and a supported build (the ProStreet demo release): what the port uses.
  plain       plain code with EA's valid signature, but not a build the port supports.
  unverified  plain code without a valid EA signature: possibly modified, so not used.
  protected   copy protection (SecuROM and the like). The port never strips it (CLAUDE.md rule 2).
  packed      compressed, encrypted or otherwise modified; not an EA executable as shipped.
  not_found   no nfs.exe where the player pointed; not_pe: not a 32-bit Windows executable.
Exit status 0 whenever a result was printed (the verdict is in the JSON); 1 for a usage error.
"""
import datetime
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
for cand in (HERE, os.path.join(HERE, "..", "..", "recomp")):          # bundled flat, or in the checkout
    if os.path.exists(os.path.join(cand, "pe_report.py")):
        sys.path.insert(0, cand)
        break
import authenticode  # noqa: E402
import exe_fingerprint  # noqa: E402
import import_coverage  # noqa: E402
import pe_report  # noqa: E402

RUNTIME = next((d for d in (os.path.join(HERE, "runtime"), os.path.join(HERE, "..", "..", "runtime"))
                if os.path.exists(os.path.join(d, "boot.c"))), None)
DRM = {"SecuROM", "StarForce", "TAGES", "SafeDisc", "LaserLock", "Steam DRM", "CrackProof"}

TEXT = {
    "supported": ("This is EA's ProStreet demo executable",
                  "Plain code, signed by Electronic Arts and unchanged since: exactly the build the port targets. Setup "
                  "can build the game from it."),
    "plain": ("This nfs.exe is plain code, signed by EA",
              "It has no copy protection or packing and is exactly what EA signed, but it isn't the build the port "
              "targets (EA's ProStreet demo release executable)."),
    "unverified": ("This nfs.exe is plain code, but not as EA signed it",
                   "It has no copy protection or packing, but it doesn't carry a valid Electronic Arts signature, so it "
                   "may have been modified. The port only uses EA's own executable."),
    "protected": ("This nfs.exe is copy-protected ({tool})",
                  "Its game code is encrypted by {tool}, so it can't be translated. The port never removes copy "
                  "protection. It needs an nfs.exe without {tool} from a release you own."),
    "packed": ("This nfs.exe is packed or modified",
               "Its code is compressed or encrypted and only unpacked when it runs, so it can't be translated. That "
               "isn't how EA shipped the game. The port needs EA's own nfs.exe from a release you own, without copy "
               "protection."),
    "not_found": ("No nfs.exe found", "Choose the nfs.exe file itself, the installed game folder that holds it, or "
                                      "your ProStreet disc image (.iso)."),
    "not_pe": ("This isn't a Windows game executable", "Choose ProStreet's nfs.exe."),
}
NEXT = ("To build NFS ProStreet Native, choose the folder EA's ProStreet demo is installed in (it holds nfsdemo.exe "
        "and the demo's data), then Build and Install.")


def find_exe(folder):
    for top, dirs, files in os.walk(folder):
        if top[len(folder):].count(os.sep) >= 3:
            dirs[:] = []
        for f in files:
            if f.lower() in ("nfs.exe", "nfsdemo.exe"):    # EA's demo installer names it nfsdemo.exe
                return os.path.join(top, f)
        dirs.sort()
    return None


def attach(iso):
    mnt = tempfile.mkdtemp(prefix="ps_setup_disc.")
    r = subprocess.run(["hdiutil", "attach", "-readonly", "-nobrowse", "-noautoopen", "-mountpoint", mnt, iso],
                       capture_output=True, text=True)
    if r.returncode:
        os.rmdir(mnt)
        return None, r.stderr.strip()
    return mnt, ""


def detach(mnt):
    subprocess.run(["hdiutil", "detach", mnt], capture_output=True)
    try:
        os.rmdir(mnt)
    except OSError:
        pass


def assess(exe):
    with open(exe, "rb") as f:
        data = f.read()
    try:
        info = pe_report.parse(data)
    except pe_report.NotPE:
        return {"verdict": "not_pe"}
    findings = pe_report.findings(info)
    tools = sorted({tool for name, tool in ((s["name"].lower(), pe_report.WRAPPER_SECTIONS.get(s["name"].lower()))
                                            for s in info["sections"]) if tool})
    drm = [t for t in tools if t in DRM]
    sig = authenticode.verify(data)
    ea = sig["ok"] and sig["signer_sha256"] == authenticode.EA_2007
    profile = exe_fingerprint.identify(data)
    if drm:
        verdict = "protected"
    elif any(s == "strong" for s, _ in findings):
        verdict = "packed"
    elif not ea:
        verdict = "unverified"
    else:
        verdict = "supported" if profile == "ps_demo" else "plain"
    signature = ("Electronic Arts, valid" if ea else f"{sig['signer']}: {sig['why']}" if sig["signer"] else sig["why"])
    imports = info["imports"]
    cov = None
    if RUNTIME:
        rows = import_coverage.coverage(imports, import_coverage.Host(RUNTIME))
        cov = {"handled": sum(r["handled"] for r in rows), "total": sum(r["total"] for r in rows)}
    base = info["image_base"]
    return {
        "verdict": verdict, "tool": drm[0] if drm else (tools[0] if tools else ""),
        "facts": {
            "size": info["size"], "sha256": info["sha256"],
            "linked": datetime.datetime.fromtimestamp(info["timestamp"], datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            "entry": f"{base + info['entry_rva']:08X} in {info['entry_section']}",
            "sections": ", ".join(f"{s['name'] or '?'} ({s['entropy']:.2f})" for s in info["sections"]),
            "imports": f"{sum(map(len, imports.values()))} functions in {len(imports)} DLLs",
            "signature": signature,
            "build": exe_fingerprint.PROFILES[profile]["name"] if profile else "not a supported build",
        },
        "findings": [t for _, t in findings],
        "coverage": cov,
    }


def check(path):
    path = os.path.abspath(os.path.expanduser(path))
    out = {"input": path, "exe": None}
    mnt = None
    try:
        if not os.path.exists(path):
            r = {"verdict": "not_found"}
        elif os.path.isdir(path):
            exe = find_exe(path)
            r = assess(exe) if exe else {"verdict": "not_found"}
            out["exe"] = exe
        elif path.lower().endswith((".iso", ".dmg", ".cdr")):
            mnt, err = attach(path)
            exe = find_exe(mnt) if mnt else None
            r = assess(exe) if exe else {"verdict": "not_found", "detail_extra": err}
            out["exe"] = exe and os.path.join(path, os.path.relpath(exe, mnt))
            out["disc"] = True
        else:
            r = assess(path)
            out["exe"] = path
    finally:
        if mnt:
            detach(mnt)
    out.update(r)
    title, detail = TEXT[r["verdict"]]
    out["title"] = title.format(tool=r.get("tool") or "copy protection")
    out["detail"] = detail.format(tool=r.get("tool") or "copy protection")
    out["next"] = NEXT
    return out


def main(argv):
    if len(argv) != 1:
        print(__doc__.strip().splitlines()[2].strip(), file=sys.stderr)
        return 1
    print(json.dumps(check(argv[0]), indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
