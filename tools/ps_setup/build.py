"""The ProStreet Setup's build backend: builds NFS ProStreet Native.app on the player's Mac from their own game files.

    /usr/bin/python3 -I build.py --game <game folder> [--exe <nfs.exe>] [--resources <Setup.app/Contents/Resources>]
                                 [--dest <folder for the app>] [--work <work folder>]

Like MW's Setup (tools/setup_kit/backend.py), nothing from the game is distributed: Setup carries this project's own
source (a git archive), capstone and the FFmpeg source, and everything derived from the game (translated C, objects,
the app) is made here, on the player's Mac, in the work folder and the installed app. The game folder is only read.

Runs on the Python of Apple's Command Line Tools (3.9; stdlib only). Prints one JSON object per line on stdout:
    {"event": "stage", "id": ..., "title": ..., "index": n, "count": n}
    {"event": "log", "line": ...}
    {"event": "done", "app": <installed app>}
    {"event": "error", "stage": ..., "message": ..., "fix": ...}
The full log is ~/Library/Logs/NFSPS-Setup/build.log. Exit status 0 on success.

Stages: preflight (developer tools, disk space), game (the folder's exe and data), source (unpack the bundled source),
recompile (recomp/build_game.py), ffmpeg (media/build_ffmpeg.sh; kept between runs), shaders, audio (host libraries),
runtime (runtime/build_ps.sh), bundle (app bundle, ad hoc signature), install (replace the installed app, remember the
game folder for it).
"""
import argparse
import hashlib
import json
import os
import plistlib
import shutil
import subprocess
import sys
import tarfile
import time
from pathlib import Path

APP_NAME = "NFS ProStreet Native"
APP_EXEC = "NFSProStreet"
APP_ID = "org.nfsps-native.game"
APP_VERSION = "0.2"
FFMPEG_SHA = "733984395e0dbbe5c046abda2dc49a5544e7e0e1e2366bba849222ae9e3a03b1"
FFMPEG_TARBALL = "ffmpeg-7.1.1.tar.xz"
# The demo exe hard-codes offsets into its own NIS sound bank: on other data (retail) the race load never finishes.
DEMO_NIS_BANK = ("SOUND", "NIs", "ps_nis_pc_en.sbk")
DEMO_NIS_BANK_SIZE = 15352192
MIN_FREE = 4 << 30
SUPPORT = Path.home() / "Library/Application Support"
LOGS = Path.home() / "Library/Logs/NFSPS-Setup"
STAGES = [
    ("preflight", "Checking developer tools"), ("game", "Checking your game folder"),
    ("source", "Preparing the source"), ("recompile", "Recompiling nfs.exe"),
    ("ffmpeg", "Building the video decoder"), ("shaders", "Building the shader translator"),
    ("audio", "Building audio"), ("runtime", "Building the native runtime"),
    ("bundle", "Signing the app"), ("install", "Installing the app"),
]


class SetupError(Exception):
    def __init__(self, message, fix="Open the log for details, correct the problem and try again."):
        super().__init__(message)
        self.fix = fix


class Events:
    def __init__(self, log_path):
        log_path.parent.mkdir(parents=True, exist_ok=True)
        self.log = open(log_path, "w", encoding="utf-8")
        self.current = "preflight"

    def emit(self, **obj):
        sys.stdout.write(json.dumps(obj) + "\n")
        sys.stdout.flush()

    def write(self, line):
        self.log.write(line + "\n")
        self.log.flush()

    def stage(self, sid):
        self.current = sid
        index = [s for s, _ in STAGES].index(sid)
        title = dict(STAGES)[sid]
        self.write("== %s: %s" % (time.strftime("%H:%M:%S"), title))
        self.emit(event="stage", id=sid, title=title, index=index, count=len(STAGES))

    def say(self, line):
        self.write(line)
        self.emit(event="log", line=line)


def run(events, argv, cwd, env):
    events.write("$ " + " ".join(str(a) for a in argv))
    p = subprocess.Popen([str(a) for a in argv], cwd=str(cwd), env=env, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT, text=True, errors="replace")
    tail = []
    for line in p.stdout:
        line = line.rstrip("\n")
        events.write(line)
        tail = (tail + [line])[-20:]
        if line.strip():
            events.emit(event="log", line=line[:300])
    if p.wait() != 0:
        raise SetupError("%s failed (exit %d): %s" % (Path(str(argv[1] if len(argv) > 1 else argv[0])).name, p.returncode,
                                                      tail[-1] if tail else "no output"))


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def preflight(events):
    if os.uname().machine != "arm64":
        raise SetupError("This Mac doesn't have Apple silicon.", "The port is built for Apple silicon Macs (M1 or later).")
    r = subprocess.run(["/usr/bin/xcode-select", "-p"], capture_output=True, text=True)
    if r.returncode != 0:
        raise SetupError("Apple's Command Line Tools aren't installed.",
                         "Install them (Setup offers a button, or run xcode-select --install), then try again.")
    for tool in ("clang", "clang++", "make"):
        if subprocess.run(["/usr/bin/xcrun", "--find", tool], capture_output=True).returncode != 0:
            raise SetupError("The developer tool %s is missing." % tool, "Reinstall the Command Line Tools and try again.")
    SUPPORT.mkdir(parents=True, exist_ok=True)
    free = shutil.disk_usage(str(SUPPORT)).free
    if free < MIN_FREE:
        raise SetupError("Not enough free disk space: %.1f GB free, about 4 GB needed." % (free / 2 ** 30),
                         "Free some space and try again.")
    events.say("Developer tools: %s" % r.stdout.strip())


def find_child(folder, name):
    """A file or folder in `folder` whose name matches `name` ignoring case (Windows paths), or None."""
    try:
        for entry in os.listdir(str(folder)):
            if entry.lower() == name.lower():
                return Path(folder) / entry
    except OSError:
        return None
    return None


def check_game(events, resources, game, exe):
    game = Path(game).expanduser()
    if game.is_file():
        exe, game = exe or game, game.parent
    if not game.is_dir():
        raise SetupError("The game folder %s can't be found." % game, "Choose the folder your ProStreet demo is installed in.")
    if exe is None:
        exe = find_child(game, "nfs.exe") or find_child(game, "nfsdemo.exe")
    if exe is None or not Path(exe).is_file():
        raise SetupError("%s contains no nfs.exe or nfsdemo.exe." % game,
                         "Choose the folder EA's ProStreet demo is installed in (it holds nfsdemo.exe).")
    sys.path.insert(0, str(Path(resources) / "check"))
    import exe_fingerprint  # noqa: E402  (bundled with the check backend)
    data = Path(exe).read_bytes()
    if exe_fingerprint.identify(data) != "ps_demo":
        raise SetupError("%s isn't the supported executable." % Path(exe).name,
                         "The port supports EA's ProStreet demo release (nfsdemo.exe, as EA's demo installs it). "
                         "Copy-protected retail executables can't be used.")
    bank = game
    for part in DEMO_NIS_BANK:
        bank = find_child(bank, part) if bank else None
    if not bank or not bank.is_file() or bank.stat().st_size != DEMO_NIS_BANK_SIZE:
        raise SetupError("%s doesn't hold the demo's own game data." % game,
                         "The demo executable needs the demo's data (its sound offsets are built in): choose the folder "
                         "EA's ProStreet demo installed, not the full game's.")
    events.say("Game folder: %s" % game)
    events.say("Executable: %s (EA's ProStreet demo release)" % Path(exe).name)
    return game, Path(exe)


def prepare_source(events, resources, work):
    resources = Path(resources)
    payload = resources / "source.tar.gz"
    if not payload.is_file():
        raise SetupError("This Setup carries no source (source.tar.gz).", "Download Setup again.")
    stamp = sha256(payload)
    src = work / "source"
    if (work / "source.sha256").is_file() and (work / "source.sha256").read_text().strip() == stamp and src.is_dir():
        events.say("Source unchanged since the last build: reusing it")
    else:
        keep = work / "third_party.keep"
        if (src / "third_party").is_dir():                     # the built FFmpeg survives a source update
            shutil.rmtree(str(keep), ignore_errors=True)
            shutil.move(str(src / "third_party"), str(keep))
        shutil.rmtree(str(src), ignore_errors=True)
        src.mkdir(parents=True)
        with tarfile.open(str(payload)) as t:
            for m in t.getmembers():                               # refuse paths and links leaving the tree
                bad = m.name.startswith("/") or ".." in Path(m.name).parts
                if m.issym() or m.islnk():
                    target = os.path.normpath(os.path.join(os.path.dirname(m.name), m.linkname) if m.issym() else m.linkname)
                    bad = bad or m.linkname.startswith("/") or target == ".." or target.startswith("../")
                if bad:
                    raise SetupError("The bundled source contains an unsafe entry: %s" % m.name, "Download Setup again.")
            t.extractall(str(src))
        if keep.is_dir():
            shutil.rmtree(str(src / "third_party"), ignore_errors=True)
            shutil.move(str(keep), str(src / "third_party"))
        (work / "source.sha256").write_text(stamp + "\n")
        events.say("Source unpacked: %s" % src)
    # capstone (the translator's disassembler) next to the translator: build_game.py puts recomp/ on its path, so the
    # bundled copy is found under python3 -I (no PYTHONPATH), in the worker processes too.
    shutil.rmtree(str(src / "recomp/capstone"), ignore_errors=True)
    shutil.copytree(str(resources / "capstone"), str(src / "recomp/capstone"))
    tarball = resources / FFMPEG_TARBALL
    dl = src / "third_party/dl"
    dl.mkdir(parents=True, exist_ok=True)
    if not (dl / FFMPEG_TARBALL).is_file() or sha256(dl / FFMPEG_TARBALL) != FFMPEG_SHA:
        if not tarball.is_file() or sha256(tarball) != FFMPEG_SHA:
            raise SetupError("The bundled FFmpeg source is missing or damaged.", "Download Setup again.")
        shutil.copy(str(tarball), str(dl / FFMPEG_TARBALL))
    return src


def bundle(events, src, stage_dir):
    app = stage_dir / (APP_NAME + ".app")
    shutil.rmtree(str(app), ignore_errors=True)
    (app / "Contents/MacOS").mkdir(parents=True)
    (app / "Contents/Resources").mkdir(parents=True)
    shutil.copy(str(src / "recomp/out/ps_demo/boot_ps"), str(app / "Contents/MacOS" / APP_EXEC))
    info = {
        "CFBundleIdentifier": APP_ID, "CFBundleName": APP_NAME, "CFBundleDisplayName": APP_NAME,
        "CFBundleExecutable": APP_EXEC, "CFBundlePackageType": "APPL", "CFBundleShortVersionString": APP_VERSION,
        "CFBundleVersion": APP_VERSION, "LSMinimumSystemVersion": "13.0",
        "LSApplicationCategoryType": "public.app-category.racing-games", "NSHighResolutionCapable": True,
        "GCSupportsControllerUserInteraction": True,
    }
    with open(str(app / "Contents/Info.plist"), "wb") as f:
        plistlib.dump(info, f)
    for argv in (["/usr/bin/codesign", "--force", "--sign", "-", str(app)],
                 ["/usr/bin/codesign", "--verify", "--strict", str(app)]):
        r = subprocess.run(argv, capture_output=True, text=True)
        if r.returncode != 0:
            raise SetupError("Signing the app failed: %s" % (r.stderr.strip() or r.stdout.strip()))
    events.say("App signed: %s" % app)
    return app


def install(events, app, dest, game, exe):
    dest = Path(dest).expanduser()
    if dest == Path("/Applications") and not os.access("/Applications", os.W_OK):
        dest = Path.home() / "Applications"
    dest.mkdir(parents=True, exist_ok=True)
    target = dest / app.name
    old = dest / (app.name + ".previous")
    shutil.rmtree(str(old), ignore_errors=True)
    if target.exists():
        os.rename(str(target), str(old))
    try:
        shutil.move(str(app), str(target))
    except OSError:
        if old.exists():
            os.rename(str(old), str(target))
        raise
    shutil.rmtree(str(old), ignore_errors=True)
    # The app reads its game folder from its preferences (runtime/app.m app_pref "game_dir"); EA's demo installer
    # names the exe nfsdemo.exe, which the app finds there by itself.
    data = SUPPORT / "NFSPS-port"
    data.mkdir(parents=True, exist_ok=True)
    prefs = data / "app.txt"
    lines = [l for l in (prefs.read_text().splitlines() if prefs.is_file() else []) if not l.startswith("game_dir")]
    lines.append("game_dir=%s" % game)
    prefs.write_text("\n".join(lines) + "\n")
    events.say("Installed: %s" % target)
    return target


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    ap.add_argument("--game", required=True)
    ap.add_argument("--exe")
    ap.add_argument("--resources", default=str(Path(__file__).resolve().parent))
    ap.add_argument("--dest", default="/Applications")
    ap.add_argument("--work", default=str(SUPPORT / "NFSPS-Setup/work"))
    a = ap.parse_args(argv)
    events = Events(LOGS / "build.log")
    work = Path(a.work)
    try:
        events.stage("preflight")
        preflight(events)
        events.stage("game")
        game, exe = check_game(events, a.resources, a.game, Path(a.exe) if a.exe else None)
        events.stage("source")
        work.mkdir(parents=True, exist_ok=True)
        src = prepare_source(events, a.resources, work)
        py = "/usr/bin/python3"
        env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": str(Path.home()), "TMPDIR": os.environ.get("TMPDIR", "/tmp"),
               "LANG": "en_US.UTF-8", "TOOLS_PY": py, "JOBS": str(max(2, (os.cpu_count() or 4)))}
        events.stage("recompile")
        run(events, [py, "-I", "recomp/build_game.py", "--game", "ps_demo", "--exe", exe], src, env)
        if not (src / "recomp/out/ps_demo/nfs.a").is_file():
            raise SetupError("The recompiler produced no nfs.a.")
        events.stage("ffmpeg")
        ff = src / "third_party/ffmpeg/lib"
        if all((ff / ("lib%s.a" % n)).is_file() for n in ("avformat", "avcodec", "swscale", "swresample", "avutil")):
            events.say("FFmpeg already built: reusing it")
        else:
            run(events, ["/bin/sh", "media/build_ffmpeg.sh"], src, env)
        events.stage("shaders")
        run(events, ["/bin/sh", "host/shaders/build.sh", "lib"], src, env)
        events.stage("audio")
        run(events, ["/bin/sh", "host/audio/build.sh", "lib"], src, env)
        events.stage("runtime")
        run(events, ["/bin/sh", "runtime/build_ps.sh"], src, env)
        events.stage("bundle")
        app = bundle(events, src, work / "stage")
        events.stage("install")
        installed = install(events, app, a.dest, game, exe)
        events.emit(event="done", app=str(installed))
        return 0
    except SetupError as e:
        events.write("ERROR: %s\n%s" % (e, e.fix))
        events.emit(event="error", stage=events.current, message=str(e), fix=e.fix)
        return 1
    except Exception as e:  # noqa: BLE001  (reported to the player, with the log)
        import traceback
        events.write(traceback.format_exc())
        events.emit(event="error", stage=events.current, message="%s: %s" % (type(e).__name__, e),
                    fix="Open the log for details and try again.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
