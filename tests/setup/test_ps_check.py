#!/usr/bin/env python3
"""The early ProStreet Setup (tools/ps_setup): its check backend and the Swift app's headless check (offline; temp dirs).

Run: python3 -I tests/setup/test_ps_check.py      (stdlib only; the app check needs swiftc, the disc check hdiutil)

Synthetic executables (recomp/pe_report_test.build_pe, signed with authenticode_test.sign_pe's own test key) cover
each verdict: supported (EA's pinned certificate and a pinned build, both pointed at the test key and the synthetic
build for the test), plain (EA-signed, another build), unverified (unsigned; or signed by someone else; or changed
after signing), protected (a .securom section), packed (entry point outside the first code section, encrypted code),
not a PE, nothing at the path. A folder is
searched for nfs.exe whatever its case, down to three levels and no deeper. A real disc image (hdiutil makehybrid)
is attached read-only, checked and detached again. The compiled Swift app's `--check` runs in its bundle layout.
Broken control: with the DRM name list emptied, the protected executable must stop being called protected.
"""
import importlib
import os
import random
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "recomp"))
sys.path.insert(0, str(ROOT / "tools" / "ps_setup"))
import authenticode  # noqa: E402
import authenticode_test  # noqa: E402
import check  # noqa: E402
import exe_fingerprint  # noqa: E402
import pe_report_test  # noqa: E402

PLAIN = pe_report_test.build_pe()
SECUROM = pe_report_test.build_pe(extra=[(".securom", pe_report_test.plain_code(0x800), 0xE0000020)])
KEY = authenticode_test.key(1)
SIGNED, TEST_CERT = authenticode_test.sign_pe(PLAIN, KEY, KEY)
PACKED = pe_report_test.build_pe(text=random.Random(3).randbytes(0x3000), extra=[(".IN", random.Random(4).randbytes(0x800), 0xE0000020)],
                                 entry_section=".IN")


class Check(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="test_ps_check."))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def put(self, rel, data):
        p = self.tmp / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        return p

    def pinned(self, build=False):
        """Point EA's pinned certificate (and, with build, the ps_demo profile) at the synthetic test key/build."""
        saved = (authenticode.EA_2007, dict(exe_fingerprint.PROFILES["ps_demo"]))
        authenticode.EA_2007 = TEST_CERT
        if build:
            p = exe_fingerprint.PROFILES["ps_demo"]
            p["regions"] = ((".text", 0x1000, 0x3000),)
            p["fingerprint"] = exe_fingerprint.describe_regions(SIGNED, p["regions"], p["tag"])[1]
        self.addCleanup(lambda: (setattr(authenticode, "EA_2007", saved[0]), exe_fingerprint.PROFILES["ps_demo"].update(saved[1])))

    def test_supported(self):
        self.pinned(build=True)
        r = check.check(str(self.put("nfs.exe", SIGNED)))
        self.assertEqual(r["verdict"], "supported")
        self.assertEqual(r["facts"]["signature"], "Electronic Arts, valid")
        self.assertTrue(r["facts"]["build"].startswith("NFS ProStreet demo release"))

    def test_plain_other_build(self):
        self.pinned()
        r = check.check(str(self.put("nfs.exe", SIGNED)))
        self.assertEqual((r["verdict"], r["facts"]["build"]), ("plain", "not a supported build"))

    def test_unverified(self):
        self.assertEqual(check.check(str(self.put("a/nfs.exe", PLAIN)))["verdict"], "unverified")      # unsigned
        r = check.check(str(self.put("b/nfs.exe", SIGNED)))                                             # not EA's certificate
        self.assertEqual(r["verdict"], "unverified")
        self.assertIn("Test Signer", r["facts"]["signature"])
        self.pinned(build=True)
        t = bytearray(SIGNED)
        t[0x400 + 0x20] ^= 1                                                                            # changed after signing
        r = check.check(str(self.put("c/nfs.exe", bytes(t))))
        self.assertEqual(r["verdict"], "unverified")
        self.assertIn("file changed after signing", r["facts"]["signature"])

    def test_plain(self):
        self.pinned()
        r = check.check(str(self.put("nfs.exe", SIGNED)))
        self.assertEqual(r["verdict"], "plain")
        self.assertEqual(r["title"], "This nfs.exe is plain code, signed by EA")
        self.assertEqual(set(r["facts"]), {"size", "sha256", "linked", "entry", "sections", "imports", "signature", "build"})
        self.assertEqual(r["facts"]["linked"], "2007-10-27 05:36 UTC")
        self.assertEqual(r["coverage"]["total"], 3)                    # GetTickCount, Sleep, WS2_32 #3: all handled
        self.assertEqual(r["coverage"]["handled"], 3)

    def test_protected(self):
        r = check.check(str(self.put("nfs.exe", SECUROM)))
        self.assertEqual((r["verdict"], r["tool"]), ("protected", "SecuROM"))
        self.assertEqual(r["title"], "This nfs.exe is copy-protected (SecuROM)")
        self.assertIn("never removes copy protection", r["detail"])

    def test_packed(self):
        r = check.check(str(self.put("nfs.exe", PACKED)))
        self.assertEqual(r["verdict"], "packed")
        self.assertTrue(any("entropy" in f for f in r["findings"]) and any("'.IN'" in f for f in r["findings"]), r["findings"])

    def test_not_pe_and_missing(self):
        self.assertEqual(check.check(str(self.put("nfs.exe", b"MZ nope")))["verdict"], "not_pe")
        self.assertEqual(check.check(str(self.tmp / "absent"))["verdict"], "not_found")

    def test_folder_search(self):
        self.put("Game/Program/NFS.EXE", PLAIN)
        r = check.check(str(self.tmp))
        self.assertEqual(r["verdict"], "unverified")
        self.assertTrue(r["exe"].endswith("Game/Program/NFS.EXE"), r["exe"])
        deep = self.tmp / "deep"
        self.put("deep/a/b/c/d/nfs.exe", PLAIN)
        self.assertEqual(check.check(str(deep))["verdict"], "not_found")   # four folders down: not searched

    @unittest.skipUnless(shutil.which("hdiutil"), "needs hdiutil")
    def test_disc_image(self):
        self.put("disc/nfs.exe", SECUROM)
        iso = self.tmp / "disc.iso"
        subprocess.run(["hdiutil", "makehybrid", "-quiet", "-iso", "-joliet", "-o", str(iso), str(self.tmp / "disc")], check=True)
        r = check.check(str(iso))
        self.assertEqual(r["verdict"], "protected")
        self.assertTrue(r.get("disc") and r["exe"].startswith(str(iso)), r["exe"])
        info = subprocess.run(["hdiutil", "info"], capture_output=True, text=True).stdout
        self.assertNotIn("ps_setup_disc.", info, "the disc image was left attached")

    def test_broken_control(self):
        saved = check.DRM
        check.DRM = set()
        try:
            v = check.check(str(self.put("nfs.exe", SECUROM)))["verdict"]
        finally:
            check.DRM = saved
        self.assertNotEqual(v, "protected", "without the DRM list the protected exe must not be called protected")

    @unittest.skipUnless(shutil.which("swiftc"), "needs swiftc")
    def test_swift_app_headless(self):
        # The app finds Resources/check/check.py; a bare executable's resource folder is its own folder.
        app = self.tmp / "app"
        (app / "check" / "runtime").mkdir(parents=True)
        for f in ("tools/ps_setup/check.py", "recomp/pe_report.py", "recomp/import_coverage.py", "recomp/authenticode.py",
                  "recomp/exe_fingerprint.py"):
            shutil.copy(ROOT / f, app / "check")
        sys.path.insert(0, str(ROOT / "recomp"))
        ic = importlib.import_module("import_coverage")
        for f in set(ic.Host(str(ROOT / "runtime")).files.values()) | {"runtime/boot.c"}:
            shutil.copy(ROOT / f, app / "check" / "runtime")
        subprocess.run(["swiftc", "-O", "-parse-as-library", "-target", "arm64-apple-macos14.5", "-o", str(app / "Setup"),
                        str(ROOT / "tools/ps_setup/SetupApp.swift")], check=True, capture_output=True)
        out = subprocess.run([str(app / "Setup"), "--check", str(self.put("nfs.exe", SECUROM))], capture_output=True, text=True, timeout=120)
        self.assertEqual(out.returncode, 0, out.stderr)
        verdict, title, facts, coverage = out.stdout.rstrip("\n").split("\t")
        self.assertEqual((verdict, title, facts), ("protected", "This nfs.exe is copy-protected (SecuROM)", "8 facts"))
        self.assertIn("of 3 imported functions", coverage)


if __name__ == "__main__":
    unittest.main(verbosity=2)
