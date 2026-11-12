#!/usr/bin/env python3
"""MW's inline translator patches apply only to MW's speed.exe (recomp.Recompiler.mw_patches).

Run: tools/.venv/bin/python -I recomp/mw_patches_test.py        (needs capstone)

ProStreet code sits at addresses MW patches (e.g. the car85 bound at 006690BB). A synthetic function there holding a
different instruction must translate as is when the image isn't MW's, and must still hit MW's own guard (the
"car85 bound instruction changed" assert) when the image carries MW's code fingerprint: the gate keeps MW's
translation unchanged and keeps every other game out of it.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import recomp  # noqa: E402

SITE = 0x006690BB                                   # MW: car85 bound "cmp ..., 0x54"
CODE = b"\x55\x89\xe5" + b"\x90" * (SITE - 0x006690B0 - 3) + b"\x83\xf8\x07" + b"\x5d\xc3"   # here: cmp eax, 7


class FakeImage:
    def __init__(self, fingerprint):
        self.fingerprint, self.imports = fingerprint, {}

    def read(self, va, n):
        off = va - 0x006690B0
        return CODE[off:off + n] if 0 <= off < len(CODE) else b"\xcc" * n


def translate(fingerprint):
    rc = recomp.Recompiler(pe=FakeImage(fingerprint), functions={0x006690B0: 0x006690B0 + len(CODE)})
    rc.calls = True
    return rc, rc.translate(0x006690B0, 0x006690B0 + len(CODE), name="f")


class Gate(unittest.TestCase):
    def test_other_image_translates_as_is(self):
        for fp in (None, "78c0d3abe0699de96ef8b3adea3de79d309cce641281e111ff6729b7a841f91f"):
            rc, (code, why) = translate(fp)
            self.assertFalse(rc.mw_patches)
            self.assertIsNotNone(code, why)
            self.assertNotIn("car85", "\n".join(code))

    def test_mw_image_keeps_mw_patches(self):
        rc = recomp.Recompiler(pe=FakeImage(recomp.SPEED_EXE_FINGERPRINT))
        self.assertFalse(rc.mw_patches)             # only with calls translated, as before
        rc.calls = True
        self.assertTrue(rc.mw_patches)
        with self.assertRaisesRegex(AssertionError, "car85 bound instruction changed"):
            translate(recomp.SPEED_EXE_FINGERPRINT)


if __name__ == "__main__":
    unittest.main(verbosity=2)
