"""A 32-bit PE image as recomp.Recompiler sees it, for any exe or DLL (recomp.PE is pinned to MW's speed.exe).

    img = pe_image.Image(path)               # at its preferred base
    img = pe_image.Image(path, base=0x02000000)   # moved: HIGHLOW base relocations applied

Provides what the translator reads: read(va, n) over the mapped image (bytes past a section's raw data are zero, as the
loader maps them), and imports {IAT slot VA: "DLL!name"}. Also base, size, entry (VA), sections
[(name, vsize, rva, raw_size, raw_offset, characteristics)] and code() (the first executable section's VA range).
The file is only read; nothing is executed. Stdlib only.
"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pe_report  # noqa: E402


class Image:
    def __init__(self, src, base=None):
        raw = open(src, "rb").read() if isinstance(src, (str, os.PathLike)) else bytes(src)
        info = pe_report.parse(raw)                        # NotPE for anything that isn't a 32-bit x86 PE
        self.preferred_base = info["image_base"]
        self.base = self.preferred_base if base is None else base
        self.size = info["size_of_image"]
        self.entry = self.base + info["entry_rva"]
        self.sections = [(s["name"], s["vsize"], s["va"], s["raw_size"], s["raw_off"], s["chars"]) for s in info["sections"]]
        image = bytearray(self.size)
        off = struct.unpack_from("<I", raw, 0x3C)[0]
        headers = struct.unpack_from("<I", raw, off + 24 + 60)[0]
        image[:min(headers, self.size)] = raw[:min(headers, self.size)]
        for _, vs, rva, rs, ro, _ in self.sections:
            n = min(rs, max(0, self.size - rva), max(0, len(raw) - ro))
            image[rva:rva + n] = raw[ro:ro + n]
        self.relocations = 0
        delta = (self.base - self.preferred_base) & 0xFFFFFFFF
        rva, size = info["dirs"].get("basereloc", (0, 0))
        if delta and not rva:
            raise ValueError("image has no relocations and can't be moved from its preferred base")
        if delta:
            pos, end = rva, rva + size
            while pos + 8 <= end:
                page, bs = struct.unpack_from("<II", image, pos)
                if bs < 8:
                    break
                for at in range(pos + 8, pos + bs, 2):
                    item = struct.unpack_from("<H", image, at)[0]
                    if item >> 12 == 3:                    # IMAGE_REL_BASED_HIGHLOW
                        t = page + (item & 0xFFF)
                        v = struct.unpack_from("<I", image, t)[0]
                        struct.pack_into("<I", image, t, (v + delta) & 0xFFFFFFFF)
                        self.relocations += 1
                pos += bs
        self.data = bytes(image)
        shift = self.base - self.preferred_base
        self.imports = {slot + shift: f"{dll}!{fn}" for dll, fns in info["imports"].items() for slot, fn in fns}

    def read(self, va, n):
        rva = va - self.base
        return self.data[rva:rva + n] if 0 <= rva and rva + n <= self.size else None

    def code(self):
        """(lo, hi) VA range of the first executable section."""
        for name, vs, rva, rs, _, chars in self.sections:
            if chars & 0x20000000:
                return self.base + rva, self.base + rva + (vs or rs)
        raise ValueError("no executable section")
