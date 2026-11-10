"""A public stand-in for the developer emulator (tools/scripts/speed_emu.py, not in this checkout), for
`difftest.py --synth` only: the synthetic cases need a Unicorn x86-32 instance with the stack, a small image region and
the return trap mapped, and the register-name map. They never touch the game's own image, so nothing else is modelled.
Full-function difftests (without --synth) still need the real tools and MW's speed.exe.

    emu = SpeedEmu(); emu.uc.emu_start(entry, RETURN_TRAP, count=...)
"""
from unicorn import UC_ARCH_X86, UC_MODE_32, Uc
from unicorn.x86_const import (UC_X86_REG_EAX, UC_X86_REG_EBP, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDI,
                               UC_X86_REG_EDX, UC_X86_REG_EFLAGS, UC_X86_REG_ESI, UC_X86_REG_ESP)

STACK_HI = 0x7FF00000                    # difftest.py's STACK_LO..STACK_HI
STACK_LO = STACK_HI - 0x100000
IMAGE_BASE, IMAGE_SIZE = 0x00400000, 0x10000   # covers difftest's stand-in image (one .data page at 0x401000)
RETURN_TRAP = 0x7FFF0000                 # the return address the cases ret to; emulation stops when EIP gets here
REGS = {"eax": UC_X86_REG_EAX, "ecx": UC_X86_REG_ECX, "edx": UC_X86_REG_EDX, "ebx": UC_X86_REG_EBX,
        "esp": UC_X86_REG_ESP, "ebp": UC_X86_REG_EBP, "esi": UC_X86_REG_ESI, "edi": UC_X86_REG_EDI,
        "eflags": UC_X86_REG_EFLAGS}


class SpeedEmu:
    def __init__(self, heap_size=0):
        del heap_size                        # accepted for speed_emu's signature; the synthetic cases use no heap
        self.uc = Uc(UC_ARCH_X86, UC_MODE_32)
        self.uc.mem_map(STACK_LO, STACK_HI - STACK_LO + 0x10000)   # the cases' esp window reaches a little above STACK_HI - 0x800
        self.uc.mem_map(IMAGE_BASE, IMAGE_SIZE)
        self.uc.mem_map(RETURN_TRAP, 0x1000)
        self.uc.mem_write(RETURN_TRAP, b"\xf4")                   # hlt, never executed: emu_start stops at the address
