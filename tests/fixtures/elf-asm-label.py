#!/usr/bin/env python3
"""TI-style C6000 ELF whose hand-written assembly labels are local, size-0 STT_FUNC, as cl6x emits them,
next to a static function of the same symbol type. Usage: IMAGE [be].

  1000 f_cond:  [!A1] B.S1 a_else ; NOP 5 ; MVK.S2 1,B5 ; B.S1 a_join ; NOP 5
  1014 a_else:  MVK.S2 2,B5            (reached by a conditional branch: a label)
  1018 a_join:  B.S2 B3 ; NOP 5        (fallen into: a label, also the target of the unconditional B)
  1040 f_loop:  MVK.S2 3,B5
  1044 b_loop:  MVK.S2 4,B5 ; [A1] B.S1 b_loop ; NOP 5 ; B.S2 B3 ; NOP 5   (loop head: a label)
  1080 f_tail:  B.S1 c_tail ; NOP 5
  10a0 c_tail:  B.S2 B3 ; NOP 5        (reached only by an unconditional B, maybe a tail call: stays a function)
  10c0 f_call:  [A1] B.S1 d_help ; NOP 5 ; B.S1 d_help ; ADDKPC.S2 d_ret,B3,4
  10d0 d_ret:   B.S2 B3 ; NOP 5        (the call's return point: a label)
  1100 d_help:  B.S2 B3 ; NOP 5        (called, and also branched to conditionally: stays a function)
  1140 e_static: B.S2 B3 ; NOP 5       (nothing reaches it, like an address-taken static: stays a function)
"""

from pathlib import Path
import importlib.util
import sys

spec = importlib.util.spec_from_file_location("elf_local_label", Path(__file__).with_name("elf-local-label.py"))
elf = importlib.util.module_from_spec(spec)
spec.loader.exec_module(elf)

B_B3, NOP5 = elf.B_B3, elf.NOP5
A1, NOT_A1 = 4 << 29, (4 << 29) | (1 << 28)


def b(at, to, cond=0):
    """B.S1 to a displacement from the fetch packet (SPRUFE8B 3.12)."""
    return cond | 0x10 | ((((to - (at & ~0x1F)) >> 2) & 0x1FFFFF) << 7)


def mvk(value):
    return 0x2A | (value << 7) | (5 << 23)  # MVK.S2 value,B5


TEXT = {
    0x1000: b(0x1000, 0x1014, NOT_A1), 0x1004: NOP5, 0x1008: mvk(1), 0x100C: b(0x100C, 0x1018), 0x1010: NOP5,
    0x1014: mvk(2), 0x1018: B_B3, 0x101C: NOP5,
    0x1040: mvk(3), 0x1044: mvk(4), 0x1048: b(0x1048, 0x1044, A1), 0x104C: NOP5, 0x1050: B_B3, 0x1054: NOP5,
    0x1080: b(0x1080, 0x10A0), 0x1084: NOP5, 0x10A0: B_B3, 0x10A4: NOP5,
    0x10C0: b(0x10C0, 0x1100, A1), 0x10C4: NOP5, 0x10C8: b(0x10C8, 0x1100),
    0x10CC: 0x162 | (4 << 16) | (4 << 13) | (3 << 23),  # ADDKPC.S2 packet+0x10,B3,4
    0x10D0: B_B3, 0x10D4: NOP5,
    0x1100: B_B3, 0x1104: NOP5,
    0x1140: B_B3, 0x1144: NOP5,
}
SIZE = 0x160
# name, value, bind (0 local, 1 global), st_other (2 = STV_HIDDEN, as cl6x emits); all STT_FUNC, size 0
SYMS = [("f_cond", 0x1000, 1, 0), ("a_else", 0x1014, 0, 2), ("a_join", 0x1018, 0, 2),
        ("f_loop", 0x1040, 1, 0), ("b_loop", 0x1044, 0, 2), ("f_tail", 0x1080, 1, 0), ("c_tail", 0x10A0, 0, 2),
        ("f_call", 0x10C0, 1, 0), ("d_ret", 0x10D0, 0, 2), ("d_help", 0x1100, 0, 2), ("e_static", 0x1140, 0, 2)]

if __name__ == "__main__":
    Path(sys.argv[1]).write_bytes(elf.build(len(sys.argv) > 2 and sys.argv[2] == "be", TEXT, SYMS, SIZE))
