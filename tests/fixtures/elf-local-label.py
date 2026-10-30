#!/usr/bin/env python3
"""TI-style C6000 ELF whose code labels are local, size-0 STT_FUNC, as cl6x emits them. Usage: IMAGE [be].

  1000 f:      MVK.S2 1,B5
  1004         B.S1 0x1020            (jump to a local label)
  1008         NOP 5
  1010 $C$RL3: NOP                   (padding after the jump's delay slots: no flow reaches it)
  1020 $C$L1:  B.S1 0x1100            (call g)
  1024         ADDKPC.S2 0x1028,B3,4
  1028 $C$RL1: B.S1 0x1140            (call $C$L2)
  102c         ADDKPC.S2 0x1030,B3,4
  1030 $C$RL2: B.S2 B3 ; NOP 5        (return)
  10c0 h:      B.S2 B3 ; NOP 5        (static function: also local, size-0, hidden STT_FUNC)
  10e0 $Tramp$S$$g: MVKL/MVKH g,B30 ; B.S2 B30 ; NOP 5  (linker far-call trampoline: local, size-0
                                      STT_FUNC, not a compiler label; not called here)
  1100 g:      B.S2 B3 ; NOP 5
  1140 $C$L2:  B.S2 B3 ; NOP 5        (a called compiler label stays a function)
  11e0 $C$L:   B.S2 B3 ; NOP 5        (near-miss names, not emitted by TI tools: stay functions)
  1200 $C$L1a: B.S2 B3 ; NOP 5
"""

from pathlib import Path
import struct
import sys

B_B3 = 0x362 | (3 << 18)
NOP5 = 4 << 13
TEXT = {
    0x1000: 0x2A | (1 << 7) | (5 << 23),                # MVK.S2 1,B5 (not a thunk)
    0x1004: 0x10 | (0x08 << 7),                         # B.S1 packet+0x20
    0x1008: NOP5,
    0x1020: 0x10 | (0x38 << 7),                         # B.S1 packet+0xe0
    0x1024: 0x162 | (2 << 16) | (4 << 13) | (3 << 23),  # ADDKPC.S2 packet+8,B3,4
    0x1028: 0x10 | (0x48 << 7),                         # B.S1 packet+0x120
    0x102C: 0x162 | (4 << 16) | (4 << 13) | (3 << 23),  # ADDKPC.S2 packet+0x10,B3,4
    0x1030: B_B3,
    0x1034: NOP5,
    0x10C0: B_B3,
    0x10C4: NOP5,
    0x10E0: 0x2A | (0x1100 << 7) | (30 << 23),          # MVKL.S2 g,B30
    0x10E4: 0x6A | (30 << 23),                          # MVKH.S2 g,B30
    0x10E8: 0x362 | (30 << 18),                         # B.S2 B30
    0x10EC: NOP5,
    0x1100: B_B3,
    0x1104: NOP5,
    0x1140: B_B3,
    0x1144: NOP5,
    0x11E0: B_B3,
    0x11E4: NOP5,
    0x1200: B_B3,
    0x1204: NOP5,
}
BASE, SIZE = 0x1000, 0x220
# name, value, bind (0 local, 1 global), st_other (2 = STV_HIDDEN, as cl6x emits); all STT_FUNC
SYMS = [("f", 0x1000, 1, 0), ("$C$RL3", 0x1010, 0, 2), ("$C$L1", 0x1020, 0, 2), ("$C$RL1", 0x1028, 0, 2),
        ("$C$RL2", 0x1030, 0, 2), ("h", 0x10C0, 0, 2), ("$Tramp$S$$g", 0x10E0, 0, 0), ("g", 0x1100, 1, 0),
        ("$C$L2", 0x1140, 0, 2), ("$C$L", 0x11E0, 0, 2), ("$C$L1a", 0x1200, 0, 2)]


def build(be):
    e = ">" if be else "<"
    text = bytearray(SIZE)
    for a, w in TEXT.items():
        struct.pack_into(e + "I", text, a - BASE, w)
    strtab = b"\0" + b"".join(n.encode() + b"\0" for n, *_ in SYMS)
    name = {n: strtab.index(b"\0" + n.encode() + b"\0") + 1 for n, *_ in SYMS}
    sym = bytearray(16)  # null symbol
    for bind in (0, 1):  # locals first, as sh_info requires
        for n, v, b, vis in SYMS:
            if b == bind:
                sym += struct.pack(e + "IIIBBH", name[n], v, 0, (b << 4) | 2, vis, 1)
    nlocal = 1 + sum(1 for s in SYMS if s[2] == 0)
    shstr = b"\0.text\0.symtab\0.strtab\0.shstrtab\0"
    # layout: ehdr(52) phdr(32) text symtab strtab shstrtab shdrs
    o_text = 0x100
    o_sym = o_text + SIZE
    o_str = o_sym + len(sym)
    o_shs = o_str + len(strtab)
    o_sh = (o_shs + len(shstr) + 3) & ~3
    ident = b"\x7fELF" + bytes([1, 2 if be else 1, 1, 0]) + bytes(8)
    eh = ident + struct.pack(e + "HHIIIIIHHHHHH", 2, 140, 1, 0x1000, 52, o_sh, 0, 52, 32, 1, 40, 5, 4)
    ph = struct.pack(e + "IIIIIIII", 1, o_text, BASE, BASE, SIZE, SIZE, 5, 0x20)
    sh = bytes(40)
    sh += struct.pack(e + "IIIIIIIIII", 1, 1, 6, BASE, o_text, SIZE, 0, 0, 32, 0)
    sh += struct.pack(e + "IIIIIIIIII", 7, 2, 0, 0, o_sym, len(sym), 3, nlocal, 4, 16)
    sh += struct.pack(e + "IIIIIIIIII", 15, 3, 0, 0, o_str, len(strtab), 0, 0, 1, 0)
    sh += struct.pack(e + "IIIIIIIIII", 23, 3, 0, 0, o_shs, len(shstr), 0, 0, 1, 0)
    img = bytearray(o_sh)
    img[0:52] = eh
    img[52:84] = ph
    img[o_text:o_text + SIZE] = text
    img[o_sym:o_sym + len(sym)] = sym
    img[o_str:o_str + len(strtab)] = strtab
    img[o_shs:o_shs + len(shstr)] = shstr
    return bytes(img) + sh


if __name__ == "__main__":
    Path(sys.argv[1]).write_bytes(build(len(sys.argv) > 2 and sys.argv[2] == "be"))
