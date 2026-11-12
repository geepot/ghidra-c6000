#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""SAT phase contract (SPRUFE8B SAT p.437, Table 2-9, 2.9.13): .L reads the 40-bit pair and writes dst in E1;
CSR.SAT and the SSR unit bit are set one cycle later and outrank an MVC write in that cycle.
IMAGE CASES.json [be]. Words are TI cl6x 8.3.15 output (-mv6740 --no_compress), no firmware bytes:

  1000 sat1     SAT .L1 A5:A4,A6 || MV .S1 A6,A8 ; MV .S1 A6,A9 ; B B3 ; NOP 5
  1040 sat2     SAT .L2 B5:B4,B6 || MV .S2 B6,B8 ; MV .S2 B6,B9 ; B B3 ; NOP 5
  1080 satp     [B0] SAT .L1 A5:A4,A6 ; MV .S1 A6,A9 ; B B3 ; NOP 5
  10c0 satpair  SAT .L1 A5:A4,A6 || SAT .L2 B5:B4,B6 ; B B3 ; NOP 5         both units' flags survive
  1100 satcsr   SAT .L1 A5:A4,A6 ; MVC .S2 CSR,B8 ; MVC .S2 CSR,B9 ; B B3 ; NOP 5
                                                     B8 is read before CSR.SAT is set, B9 after
  1140 satclr   SAT .L1 A5:A4,A6 || MVC .S2 B8,CSR ; B B3 ; NOP 5         the MVC clear lands first
  1180 satmvc   SAT .L1 A5:A4,A6 ; MVC .S2 B8,CSR ; B B3 ; NOP 5          same cycle as the flag: refused
  11c0 satret   B B3 ; NOP 4 ; SAT .L1 A5:A4,A6                           flag lands after the return: refused
"""
from pathlib import Path
import json, struct, sys

TAIL = [0x000C0362, 0x00008000]
WORDS = {0x1000: [0x03100819, 0x041806A0, 0x049806A0] + TAIL, 0x1040: [0x0310081B, 0x041806A2, 0x049806A2] + TAIL,
         0x1080: [0x23100818, 0x049806A0] + TAIL, 0x10C0: [0x03100819, 0x0310081A] + TAIL,
         0x1100: [0x03100818, 0x040403E2, 0x048403E2] + TAIL, 0x1140: [0x03100819, 0x00A003A2] + TAIL,
         0x1180: [0x03100818, 0x00A003A2] + TAIL, 0x11C0: [0x000C0362, 0x00006000, 0x03100818]}
OLD, CSR = 0x13579BDF, 0x00000100
NOSAT, SATNEG = (0, 0x12345678), (0xFF, 0x7FFFFFFF)


def sat(hi, lo):
    v = (hi & 0xFF) << 32 | lo
    v -= (1 << 40) if v >> 39 else 0
    if v > 0x7FFFFFFF: return 0x7FFFFFFF, True
    if v < -0x80000000: return 0x80000000, True
    return v & 0xFFFFFFFF, False


def main():
    if len(sys.argv) not in (3, 4) or (len(sys.argv) == 4 and sys.argv[3] != "be"):
        raise SystemExit(__doc__)
    endian = ">" if len(sys.argv) == 4 else "<"
    image = bytearray(0x200)
    for entry, words in WORDS.items():
        for i, w in enumerate(words):
            struct.pack_into(endian + "I", image, entry - 0x1000 + 4 * i, w)
    pairs = [(0, 0x12345678), (0xFF, 0x80000000), (0x12345600, 0x7FFFFFFF), (1, 0), (0xFE, 0), (0x7F, 0xFFFFFFFF), (0x80, 0)]
    rows = []
    for hi, lo in pairs:
        value, saturated = sat(hi, lo)
        csr = CSR | (0x200 if saturated else 0)
        for name, entry, bank, unit in (("sat1", 0x1000, "A", 1), ("sat2", 0x1040, "B", 2)):
            rows.append(dict(name=f"{name}_{hi:x}_{lo:x}", entry=entry,
                             input={"B3": 0x9000, "CSR": CSR, f"{bank}5": hi, f"{bank}4": lo, f"{bank}6": OLD},
                             expected={f"{bank}6": value, f"{bank}8": OLD, f"{bank}9": value, "CSR": csr,
                                       "SSR": unit if saturated else 0, "PC": 0x9000}))
        for truth in (0, 1):
            rows.append(dict(name=f"satp_{truth}_{hi:x}_{lo:x}", entry=0x1080,
                             input={"B3": 0x9000, "CSR": CSR, "A5": hi, "A4": lo, "A6": OLD, "B0": truth},
                             expected={"A6": value if truth else OLD, "A9": value if truth else OLD,
                                       "CSR": csr if truth else CSR, "SSR": 1 if truth and saturated else 0, "PC": 0x9000}))
    for a in (NOSAT, SATNEG):
        for b in (NOSAT, SATNEG):
            (va, sa), (vb, sb) = sat(*a), sat(*b)
            rows.append(dict(name=f"satpair_{int(sa)}{int(sb)}", entry=0x10C0,
                             input={"B3": 0x9000, "CSR": CSR, "A5": a[0], "A4": a[1], "B5": b[0], "B4": b[1]},
                             expected={"A6": va, "B6": vb, "CSR": CSR | (0x200 if sa or sb else 0),
                                       "SSR": (1 if sa else 0) | (2 if sb else 0), "PC": 0x9000}))
    for pair in (NOSAT, SATNEG):
        value, saturated = sat(*pair)
        flag = 0x200 if saturated else 0
        rows.append(dict(name=f"satcsr_{int(saturated)}", entry=0x1100,
                         input={"B3": 0x9000, "CSR": CSR, "A5": pair[0], "A4": pair[1]},
                         expected={"A6": value, "B8": CSR, "B9": CSR | flag, "CSR": CSR | flag, "SSR": flag >> 9, "PC": 0x9000}))
        rows.append(dict(name=f"satclr_{int(saturated)}", entry=0x1140,
                         input={"B3": 0x9000, "CSR": CSR | 0x200, "A5": pair[0], "A4": pair[1], "B8": 0},
                         expected={"A6": value, "CSR": CSR | flag, "SSR": flag >> 9, "PC": 0x9000}))
    rows.append(dict(name="satmvc", entry=0x1180, refused="control-register write lands with SAT status flags"))
    rows.append(dict(name="satret", entry=0x11C0, refused="return leaves architectural pipeline effects pending"))
    Path(sys.argv[1]).write_bytes(image)
    Path(sys.argv[2]).write_text(json.dumps(rows, indent=2) + "\n")


if __name__ == "__main__":
    main()
