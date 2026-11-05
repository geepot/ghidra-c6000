#!/usr/bin/env python3
"""Generate AMR circular-addressing execution cases. IMAGE CASES.tsv [be]."""
import re
import struct
import sys
from pathlib import Path


# index, instruction, addressing mode, base, offset register, offset value,
# AMR, initial base, target register, target value, expected target,
# expected base, store address, expected stored halfword; the manifest adds
# the code address.
CASES = [
    ("ADDAH.D1", None, "A4", "A1", 0x13, 0x00040001, 0x1100,
     "A4", 0, 0x1106, 0x1106, 0, 0),
    ("ADDAW.D2", None, "B5", "B1", 9, 0x00800800, 0x1120,
     "B6", 0, 0x1124, 0x1120, 0, 0),
    ("SUBAW.D1", None, "A6", "A1", 2, 0x00040010, 0x1104,
     "A7", 0, 0x111C, 0x1104, 0, 0),
    ("ADDAD.D2", None, "B4", "B1", 5, 0x00040100, 0x1300,
     "B8", 0, 0x1308, 0x1300, 0, 0),
    ("SUBAB.D2", None, "B4", "B1", 5, 0x00040100, 0x1302,
     "B8", 0, 0x131D, 0x1302, 0, 0),
    ("SUBAH.D1", None, "A7", "A1", 5, 0x00040040, 0x1324,
     "A10", 0, 0x133A, 0x1324, 0, 0),
    ("ADDAB.D1", None, "A8", "A1", 0x25, 0x00040001, 0x1130,
     "A9", 0, 0x1155, 0x1130, 0, 0),
    ("LDW.D1", 0x9, "A4", "", 9, 0x00040001, 0x1200,
     "A1", 0, 0x12345678, 0x1204, 0, 0),
    ("LDW.D1", 0xA, "A4", "", 2, 0x00040001, 0x1204,
     "A1", 0, 0x12345678, 0x121C, 0, 0),
    ("STH.D2", 0x1, "B7", "", 19, 0x00808000, 0x1240,
     "B2", 0xA1B2C3D4, 0xA1B2C3D4, 0x1240, 0x1246, 0xC3D4),
    ("STB.D1", 0x1, "A5", "", 9, 0x00040004, 0x127C,
     "A2", 0xA1B2C3D4, 0xA1B2C3D4, 0x127C, 0x1265, 0xD4),
    ("LDW.D1", 0x9, "A8", "", 9, 0x00040001, 0x1200,
     "A1", 0, 0x0BADC0DE, 0x1224, 0, 0),
    ("LDW.D1", 0x8, "A4", "", 1, 0x00040001, 0x1200,
     "A1", 0, 0x89ABCDEF, 0x121C, 0, 0),
    ("LDW.D1", 0x9, "A4", "", 9, 0x001F0001, 0x1200,
     "A1", 0, 0x0BADC0DE, 0x1224, 0, 0),
]

# Every AMR field set (BK0 = 32 bytes): A4-A7/B4-B7 wrap, every other base,
# including the stack pointer B15, stays linear (SPRUFE8B 2.8.3).
ALL_BK0 = 0x00045555
CIRCULAR = (0x12345678, 0x1204)
LINEAR = (0x0BADC0DE, 0x1224)
for _base in ("A4", "A5", "A6", "A7", "B4", "B5", "B6", "B7",
              "A3", "A8", "B3", "B8", "B15"):
    _unit, _target = ("D1", "A1") if _base[0] == "A" else ("D2", "B1")
    _expect = CIRCULAR if 4 <= int(_base[1:]) <= 7 else LINEAR
    CASES.append((f"LDW.{_unit}", 0x9, _base, "", 9, ALL_BK0, 0x1200,
                  _target, 0, *_expect, 0, 0))
CASES += [
    # *+R[ucst5]: the address wraps, the base is unchanged.
    ("LDW.D1", 0x1, "A4", "", 9, ALL_BK0, 0x1200, "A1", 0, 0x12345678, 0x1200, 0, 0),
    ("LDW.D2", 0x1, "B15", "", 9, ALL_BK0, 0x1200, "B1", 0, 0x0BADC0DE, 0x1200, 0, 0),
    # *R++[ucst5]: transfer from the old base, then the updated base wraps.
    ("LDW.D1", 0xB, "A4", "", 9, ALL_BK0, 0x1204, "A1", 0, 0x12345678, 0x1208, 0, 0),
    ("LDW.D2", 0xB, "B15", "", 9, ALL_BK0, 0x1204, "B1", 0, 0x12345678, 0x1228, 0, 0),
    # *++R[offsetR] and *-R[offsetR].
    ("LDW.D1", 0xD, "A4", "A0", 9, ALL_BK0, 0x1200, "A1", 0, 0x12345678, 0x1204, 0, 0),
    ("LDW.D2", 0xD, "B15", "B0", 9, ALL_BK0, 0x1200, "B1", 0, 0x0BADC0DE, 0x1224, 0, 0),
    ("LDW.D1", 0x4, "A4", "A0", 7, ALL_BK0, 0x1200, "A1", 0, 0x12345678, 0x1200, 0, 0),
    ("LDW.D2", 0x4, "B15", "B0", 7, ALL_BK0, 0x1240, "B1", 0, 0x0BADC0DE, 0x1240, 0, 0),
    # Every field selects BK1 (32 bytes); BK0 is 2 bytes.
    ("LDW.D1", 0x9, "A4", "", 9, 0x0080AAAA, 0x1200, "A1", 0, 0x12345678, 0x1204, 0, 0),
]


def slot(index):
    """Code address of a case; 0x1200-0x123F holds the data words."""
    return 0x1000 + 32 * (index if index < 16 else index + 2)


def encode(mnemonic, mode, base, offset_reg, offset, target):
    decode = Path(__file__).resolve().parents[2] / "data/languages/c6000_decode.sinc"
    operand = "Src1," if offset_reg else "UCst5,"
    candidates = [line for line in decode.read_text().splitlines()
                  if line.startswith(f':^Cond^"{mnemonic}" ') and
                  (f"mode=0x{mode:x} " in line if mode is not None
                   else f"Src2Local, {operand}" in line)]
    if not candidates:
        raise ValueError((mnemonic, mode))
    line = candidates[0]
    word = sum(int(value) << int(bit) for bit, value in
               re.findall(r"\bi(\d+)=(\d)\b", line))
    if mode is not None:
        word |= mode << 9
    word |= (int(base[1:]) << 18) | (offset << 13 if not offset_reg else
                                      int(offset_reg[1:]) << 13)
    word |= int(target[1:]) << 23
    if base[0] == "B":
        word |= 1 << 1
    return word


def main():
    image, manifest = map(Path, sys.argv[1:3])
    endian = ">" if len(sys.argv) > 3 and sys.argv[3] == "be" else "<"
    data = bytearray(0x800)
    for index, row in enumerate(CASES):
        mnemonic, mode, base, source, offset, amr, base_in, target, target_in, \
            expected_target, expected_base, store_addr, store_value = row
        word = encode(mnemonic, mode, base, source, offset, target)
        struct.pack_into(endian + "I", data, slot(index) - 0x1000, word)
    for addr, value in ((0x1204, 0x12345678), (0x121C, 0x89ABCDEF),
                        (0x1224, 0x0BADC0DE)):
        struct.pack_into(endian + "I", data, addr - 0x1000, value)
    image.parent.mkdir(parents=True, exist_ok=True)
    image.write_bytes(data)
    with manifest.open("w") as out:
        for index, row in enumerate(CASES):
            mnemonic, mode, base, source, offset, amr, base_in, target, target_in, \
                expected_target, expected_base, store_addr, store_value = row
            out.write("\t".join((str(index), mnemonic, base, source or "-",
                                 f"{offset:x}", f"{amr:x}", f"{base_in:x}",
                                 target, f"{target_in:x}", f"{expected_target:x}",
                                 f"{expected_base:x}", f"{store_addr:x}",
                                 f"{store_value:x}", f"{slot(index):x}")) + "\n")


if __name__ == "__main__":
    main()
