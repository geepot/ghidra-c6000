#!/usr/bin/env python3
"""Generate nonaligned transfers across an AMR circular-buffer boundary."""
import re
import struct
import sys
from pathlib import Path


# mnemonic, base register, initial base, data register, store value, AMR, mask
CASES = [
    ("LDNW.D1", "A4", 0x131E, "A2", 0, 0x00040001, 0x1F),
    ("LDNDW.D1", "A4", 0x131C, "A1_A0", 0, 0x00040001, 0x1F),
    ("STNW.D1", "A4", 0x131E, "A2", 0xAABBCCDD, 0x00040001, 0x1F),
    ("STNDW.D1", "A4", 0x131C, "A1_A0", 0x1122334455667788,
     0x00040001, 0x1F),
    ("LDNW.D1", "A4", 0x131E, "A2", 0, 0, 0xFFFFFFFF),
    ("LDNW.D1", "A8", 0x131E, "A2", 0, 0x00040001, 0xFFFFFFFF),
]


def encode(mnemonic, base, target):
    decode = Path(__file__).resolve().parents[2] / "data/languages/c6000_decode.sinc"
    line = next(line for line in decode.read_text().splitlines()
                if line.startswith(f":{mnemonic} ") and "mode=0x1" in line)
    word = sum(int(value) << int(bit) for bit, value in
               re.findall(r"\bi(\d+)=(\d)\b", line))
    word |= 1 << 9  # *+base[offset], with offset zero
    word |= int(base[1:]) << 18
    if "_" in target:
        pair = int(target.split("_")[1][1:]) // 2
        word |= pair << 24
    else:
        word |= int(target[1:]) << 23
    return word


def main():
    image, manifest = map(Path, sys.argv[1:3])
    byteorder = "big" if len(sys.argv) > 3 and sys.argv[3] == "be" else "little"
    endian = ">" if byteorder == "big" else "<"
    data = bytearray(0x500)
    for index, (mnemonic, base, _, target, _, _, _) in enumerate(CASES):
        struct.pack_into(endian + "I", data, index * 32,
                         encode(mnemonic, base, target))
    data[0x300:0x308] = bytes.fromhex("55 66 77 88 99 aa bb cc")
    data[0x31C:0x320] = bytes.fromhex("11 22 33 44")
    data[0x320:0x322] = bytes.fromhex("de ad")
    image.parent.mkdir(parents=True, exist_ok=True)
    image.write_bytes(data)

    with manifest.open("w") as out:
        for index, (mnemonic, base, address, target, store_value, amr, mask) \
                in enumerate(CASES):
            width = 8 if "NDW" in mnemonic else 4
            is_store = mnemonic.startswith("ST")
            logical = (store_value.to_bytes(width, byteorder) if is_store else
                       bytes(data[((address & ~mask) | ((address + offset) & mask))
                                  - 0x1000] for offset in range(width)))
            result = store_value if is_store else int.from_bytes(logical, byteorder)
            out.write("\t".join((str(index), mnemonic, base, f"{address:x}",
                                 target, f"{store_value:x}", f"{amr:x}",
                                 f"{mask:x}", str(width), f"{result:x}",
                                 logical.hex() if is_store else "-")) + "\n")


if __name__ == "__main__":
    main()
