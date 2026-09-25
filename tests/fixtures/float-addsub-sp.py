#!/usr/bin/env python3
"""Generate exact-rational ADDSP/SUBSP oracle cases. IMAGE CASES.tsv [be]."""
from fractions import Fraction
import random
import re
import struct
import sys
from pathlib import Path


OPERANDS = [
    (0x3f800000, 0x40000000),       # 1, 2
    (0x3f800000, 0xbf800000),       # cancellation
    (0, 0x80000000),                # opposite signed zero
    (0x80000000, 0x80000000),       # matching signed zero
    (0x00800001, 0x00800000),       # one minimum-normal ULP apart
    (0x3f800000, 0x00800000),       # tiny source lost by DP addition
    (0xbf800000, 0x00800000),       # tiny source lost from negative result
    (0x7f7fffff, 0x7f7fffff),       # overflow
    (0x7f7fffff, 0x3f800000),       # overflow with a tiny normal source
    (0xff7fffff, 0xbf800000),       # negative overflow with tiny source
    (0x7f800000, 0xff800000),       # opposing infinity
    (0x7f800000, 0x7f800000),       # matching infinity
    (0x7fc00001, 0x3f800000),       # QNaN in encoded src1
    (0x3f800000, 0x7f800001),       # SNaN in encoded src2
    (0x00000001, 0x3f800000),       # DEN1
    (0x3f800000, 0x80000001),       # DEN2
    (0x00000001, 0),                # denormal and zero
    (0x00000001, 0x80000001),       # two denormals
    (0x7f800000, 0x00000001),       # infinity and denormal
    (0x3f800000, 0x33800000),       # 1 and 2^-24: halfway to next SP
    (0xbf800000, 0xb3800000),       # negative halfway
]

random_cases = random.Random(0xc674)
OPERANDS.extend((random_cases.getrandbits(32), random_cases.getrandbits(32))
                for _ in range(40))


def value(bits):
    sign = -1 if bits >> 31 else 1
    exp = (bits >> 23) & 255
    frac = bits & 0x7fffff
    if exp == 0:
        return Fraction(0) # denormals are flushed to signed zero
    significand = (1 << 23) | frac
    shift = exp - 150
    magnitude = Fraction(significand << shift) if shift >= 0 else Fraction(significand, 1 << -shift)
    return sign * magnitude


MIN_NORMAL = value(0x00800000)
MAX_NORMAL = value(0x7f7fffff)


def rounded_bits(magnitude, sign, mode):
    lo, hi = 0x00800000, 0x7f7fffff
    while lo <= hi:
        mid = (lo + hi) // 2
        candidate = value(mid)
        if candidate == magnitude:
            return mid | sign, False
        if candidate < magnitude:
            lo = mid + 1
        else:
            hi = mid - 1
    lower, upper = hi, lo
    if mode == 1 or (mode == 2 and sign) or (mode == 3 and not sign):
        chosen = lower
    elif mode == 2 or mode == 3:
        chosen = upper
    else:
        low_distance = magnitude - value(lower)
        high_distance = value(upper) - magnitude
        chosen = lower if low_distance < high_distance or (low_distance == high_distance and not lower & 1) else upper
    return chosen | sign, True


def expected(a, b, subtract, reverse, mode):
    aexp, bexp = (a >> 23) & 255, (b >> 23) & 255
    afrac, bfrac = a & 0x7fffff, b & 0x7fffff
    flags = 0
    if aexp == 255 and afrac:
        flags |= 1
        if not afrac & 0x400000:
            flags |= 0x10
    if bexp == 255 and bfrac:
        flags |= 2
        if not bfrac & 0x400000:
            flags |= 0x10
    if aexp == 0 and afrac:
        flags |= 4
        if bexp != 255:
            flags |= 0x80
    if bexp == 0 and bfrac:
        flags |= 8
        if aexp != 255:
            flags |= 0x80
    if flags & 3:
        return 0x7fffffff, flags

    left, right = (b, a) if reverse else (a, b)
    if subtract:
        right ^= 0x80000000
    lexp, rexp = (left >> 23) & 255, (right >> 23) & 255
    lsign, rsign = left & 0x80000000, right & 0x80000000
    if lexp == 255 or rexp == 255:
        if lexp == rexp == 255 and lsign != rsign:
            return 0x7fffffff, flags | 0x10
        return (lsign if lexp == 255 else rsign) | 0x7f800000, flags | 0x20

    exact = value(left) + value(right)
    if not exact:
        same_zero_sign = value(left) == value(right) == 0 and lsign == rsign
        sign = lsign if same_zero_sign else (0x80000000 if mode == 3 else 0)
        return sign, flags
    sign = 0x80000000 if exact < 0 else 0
    magnitude = abs(exact)
    if magnitude > MAX_NORMAL:
        infinity = mode == 0 or (mode == 2 and not sign) or (mode == 3 and sign)
        return sign | (0x7f800000 if infinity else 0x7f7fffff), flags | 0xc0
    if magnitude < MIN_NORMAL:
        smallest = (mode == 2 and not sign) or (mode == 3 and sign)
        return sign | (0x00800000 if smallest else 0), flags | 0x180
    bits, inexact = rounded_bits(magnitude, sign, mode)
    return bits, flags | (0x80 if inexact else 0)


def opcode(mnemonic, unit, side, opfield, cross):
    decode = Path(__file__).resolve().parents[2] / "data/languages/c6000_decode.sinc"
    prefix = f":{mnemonic}.{unit}{side} "
    for line in decode.read_text().splitlines():
        if not line.startswith(prefix):
            continue
        fixed = {int(bit): int(v) for bit, v in re.findall(r"\bi(\d+)=(\d)\b", line)}
        bits = "".join(str(fixed[i]) for i in range(11, 4, -1))
        if bits == opfield:
            return (sum(v << bit for bit, v in fixed.items()) |
                    (1 << 13) | (2 << 18) | (4 << 23) | (int(cross) << 12))
    raise ValueError((mnemonic, unit, side, opfield))


def main():
    image, manifest = map(Path, sys.argv[1:3])
    endian = ">" if len(sys.argv) > 3 and sys.argv[3] == "be" else "<"
    image.parent.mkdir(parents=True, exist_ok=True)
    with image.open("wb") as out, manifest.open("w") as rows:
        index = 0
        for mnemonic in ("ADDSP", "SUBSP"):
            for unit in ("L", "S"):
                for side in (1, 2):
                    bank = "A" if side == 1 else "B"
                    other = "B" if side == 1 else "A"
                    variants = [(False, "0010000" if unit == "L" else "1110000")]
                    if mnemonic == "SUBSP":
                        variants = [(False, "0010001" if unit == "L" else "1110001"),
                                    (True, "0010101" if unit == "L" else "1110101")]
                    for reverse, opfield in variants:
                        for mode in range(4):
                            for case_index, (a, b) in enumerate(OPERANDS):
                                cross = case_index in (0, 14)
                                src1 = f"{bank}1"
                                src2 = f"{other if cross else bank}2"
                                word = opcode(mnemonic, unit, side, opfield, cross)
                                result, flags = expected(a, b, mnemonic == "SUBSP", reverse, mode)
                                out.write(struct.pack(endian + "I", word))
                                out.write(bytes(28))
                                preset = (mode << (9 + (16 if side == 2 else 0))) | (1 if side == 2 else 0x10000)
                                expected_flags = preset | (flags << (16 if side == 2 else 0))
                                rows.write(f"{index}\t{mnemonic}.{unit}{side}\t"
                                           f"{src2 if reverse else src1}\t{src1 if reverse else src2}\t{bank}4\t"
                                           f"{src1}\t{src2}\t{a:x}\t{b:x}\t{result:x}\t"
                                           f"{preset:x}\t{expected_flags:x}\n")
                                index += 1


if __name__ == "__main__":
    main()
