#!/usr/bin/env python3
"""Generate DP add/sub/multiply emulator cases. IMAGE ADD.tsv MUL.tsv [be]."""

from fractions import Fraction
from pathlib import Path
import random
import re
import struct
import sys


SIGN = 1 << 63
MASK = SIGN - 1
INF = 0x7ff0000000000000
MAX = 0x7fefffffffffffff
MIN = 0x0010000000000000
NAN = 0x7fffffffffffffff


def value(bits):
    exponent = (bits >> 52) & 2047
    if exponent == 0:
        return Fraction(0)
    significand = (1 << 52) | (bits & ((1 << 52) - 1))
    shift = exponent - 1075
    number = Fraction(significand << shift) if shift >= 0 else Fraction(significand, 1 << -shift)
    return -number if bits & SIGN else number


def round_finite(exact, mode):
    if not exact:
        return 0, 0
    sign = SIGN if exact < 0 else 0
    magnitude = abs(exact)
    if magnitude > value(MAX):
        infinite = mode == 0 or (mode == 2 and not sign) or (mode == 3 and sign)
        return sign | (INF if infinite else MAX), 0xc0
    if magnitude < value(MIN):
        smallest = (mode == 2 and not sign) or (mode == 3 and sign)
        return sign | (MIN if smallest else 0), 0x180
    lo, hi = MIN, MAX
    while lo <= hi:
        mid = (lo + hi) // 2
        if value(mid) == magnitude:
            return sign | mid, 0
        if value(mid) < magnitude:
            lo = mid + 1
        else:
            hi = mid - 1
    lower, upper = hi, lo
    if mode == 1 or (mode == 2 and sign) or (mode == 3 and not sign):
        chosen = lower
    elif mode in (2, 3):
        chosen = upper
    else:
        low_dist = magnitude - value(lower)
        high_dist = value(upper) - magnitude
        chosen = lower if low_dist < high_dist or (low_dist == high_dist and lower % 2 == 0) else upper
    return sign | chosen, 0x80


def classify(bits):
    exp = (bits >> 52) & 2047
    frac = bits & ((1 << 52) - 1)
    return exp, frac


def addsub(a, b, mode, subtract=False, reverse=False):
    ae, af = classify(a)
    be, bf = classify(b)
    flags = 0
    if ae == 2047 and af:
        flags |= 1 | (0 if af & (1 << 51) else 0x10)
    if be == 2047 and bf:
        flags |= 2 | (0 if bf & (1 << 51) else 0x10)
    if ae == 0 and af:
        flags |= 4 | (0x80 if be != 2047 else 0)
        a &= SIGN
    if be == 0 and bf:
        flags |= 8 | (0x80 if ae != 2047 else 0)
        b &= SIGN
    if flags & 3:
        return NAN, flags
    left, right = (b, a) if reverse else (a, b)
    if subtract:
        right ^= SIGN
    le, _ = classify(left)
    re, _ = classify(right)
    if le == re == 2047 and (left ^ right) & SIGN:
        return NAN, flags | 0x10
    if le == 2047 or re == 2047:
        return (left if le == 2047 else right), flags | 0x20
    exact = value(left) + value(right)
    if not exact:
        same_zero_sign = not left & MASK and not right & MASK and (left ^ right) & SIGN == 0
        sign = left & SIGN if same_zero_sign else (SIGN if mode == 3 else 0)
        return sign, flags
    result, rounding = round_finite(exact, mode)
    return result, flags | rounding


def multiply(a, b, mode):
    ae, af = classify(a)
    be, bf = classify(b)
    sign = (a ^ b) & SIGN
    flags = 0
    if ae == 2047 and af:
        flags |= 1 | (0 if af & (1 << 51) else 0x10)
    if be == 2047 and bf:
        flags |= 2 | (0 if bf & (1 << 51) else 0x10)
    if ae == 0 and af:
        flags |= 4 | (0x80 if be != 2047 and b & MASK else 0)
        a &= SIGN
    if be == 0 and bf:
        flags |= 8 | (0x80 if ae != 2047 and a & MASK else 0)
        b &= SIGN
    if flags & 3:
        return sign | NAN, flags
    if ae == 2047 or be == 2047:
        if (ae == 2047 and not b & MASK) or (be == 2047 and not a & MASK):
            return sign | NAN, flags | 0x10
        return sign | INF, flags
    if not a & MASK or not b & MASK:
        return sign, flags
    result, rounding = round_finite(value(a) * value(b), mode)
    return result, flags | rounding


ADD_CASES = [
    (0x3ff0000000000000, 0x4000000000000000),
    (0x3ff0000000000000, 0x3ff0000000000000),
    (0, SIGN), (SIGN, SIGN),
    (MAX, MAX), (MAX, 0x3ff0000000000000),
    (SIGN | MAX, SIGN | 0x3ff0000000000000),
    (INF, SIGN | INF), (INF, INF),
    (0x7ff8000000000001, 0x3ff0000000000000),
    (0x3ff0000000000000, 0x7ff0000000000001),
    (1, 0x3ff0000000000000), (0x3ff0000000000000, SIGN | 1),
    (MIN, SIGN | MIN),
    (0x3ff0000000000000, 0x3ca0000000000000),  # half an ULP
    (0x3ff0000000000000, 0x1b70000000000000),  # beyond quad precision
    (1, SIGN | 1), (0x7ff0000000000001, 0x7ff8000000000001),
]

MUL_CASES = [
    (0x3ff8000000000000, 0x4000000000000000),
    (0x3ff199999999999a, 0x3ff199999999999a),
    (MAX, 0x4000000000000000),
    (MIN, 0x3fe0000000000000),
    (INF, 0), (SIGN | INF, SIGN),
    (INF, 1), (1, 0x3ff0000000000000),
    (1, 0), (0x3ff0000000000000, 0x7ff0000000000001),
    (0x7ff8000000000001, 0x3ff0000000000000),
    (SIGN, 0x4000000000000000),
    (1, 1), (SIGN | MIN, 0x3fe0000000000000),
]


random_cases = random.Random(0xc674)


def random_normal():
    exponent = random_cases.randint(1, 2046)
    fraction = random_cases.getrandbits(52)
    return (random_cases.getrandbits(1) << 63) | (exponent << 52) | fraction


ADD_CASES.extend((random_normal(), random_normal()) for _ in range(24))
MUL_CASES.extend((random_normal(), random_normal()) for _ in range(24))


def opcode(mnemonic, unit, side, opfield):
    decode = Path(__file__).resolve().parents[2] / "data/languages/c6000_decode.sinc"
    prefix = f":{mnemonic}.{unit}{side} "
    for line in decode.read_text().splitlines():
        if not line.startswith(prefix):
            continue
        fixed = {int(bit): int(v) for bit, v in re.findall(r"\bi(\d+)=(\d)\b", line)}
        if unit == "M" or "".join(str(fixed[i]) for i in range(11, 4, -1)) == opfield:
            return sum(v << bit for bit, v in fixed.items()) | (2 << 18) | (4 << 23)
    raise ValueError((mnemonic, unit, side, opfield))


def main():
    image, add_rows, mul_rows = map(Path, sys.argv[1:4])
    endian = ">" if len(sys.argv) > 4 and sys.argv[4] == "be" else "<"
    image.parent.mkdir(parents=True, exist_ok=True)
    with image.open("wb") as out, add_rows.open("w") as add_file, mul_rows.open("w") as mul_file:
        index = 0
        for mnemonic, unit, side, reverse, field in (
            ("ADDDP", "L", 1, False, "0011000"),
            ("ADDDP", "S", 2, False, "1110010"),
            ("SUBDP", "L", 1, False, "0011001"),
            ("SUBDP", "L", 2, True, "0011101"),
            ("SUBDP", "S", 1, True, "1110111"),
            ("MPYDP", "M", 1, False, ""),
            ("MPYDP", "M", 2, False, ""),
        ):
            bank = "A" if side == 1 else "B"
            src1, src2, dst = f"{bank}1_{bank}0", f"{bank}3_{bank}2", f"{bank}5_{bank}4"
            shown1, shown2, shown_dst = src1.replace("_", ":"), src2.replace("_", ":"), dst.replace("_", ":")
            word = opcode(mnemonic, unit, side, field)
            for mode in range(4):
                for a, b in MUL_CASES if mnemonic == "MPYDP" else ADD_CASES:
                    result, flags = multiply(a, b, mode) if mnemonic == "MPYDP" else addsub(a, b, mode, mnemonic == "SUBDP", reverse)
                    shift = 0 if side == 1 else 16
                    preset = (mode << (9 + shift)) | (1 << (16 if side == 1 else 0))
                    out.write(struct.pack(endian + "I", word) + bytes(28))
                    if mnemonic == "MPYDP":
                        mul_file.write(f"{index}\t{mnemonic}.{unit}{side}\t{src1}\t{src2}\t{dst}\t{a:x}\t{b:x}\t{result:x}\t{preset:x}\t{preset | flags << shift:x}\n")
                    else:
                        op1, op2 = (shown2, shown1) if reverse else (shown1, shown2)
                        add_file.write(f"{index}\t{mnemonic}.{unit}{side}\t{op1}\t{op2}\t{shown_dst}\t{src1}\t{src2}\t{a:x}\t{b:x}\t{result:x}\t{preset:x}\t{preset | flags << shift:x}\n")
                    index += 1


if __name__ == "__main__":
    main()
