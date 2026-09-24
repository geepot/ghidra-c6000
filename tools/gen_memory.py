#!/usr/bin/env python3
"""Generate size-aware .D-unit memory operands for c6000_memory.sinc.

The addressing modes and offset scaling follow SPRUFE8B section 3.9.3 and
Table C-3. Circular AMR addressing is not modelled here.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "data/languages/c6000_memory.sinc"
lines = [
    "# GENERATED FILE - tools/gen_memory.py; edit the generator, not this file.",
    "# .D-unit addressing modes and scaled offsets (SPRUFE8B section 3.9.3).",
    "",
    'BaseLong: "B14" is i7=0 { export B14; }',
    'BaseLong: "B15" is i7=1 { export B15; }',
    "",
]

# Doubleword memory instructions name an even/odd register pair.  Their
# transfer remains an explicit placeholder, but decoding must not treat the
# encoded pair selector (or LDNDW/STNDW's sc bit) as a scalar register index.
for side, file in ((0, "A"), (1, "B")):
    for pair in range(16):
        even = pair * 2
        label = f'"{file}{even + 1}:{file}{even}"'
        for role in ("DstPair", "StoreSrcPair"):
            lines.append(
                f'{role}: {label} is pair_index={pair} & i23=0 & i1={side} '
                f'{{ export {file}{even}; }}'
            )
        for role in ("DstPairN", "StoreSrcPairN"):
            lines.append(
                f'{role}: {label} is pair_index={pair} & i1={side} '
                f'{{ export {file}{even}; }}'
            )
lines.append("")


def offset(name, shift):
    return name if shift == 0 else f"({name} << {shift})"


for suffix, default_shift in (("B", 0), ("H", 1), ("W", 2), ("D", 3), ("N", 0)):
    table = f"MemReg{suffix}"
    scales = ((0, 0), (1, 3)) if suffix == "N" else ((None, default_shift),)
    for sc, shift in scales:
        for mode, sign, off, prefix, update in (
            (0x0, "-", "UCst5", "*-", "none"),
            (0x1, "+", "UCst5", "*+", "none"),
            (0x4, "-", "OffReg", "*-", "none"),
            (0x5, "+", "OffReg", "*+", "none"),
            (0x8, "-", "UCst5", "*--", "pre"),
            (0x9, "+", "UCst5", "*++", "pre"),
            (0xA, "-", "UCst5", "*", "post"),
            (0xB, "+", "UCst5", "*", "post"),
            (0xC, "-", "OffReg", "*--", "pre"),
            (0xD, "+", "OffReg", "*++", "pre"),
            (0xE, "-", "OffReg", "*", "post"),
            (0xF, "+", "OffReg", "*", "post"),
        ):
            left, right = ("(", ")") if sc == 0 else ("[", "]")
            bracket = left if update != "post" else f"{sign}{sign}{left}"
            display = f'"{prefix}" ^ BaseReg ^ "{bracket}" ^ {off} ^ "{right}"'
            field = "ucst5" if off == "UCst5" else "offr"
            pattern = f"mode=0x{mode:x} & {field} & BaseReg & {off}"
            if sc is not None:
                pattern += f" & scbit={sc}"
            delta = offset(off, shift)
            # The constructor commits pre/post updates after the transfer.
            sem = f"local a:4 = BaseReg {sign} {delta}; export a;"
            lines.append(f"{table}: {display} is {pattern} {{ {sem} }}")
    lines.append("")

for suffix, shift in (("B", 0), ("H", 1), ("W", 2)):
    table = f"MemLong{suffix}"
    delta = offset("UCst15", shift)
    for y, base in ((0, "B14"), (1, "B15")):
        lines.append(
            f'{table}: "*+{base}[" ^ UCst15 ^ "]" is i7={y} & ucst15 & UCst15 '
            f'{{ local a:4 = {base} + {delta}; export a; }}'
        )
    lines.append("")

OUT.write_text("\n".join(lines))
print(f"wrote {OUT}: {len(lines)} lines")
