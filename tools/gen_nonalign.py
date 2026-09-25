#!/usr/bin/env python3
"""Generate bytewise circular nonaligned transfers for both endian modes."""
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "data/languages/c6000_nonalign.sinc"
lines = [
    "# GENERATED FILE - tools/gen_nonalign.py; edit the generator, not this file.",
    "# SPRUFE8B section 3.9.2.3: each byte of a nonaligned transfer wraps",
    "# independently inside the selected AMR circular buffer.",
    "",
]


def emit(name, count, store, big):
    size = count
    params = "s, a, index, side" if store else "a, d, index, side"
    lines.append(f"macro c6000_sem_{name}({params}) {{")
    lines.extend((
        "  local address:4 = a;",
        "  local mask:4;",
        "  c6000_circular_mask(index, side, mask);",
        "  local fixed:4 = address & ~mask;",
    ))
    if store:
        lines.append(f"  local full:{size} = s;")
    else:
        lines.append(f"  local full:{size} = 0;")
    for i in range(count):
        shift = 8 * (count - 1 - i if big else i)
        lines.append(f"  local addr{i}:4 = fixed | ((address + {i}) & mask);")
        if store:
            lines.append(f"  local part{i}:{size} = full >> {shift};")
            lines.append(f"  local byte{i}:1 = part{i}:1;")
            lines.append(f"  *[ram]:1 addr{i} = byte{i};")
        else:
            lines.append(f"  local byte{i}:1 = *[ram]:1 addr{i};")
            lines.append(f"  local part{i}:{size} = zext(byte{i});")
            lines.append(f"  full = full | (part{i} << {shift});")
    if not store:
        lines.append("  d = full;")
    lines.extend(("}", ""))


for big in (True, False):
    lines.append('@if ENDIAN == "big"' if big else "@else")
    for name, count, store in (("ldnw", 4, False), ("ldndw", 8, False),
                               ("stnw", 4, True), ("stndw", 8, True)):
        emit(name, count, store, big)
lines.append("@endif")
OUT.write_text("\n".join(lines) + "\n")
print(f"wrote {OUT}: {len(lines)} lines")
