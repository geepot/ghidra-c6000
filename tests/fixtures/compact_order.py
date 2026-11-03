# SPDX-License-Identifier: Apache-2.0
"""Store big-endian compact words in hardware order (issue #31).

Hand-built fixtures list compact slots in execution order, one halfword per
address. A word's first slot is its 16 LSBs in either byte order (SPRUFE8B
3.10.2.3, Table 3-16), so a big-endian image swaps the halfwords of every
compact word named by a header. Call big_endian_on_exit() before writing
IMAGE (sys.argv[1]); it converts the file when "be" is an argument.
"""
import atexit
from pathlib import Path
import struct
import sys


def hardware_order(data):
    data = bytearray(data)
    for packet in range(0, len(data) - 31, 32):
        header, = struct.unpack_from(">I", data, packet + 28)
        if header >> 28 != 0xE:
            continue
        for word in range(7):
            if header >> (21 + word) & 1:
                at = packet + 4 * word
                data[at:at + 4] = data[at + 2:at + 4] + data[at:at + 2]
    return bytes(data)


_registered = False


def big_endian_on_exit():
    # Once per process: runpy-chained generators share IMAGE.
    global _registered
    if "be" in sys.argv[2:] and not _registered:
        _registered = True
        image = Path(sys.argv[1])
        atexit.register(lambda: image.exists() and image.write_bytes(hardware_order(image.read_bytes())))
