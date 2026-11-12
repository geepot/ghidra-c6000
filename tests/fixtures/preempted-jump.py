#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build jumps preempted by a return in their delay window. Usage: IMAGE [be].

Load at 0x1000 with auto-analysis; C6000PreemptedJumpTest.java prepare declares
the functions, as ELF symbols would. Words are TI cl6x 8.3.15 output (-mv6740
--abi=eabi --no_compress), listed by dis6x. Cycles count from the jump's packet;
a landing branch ends a multicycle NOP (SPRUFE8B 3.5, 4.2.6 B, NOP):

  1000 padret   MV A4,A1 ; [A1] B pad1 ; MVK 0x100,A4 ; [A1] B B3 || ADDK 0x11,A4 ; NOP ;
                [!A1] MVK 0x200,A4 ; NOP ; ADDK 0x22,A4 ; B B3 ; ADDK 0x111,A4 ; NOP 2 ;
                pad1: NOP 2. The return issues in c2 under the jump's predicate and the
                jump lands on the fall-through return's last two slots, which only idle
                until it lands: a ? 0x111 : 0x333
  1040            unused here
  1080 callee   B B3 ; ADD A4,A4,A4 ; NOP 4
  10a0 padtail  B pad3 ; MVK 0x300,A4 ; B B3 ; ADDK 48,A4 ; ADDK 3,A4 ; NOP ;
                MVK 0x999,A4 ; pad3: NOP 2. No fall-through, so the window is decoded
                only once the jump is known to continue: 0x333
  10c0            unused here
  Known-bads, the jump keeps its target:
  1100 padcode    the target runs ADDK before the return lands
  1140 padother   the return is under [B0], not the jump's [A1]
  1180 padwritten MV B4,A1 between the jump and the [A1] return
  11c0 padshort   one NOP cycle at the target, then ADDK
  1200 padleak    unconditional return; not taken, its last slots run ADDK 0x22, which
                  a window cut at the jump's landing would drop
  1220 padcall    a call under [A1] preempts the jump: one fall-through cannot hold
                  both its return past the landing NOPs and its not-taken path
  1280 padentry   padret's words; prepare declares a function at 1298 inside the
                  return's window, so the cut window is unproven
  Prepare also gives padcode's jump a stale analysis override and padshort's jump a
  user override: the first is removed, the second stands.
"""

from pathlib import Path
import struct
import sys

WORDS = {
    0x1000: 0x00900FD8, 0x1004: 0x80000610, 0x1008: 0x02008028, 0x100C: 0x800C0363,
    0x1010: 0x020008D0, 0x1018: 0x92010028, 0x1020: 0x02001150, 0x1024: 0x000C0362,
    0x1028: 0x020088D0, 0x102C: 0x00002000, 0x1030: 0x00002000, 0x1040: 0x068C0FDA,
    0x1044: 0x00000410, 0x1048: 0x020002A8, 0x104C: 0x00000811, 0x1050: 0x0188322A,
    0x1054: 0x0180006A, 0x1058: 0x00002000, 0x105C: 0x0204CCA8, 0x1060: 0x00002000,
    0x1064: 0x02000850, 0x1068: 0x01B406A2, 0x106C: 0x000C0362, 0x1070: 0x00008000,
    0x1080: 0x000C0362, 0x1084: 0x02108078, 0x1088: 0x00006000, 0x10A0: 0x00000390,
    0x10A4: 0x02018028, 0x10A8: 0x000C0362, 0x10AC: 0x02001850, 0x10B0: 0x020001D0,
    0x10B8: 0x0204CCA8, 0x10BC: 0x00002000, 0x10C0: 0x00900FD9, 0x10C4: 0x00100FDA,
    0x10C8: 0x20000410, 0x10CC: 0x00008000, 0x10D0: 0x80000690, 0x10D4: 0x02008028,
    0x10D8: 0x000C0362, 0x10DC: 0x00004000, 0x10E0: 0x02001150, 0x10E8: 0x000C0362,
    0x10EC: 0x020008D0, 0x10F0: 0x00002000, 0x10F4: 0x00002000, 0x1100: 0x00900FD8,
    0x1104: 0x80000410, 0x1108: 0x02008028, 0x110C: 0x800C0362, 0x1110: 0x00004000,
    0x1114: 0x02011128, 0x1118: 0x000C0362, 0x111C: 0x00008000, 0x1120: 0x020008D0,
    0x1140: 0x00900FD9, 0x1144: 0x00100FDA, 0x1148: 0x80000510, 0x114C: 0x02008028,
    0x1150: 0x200C0362, 0x1154: 0x00004000, 0x1158: 0x02011128, 0x115C: 0x000C0362,
    0x1160: 0x020088D0, 0x1164: 0x00002000, 0x1168: 0x00002000, 0x1180: 0x00900FD8,
    0x1184: 0x80000490, 0x1188: 0x00901FD8, 0x118C: 0x800C0362, 0x1190: 0x00004000,
    0x1194: 0x02011128, 0x1198: 0x000C0362, 0x119C: 0x020088D0, 0x11A0: 0x00002000,
    0x11A4: 0x00002000, 0x11C0: 0x00900FD8, 0x11C4: 0x80000410, 0x11C8: 0x02008028,
    0x11CC: 0x800C0362, 0x11D0: 0x00004000, 0x11D4: 0x02011128, 0x11D8: 0x000C0362,
    0x11DC: 0x00008000, 0x11E4: 0x020008D0, 0x1200: 0x00900FD8, 0x1204: 0x80000390,
    0x1208: 0x02008028, 0x120C: 0x000C0362, 0x1210: 0x00004000, 0x1214: 0x02001150,
    0x121C: 0x00002000, 0x1220: 0x00900FD9, 0x1224: 0x068C0FDA, 0x1228: 0x80000610,
    0x122C: 0x820002A8, 0x1230: 0x8FFFCC11, 0x1234: 0x81892A2A, 0x1238: 0x8180006A,
    0x123C: 0x00002000, 0x1240: 0x01B406A2, 0x1244: 0x000C0362, 0x1248: 0x02011128,
    0x124C: 0x00006000, 0x1250: 0x00002000, 0x1254: 0x02000850, 0x1258: 0x01B406A2,
    0x125C: 0x000C0362, 0x1260: 0x00008000,
}


# padentry: padret moved by 0x280, a whole number of fetch packets, so displacements hold.
WORDS.update({a + 0x280: w for a, w in list(WORDS.items()) if 0x1000 <= a < 0x1040})


def main():
    if len(sys.argv) not in (2, 3) or (len(sys.argv) == 3 and sys.argv[2] != "be"):
        raise SystemExit(__doc__)
    endian = ">" if len(sys.argv) == 3 else "<"
    image = bytearray(0x300)
    for address, word in WORDS.items():
        struct.pack_into(endian + "I", image, address - 0x1000, word)
    Path(sys.argv[1]).write_bytes(image)


if __name__ == "__main__":
    main()
