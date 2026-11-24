#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""TI-assembled transfers that native lifting cannot place: IMAGE CASES.json [be].

Requires TI's C6000 assembler (TI_C6000_BIN as in pipeline-predicate-facts.py).
Each case is a function and its own h(x) = 2x, in one section loaded at
0x1000 + 0x100 * index; C6000NestedWindowTest.java prepare declares both, as ELF
symbols would. A transfer issued in a delay cycle of another lands after it
(SPRUFE8B 3.5, 4.2.6), and a predicated call whose B3 is at or before it has two
successors; native lifting places neither, so each known-bad must carry a
"C6000 Nested Delay Window" warning at its labelled transfers (issues #64-#66),
and each known-good none. MVKL/MVKH and .word operands are assembled once with labels
and again with the label addresses, so the object needs no relocation. Full32 only,
so BE swaps each word's bytes.
"""
from pathlib import Path
import importlib.util
import json
import os
import re
import subprocess
import sys

SIZE = 0x100
H = """{n}_h:
        B       .S2     B3
        ADD     .L1     A4,A4,A4
        NOP             4
"""
RET = """        LDW     .D2T2   *++B15[2],B3
        NOP             4
        B       .S2     B3
        NOP             5
"""
# name, known-bad, body; {n} is the case name, labels ending _in mark the transfers to warn at.
CASES = [
    # issue #64: a call and a return on complementary predicates, the return in the call's window
    ("callret", True, """{n}:
        STW     .D2T2   B3,*B15--[2]
||      MV      .L1     A4,A1
        MV      .L1X    B4,A4
  [ A1] B       .S1     {n}_h
{n}_in:
  [!A1] B       .S2     B3
        MVKL    .S2     {n}_ret,B3
        MVKH    .S2     {n}_ret,B3
        ADD     .L1     A4,1,A4
||      ADDK    .S2     8,B15
        NOP             1
        NOP             1
{n}_ret:
        LDW     .D2T2   *B15,B3
        NOP             4
        B       .S2     B3
        NOP             5
"""),
    # issue #64: a call taken with a jump, landing in the jump's target, which sets its link
    ("busytgt", True, """{n}:
        STW     .D2T2   B3,*B15--[2]
||      MV      .L1     A4,A1
        MV      .L1X    B4,A4
  [ A1] B       .S1     {n}_tgt
        NOP             1
{n}_in:
  [ A1] B       .S1     {n}_h
        NOP             3
        ADD     .L1     A4,7,A4
""" + RET + """{n}_tgt:
        MVKL    .S2     {n}_ret,B3
        MVKH    .S2     {n}_ret,B3
        ADDK    .S1     1000,A4
        NOP             5
{n}_ret:
        ADD     .L1     A4,1,A4
""" + RET),
    # issue #64: a second jump on an independent predicate, landing four cycles into the first's target
    ("indep", True, """{n}:
        MV      .L1     A4,A1
||      MV      .L2     B4,B0
        ZERO    .L1     A5
  [ A1] B       .S1     {n}_t1
        NOP             3
{n}_in:
  [!B0] B       .S2     {n}_t2
        ADD     .L1     A5,1,A5
        ADD     .L1     A5,15,A5
        ADD     .L1     A5,15,A5
        ADD     .L1     A5,15,A5
        ADDK    .S1     211,A5
        ADDK    .S1     256,A5
        B       .S2     B3
        MV      .L1     A5,A4
        NOP             4
{n}_t1:
        ADD     .L1     A5,4,A5
        ADD     .L1     A5,4,A5
        ADD     .L1     A5,4,A5
        ADD     .L1     A5,4,A5
        ADD     .L1     A5,15,A5
        ADD     .L1     A5,1,A5
        B       .S2     B3
        MV      .L1     A5,A4
        NOP             4
{n}_t2:
        ADDK    .S1     4096,A5
        B       .S2     B3
        MV      .L1     A5,A4
        NOP             4
"""),
    # issue #64: three overlapping windows, a predicated ZERO choosing the later branch
    ("tri", True, """{n}:
        MV      .L2X    A4,B1
||      MV      .L1X    B4,A1
  [ B1] B       .S2     B3
        MVK     .S1     1,A4
        NOP             1
  [ B1] ZERO    .L1     A1
{n}_in:
  [ A1] B       .S2     B3
        ADD     .L1     A4,2,A4
        ADD     .L1     A4,4,A4
        ADD     .L1     A4,4,A4
{n}_in2:
  [!A1] B       .S1     {n}_far
        ADD     .L1     A4,8,A4
        ADDK    .S1     16,A4
        ADDK    .S1     16,A4
        ADDK    .S1     16,A4
        ADDK    .S1     16,A4
        ADDK    .S1     30000,A4
        B       .S2     B3
        NOP             5
{n}_far:
        ADDK    .S1     1000,A4
        B       .S2     B3
        NOP             5
"""),
    # issue #65: a jump onto NOP 5 whose last delay slot issues a direct call
    ("pjcall", True, """{n}:
        STW     .D2T2   B3,*B15--[2]
||      MV      .L1     A4,A1
        MV      .L1X    B4,A4
  [!A1] B       .S1     {n}_nop
        MVKL    .S2     {n}_ret,B3
        MVKH    .S2     {n}_ret,B3
        NOP             2
{n}_in:
  [!A1] B       .S1     {n}_h
        ADD     .L1     A4,7,A4
""" + RET + """{n}_nop:
        NOP             5
{n}_ret:
        ADD     .L1     A4,1,A4
""" + RET),
    # issue #65: the same with a register call
    ("pjreg", True, """{n}:
        STW     .D2T2   B3,*B15--[2]
||      MV      .L1     A4,A1
        MV      .L1X    B4,A4
  [!A1] B       .S1     {n}_nop
        MVKL    .S2     {n}_ret,B3
        MVKH    .S2     {n}_ret,B3
        MVKL    .S1     {n}_h,A3
        MVKH    .S1     {n}_h,A3
{n}_in:
  [!A1] B       .S2X    A3
        ADD     .L1     A4,7,A4
""" + RET + """{n}_nop:
        NOP             5
{n}_ret:
        ADD     .L1     A4,1,A4
""" + RET),
    # issue #66: a predicated call whose link, set before the loop, is the loop head
    ("loopcall", True, """{n}:
        STW     .D2T2   B3,*B15--[2]
||      MV      .L1X    B4,A2
        MVKL    .S2     {n}_in,B3
        MVKH    .S2     {n}_in,B3
{n}_in:
  [ A2] B       .S1     {n}_h
  [ A2] SUB     .L1     A2,1,A2
        NOP             4
""" + RET),
    # BNOP n spends n of its five delay cycles: a branch in the fifth is in its window, and the ADD
    # beside it runs on the taken path too
    ("bnop4", True, """{n}:
        MV      .L1     A4,A1
  [ A1] BNOP    .S1     {n}_t,4
{n}_in:
  [!A1] B       .S1     {n}_u
||      ADD     .L1     A4,1,A4
        NOP             5
{n}_t:
        B       .S2     B3
        NOP             5
{n}_u:
        B       .S2     B3
        MVK     .S1     1,A4
        NOP             4
"""),
    # issue #103: a software-pipelined loop. The one-packet kernel issues its branch again on every
    # pass, before the last issue has landed, so one latch per branch cannot hold them: it runs n + 1
    # times and must stay warned. [B0] SUB B0,1,B0 leaves B0 unknown, not zero, for the next branch.
    ("plloopn", True, """{n}:
        MV      .L2X    A4,B0
        ZERO    .L1     A4
  [ B0] B       .S1     {n}_k
||[ B0] SUB     .L2     B0,1,B0
{n}_in:
  [ B0] B       .S1     {n}_k
||[ B0] SUB     .L2     B0,1,B0
  [ B0] B       .S1     {n}_k
||[ B0] SUB     .L2     B0,1,B0
  [ B0] B       .S1     {n}_k
||[ B0] SUB     .L2     B0,1,B0
  [ B0] B       .S1     {n}_k
||[ B0] SUB     .L2     B0,1,B0
{n}_k:
        ADD     .L1     A4,1,A4
||[ B0] B       .S1     {n}_k
||[ B0] SUB     .L2     B0,1,B0
        NOP
        NOP
        NOP
        NOP
        NOP
        B       .S2     B3
        NOP             5
"""),
    # issue #99: four native windows are entered already, the limit of Ghidra 12.2's decompiler.
    # Latching the nest lands a jump inside a fifth, and there the function would not decompile at
    # all, so the lifting is taken back and the nest stays warned. Ghidra 12.1.4 has no such limit
    # and keeps the lifting: a ? a + 0xfe : c ? 0x50 : 0x1ff, printed as (a ? a + 0x10 : 0x111) + 0xee (EITHER).
    ("entmany", True, """{n}:
        MV      .L1     A4,A2
  [ A2] B       .S1     {n}_e1
        NOP             5
  [ A2] B       .S1     {n}_e2
        NOP             5
  [ A2] B       .S1     {n}_e3
        NOP             5
  [ A2] B       .S1     {n}_e4
        NOP             5
{n}_in:
        B       .S1     {n}_x
||      MV      .L1     A6,A1
        NOP
        NOP
        NOP
        NOP
  [ A1] B       .S1     {n}_e5
{n}_x:
  [!A1] B       .S1     {n}_w1
        NOP             4
        ADDK    .S1     0x100,A4
{n}_w1:
        B       .S1     {n}_w2
        ADDK    .S1     1,A4
{n}_e1:
        ADDK    .S1     16,A4
        NOP             3
{n}_w2:
        B       .S1     {n}_w3
        ADDK    .S1     2,A4
{n}_e2:
        ADDK    .S1     32,A4
        NOP             3
{n}_w3:
        B       .S1     {n}_w4
        ADDK    .S1     3,A4
{n}_e3:
        ADDK    .S1     48,A4
        NOP             3
{n}_w4:
        B       .S1     {n}_w5
        ADDK    .S1     4,A4
{n}_e4:
        ADDK    .S1     64,A4
        NOP             3
{n}_w5:
        B       .S1     {n}_end
        ADDK    .S1     5,A4
{n}_e5:
        ADDK    .S1     80,A4
        NOP             3
{n}_end:
        B       .S2     B3
        NOP             5
"""),
    # issue #104: the link is copied at entry and the function returns through the copy: a + 1.
    ("cpyret", False, """{n}:
        ADD     .D2     B3,0,B9
        ADD     .L1     A4,1,A4
        B       .S2     B9
        NOP             5
"""),
    # Known-bad for the rule: the copy is predicated, so B9 need not hold the link, and the branch
    # stays a computed jump.
    ("cpyretp", False, """{n}:
        MV      .L1     A4,A1
  [ A1] ADD     .D2     B3,0,B9
        ADD     .L1     A4,1,A4
        B       .S2     B9
        NOP             5
"""),
    # Known-goods: an ordinary call; a forward predicated call; a loop branch to its own head with B3 there
    # A callback is only named by its address: the code that takes it makes it a function. The return
    # link beside it is an address too, and is not one.
    ("cbptr", False, """{n}:
        MVKL    .S1     {n}_cb,A4
        MVKH    .S1     {n}_cb,A4
        B       .S2     B3
        MVKL    .S2     {n}_notcb,B3
        MVKH    .S2     {n}_notcb,B3
        NOP             3
        NOP
        NOP
{n}_notcb:
        B       .S2     B3
        NOP             5
{n}_cb:
        B       .S2     B3
        ADD     .L1     A4,1,A4
        NOP             4
"""),
    ("plain", False, """{n}:
        STW     .D2T2   B3,*B15--[2]
        B       .S1     {n}_h
        MVKL    .S2     {n}_ret,B3
        MVKH    .S2     {n}_ret,B3
        NOP             3
{n}_ret:
""" + RET),
    ("predcall", False, """{n}:
        STW     .D2T2   B3,*B15--[2]
||      MV      .L1     A4,A1
        MV      .L1X    B4,A4
  [ A1] B       .S1     {n}_h
        MVKL    .S2     {n}_ret,B3
        MVKH    .S2     {n}_ret,B3
        NOP             3
{n}_ret:
""" + RET),
    ("loopjump", False, """{n}:
        STW     .D2T2   B3,*B15--[2]
||      MV      .L1X    B4,A2
        MVKL    .S2     {n}_top,B3
        MVKH    .S2     {n}_top,B3
{n}_top:
  [ A2] B       .S1     {n}_top
  [ A2] SUB     .L1     A2,1,A2
        NOP             4
""" + RET),
    # Known-goods: a branch in the cycle after a window, after a BNOP 5, and in the same packet
    ("adjacent", False, """{n}:
        MV      .L1     A4,A1
  [ A1] B       .S1     {n}_t
        NOP             5
  [!A1] B       .S1     {n}_u
        NOP             5
{n}_t:
        B       .S2     B3
        NOP             5
{n}_u:
        B       .S2     B3
        MVK     .S1     1,A4
        NOP             4
"""),
    ("bnop5", False, """{n}:
        MV      .L1     A4,A1
  [ A1] BNOP    .S1     {n}_t,5
  [!A1] B       .S1     {n}_u
        NOP             5
{n}_t:
        B       .S2     B3
        NOP             5
{n}_u:
        B       .S2     B3
        MVK     .S1     1,A4
        NOP             4
"""),
    # Its delay cycle holds only the opposite arm: taken, the BNOP is exact as an immediate jump
    ("bnop4idle", False, """{n}:
        MV      .L1     A4,A1
  [ A1] BNOP    .S1     {n}_t,4
  [!A1] B       .S1     {n}_u
        NOP             5
{n}_t:
        B       .S2     B3
        NOP             5
{n}_u:
        B       .S2     B3
        MVK     .S1     1,A4
        NOP             4
"""),
    ("samepkt", False, """{n}:
        MV      .L1     A4,A1
  [ A1] B       .S1     {n}_t
||[!A1] B       .S2     B3
        NOP             5
{n}_t:
        B       .S2     B3
        MVK     .S1     1,A4
        NOP             4
"""),
    # Known-good (issue #50): a jump onto NOPs that only wait out a return issued in its window is continued
    ("preempt", False, """{n}:
        MV      .L1     A4,A1
  [ A1] B       .S1     {n}_pad
        MVK     .S1     0x100,A4
  [ A1] B       .S2     B3
||      ADDK    .S1     0x11,A4
        NOP
  [!A1] MVK     .S1     0x200,A4
        NOP
        ADDK    .S1     0x22,A4
        B       .S2     B3
        ADDK    .S1     0x111,A4
        NOP             2
{n}_pad:
        NOP             2
"""),
    # issue #73: a return in a jump's last slot carries the jump's landing, and the jump lands on the complementary
    # return. The store at 3 runs on both paths, the one at 1 only when a == 0: the [ A1] return lands before it.
    ("landret", True, """{n}:
        B       .S1     {n}_x
||      MV      .L1     A6,A1
        NOP
        NOP
        NOP
        NOP
{n}_in:
  [ A1] B       .S2     B3
{n}_x:
  [!A1] B       .S2     B3
        NOP
        NOP
        NOP
        STW     .D1T1   A5,*+A4[3]
        STW     .D1T1   A5,*+A4[1]
        NOP             5
"""),
    # issue #73: the same, entered by a jump that sets B3 to a link (not its fall-through) in its delay slots
    ("landlink", True, """{n}:
        STW     .D2T2   B3,*B15--[2]
        MVK     .S2     1,B1
        MVK     .S2     0,B0
  [!B0] B       .S1     {n}_t
  [ B1] MVKL    .S2     {n}_back,B3
  [ B1] MVKH    .S2     {n}_back,B3
        NOP             4
        MVK     .S1     0x77,A4
        NOP
{n}_back:
        LDW     .D2T2   *++B15[2],B3
        NOP             4
        B       .S2     B3
        NOP             5
{n}_t:
        B       .S1     {n}_x
||      MV      .L1     A6,A1
        NOP
        NOP
        NOP
        NOP
{n}_in:
  [ A1] B       .S2     B3
{n}_x:
  [!A1] B       .S2     B3
        NOP
        NOP
        NOP
        STW     .D1T1   A5,*+A4[3]
        STW     .D1T1   A5,*+A4[1]
        NOP             5
"""),
    # A switch whose dispatch is entered through a jump taken when the index is in range, with the
    # table's address built in that jump's delay slots and the default's jump nested among them, on
    # a copy of the flag, so that both count as possibly taken and the second gets a landing in the
    # dispatch code. The table is found by following the latched jump to where it lands: a ? (a == 1 ? 0x222 : a == 2 ?
    # 0x333 : 0x999) : 0x111.
    ("swjump", True, """{n}:
        CMPLTU  .L2X    2,A4,B1
        MV      .L2     B1,B0
  [!B1] B       .S1     {n}_disp
        MVKL    .S1     {n}_tab,A1
        MVKH    .S1     {n}_tab,A1
        SHL     .S2X    A4,2,B5
{n}_in:
  [ B0] B       .S1     {n}_dflt
        NOP             5
{n}_dflt:
        B       .S2     B3
        MVK     .S1     0x999,A4
        NOP             4
{n}_disp:
        ADD     .L1X    A1,B5,A5
        LDW     .D1T2   *A5,B5
        NOP             4
        B       .S2     B5
        NOP             5
{n}_c0:
        B       .S2     B3
        MVK     .S1     0x111,A4
        NOP             4
{n}_c1:
        B       .S2     B3
        MVK     .S1     0x222,A4
        NOP             4
{n}_c2:
        B       .S2     B3
        MVK     .S1     0x333,A4
        NOP             4
{n}_tab:
        .word   {n}_c0
        .word   {n}_c1
        .word   {n}_c2
"""),
    # issue #111: the [!A1] landing is sure, so it has no fall-through, and the code after it is reached
    # only by the [A1] jump's landing, which relifting must decode too. a ? a + 7 : 107.
    ("sureland", True, """{n}:
        MV      .L1     A4,A1
  [ A1] B       .S1     {n}_x
{n}_in:
  [!A1] B       .S1     {n}_far
  [ A1] B       .S2     B3
        ADD     .L1     A4,1,A4
        ADD     .L1     A4,2,A4
        ADD     .L1     A4,4,A4
        NOP
{n}_x:
        NOP             2
        NOP             5
{n}_far:
        B       .S2     B3
        ADDK    .S1     100,A4
        NOP             4
"""),
    # Known-good (issue #111): sureland without the [!A1] jump, so no landing is sure and !a falls into far.
    ("sureland0", False, """{n}:
        MV      .L1     A4,A1
  [ A1] B       .S1     {n}_x
        NOP
  [ A1] B       .S2     B3
        ADD     .L1     A4,1,A4
        ADD     .L1     A4,2,A4
        ADD     .L1     A4,4,A4
        NOP
{n}_x:
        NOP             2
        NOP             5
{n}_far:
        B       .S2     B3
        ADDK    .S1     100,A4
        NOP             4
"""),
    # issue #116: callret with the call made to a local label, so no function is declared at it. The return
    # reads the caller's link, which the call's link replaces only in its window. a ? 2(b + 1) + 16 : b + 1.
    ("localsub", True, """{n}:
        STW     .D2T2   B3,*B15--[2]
||      MV      .L1     A4,A1
        MV      .L1X    B4,A4
  [ A1] B       .S1     {n}_s
{n}_in:
  [!A1] B       .S2     B3
        MVKL    .S2     {n}_ret,B3
        MVKH    .S2     {n}_ret,B3
        ADD     .L1     A4,1,A4
||      ADDK    .S2     8,B15
        NOP             1
        NOP             1
{n}_ret:
        ADDK    .S1     16,A4
        LDW     .D2T2   *B15,B3
        NOP             4
        B       .S2     B3
        NOP             5
{n}_s:
        B       .S2     B3
        ADD     .L1     A4,A4,A4
        NOP             4
"""),
    # Known-good (issue #116): localsub with B3 set to h before the pair, so the B B3 is a call to h that returns
    # to ret. a ? b + 1017 : 2(b + 1) + 16.
    ("localptr", False, """{n}:
        STW     .D2T2   B3,*B15--[2]
||      MV      .L1     A4,A1
        MV      .L1X    B4,A4
        MVKL    .S2     {n}_h,B3
        MVKH    .S2     {n}_h,B3
  [ A1] B       .S1     {n}_s
  [!A1] B       .S2     B3
        MVKL    .S2     {n}_ret,B3
        MVKH    .S2     {n}_ret,B3
        ADD     .L1     A4,1,A4
||      ADDK    .S2     8,B15
        NOP             1
        NOP             1
{n}_ret:
        ADDK    .S1     16,A4
        LDW     .D2T2   *B15,B3
        NOP             4
        B       .S2     B3
        NOP             5
{n}_s:
        B       .S2     B3
        ADDK    .S1     1000,A4
        NOP             4
"""),
    # issue #109: the inner [!A2] B far lands behind tail's ADDK 256, outside the stretch, which is the last
    # native delay slot of twin's [!A2] B far; latching twin's branch too makes it plain code.
    # b ? (a ? a + 0x1f0 : 0x5d8) : (a ? a + 0x187 : 0x56f).
    ("owntail", True, """{n}:
        MV      .L1     A4,A2
||      MV      .L2     B4,B0
  [ B0] B       .S1     {n}_twin
        NOP             5
{n}_in:
        B       .S1     {n}_tail
        NOP
  [!A2] B       .S1     {n}_far
        ADD     .L1     A4,1,A4
        ADD     .L1     A4,2,A4
        ADD     .L1     A4,4,A4
        NOP             5
{n}_twin:
  [!A2] B       .S1     {n}_far
        ADDK    .S1     16,A4
        ADDK    .S1     32,A4
        ADDK    .S1     64,A4
{n}_tail:
        ADDK    .S1     128,A4
        ADDK    .S1     256,A4
        B       .S2     B3
        NOP             5
{n}_far:
        B       .S2     B3
        ADDK    .S1     1000,A4
        NOP             4
"""),
    # Known-good (issue #109): owntail with twin's branch replaced by a NOP, so the inner lands behind plain code.
    ("owntail0", False, """{n}:
        MV      .L1     A4,A2
||      MV      .L2     B4,B0
  [ B0] B       .S1     {n}_twin
        NOP             5
        B       .S1     {n}_tail
        NOP
  [!A2] B       .S1     {n}_far
        ADD     .L1     A4,1,A4
        ADD     .L1     A4,2,A4
        ADD     .L1     A4,4,A4
        NOP             5
{n}_twin:
        NOP
        ADDK    .S1     16,A4
        ADDK    .S1     32,A4
        ADDK    .S1     64,A4
{n}_tail:
        ADDK    .S1     128,A4
        ADDK    .S1     256,A4
        B       .S2     B3
        NOP             5
{n}_far:
        B       .S2     B3
        ADDK    .S1     1000,A4
        NOP             4
"""),
    # issue #110: a jump, a call on the other predicate in its window with the link set before both, and a
    # second jump on the jump's predicate in the call's window. The call returns where B3 points. a ? 2b + 16 : b + 103.
    ("callarm", True, """{n}:
        STW     .D2T2   B3,*B15--[2]
||      MV      .L1     A4,A1
        MV      .L1X    B4,A4
        MVKL    .S2     {n}_ret,B3
        MVKH    .S2     {n}_ret,B3
  [!A1] B       .S1     {n}_x
{n}_in:
  [ A1] B       .S1     {n}_h
  [!A1] B       .S1     {n}_y
        NOP             4
{n}_ret:
        ADDK    .S1     16,A4
""" + RET + """{n}_x:
        ADD     .L1     A4,1,A4
        ADD     .L1     A4,2,A4
        ADD     .L1     A4,4,A4
""" + RET + """{n}_y:
        ADDK    .S1     100,A4
""" + RET),
    # Known-good (issue #110): callarm without the second jump, so the call keeps its whole window. a ? 2b + 16 : b + 7.
    ("callarm0", False, """{n}:
        STW     .D2T2   B3,*B15--[2]
||      MV      .L1     A4,A1
        MV      .L1X    B4,A4
        MVKL    .S2     {n}_ret,B3
        MVKH    .S2     {n}_ret,B3
  [!A1] B       .S1     {n}_x
  [ A1] B       .S1     {n}_h
        NOP             5
{n}_ret:
        ADDK    .S1     16,A4
""" + RET + """{n}_x:
        ADD     .L1     A4,1,A4
        ADD     .L1     A4,2,A4
        ADD     .L1     A4,4,A4
""" + RET),
    # issue #110: callarm with the link's low half written before an earlier jump, which the B3 scan starts
    # after, so B3 is unknown and the call returns to its listed fall-through: still warned.
    ("callarml", True, """{n}:
        STW     .D2T2   B3,*B15--[2]
||      MV      .L1     A4,A1
        MV      .L1X    B4,A4
        MVKL    .S2     {n}_ret,B3
        B       .S1     {n}_go
        NOP             5
{n}_go:
        MVKH    .S2     {n}_ret,B3
  [!A1] B       .S1     {n}_x
{n}_in:
  [ A1] B       .S1     {n}_h
  [!A1] B       .S1     {n}_y
        NOP             4
{n}_ret:
        ADDK    .S1     16,A4
""" + RET + """{n}_x:
        ADD     .L1     A4,1,A4
        ADD     .L1     A4,2,A4
        ADD     .L1     A4,4,A4
""" + RET + """{n}_y:
        ADDK    .S1     100,A4
""" + RET),
    # issue #110: callarml with both halves of the link after the earlier jump. a ? 2b + 16 : b + 103.
    ("callarml0", True, """{n}:
        STW     .D2T2   B3,*B15--[2]
||      MV      .L1     A4,A1
        MV      .L1X    B4,A4
        B       .S1     {n}_go
        NOP             5
{n}_go:
        MVKL    .S2     {n}_ret,B3
        MVKH    .S2     {n}_ret,B3
  [!A1] B       .S1     {n}_x
{n}_in:
  [ A1] B       .S1     {n}_h
  [!A1] B       .S1     {n}_y
        NOP             4
{n}_ret:
        ADDK    .S1     16,A4
""" + RET + """{n}_x:
        ADD     .L1     A4,1,A4
        ADD     .L1     A4,2,A4
        ADD     .L1     A4,4,A4
""" + RET + """{n}_y:
        ADDK    .S1     100,A4
""" + RET),
]
# Known-bads that native lifting now gets right by latching their branches (issue #73). What
# their C must contain:
#   callret  a ? h(b + 1) : b + 1; the jump lands with a fresh link in B3, so it is lifted as a call
#   tri      a ? 3 : b ? 0x13 : 0x43b
#   bnop4    x ? x + 1 : 1
#   indep    a ? (b ? 0x21 : 0x1011) : (b ? 0x201 : 0x1101): with both jumps taken, the second
#            lands in the first's target
LIFTED = {
    "callret": ["callret_h(param_2 + 1)"],
    # both taken: the second jump lands behind the fourth instruction of the first's target
    "indep": ["0x11", "0x21", "0x101", "0x201", "+ 0x1000"],
    "tri": ["return 3;", "0x13", "0x43b"],
    "bnop4": ["param_1 + 1"],
    "swjump": ["0x111", "0x222", "0x333", "0x999"],
    "landret": ["param_1 + 0xc", "param_3 != 0", "param_1 + 4"],
    # Ghidra 12.1.4 prints the test as param_3 == 0 with the arms the other way round
    "landlink": ["param_1 + 0xc", "if (param_3 ", "param_1 + 4"],
    # a ? a + 7 : 107: the relifted stretch decodes past its sure landing
    "sureland": ["return 0x6b;", "return param_1 + 7;"],
    # the !a arm returns b + 1 instead of calling through the caller's link
    "localsub": ["return param_2 + 1;"],
    # known-good, latched before the fix: the B B3 stays a call to h, which returns to ret
    "localptr": ["localptr_h(", "iVar1 + 0x10"],
    # b ? (a ? a + 0x1f0 : 0x5d8) : (a ? a + 0x187 : 0x56f): the landing in twin's delay slot is carried
    "owntail": ["param_1 + 7;", "+ 0x568;"],
    # a ? 2b + 16 : b + 103: the call returns where B3 points, not to its listed fall-through
    "callarm": ["param_2 + 3;", "return param_2 + 100;"],
    "callarml0": ["param_2 + 3;", "return param_2 + 100;"],
}
# What the C of a case that latches nothing must hold, and must not.
PLAIN = {"cpyret": ["return param_1 + 1;"]}
ABSENT = {"cpyretp": ["return param_1 + 1;"]}
# Cases that are warned or lifted depending on the decompiler, and what their C holds when lifted.
EITHER = {"entmany": ["return 0x50;", "0x111", "+ 0xee"]}
LINK = re.compile(r"(MVK[LH]\s+\.S[12]\s+|\.word\s+)(\w+)")


def assemble(compiler, source, object_file, log):
    command = [str(compiler), "-mv6740", "--abi=eabi", "--no_compress", "-c",
               str(source), "--output_file=" + str(object_file)]
    completed = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    log.write_text(completed.stdout)
    if completed.returncode:
        raise RuntimeError("TI assembly failed; see " + str(log))


def main():
    if len(sys.argv) not in (3, 4) or len(sys.argv) == 4 and sys.argv[3] != "be":
        raise SystemExit("Usage: nested-window.py IMAGE CASES.json [be]")
    image_path, manifest_path = map(Path, sys.argv[1:3])
    image_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    prefix = image_path.parent / (image_path.stem + ".nested-window")
    assembly, object_file, log = (Path(str(prefix) + suffix) for suffix in (".asm", ".obj", ".log"))
    binary = Path(os.environ.get("TI_C6000_BIN", "/Applications/ti/ti-cgt-c6000_8.3.15/bin"))
    tool = (lambda name: binary / name) if binary.is_dir() else (lambda name: binary.with_name(name))
    sections = []
    for name, _, body in CASES:
        sections.append(' .sect ".pf_' + name + '"\n .nocmp\n' + body.format(n=name) + H.format(n=name))
    text = "\n".join(sections)
    assembly.write_text(text)
    assemble(tool("cl6x"), assembly, object_file, log)
    # Section offsets of every label: each case's labels are prefixed by its name.
    listed = subprocess.run([str(tool("nm6x")), str(object_file)], text=True, stdout=subprocess.PIPE, check=True).stdout
    offsets = {parts[2]: int(parts[0], 16) for parts in map(str.split, listed.splitlines())
               if len(parts) == 3 and parts[1] in "tT" and not parts[2].startswith(".")}
    addresses = {}
    for index, (name, _, _) in enumerate(CASES):
        for label, offset in offsets.items():
            if label == name or label.startswith(name + "_"):
                addresses[label] = 0x1000 + index * SIZE + offset
    assembly.write_text(LINK.sub(lambda m: m.group(1) + hex(addresses[m.group(2)]), text))
    assemble(tool("cl6x"), assembly, object_file, log)
    spec = importlib.util.spec_from_file_location(
        "predicate_facts", Path(__file__).with_name("pipeline-predicate-facts.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    code = module.object_sections(object_file)
    image = bytearray(len(CASES) * SIZE)
    manifest = []
    for index, (name, bad, _) in enumerate(CASES):
        words = code[".pf_" + name]
        if len(words) > SIZE:
            raise ValueError("Section too long for " + name)
        image[index * SIZE:index * SIZE + len(words)] = words
        warn = sorted(address for label, address in addresses.items()
                      if label.startswith(name + "_in"))
        if bool(warn) != bad:
            raise ValueError("Known-bad " + name + " needs a _in label, and a known-good none")
        # A lifted case is not warned: its branches are latched and its C is the hardware's.
        manifest.append(dict(name=name, entry=addresses[name], h=addresses[name + "_h"],
                             end=0x1000 + index * SIZE + SIZE - 1, warn=[] if name in LIFTED else warn,
                             c=LIFTED.get(name, []), either=EITHER.get(name), plain=PLAIN.get(name), absent=ABSENT.get(name),
                             functions=[a for label, a in addresses.items() if label == name + "_cb"],
                             labels=[a for label, a in addresses.items() if label == name + "_notcb"]))
    if len(sys.argv) == 4:
        image = b"".join(image[index:index + 4][::-1] for index in range(0, len(image), 4))
    image_path.write_bytes(image)
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    print("NESTED_WINDOW_FIXTURE_OK cases=" + str(len(manifest)))


if __name__ == "__main__":
    main()
