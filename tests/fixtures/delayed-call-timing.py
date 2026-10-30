#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Delayed-call E1 snapshots and E5 load writes, issues #23/#24.

IMAGE CASES.json [be]. Synthetic SPRUFE8B 3.5, 3.6, Tables 4-6/4-10/4-11
and the LDW/LDDW/B/ADDKPC/MVK/MVKH opcode diagrams.
"""
import json
from pathlib import Path
import runpy
import struct
import sys

helpers = runpy.run_path(str(Path(__file__).with_name('delayed-call.py')))
mvk, mvkh, nop, addkpc, branch = (helpers[n] for n in ('mvk', 'mvkh', 'nop', 'addkpc', 'b_s1'))
PREDICATES = [('B0', 2), ('B1', 4), ('B2', 6), ('A1', 8), ('A2', 10), ('A0', 12)]


def load(data=3, base=15, mode=1, pair=False, predicate=0, data_bank=1, side=1):
    return predicate << 28 | data << 23 | base << 18 | mode << 9 | (0x164 if pair else 0x64) | side << 7 | data_bank << 1


def main():
    endian = '>' if len(sys.argv) > 3 and sys.argv[3] == 'be' else '<'
    image, rows = bytearray(), []

    def emit(name, build):
        base = 0x1000 + len(image)
        words, site, ret, accepted, target = build(base)
        data = bytearray(0x100)
        for at, word in words.items():
            struct.pack_into(endian+'I', data, at-base, word)
        for offset in (0x80, 0xc0):
            struct.pack_into(endian+'II', data, offset, helpers['B_B3'], nop(5))
        if not accepted:
            struct.pack_into(endian+'I', data, ret-base, 0x0200a358)
        else:
            struct.pack_into(endian+'II', data, ret-base, helpers['B_B3'], nop(5))
        image.extend(data)
        rows.append(dict(name=name, entry=base, site=site, ret=ret, call=accepted,
                         target=target, other=base+0xc0 if target!=base+0xc0 else base+0x80,
                         untyped_return=not accepted and words[site] >> 28 == 0))

    def window(base, guard=0, branch_guard=0, data=3, pointer=15, mode=1, pair=False):
        ret = base+12
        return ({base: branch_guard << 28 | branch(base, base+0x80),
                 base+4: load(data, pointer, mode, pair, guard), base+8: addkpc(base+8, ret, 3)},
                base, ret, guard == (branch_guard ^ 1) and branch_guard != 0 or data not in (2,3), base+0x80)

    emit('reported_late_B3_load', window)
    emit('late_pair_contains_B3', lambda b: window(b, data=2, pair=True))
    emit('updating_B3_base_only', lambda b: window(b, data=7, pointer=3, mode=11))
    emit('updating_B3_base_and_data', lambda b: window(b, pointer=3, mode=11))
    for preg, encoding in PREDICATES:
        for inverted in (0,1):
            taken = encoding | inverted
            for name, guard in [('matching',taken),('opposite',taken^1),('unknown',2 if encoding!=2 else 8)]:
                emit(f'load_{preg}_{inverted}_{name}', lambda b,g=guard,p=taken: window(b,g,p))
    for before in range(1,7):
        def earlier(b,n=before):
            site=b+4*n;ret=site+8
            code={b:load(), **{b+4*k:nop(1) for k in range(1,n)}, site:branch(site,b+0x80), site+4:addkpc(site+4,ret,4)}
            return code,site,ret,n>=4,b+0x80
        emit(f'lookback_load_{before}_cycles',earlier)
    for first in (True,False):
        def parallel_load(b,first=first):
            site=b+4 if first else b;ret=b+12
            code={b:(load() if first else branch(site,b+0x80))|1,
                  b+4:branch(site,b+0x80) if first else load(), b+8:addkpc(b+8,ret,4)}
            return code,site,ret,False,b+0x80
        emit('parallel_load_'+('before' if first else 'after'),parallel_load)
    for bank in (0,1):
        for preg, encoding in PREDICATES:
            for order in ('before','after'):
                for kind in ('always','matching','opposite','unknown'):
                    def target(b,enc=encoding,order=order,kind=kind,bank=bank):
                        site=b+12 if order=='before' else b+8;ret=b+20
                        guard={'always':0,'matching':enc,'opposite':enc^1,'unknown':2 if enc!=2 else 8}[kind]
                        writer=guard << 28 | ((mvk(b+0xc0,5)&~2) if bank==0 else (5<<23 | 6<<18 | 0xfda))
                        # Full32 register B uses .S2: A5 via 2X, or local B5.
                        # Its peer writes on .S1 or .L2, respectively.
                        jump=enc << 28 | (0x1362 if bank==0 else 0x362) | 5 << 18
                        code={b:(mvk(b+0x80,5)&~2)|bank<<1,b+4:(mvkh(0,5)&~2)|bank<<1,
                              b+8:(writer if order=='before' else jump)|1,
                              b+12:jump if order=='before' else writer,b+16:addkpc(b+16,ret,4)}
                        return code,site,ret,True,b+0x80
                    emit(f'target_bank{bank}_{preg}_{order}_{kind}',target)
    def sequential(b):
        ret=b+24
        return {b:mvk(b+0x80,5)&~2,b+4:mvkh(0,5)&~2,b+8:mvk(b+0xc0,5)&~2,
                b+12:mvkh(0,5)&~2,b+16:0x1362|5<<18,b+20:addkpc(b+20,ret,4)},b+16,ret,True,b+0xc0
    emit('target_previous_cycle_writer',sequential)
    for preg, encoding in PREDICATES:
        for before in (1,3):
            for opposite in (False,True):
                def guarded(b,n=before,enc=encoding,opposite=opposite):
                    site=b+4*n;ret=site+8
                    code={b:load(predicate=enc ^ int(opposite)), **{b+4*k:nop(1) for k in range(1,n)},
                          site:enc << 28 | branch(site,b+0x80), site+4:addkpc(site+4,ret,4)}
                    return code,site,ret,opposite,b+0x80
                emit(f'lookback_{preg}_{before}_opposite{opposite}',guarded)
        for kind in ('always','matching','opposite','read_before_E5'):
            def predicate_load(b,preg=preg,enc=encoding,kind=kind):
                ret=b+16;early=kind=='read_before_E5'
                guard={'always':0,'matching':enc,'opposite':enc^1,'read_before_E5':0}[kind]
                code={b:load(data=int(preg[1:]),predicate=guard,data_bank='AB'.index(preg[0])),
                      b+4:enc << 28 | branch(b+4,b+0x80),b+8:nop(2 if early else 3),
                      b+12:enc << 28 | addkpc(b+12,ret,2 if early else 1)}
                return code,b+4,ret,kind in ('opposite','read_before_E5'),b+0x80
            emit(f'predicate_load_{preg}_{kind}',predicate_load)
    for first in (True,False):
        def compact(b,first=first):
            ret=b+20;site=b+12 if first else b+8
            # SPRUFE8B G-1: MV.S1 A6,A5 and NOP 1, physical halfword order.
            payload=struct.unpack(endian+'I',struct.pack(endian+'HH',0xa30e,0x0c6e))[0]
            code={b:mvk(b+0x80,5)&~2,b+4:mvkh(0,5)&~2,
                  b+8:payload if first else (0x1362|5<<18|1),
                  b+12:(0x1362|5<<18) if first else payload,
                  b+16:addkpc(b+16,ret,4), b+28:0xe0800030 if first else 0xe1000040}
            return code,site,ret,True,b+0x80
        emit('compact_writer_'+('before' if first else 'after'),compact)
    def crossing(b):
        ret=b+40
        code={b:mvk(b+0x80,5)&~2,b+4:mvkh(0,5)&~2,
              **{b+offset:nop(1) for offset in range(8,28,4)},
              b+28:(mvk(b+0xc0,5)&~2)|1,b+32:0x1362|5<<18,b+36:addkpc(b+36,ret,4)}
        return code,b+32,ret,True,b+0x80
    emit('target_packet_crosses_fetch_boundary',crossing)
    for pair in (False,True):
        def other_side(b,pair=pair):
            code,site,ret,accepted,target=window(b,data=2 if pair else 3,pair=pair)
            code[b+4]=load(data=2 if pair else 3,pair=pair,side=0)
            return code,site,ret,accepted,target
        emit('D1_B3_load_pair'+str(pair),other_side)
        def compact_load(b,pair=pair):
            ret=b+12
            word=0x102d if pair else 0x103d
            payload=struct.unpack(endian+'I',struct.pack(endian+'HH',word,0x0c6e))[0]
            return {b:branch(b,b+0x80),b+4:payload,b+8:addkpc(b+8,ret,2),
                    b+28:0xe0400000 | (4<<16 if pair else 0)},b,ret,False,b+0x80
        emit('compact_B3_load_pair'+str(pair),compact_load)
    def protected_window(b):
        ret=b+12
        payload=struct.unpack(endian+'I',struct.pack(endian+'HH',0x107d,0x0c6e))[0]
        return {b:branch(b,b+0x80),b+4:payload,b+8:addkpc(b+8,ret,2),
                b+28:0xe0500000},b,ret,False,b+0x80
    emit('protected_load_exhausts_delay_window',protected_window)
    def protected_prefix(b):
        ret=b+12
        return {b:load(data=7),b+4:branch(b+4,b+0x80),b+8:addkpc(b+8,ret,4),
                b+28:0xe0100000},b+4,ret,True,b+0x80
    emit('protected_lookback_load_drains_before_branch',protected_prefix)
    assert len(rows)==202
    Path(sys.argv[1]).write_bytes(image)
    Path(sys.argv[2]).write_text(json.dumps(rows,indent=2)+'\n')


if __name__=='__main__':main()
