#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Updating loads: raw final value and E1/E5 writes, SPRUFE8B 4.2.5. IMAGE JSON [be]."""
from pathlib import Path
import json,struct,sys
import compact_order

compact_order.big_endian_on_exit()


def main():
    image=bytearray(0x4000);rows=[];endian='>' if len(sys.argv)>3 and sys.argv[3]=='be' else '<'
    def mv(src,dst,side=1,unit='L'):
        return (dst<<23)|(src<<18)|(0xfd8 if unit=='L' else 0x6a0)|(2 if side==2 else 0)
    def mvk(value,dst,side=1):return (dst<<23)|((value&0xffff)<<7)|(0x28 if side==1 else 0x2a)
    def load(base,dst,mode=0xb,off=1,side=1,pair=False,nonalign=False):
        # TI-independent manual fields, checked by load-alias-opcodes.asm.
        opcode=0x124 if nonalign else 0x164 if pair else 0x64
        encoded=dst+1 if nonalign else dst
        return (encoded<<23)|(base<<18)|(off<<13)|(mode<<9)|opcode|(0x82 if side==2 else 0)
    def emit(name,word,base,newbase,old,loaded,inputs=None,dst=None,side=1,pair=False,
             memory=None,memory64=None,companions=(),prefix=(),refused=None,late_base=None):
        bank='A' if side==1 else 'B';dst=base if dst is None else dst
        inputs=dict(inputs or {});inputs[f'{bank}{base}']=old
        if dst!=base:inputs.setdefault(f'{bank}{dst}',0x11112222)
        if pair:inputs.setdefault(f'{bank}{dst+1}',0x33334444)
        initial=dict(inputs)
        first=[word,*companions];first=[w|(1 if k<len(first)-1 else 0) for k,w in enumerate(first)]
        early=[mv(dst,17,side)];late=[mv(dst,18,side)]
        if pair:early=[early[0]|1,mv(dst+1,19,side,'S')];late=[late[0]|1,mv(dst+1,20,side,'S')]
        words=list(prefix)+first+[mv(base,16,side),0x2000]+early+late+[0xc0362,0x8000]
        expected={f'{bank}16':newbase,f'{bank}17':newbase if base==dst else initial[f'{bank}{dst}'],f'{bank}18':loaded&0xffffffff}
        if late_base is not None:expected[f'{bank}17']=late_base
        expected[f'{bank}{base}']=loaded&0xffffffff if base==dst else loaded>>32 if pair and base==dst+1 else newbase
        raw_expected={f'{bank}{dst}':loaded&0xffffffff}
        if pair:
            expected.update({f'{bank}{dst+1}':loaded>>32,f'{bank}19':newbase if base==dst+1 else initial[f'{bank}{dst+1}'],f'{bank}20':loaded>>32})
            raw_expected[f'{bank}{dst+1}']=loaded>>32
        expected[f'{bank}{dst}']=loaded&0xffffffff
        if base!=dst and not(pair and base==dst+1):raw_expected[f'{bank}{base}']=newbase
        entry=0x1000+len(rows)*0x100
        for k,w in enumerate(words):struct.pack_into(endian+'I',image,entry-0x1000+4*k,w)
        row=dict(name=name,entry=entry,input=inputs,expected=expected,raw_expected=raw_expected,
                 memory=memory or {str(old):loaded&0xffffffff})
        if memory64:row['memory64']={str(k):v for k,v in memory64.items()};row['memory']={}
        if refused:row['refused']=refused
        rows.append(row);return row

    for side,base in [(1,4),(2,8)]:
        emit(f'post_word_side{side}',load(base,base,side=side),base,0x8004,0x8000,0x12345678,side=side)
    for mode,name,old,address,new in [(9,'pre_increment',0x8000,0x8004,0x8004),(10,'post_decrement',0x8004,0x8004,0x8000),(8,'pre_decrement',0x8004,0x8000,0x8000)]:
        emit(name,load(4,4,mode),4,new,old,0x87654321,memory={str(address):0x87654321})
    emit('destination_alias_index',load(8,9,15,9,2),8,0x8004,0x8000,0x12345678,inputs={'B9':1},dst=9,side=2)
    for base in [4,5]:
        emit(f'pair_alias_base_{base}',load(base,4,pair=True),base,0x8008,0x8000,0x1122334455667788,dst=4,pair=True,memory64={0x8000:0x1122334455667788})
    emit('nonaligned_pair_alias',load(4,4,pair=True,nonalign=True),4,0x8009,0x8001,0x1122334455667788,pair=True,memory64={0x8001:0x1122334455667788})
    emit('circular_post_word',load(4,4),4,0x8000,0x801c,0x12345678,inputs={'AMR':0x40001})
    emit('circular_pre_word',load(4,4,9),4,0x8000,0x801c,0x12345678,inputs={'AMR':0x40001},memory={str(0x8000):0x12345678})
    blocks={k:(0x1111111111111111 if k<0x8020 else 0x2222222222222222) for k in range(0x8000,0x8030,8)}
    emit('circular_nonaligned_pair',load(4,4,pair=True,nonalign=True),4,0x8005,0x801d,0x1111111111111111,pair=True,inputs={'AMR':0x40001},memory64=blocks)
    emit('captured_true_predicate',load(4,4)|0xc0000000,4,0x8004,0x8000,0x12345678,inputs={'A0':1},companions=[mvk(0,0)])
    row=emit('captured_false_predicate',load(4,4)|0xc0000000,4,0x8000,0x8000,0x8000,inputs={'A0':0},companions=[mvk(1,0)],memory={str(0x8000):0x12345678})
    row['expected'].update(A4=0x8000,A16=0x8000,A17=0x8000,A18=0x8000);row['raw_expected']={'A4':0x8000}
    # A legal E1 write in a later EP must not change the load's captured address.
    row=emit('intervening_base_writer',load(4,4),4,0x8004,0x8000,0x12345678,memory={str(0x8000):0x12345678,str(0x7000):0x87654321},late_base=0x7000)
    at=row['entry']-0x1000;struct.pack_into(endian+'I',image,at+4,mv(4,16)|1);struct.pack_into(endian+'I',image,at+8,mvk(0x7000,4));struct.pack_into(endian+'I',image,at+12,0x2000)
    # Above inserts a companion into the observer EP: shift later words by four.
    later=[mv(4,17),mv(4,18),0xc0362,0x8000]
    for k,w in enumerate(later):struct.pack_into(endian+'I',image,at+16+4*k,w)
    # Genuine same-cycle conflicts remain refused rather than assigned priority.
    emit('e1_base_collision',load(4,4),4,0x8004,0x8000,0x12345678,inputs={'A6':7},companions=[mv(6,4,unit='S')],refused='potential simultaneous memory/register writes')
    row=emit('e5_data_collision',load(4,4),4,0x8004,0x8000,0x12345678,refused='potential simultaneous memory/register writes')
    struct.pack_into(endian+'I',image,row['entry']-0x1000+12,mvk(7,4))
    row=emit('e5_pair_partial_collision',load(4,4,pair=True),4,0x8008,0x8000,0x1122334455667788,pair=True,memory64={0x8000:0x1122334455667788},refused='potential simultaneous memory/register writes')
    struct.pack_into(endian+'I',image,row['entry']-0x1000+12,mvk(7,5))
    # Header layout0000001: compact LDW and NOP, then six full32 payload words.
    entry=0x1000+len(rows)*0x100;offset=entry-0x1000
    struct.pack_into(endian+'HH',image,offset,0x0c4c,0x0c6e)
    for k,w in enumerate([mv(4,16),0,mv(4,17),mv(4,18),0xc0362,0]):struct.pack_into(endian+'I',image,offset+4+4*k,w)
    struct.pack_into(endian+'I',image,offset+28,0xe0200000)
    rows.append(dict(name='compact_post_word',entry=entry,input={'A4':0x8000},memory={str(0x8000):0x12345678},raw_expected={'A4':0x12345678},expected={'A4':0x12345678,'A16':0x8004,'A17':0x8004,'A18':0x12345678}))
    Path(sys.argv[1]).write_bytes(image);Path(sys.argv[2]).write_text(json.dumps(rows,indent=2)+'\n')


if __name__=='__main__':main()
