#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Synthetic loop-buffer phase/epilog cases, SPRUFE8B chapter 7. IMAGE CASES.json [be]."""
from pathlib import Path
import json, re, struct, sys


def main():
    image=bytearray(0x10000);rows=[];endian='>' if len(sys.argv)>3 and sys.argv[3]=='be' else '<';lines=(Path(__file__).resolve().parents[2]/'data/languages/c6000_decode.sinc').read_text().splitlines()
    def add(side,reg):
        line=next(s for s in lines if f'"ADD.L{side}" SCst5, Src2, Dst is' in s)
        fixed={int(bit):int(v) for bit,v in re.findall(r'\bi(\d+)=(\d)\b',line)}
        return sum(v<<bit for bit,v in fixed.items())|(1<<13)|(reg<<18)|(reg<<23)
    def mvk(value,reg,side=2):return (reg<<23)|((value&0xffff)<<7)|(0x2a if side==2 else 0x28)
    for kind in ['SPLOOP','SPLOOPD','SPLOOPW']:
        for ii in [1,2,3,6,14]:
            for count in ([0,1,7] if kind!='SPLOOPW' else [0]):
                entry=0x1000+len(rows)*0x200;words=[];start={'SPLOOP':0x38000,'SPLOOPD':0x3a000,'SPLOOPW':0x3e000|0xc0000000}[kind]|((ii-1)<<23)
                if kind=='SPLOOPD':words.extend([start|1,(13<<23)|(4<<18)|0x3a2])
                else:words.append(start)
                for t in range(2*ii+1):
                    if t==0:words.append(add(1,4))
                    elif t==ii:
                        if kind=='SPLOOPW':words.extend([0x30001|(4<<18),mvk(0,0,1)])
                        else:words.extend([0x30001|(8<<18),mvk(0x55,6)])
                    elif t==2*ii:words.extend([0x34001,add(2,5)])
                    else:words.append(0)
                words.extend([(7<<23)|(5<<18)|0x1a2,0x10000,0x10000,0xc0362,0x8000])
                for k,word in enumerate(words):struct.pack_into(endian+'I',image,entry-0x1000+4*k,word)
                n=count if kind=='SPLOOP' else count+(4+ii-1)//ii
                if kind=='SPLOOPW':
                    terminal=((ii+5+ii-1)//ii)*ii-1;a=terminal//ii+1;b=max(1,(terminal-2*ii)//ii+1);expected={'A4':a,'B5':b,'B7':b,'ILC':0x89abcdef,'TSR':0}
                else:expected={'A4':n,'B5':n,'B6':0x55,'ILC':0,'TSR':0}
                rows.append(dict(name=f'{kind}_{ii}_{count}',entry=entry,input={'ILC':count if kind=='SPLOOP' else (0x89abcdef if kind=='SPLOOPW' else 0),'B4':count,'A0':1},expected=expected))
                # 7.9.1 and 7.9.5: initial zero and one share the padding tail.
                if kind=='SPLOOP' and count in [0,1] or kind=='SPLOOPD' and count==0 and ii>=4:rows[-1]['expected_cycles']=26+3*ii
    for count in [1,3,7]:
        entry=0x1000+len(rows)*0x200;words=[0x38000|(5<<23)]
        for t in range(12):
            if t==0:words.append(0x264|(11<<9)|(1<<13)|(8<<18)|(3<<23))
            elif t==5:words.append(0xe00|(3<<13)|(4<<18)|(5<<23))
            elif t==9:words.append(0x274|0x80|(11<<9)|(1<<13)|(8<<18)|(5<<23))
            elif t==11:words.append(0x34000)
            else:words.append(0)
        words.extend([mvk(9,5,1),0x10000,0x10000,0xc0362,0x8000])
        for k,word in enumerate(words):struct.pack_into(endian+'I',image,entry-0x1000+4*k,word)
        inputs={str(0x8000+4*k):int.from_bytes(struct.pack('<f',(k+1)*0.5),'little') for k in range(count)}
        outputs={str(0x8100+4*k):int.from_bytes(struct.pack('<f',float(k+1)),'little') for k in range(count)}
        rows.append(dict(name=f'buffered_float_pipeline_{count}',entry=entry,input={'ILC':count,'A4':0x40000000,'A8':0x8000,'B8':0x8100},expected={'A8':0x8000+4*count,'B8':0x8100+4*count,'ILC':0,'TSR':0},memory=inputs,expected_memory=outputs))
    for predicate in [0,1]:
        entry=0x1000+len(rows)*0x200
        words=[0x10|((0x100//4)<<7),0xc003e000,add(1,4)]+[0]*7+[0x34001,add(2,5)]
        for k,word in enumerate(words):struct.pack_into(endian+'I',image,entry-0x1000+4*k,word)
        struct.pack_into(endian+'II',image,entry-0x1000+0x100,0xc0362,0x8000)
        rows.append(dict(name=f'branch_idles_loading_loop_{predicate}',entry=entry,input={'A0':predicate,'ILC':0x777},expected={'A4':4,'B5':0,'ILC':0x777,'TSR':0},expected_cycles=12,extent=0x1ff))
    entry=0x1000+len(rows)*0x200
    words=[0x10|((0x100//4)<<7),0,0,0,0,0xc003e000,add(1,4),0,0,0,0,0,0,0x34001,add(2,5)]
    for k,word in enumerate(words):struct.pack_into(endian+'I',image,entry-0x1000+4*k,word)
    struct.pack_into(endian+'II',image,entry-0x1000+0x100,0xc0362,0x8000)
    rows.append(dict(name='branch_idles_new_loop_in_last_slot',entry=entry,input={'A0':1,'ILC':0x777},expected={'A4':0,'B5':0,'ILC':0x777,'TSR':0},expected_cycles=12,extent=0x1ff))
    for encoded in range(8):
        entry=0x1000+len(rows)*0x200
        struct.pack_into(endian+'III',image,entry-0x1000,0xc6e<<16|0xc6e|(encoded<<13),0xc0362,0x8000)
        struct.pack_into(endian+'I',image,entry-0x1000+28,0xe0200000)
        rows.append(dict(name=f'compact_nop_{encoded+1}',entry=entry,input={},expected={'PC':0x9000},expected_cycles=encoded+8))
    Path(sys.argv[1]).write_bytes(image);Path(sys.argv[2]).write_text(json.dumps(rows,indent=2))


if __name__=='__main__':main()
