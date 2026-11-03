#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Closed-call proofs, late effects and multi-call capability refusals; IMAGE JSON [le|be]."""
from pathlib import Path
import json,struct,sys
import compact_order

compact_order.big_endian_on_exit()

def mv(a,d,side=1,cross=False):return d<<23|a<<18|0xfd8|(2 if side==2 else 0)|(0x1000 if cross else 0)
def branch(pc,target):return 0x10|((((target-(pc&~31))>>2)&0x1fffff)<<7)
def link(pc,target):return 3<<23|((((target-(pc&~31))>>2)&0x7f)<<16)|0x162

def main():
    endian='>' if len(sys.argv)>3 and sys.argv[3]=='be' else '<';image=bytearray(0x24000);rows=[]
    specs=[('late_mpyli',None),('captured_store',None),('bad_hash','byte hash mismatch'),('callee_B3_writer','callee changes B3'),('unknown_link','link lacks exact'),('wrong_link','link lacks exact'),('unplanned_branch','undeclared control edge'),('not_drained','explicit drained entry'),('wrong_owner','language/owner identity mismatch'),('bad_stop','endpoint still has pending effects'),('declared_unowned_tail',None),('missing_unowned_span','flow leaves declared ownership'),('claimed_gap_has_owner','unowned span overlaps an owner'),('owned_body_mid_instruction','byte ownership'),('span_starts_mid_instruction','unowned span cuts an instruction'),('data_in_instruction_suffix','instruction overlaps defined data'),('header_start','invalid physical instruction start'),('full32_halfword_start','invalid physical instruction start'),('straddling_return_target','branch-target execute packet spans fetch packets'),('stale_compact_context',None),('header_eight_instruction_ep','eight-instruction header-based execute packet'),('early_valid_link',None),('early_addkpc_nops',None)]
    for index,(name,error) in enumerate(specs):
        c=0x1000+index*0x800+(4 if name=='captured_store' else 0);f=c+0x200;continuation=c+0x1c
        words=[3<<23|15<<18|1<<13|10<<9|0xf6,branch(c+4,f),0,0,0,0,link(c+0x18,continuation),mv(4,8),0,0,mv(4,9),3<<23|15<<18|1<<13|9<<9|0xe6,0x6000,0x8ca362]
        callee=[mv(3,1,cross=True),0x8c0362,0,0,0,0,4<<23|3<<18|2<<13|0x570]
        if name in ['captured_store','straddling_return_target']:
            callee[-1]=4<<23|6<<18|0x74|2 # STW .D1T2 B4,*A6[0]
            words[7]=mv(7,4,2)|1;words[8]=mv(7,6) # same EP source/base clobber, nextpc+0x24
        if name=='callee_B3_writer':callee[0]=mv(2,3,2)
        if name=='unknown_link':words[6]=mv(2,3,2)
        if name=='wrong_link':words[6]=link(c+0x18,continuation+4)
        if name=='early_addkpc_nops':words=words[:2]+[link(c+8,c+12)|(4<<13)]+words[7:];continuation=c+12
        if name=='early_valid_link':words[5]=link(c+0x14,continuation);words[6]=0
        if name=='unplanned_branch':callee[3]=branch(f+12,f+0x80)
        if name=='header_start':words[1]=branch(c+4,f+0x1c)
        if name=='full32_halfword_start':words[1]=branch(c+4,f) # plan alone is malformed below
        for k,word in enumerate(words):struct.pack_into(endian+'I',image,c-0x1000+k*4,word)
        for k,word in enumerate(callee):struct.pack_into(endian+'I',image,f-0x1000+k*4,word)
        row=dict(name=name,caller=c,caller_end=c+len(words)*4,callee=f,callee_end=f+len(callee)*4,call=c+4,link=c+0x18,continuation=continuation,callee_return=f+4,caller_return=c+0x34)
        if name=='header_eight_instruction_ep':
            struct.pack_into(endian+'HH',image,f-0x1000,0x0c6e,0x0c6e)
            for k in range(1,7):struct.pack_into(endian+'I',image,f-0x1000+4*k,1 if k<6 else 0)
            struct.pack_into(endian+'I',image,f-0x1000+28,0xe0200003)
            struct.pack_into(endian+'I',image,f-0x1000+32,0x8ca362)
            row.update(callee_end=f+0x24,callee_return=f+0x20)
        if name=='stale_compact_context':
            struct.pack_into(endian+'HH',image,f-0x1000,(5<<13)|0x1866|(6<<7),0x0c6e)
            for k,word in enumerate([mv(3,1,cross=True),0x8c0362,0,0,0,0]):struct.pack_into(endian+'I',image,f-0x1000+4+4*k,word)
            struct.pack_into(endian+'I',image,f-0x1000+28,0xe0200000)
            struct.pack_into(endian+'I',image,f-0x1000+32,4<<23|3<<18|2<<13|0x570)
            row.update(callee_end=f+0x24,callee_return=f+8)
        if name=='header_start':
            struct.pack_into(endian+'I',image,f-0x1000+0x1c,0xe0000000)
            struct.pack_into(endian+'I',image,f-0x1000+0x20,0x8ca362)
            row.update(callee=f+0x1c,callee_end=f+0x24,callee_return=f+0x20)
        if name=='full32_halfword_start':row.update(callee=f+2,callee_end=f+0x1c,callee_return=f+4)
        if name=='bad_stop':row['caller_end']=c+0x20
        if name=='early_valid_link':row['link']=c+0x14
        if name=='early_addkpc_nops':row.update(link=c+8,caller_return=c+len(words)*4-4)
        if error:row['refused']=error
        rows.append(row)
    # SPRUFE8B 3.5/3.7, B/MVK/MVKH: independent full-width fields.
    def mvk(value,d,high=False,side=2):return d<<23|(value&0xffff)<<7|(0x68 if high else 0x28)|(2 if side==2 else 0)
    proof_cases=[('register_split',None),('target_same_packet',None),('target_delay_overwrite',None),('target_wrong','target lacks exact'),('target_missing_low','target lacks exact'),('target_predicated','target lacks exact'),('target_late_load','target lacks exact'),('target_same_packet_setup','target lacks exact'),('target_collision','target lacks exact'),('register_B3',None),('register_cross',None),('target_wrong_high','target lacks exact'),('link_wrong_low','link lacks exact'),('link_wrong_high','link lacks exact'),('link_missing_low','link lacks exact'),('link_predicated','link lacks exact'),('link_early','link lacks exact'),('link_wrong_order','link lacks exact'),('link_collision','link lacks exact'),('callee_loop',None),('callee_forward_taken',None),('callee_forward_skipped',None),('callee_outside','undeclared control edge'),('callee_mid_packet','internal target is not a packet boundary'),('callee_indirect','undeclared control edge')]
    for index,(name,error) in enumerate(proof_cases,len(rows)):
        c=0x1000+index*0x800;f=c+0x200
        same=name in ('target_same_packet','target_same_packet_setup');continuation=c+(0x28 if same else 0x24)
        words=[3<<23|15<<18|1<<13|10<<9|0xf6,mvk(f,5),mvk(f>>16,5,True),5<<18|0x362]
        if same:words[-1]|=1;words.append(mv(7,5,2))
        delay=len(words);words += [0,mvk(continuation,3),0,0,mvk(continuation>>16,3,True)]
        linkpc=c+4*(len(words)-1)
        if name=='target_delay_overwrite':words[delay]=mv(7,5,2)
        if name=='target_wrong':words[1]=mvk(f+4,5)
        if name=='target_wrong_high':words[2]=mvk((f>>16)^1,5,True)
        if name=='register_B3':words[1]=mvk(f,3);words[2]=mvk(f>>16,3,True);words[3]=3<<18|0x362
        if name=='register_cross':words[1]=mvk(f,5,side=1);words[2]=mvk(f>>16,5,True,side=1);words[3]|=0x1000
        if name=='target_missing_low':words[1]=0
        if name=='target_predicated':words[1]|=6<<29 # [A0], unknown incoming
        if name=='target_late_load':words[1]=5<<23|6<<18|0x64|2 # LDW .D1T2 *A6,B5
        if name=='target_same_packet_setup':words[2]=0;words[4]=mvk(f>>16,5,True) # high half too late: sampled before call EP writes
        if name=='target_collision':words[1]|=1;words[2]=mv(7,5,2) # S2/L2 collide before call
        if name=='link_wrong_low':words[delay+1]=mvk(continuation+4,3)
        if name=='link_wrong_high':words[-1]=mvk((continuation>>16)^1,3,True)
        if name=='link_missing_low':words[delay+1]=0
        if name=='link_predicated':words[delay+1]|=6<<29
        if name=='link_wrong_order':words[delay+1],words[-1]=words[-1],words[delay+1]
        if name=='link_early':words[-2],words[-1]=words[-1],0
        if name=='link_collision':words[-1]|=1;words.append(3<<23|0xa358|2);continuation+=4;words[delay+1]=mvk(continuation,3)
        words += [mv(4,8),0,0,mv(4,9),3<<23|15<<18|1<<13|9<<9|0xe6,0x6000,0x8ca362]
        caller_return=c+4*(len(words)-1)
        callee=[mv(3,1,cross=True),0x8c0362,0,0,0,0,4<<23|3<<18|2<<13|0x570];ret=f+4
        if name.startswith('callee_'):
            # A0 counter: decrement with ADD -1; [A0] backward B sees old A0.
            callee=[mv(3,1,cross=True),mvk(3,0,side=1),0x1f<<13|0x58,branch(f+12,f+8)|(6<<29),0,0,0,0,0,0x8c0362,0,0,0,0,4<<23|3<<18|2<<13|0x570];ret=f+36
            if name.startswith('callee_forward'):
                callee[1]=mvk(1 if name.endswith('taken') else 0,0,side=1);callee[2]=0;callee[3]=branch(f+12,f+40)|(6<<29);callee[9:9]=[mvk(99,7,side=1)];ret=f+40
            if name=='callee_outside':callee[3]=branch(f+12,f+0x200)
            if name=='callee_mid_packet':callee[3]=branch(f+12,f+20);callee[4]=1
            if name=='callee_indirect':callee[3]=5<<18|0x362
        for k,word in enumerate(words):struct.pack_into(endian+'I',image,c-0x1000+k*4,word)
        for k,word in enumerate(callee):struct.pack_into(endian+'I',image,f-0x1000+k*4,word)
        row=dict(name=name,caller=c,caller_end=c+len(words)*4,callee=f,callee_end=f+len(callee)*4,call=c+12,link=linkpc,continuation=continuation,callee_return=ret,caller_return=caller_return,register_target=True,target_register='B3' if name=='register_B3' else 'A5' if name=='register_cross' else 'B5')
        if error:row['refused']=error
        rows.append(row)
    Path(sys.argv[1]).write_bytes(image);Path(sys.argv[2]).write_text(json.dumps(rows,indent=2)+'\n')
if __name__=='__main__':main()
