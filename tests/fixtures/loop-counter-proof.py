#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exact prefix constants and unknown fallbacks, SPRUFE8B 3.7,7.4.3,7.9. IMAGE JSON [be]."""
from pathlib import Path
import json,struct,sys


def main():
    image=bytearray(0x1800);rows=[];endian='>' if len(sys.argv)>3 and sys.argv[3]=='be' else '<'
    def seed(register,value):return (register<<23)|((value&0xffff)<<7)|0x2a
    def prefix(register=5,value=325):
        # Independently checked with TI assembler: the ADDs overwrite the seed
        # register, but parallel SUB still captures its OLD value.
        return [seed(register,value)]+([0x0291005b,0x03108943,0x0217e1a2]
            if register==5 else [0x0310805b,0x02910943,0x021be1a2])
    def body(unit=35):return [0x00842940 if t==unit else 0x34000 if t==46 else 0 for t in range(47)]
    tail=[0x0100a040]+[0x10000]*10+[0xc0362,0x8000]
    def emit(name,pre,inputs,expected=None,kind='SPLOOPD',compile_only=False,unit=35):
        entry=0x1000+len(rows)*0x200
        start=[0x0283a001,0x069003a2] if kind=='SPLOOPD' else [0x069003a2,0x4000,0x02838000]
        words=pre+start+body(unit)+tail
        for k,word in enumerate(words):struct.pack_into(endian+'I',image,entry-0x1000+4*k,word)
        row=dict(name=name,entry=entry,input=inputs,expected=expected or {})
        if expected is None:row['refused']='functional-unit collision'
        if compile_only:row['compile_only']=True
        rows.append(row)
    expected={'A1':325,'A2':5,'ILC':0,'TSR':0}
    for register in [5,6]:
        for incoming in [0,0xffffffff]:
            emit(f'parallel_old_B{register}_{incoming:08x}',prefix(register),{'B4':incoming},expected)
    emit('sploop_initial_and_loading_proof',prefix(),{'B4':0},dict(expected,A1=324),kind='SPLOOP')
    # An unknown counter may stop the loop before SPKERNEL is loaded (early exit). Program fetch
    # then resumes only when the buffer is idle (SPRUFE8B 7.9.4, 7.12.2), so the tail no longer
    # meets the body's t=35 unit and the schedule is valid on every counter path. The same holds
    # for a small known counter, an unknown seed predicate and a seed a late load overwrites.
    emit('unknown_counter_early_exit_waits_for_idle',[],{'ILC':324,'B4':324},{'TSR':0})
    emit('small_known_counter_early_exit_waits_for_idle',prefix(value=7),{'B4':0},{'TSR':0})
    predicated=prefix();predicated[0]|=0xc0000000
    emit('unknown_predicate_early_exit_waits_for_idle',predicated,{'B4':0,'A0':1},{'TSR':0})
    proven_false=prefix();proven_false[1:1]=[0x28,seed(5,7)|0xc0000000]
    emit('false_predicate_does_not_clobber_constant',proven_false,{'B4':0},expected)
    delayed=[0x02a00266,0x2000,seed(5,325),0]+prefix()[1:]
    emit('late_load_early_exit_waits_for_idle',delayed,{'B8':0x8000,'B4':0},{'TSR':0},compile_only=True)
    # A genuine collision that must stay refused, so the check is still tested. This is the full
    # counter (325) of the accepted parallel_old rows -- a normal exit that loads the buffer and
    # runs to completion -- but with the body's .D1 unit one bundle earlier (t=30). Fetch resumes
    # at the SPKERNEL delay on a normal exit (SPRUFE8B 7.9.4), so the post-loop MVK.D1 issues while
    # that ADD.D1 is still draining and the units truly conflict; at t=35 the same exit clears it.
    emit('loaded_exit_unit_collision',prefix(),{'B4':0},unit=30)
    Path(sys.argv[1]).write_bytes(image);Path(sys.argv[2]).write_text(json.dumps(rows,indent=2)+'\n')


if __name__=='__main__':main()
