#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""CALLP executes its packet companions and links to the next execute packet.

SPRUFE8B 3.5, 3.10.2.3, CALLP execution; SLEIGH 7.11 inst_next semantics.
IMAGE CASES.tsv [be]. Stores intentionally read the old link register.
"""
from pathlib import Path
import struct,sys
import compact_order

compact_order.big_endian_on_exit()

def main():
 image,manifest=map(Path,sys.argv[1:3]);e='>' if len(sys.argv)>3 else '<';data=bytearray(0x600)
 with manifest.open('w') as rows:
  for i,(name,compact,parallel,side) in enumerate([('word_single_s1',False,False,0),('word_single_s2',False,False,1),('word_parallel_s1',False,True,0),('word_parallel_s2',False,True,1),('compact_mixed_s1',True,True,0),('compact_mixed_s2',True,True,1)]):
   base=0x1000+i*0x100;off=i*0x100;target=base+0x80;link='B3' if side else 'A3'
   # STW source bank is selected by bit 1; the address base stays A4 (.D1).
   store=0x274|(4<<18)|(3<<23)|(side<<1)
   if compact:
    word=0x1a|side|((0x80//4)<<6)
    struct.pack_into(e+'H',data,off,word);struct.pack_into(e+'H',data,off+2,0x0c6e) # NOP 1: CALLP cannot share a multicycle NOP
    struct.pack_into(e+'I',data,off+4,store);struct.pack_into(e+'I',data,off+8,store|(7<<13))
    struct.pack_into(e+'I',data,off+28,0xe0000000|(1<<21)|(1<<15)|3);nextpc=base+8;delay=6
   else:
    word=0x10000010|(side<<1)|((0x80//4)<<7)|int(parallel)
    struct.pack_into(e+'I',data,off,word)
    if parallel:struct.pack_into(e+'I',data,off+4,store)
    nextpc=base+(8 if parallel else 4);delay=4 if parallel else 0
    struct.pack_into(e+'I',data,off+nextpc-base,store|(7<<13))
   rows.write(f'{base:x}\t{name}\t{target:x}\t{nextpc:x}\t{link}\t{int(parallel)}\t{delay}\n')
 image.write_bytes(data)
if __name__=='__main__':main()
