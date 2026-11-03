#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Synthetic return scheduling from SPRUFE8B 3.5, 4.2.6 and B/BNOP diagrams.

IMAGE CASES.tsv [be]. Expected windows are hand-counted bytes. Each case
ends with a guard store that must not execute as part of the return.
"""
from pathlib import Path
import struct,sys
import compact_order

compact_order.big_endian_on_exit()
B3=(3<<18)|0x362
BNOP=B3|(1<<23)
def stw(index=0,p=False):return 0x274|(4<<18)|(3<<23)|(index<<13)|int(p)
def nop(cycles):return (cycles-1)<<13
def mvk_b3(value):return 0x2a|(3<<23)|((value&0xffff)<<7)
CASES=[
 ('irp_five_stores',[0x001800e2]+[stw(i) for i in range(5)]+[stw(7)],20,31,0),
 ('nrp_parallel_store',[0x001c00e3,stw(),nop(5),stw(7)],8,1,0),
 ('parallel_store',[B3|1,stw(),nop(5),stw(7)],8,1,0),
 ('five_scalar_delay_stores',[B3]+[stw(i) for i in range(5)]+[stw(7)],20,31,0),
 ('bnop5_parallel_store',[BNOP|(5<<13)|1,stw(),stw(7)],4,1,0),
 ('bnop4_rint',[BNOP|(4<<13),0x10006000,stw(7)],4,0,1),
 ('nop5_fills_window',[B3,nop(5),stw(7)],4,0,0),
 ('target_sampled_before_tail',[B3,mvk_b3(0x1234),stw(),nop(3),stw(7)],12,1,0),
 ('same_count_parallel_nops',[B3|1,nop(3)|1,nop(3),stw(),nop(3),stw(7)],16,1,0),
 ('parallel_nop_covers_four_slots',[B3|1,nop(5),stw(),stw(7)],8,1,0),
 ('parallel_tail_and_five_cycles',[B3|1,stw(0,True),stw(1)]+[stw(i) for i in range(2,7)]+[stw(7)],28,127,0),
]
def main():
 image,manifest=map(Path,sys.argv[1:3]);endian='>' if len(sys.argv)>3 else '<';data=bytearray(0x100*len(CASES))
 with manifest.open('w') as rows:
  for i,(name,words,delay,mask,rint) in enumerate(CASES):
   for k,w in enumerate(words):struct.pack_into(endian+'I',data,i*0x100+k*4,w)
   rows.write(f'{0x1000+i*0x100:x}\t{name}\t{delay}\t{mask:x}\t{rint}\t4\n')
 # BNOP companions are single-cycle NOP 1 (H-9 count is encoded minus one).
 # A multicycle NOP alongside BNOP is forbidden by SPRUFE8B 3.8.10.
 # Compact mixed-width and cross-fetch execute packets. Table 3-16 keeps
 # header p-bits clear for 32-bit words, which use their own bit zero.
 extra=[]
 for name,count,cross,rint in [('compact_mixed_parallel',5,False,0),('compact_rint_after_bnop4',4,False,1),('compact_cross_fetch',5,True,0)]:
  index=len(CASES)+len(extra);base=0x1000+index*0x100;blob=bytearray(0x100)
  offset=26 if cross else 0;entry=base+offset
  compact_bnop=0x6f|(3<<7)|(count<<13)
  if cross:
   struct.pack_into(endian+'H',blob,24,0x0c6e);struct.pack_into(endian+'H',blob,26,compact_bnop)
   struct.pack_into(endian+'I',blob,28,0xe0000000|(1<<(21+6))|(1<<13))
   for k,w in enumerate([stw(0,True),stw(1),stw(7)]):struct.pack_into(endian+'I',blob,32+4*k,w)
   delay,mask=12,3
  else:
   struct.pack_into(endian+'H',blob,0,compact_bnop);struct.pack_into(endian+'H',blob,2,0x0c6e)
   if rint:
    struct.pack_into(endian+'I',blob,4,0x10006000);struct.pack_into(endian+'I',blob,8,stw(7));delay,mask=6,0;pb=1
   else:
    struct.pack_into(endian+'I',blob,4,stw(0,True));struct.pack_into(endian+'I',blob,8,stw(1));struct.pack_into(endian+'I',blob,12,stw(7));delay,mask=10,3;pb=3
   struct.pack_into(endian+'I',blob,28,0xe0000000|(1<<21)|pb)
  extra.append((entry,name,delay,mask,rint,blob))
 with manifest.open('a') as rows:
  for entry,name,delay,mask,rint,blob in extra:
   data.extend(blob);rows.write(f'{entry:x}\t{name}\t{delay}\t{mask:x}\t{rint}\t2\n')
 # PROT applies even to a 32-bit load in a header-based packet. Its four
 # implicit NOPs fill the five delay cycles, so the guard must not execute.
 base=0x1000+len(data);blob=bytearray(0x100)
 for k,w in enumerate([B3,0x264|(4<<18)|(5<<23),stw(7)]):struct.pack_into(endian+'I',blob,k*4,w)
 struct.pack_into(endian+'I',blob,28,0xe0100000)
 data.extend(blob)
 with manifest.open('a') as rows:rows.write(f'{base:x}\tprotected_word_load\t4\t0\t0\t4\n')
 # A preceding NOP in the same EP contributes its full issue span.
 # These functions begin at the NOP; the tested branch is the next word.
 for count,mask,delay in [(5,3,8),(6,1,4)]:
  base=0x1000+len(data);blob=bytearray(0x100)
  for k,w in enumerate([nop(count)|1,B3|1,stw(0),stw(1),stw(7)]):struct.pack_into(endian+'I',blob,k*4,w)
  data.extend(blob)
  with manifest.open('a') as rows:rows.write(f'{base+4:x}\tprefix_nop{count}\t{delay}\t{mask:x}\t0\t4\t4\n')
 image.write_bytes(data)
if __name__=='__main__':main()
