#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Sequential leaf calls, CALLP and saved return links; IMAGE JSON [be].
Independent synthetic fields: SPRUFE8B 3.5, 3.7, 3.8.10, 4.2.6, CALLP p.172,
B/register and BNOP/register, compact Scs10 Figure F-19, a load disabled at issue still
in flight when the return lands, complementary writers across a branch that decides
their predicate, and predicate facts from predicated writes and across a backward jump.
No firmware bytes.
"""
from pathlib import Path
import json,struct,sys
import compact_order

compact_order.big_endian_on_exit()

def mv(src,dst,side=1,cross=False):return dst<<23|src<<18|0xfd8|(side-1)<<1|int(cross)<<12
def mvk(value,dst,side=1,high=False):return dst<<23|(value&0xffff)<<7|(0x68 if high else 0x28)|(side-1)<<1
def branch(pc,target,side=1):return 0x10|((target-(pc&~31))>>2&0x1fffff)<<7|(side-1)<<1
def bnop(src=3,cross=False):return 0x800362|src<<18|5<<13|int(cross)<<12

def main():
 endian='>' if len(sys.argv)>3 else '<';image=bytearray(0x40000);rows=[]
 def add(name,mode='callp',side=2,variant='',error=None):
  c=0x1000+len(rows)*0x800;f=c+0x200;g=c+0x300;words=[];helper=[];sites=[];expected={'A0':0x9000,'PC':0x9000,'B15':0x8100,'A9':0,'B9':0}
  if mode=='ordinary':
   words=[mv(3,0,cross=True),bnop(0,True)]
   if variant=='overwrite':words.insert(1,mvk(0,0))
   if variant=='conditional':words[0]|=6<<29
   if variant=='same_packet':words[0]|=1
   if variant=='late':words[0]=0<<23|6<<18|0x64;words.insert(1,4<<13) # unknown E5 LDW to A0
   if variant=='copy_chain':words=[mv(3,8,cross=True),mv(8,0),bnop(0,True)];expected['A8']=0x9000
   if variant=='delay_overwrite':words=[mv(3,0,cross=True),0<<18|0x1362,mvk(0,0),0,0,0,0];expected['A0']=0
   if variant=='unknown':words=[bnop(0,True)]
   if variant=='disabled_clobber':words=[mv(3,0,cross=True),mvk(0,1),mvk(0,0)|(4<<29),bnop(0,True)]
   if variant=='delay_late_overwrite':words=[mv(3,0,cross=True),0<<18|0x1362,0<<23|4<<18|0x64,0,0,0,0];expected['A0']=0
   row=dict(name=name,mode=mode,caller=c,caller_end=c+len(words)*4,sites=[],expected=expected)
  elif mode=='multi':
   # Save original return in A0, call a leaf twice (or two distinct leaves).
   expected.update(A4=0x8200,B3=c+0x38)
   words=[mv(3,0,cross=True),mvk(f,5,2),mvk(f>>16,5,2,True),5<<18|0x362,mvk(c+0x24,3,2),mvk((c+0x24)>>16,3,2,True),0,0,0]
   # Reuse B5, proving its constant survives the first callee; clobber controls refuse.
   second=f if variant!='distinct' else g
   if variant=='distinct':words += [mvk(g,5,2),mvk(g>>16,5,2,True)]
   call2=c+len(words)*4;cont2=call2+24
   words += [5<<18|0x362,mvk(cont2,3,2),mvk(cont2>>16,3,2,True),0,0,0,bnop(0,True)]
   expected['B3']=cont2
   # A store in the final return-delay EP survives into the caller each time.
   helper=[3<<18|0x362,3<<13,6<<23|4<<18|0x274]
   ret=f
   if variant=='clobber_target':helper=[mv(7,5,2),3<<18|0x362,3<<13,6<<23|4<<18|0x274];ret=f+4
   if variant=='late_target':helper=[3<<18|0x362,2<<13,5<<23|4<<18|0x66,6<<23|4<<18|0x274] # late LDW B5
   if variant=='clobber_alias':helper=[mvk(0,0),3<<18|0x362,3<<13,6<<23|4<<18|0x274];ret=f+4
   sites=[dict(call=c+12,link=c+20,continuation=c+36,callee=f,callee_end=f+len(helper)*4,callee_return=ret),dict(call=call2,link=call2+8,continuation=cont2,callee=second,callee_end=second+len(helper)*4,callee_return=ret+(second-f))]
   row=dict(name=name,mode=mode,caller=c,caller_end=c+len(words)*4,caller_return=cont2,sites=sites,expected=expected,memory_word=0x12345678)
  else:
   linkreg=3;call=c+4;compact=variant.startswith('compact');peer=variant in ('peer_after','peer_both');before=variant in ('peer_before','peer_both')
   words=[mv(3,0,cross=True)|(1 if before else 0),branch(call,f,side)|0x10000000]
   if peer:words[1]|=1;words.append(mv(7,9,2));expected['B9']=0x55
   continuation=c+len(words)*4
   if variant=='header_seam':words=[mv(3,0,cross=True),0,0,0,0,0,branch(c+24,f,side)|0x10000000,0xe0000000];call=c+24;continuation=c+32
   if compact:words=[mv(3,0,cross=True),0,bnop(0,True)];call=c+4;continuation=c+6
   else:words.append(bnop(0,True))
   caller_return=c+8 if compact else continuation
   if variant=='collision':words[1]|=1;words.insert(2,mv(7,3,side));continuation+=4;caller_return=continuation
   if variant=='nop_conflict':words[1]|=1;words.insert(2,1<<13);continuation+=4;caller_return=continuation
   if variant=='late_link':words=[3<<23|4<<18|0x64|(side-1)<<1,mv(3,0,cross=True),branch(c+8,f,side)|0x10000000,bnop(0,True)];call=c+8;continuation=c+12;caller_return=continuation
   if variant=='pending_branch':words=[branch(c,f+0x40),branch(c+4,f,side)|0x10000000,bnop(0,True)];call=c+4;continuation=c+8;caller_return=continuation
   helper=[bnop(3,side==1)]
   if variant=='clobber_saved':helper=[mvk(0,0),bnop(3,side==1)]
   if variant=='nonlocal_return':helper=[bnop(0,True)]
   ret=f+(4 if variant=='clobber_saved' else 0)
   sites=[dict(call=call,link=call,continuation=continuation,callee=f,callee_end=f+len(helper)*4,callee_return=ret)]
   expected['A3' if side==1 else 'B3']=continuation
   row=dict(name=name,mode='callp' if mode!='closed' else 'closed',caller=c,caller_end=c+len(words)*4,caller_return=caller_return,sites=sites,expected=expected)
  for k,w in enumerate(words):struct.pack_into(endian+'I',image,c-0x1000+4*k,w)
  for site in sites:
   for k,w in enumerate(helper):struct.pack_into(endian+'I',image,site['callee']-0x1000+4*k,w)
  if mode not in ('multi','ordinary') and variant.startswith('compact'):
   # Compact side/return selector is bit 0; scst10 bits 6..15.
   struct.pack_into(endian+'HH',image,c-0x1000+4,((f-(call&~31))>>2&0x3ff)<<6|0x1a|(side-1),0x0c6e)
   struct.pack_into(endian+'I',image,c-0x1000+28,0xe0408000|(0x80000 if variant=='compact_rs' else 0))
  if error:row['refused']=error
  rows.append(row)
 for side in (1,2):
  for mode in ('callp','closed'):
   for variant in ('','peer_before','peer_after','peer_both','header_seam','compact','compact_rs'):add(f'{mode}_s{side}_{variant}',mode,side,variant)
  for variant,error in [('collision','simultaneous'),('nop_conflict','multicycle NOP'),('pending_branch','CALLP requires'),('clobber_saved','unresolved register branch'),('late_link','unresolved register branch'),('nonlocal_return','unresolved register branch')]:add(f'callp_s{side}_{variant}',side=side,variant=variant,error=error)
 for variant,error in [('',None),('copy_chain',None),('delay_overwrite',None),('disabled_clobber',None),('delay_late_overwrite',None),('unknown','unresolved register branch'),('overwrite','unresolved register branch'),('conditional','unresolved register branch'),('same_packet','unresolved register branch'),('late','unresolved register branch')]:add('saved_link_'+(variant or 'plain'),'ordinary',variant=variant,error=error)
 for variant,error in [('',None),('distinct',None),('clobber_target','target lacks exact'),('late_target','target lacks exact'),('clobber_alias','unresolved register branch')]:add('multi_'+(variant or 'reuse'),'multi',variant=variant,error=error)
 def plain(name,words,expected,inputs=None,memory=None,at=None):
  # words at the entry, more blocks at offsets from it
  c=0x1000+len(rows)*0x800;blocks={0:words,**(at or {})}
  for offset,block in blocks.items():
   for k,w in enumerate(block):struct.pack_into(endian+'I',image,c+offset-0x1000+4*k,w)
  row=dict(name=name,mode='plain',caller=c,caller_end=c+max(o+len(b)*4 for o,b in blocks.items()),sites=[],expected=expected,input=inputs or {})
  if memory:row['memory']={str(k):v for k,v in memory.items()}
  rows.append(row)
 # [A1] LDW is issued after A1 was cleared, one cycle before the return lands: disabled at
 # issue, it does nothing more, so the return doesn't leave it pending.
 plain('dead_flight_at_return',[mvk(0,1)|1,3<<18|0x362,2<<13,4<<29|3<<23|4<<18|0x64,0],{'A3':0,'A1':0,'PC':0x9000},memory={0x8200:0x1234})
 # The same load issued in the packet the return lands in: its predicate is sampled at issue.
 plain('dead_flight_in_return_packet',[mvk(0,1)|1,3<<18|0x362,3<<13,4<<29|3<<23|4<<18|0x64,0],{'A3':0,'A1':0,'PC':0x9000},memory={0x8200:0x1234})
 # [!A0] LDW *B10,B0 in cycle 0 and [A0] MVK 0,B0 in cycle 4 write B0 in the same cycle, on
 # complementary senses of A0, with [!A0] B skip in cycle 1 forking the facts on A0 while the
 # load is in flight: on each path one of the two is known not to run.
 for a0 in (1,0):
  c=0x1000+len(rows)*0x800;skip=c+0x40
  ldw=6<<29|1<<28|10<<18|0x64|1<<7|1<<1  # [!A0] LDW.D2T2 *B10,B0
  words=[ldw,6<<29|1<<28|branch(c+4,skip),0,0,6<<29|mvk(0,0,2),0,mvk(1,9),bnop(3)];words+=[0]*(16-len(words))+[bnop(3)]
  plain(f'fork_collision_a{a0}',words,{'B0':0 if a0 else 0x77,'A9':1,'PC':0x9000},{'A0':a0,'B10':0x8200},memory={0x8200:0x77})
 def ret(pred=0):return pred|3<<18|0x362
 def predicate_write(name,a1,b0):
  # [A1] MVK 0,B0 ties B0 to A1: where A1 held, B0 is 0 and [B0] B y can't follow the [A1]
  # return; where it didn't, the return isn't taken. Without the split the return could
  # land with y pending.
  c=0x1000+len(rows)*0x800;a1p=4<<29
  words=[mvk(0,0,2)|a1p,ret(a1p),branch(c+8,c+32)|1<<29,3<<13,0,mvk(7,9),bnop(3)]
  plain(name,words,{'A9':0 if a1 else 2 if b0 else 7,'B0':0 if a1 else b0,'PC':0x9000},{'A1':a1,'B0':b0},at={32:[mvk(2,9),bnop(3)]})
 for a1,b0 in [(1,1),(0,1),(0,0)]:predicate_write(f'predicate_write_a{a1}_b{b0}',a1,b0)
 # [A1] MVK 0,B0 that nothing reads: the split only doubles the states after it. Over a
 # lowered state cap it compiles again without the split.
 plain('unrefined_retry',[mvk(0,0,2)|4<<29,mvk(1,8),mvk(2,7),ret(),4<<13],{'A8':1,'A7':2,'PC':0x9000},{'A1':1})
 rows[-1]['state_cap']=12  # 17 states with the split
 # The same under the store-tail contract, which retries the same way.
 plain('unrefined_retry_store_tail',[mvk(0,0,2)|4<<29,mvk(1,8),mvk(2,7),ret(),4<<13],{'A8':1,'A7':2,'PC':0x9000},{'A1':1})
 rows[-1]['state_cap']=12;rows[-1]['store_tail']=True
 # Over a lowered state cap (33 states, cap 20), and the merged retries lose the fact it needs:
 # only the last retry, refined with the caps raised, compiles it.
 predicate_write('relaxed_retry_after_lost_fact',1,1);rows[-1]['state_cap']=20
 # [B0] B join: the paths meet at join knowing B0 nonzero and zero, and B0 is overwritten
 # three packets later without being read. The dead fact is dropped at join, so the paths
 # share their states from there.
 for b0 in (1,0):
  c=0x1000+len(rows)*0x800
  plain(f'dead_fact_merges_b{b0}',[branch(c,c+0x40)|1<<29,4<<13,mvk(1,9)],{'A9':0 if b0 else 1,'A8':2,'A7':3,'B0':0,'PC':0x9000},{'B0':b0},
        at={0x40:[mvk(2,8),mvk(3,7),mvk(0,0,2),bnop(3)]})
  rows[-1]['max_states']=34  # 37 when the dead fact is kept
 # [B0] B join, or MVK 1,A9 and B join: both paths arrive drained, knowing B0 nonzero and
 # zero, and [B0] MVK 5,A6 after join still reads it. Over a lowered cap only the retry that
 # forgets facts where the pipeline is drained compiles it; B0 is then tested at run time.
 for b0 in (1,0):
  c=0x1000+len(rows)*0x800
  plain(f'merged_at_drained_join_b{b0}',[branch(c,c+0x40)|1<<29,4<<13,mvk(1,9),branch(c+12,c+0x40),4<<13],
        {'A9':0 if b0 else 1,'A8':2,'A7':3,'A6':5 if b0 else 0x12345678,'PC':0x9000},{'B0':b0},
        at={0x40:[mvk(2,8),mvk(3,7),0,mvk(5,6)|1<<29,bnop(3)]})
  rows[-1]['state_cap']=rows[-1]['max_states']=30  # 33 refined; merged 28
 assert len(rows)*0x800<=len(image)
 Path(sys.argv[1]).write_bytes(image);Path(sys.argv[2]).write_text(json.dumps(rows,indent=2)+'\n')
if __name__=='__main__':main()
