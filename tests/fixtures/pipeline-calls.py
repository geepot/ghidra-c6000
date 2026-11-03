#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Sequential leaf calls, CALLP and saved return links; IMAGE JSON [be].
Independent synthetic fields: SPRUFE8B 3.5, 3.7, 3.8.10, 4.2.6, CALLP p.172,
B/register and BNOP/register, compact Scs10 Figure F-19. No firmware bytes.
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
 endian='>' if len(sys.argv)>3 else '<';image=bytearray(0x20000);rows=[]
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
 Path(sys.argv[1]).write_bytes(image);Path(sys.argv[2]).write_text(json.dumps(rows,indent=2)+'\n')
if __name__=='__main__':main()
