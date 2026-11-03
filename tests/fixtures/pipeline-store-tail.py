#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Contracted E3 stores after B3 return: IMAGE CASES.json [be].
SPRUFE8B 3.5, 3.9.2, 4.2.3/4.2.6 and Figures C-8..C-15.
TI assembles synthetic full32 instructions; compact fields and byte oracles
are independent. No firmware bytes are distributed.
"""
import importlib.util,json,struct,subprocess,sys
from pathlib import Path

FORMATS=[('B',1,1,1,0),('H',2,3,1,0),('W',4,0,0,0),('DW',8,4,0,0),('NW',4,6,1,0),('NDW',8,4,0,1)]

def main():
 image_path,manifest_path=map(Path,sys.argv[1:3]);big=len(sys.argv)>3;endian='>' if big else '<';order='big' if big else 'little'
 spec=importlib.util.spec_from_file_location('continuation',Path(__file__).with_name('pipeline-caller-continuation.py'));module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
 rows=[];lines=[]
 def emit(fmt,side=0,age=1,predicate=None,truth=0,variant='plain',amode=0):
  suffix,size,dsz,sz,na=fmt;bank='AB'[side];index=len(rows);tag='ct_store_tail_'+str(index);entry=0x1000+index*0x100
  alias=variant=='alias';compact=variant=='compact';base=0x805f if amode else 0x8040;data=4 if alias else 0 if compact else 6
  low=base if alias else 0x89abcdef;value=low|(0x12345678<<32) if size==8 else low
  count=-size if alias else size;mask=31 if amode==1 else 63 if amode==2 else 0xffffffff
  nextbase=(base&~mask)|((base+count)&mask);access=nextbase if alias else base
  enabled=predicate is None or (truth==0 if predicate=='!A0' else truth!=0)
  inputs={'B3':0x9000,'AMR':(4<<16)|(5<<21)|(amode<<(8*side)),'CSR':0x2468,'A9':0xabcdef12,f'{bank}8':0xdeadbeef,f'{bank}4':base,f'{bank}{data}':low}
  if size==8:inputs[f'{bank}{data+1}']=0x12345678
  if predicate is not None:inputs['A0']=truth
  memory=bytearray([0x5a]*256)
  if enabled:
   for k,byte in enumerate((value&((1<<(size*8))-1)).to_bytes(size,order)):
    address=(access&~mask)|((access+k)&mask) if suffix in ('NW','NDW') else access+k
    memory[address-0x8000]=byte
  expected=dict(inputs);expected[f'{bank}4']=nextbase if enabled else base
  if variant=='capture':expected[f'{bank}{data}']=0xdeadbeef
  expected['PC']=0x9000
  prefix='' if predicate is None else '['+predicate+'] '
  source=f'{bank}{data+1}:' if size==8 else '';source+=f'{bank}{data}'
  address=('*--' if alias else '*')+bank+'4'+('' if alias else '++')+'[1]'
  body=[' B.S2 B3',' NOP '+str(4 if age==1 else 3),' '+prefix+'ST'+suffix+f'.D{side+1} '+source+','+address]
  if variant=='capture':body+=[' || MV.L'+str(side+1)+' '+bank+'8,'+bank+str(data)]
  if age==2:body+=[' NOP']
  body+=[' MVK.S1 0x55,A9',' NOP 5']
  lines.extend([' .sect ".'+tag+'"',' .nocmp',tag+':']+body)
  rows.append(dict(name=f'{suffix}_{side}_{age}_{predicate}_{truth}_{variant}_{amode}',tag=tag,entry=entry,size=size,age=age,compact=compact,dsz=dsz,sz=sz,na=na,data=data,side=side,input=inputs,expected=expected,memory=memory.hex(),enabled=enabled,advances=2))
 for fmt in FORMATS:
  for side in (0,1):
   for age in (1,2):
    for predicate,truth in [(None,0),('A0',0),('A0',1),('!A0',0),('!A0',1)]:emit(fmt,side,age,predicate,truth)
    emit(fmt,side,age,variant='compact')
   emit(fmt,side,variant='capture');emit(fmt,side,variant='alias')
   if fmt[0] in ('NW','NDW'):
    for mode in (1,2):emit(fmt,side,amode=mode)
 # Mixed pending ages must mature on distinct idle advances.
 for paired in (False,True):
  tag='ct_store_tail_'+str(len(rows));entry=0x1000+len(rows)*0x100
  inputs={'B3':0x9000,'AMR':0,'CSR':0x2468,'A4':0x8040,'A6':0x89abcdef,'A7':0x12345678,'A9':0xabcdef12}
  middle=bytearray([0x5a]*256);memory=middle.copy();expected=dict(inputs,PC=0x9000)
  if paired:
   middle[64:66]=(0xcdef).to_bytes(2,order);memory=middle.copy();memory[66]=0x78;expected['A4']=0x8043
   body=[' B.S2 B3',' NOP 3',' STH.D1 A6,*A4++[1]',' STB.D1 A7,*A4++[1]'];ages=[2,1]
  else:body=[' B.S2 B3',' NOP 5'];ages=[]
  lines.extend([' .sect ".'+tag+'"',' .nocmp',tag+':']+body+[' MVK.S1 0x55,A9'])
  rows.append(dict(name='paired_stores' if paired else 'empty_tail',tag=tag,entry=entry,age=1 if paired else 2,ages=ages,input=inputs,expected=expected,memory=memory.hex(),middle_memory=middle.hex(),enabled=True,advances=2))
 # Predicate is overwritten in the same E1 as store issue, never resampled at E3.
 emit(FORMATS[0],predicate='A0',truth=1,variant='predicate_capture')
 rows[-1]['expected']['A0']=0
 # Insert the peer before this function's guard instructions.
 guard=lines.index(' MVK.S1 0x55,A9',len(lines)-4)
 lines.insert(guard,' || MVK.L1 0,A0')
 for name,body,error in [
  ('short_budget',[' B.S2 B3',' NOP 4',' STB.D1 A6,*A4'],'idle budget is too short'),
  ('load_tail',[' B.S2 B3',' NOP 4',' LDW.D1 *A4,A6'],'only pending E3 stores'),
  ('arithmetic_tail',[' B.S2 B3',' NOP 4',' MPYLI.M1 A6,A7,A9:A8'],'only pending E3 stores'),
  ('control_tail',[' B.S2 B3',' NOP 4',' B.S1 $'],'unresolved control effects')]:
  tag='ct_store_tail_'+str(len(rows));entry=0x1000+len(rows)*0x100;lines.extend([' .sect ".'+tag+'"',' .nocmp',tag+':']+body);rows.append(dict(name=name,tag=tag,entry=entry,error=error,advances=1 if name=='short_budget' else 2))
 image_path.parent.mkdir(parents=True,exist_ok=True);asm=image_path.with_suffix('.asm');obj=image_path.with_suffix('.obj');asm.write_text('\n'.join(lines)+'\n')
 r=subprocess.run(['/Applications/ti/ti-cgt-c6000_8.3.15/bin/cl6x','-mv6740','--abi=eabi','-c',str(asm),'--output_file='+str(obj)],capture_output=True,text=True);image_path.with_suffix('.asm.log').write_text(r.stdout+r.stderr);assert r.returncode==0,r.stdout+r.stderr
 sections=module.object_sections(obj);image=bytearray(len(rows)*256)
 for row in rows:
  at=row['entry']-0x1000;raw=sections['.'+row['tag']];assert len(raw)<128;image[at:at+len(raw)]=raw
  if big:
   image[at:at+len(raw)]=b''.join(raw[k:k+4][::-1] for k in range(0,len(raw),4))
  if row.get('compact'):
   # Manual compact postincrement, data RS=0, count=1, pointer A4/B4.
   word=0xc00|row['side']<<12|row['data']<<4|row['na']<<4|row['sz']<<9|4|row['side']
   struct.pack_into(endian+'I',image,at+8,0x0c6e<<16|word)
   struct.pack_into(endian+'I',image,at+28,0xe0800010|row['dsz']<<16)
 image_path.write_bytes(image);manifest_path.write_text(json.dumps(rows,indent=2)+'\n');print('store-tail cases',len(rows))
if __name__=='__main__':main()
