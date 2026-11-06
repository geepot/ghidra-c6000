#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Strict caller/store-tail scopes; IMAGE JSON [be]. TI assembled, no stock bytes."""
from pathlib import Path
import importlib.util,json,os,struct,subprocess,sys

def main():
 image_path,manifest_path=map(Path,sys.argv[1:3]);be=len(sys.argv)>3 and sys.argv[3]=='be';endian='>' if be else '<';image_path.parent.mkdir(parents=True,exist_ok=True)
 spec=importlib.util.spec_from_file_location('continuation_fixture',Path(__file__).with_name('pipeline-caller-continuation.py'));module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
 cases=[('owned',None),('unowned_tail',None),('unreachable_data',None),('stale_context',None),('callee_bad_hash','byte hash mismatch'),('caller_bad_hash','scope/continuation mismatch'),('entry_bad_hash','byte hash mismatch'),('wrong_language','language/callee identity'),('missing_unowned_tail','declared ownership'),('body_ends_inside_instruction','byte ownership'),('data_in_suffix','instruction overlaps defined data'),('first_B3_writer','unchanged entry B3'),('header_start','invalid physical instruction start'),('halfword_start','invalid physical instruction start'),('caller_target_spans','branch-target execute packet spans fetch packets'),('omitted_B4','E1 inventory mismatch'),('wrong_idle','source span/idle evidence mismatch'),('entry_suffix_data','instruction overlaps defined data'),('outside_callee_branch','callee branch leaves declared scope'),('callp_idle',None),('callp_stale_hazards','E1 inventory mismatch'),('callp_wrong_idle','source span/idle evidence mismatch')]
 cases += [('bnop5_idle_s1',None),('bnop5_idle_s2',None),('bnop5_wrong_idle','source span/idle evidence mismatch'),('bnop5_stale_hazards','E1 inventory mismatch')]
 lines=[];rows=[]
 for i,(name,error) in enumerate(cases):
  tag='ct_strict_'+name;at=0x1000+i*0x800;caller=at+0x200
  lines+=[' .sect "'+'.'+tag+'"',' .nocmp',tag+':',' '+('MVK.S2 1,B3' if name=='first_B3_writer' else 'MVK.S1 2,A1'),tag+'_loop:',' SUB.S1 A1,1,A1',' [A1] B.S2 '+tag+'_loop',' NOP 5',' B.S2 B3',' NOP 3',' STW.D1 B5,*A4[0]',' STW.D1 B4,*A4[1]']
  if name.startswith('callp_'):lines+=[' .sect ".'+tag+'_setup"',' .nocmp',tag+'_setup_target .set $-0x1e0',' CALLP.S2 '+tag+'_setup_target,B3',' || MV.L2 B11,B4']
  rows.append(dict(name=name,at=at,callee_end=at+32,caller=caller,caller_end=caller+8,owner=caller-32,setup_start=caller-32,final_packet=caller-4,setup_end=caller,packets=[caller,caller+4],accepted=error is None,error=error))
 binary=Path(os.environ.get('TI_C6000_BIN','/Applications/ti/ti-cgt-c6000_8.3.15/bin'));compiler=str(binary/'cl6x' if binary.is_dir() else binary)
 asm=image_path.with_suffix('.asm');obj=image_path.with_suffix('.obj');asm.write_text('\n'.join(lines)+'\n');result=subprocess.run([compiler,'-mv6740','--abi=eabi','-c',str(asm),'--output_file='+str(obj)],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True);image_path.with_suffix('.asm.log').write_text(result.stdout);assert result.returncode==0,result.stdout
 sections=module.object_sections(obj);image=bytearray(len(rows)*0x800)
 for row in rows:
  at=row['at'];name=row['name'];raw=sections['.ct_strict_'+name];image[at-0x1000:at-0x1000+len(raw)]=raw
  struct.pack_into('<I',image,row['caller']-0x1000+4,(4<<23)|(10<<18)|(10<<13)|0x1e42)
  row.update(trailing_idle=0,declared_writes=[])
  if name.startswith('callp_'):
   final=row['caller']-8;row.update(final_packet=final,trailing_idle=4 if name=='callp_wrong_idle' else 5,declared_writes=['B4'] if name=='callp_stale_hazards' else []);data=sections['.ct_strict_'+name+'_setup'];image[final-0x1000:final-0x1000+8]=data[:8]
  if name.startswith('bnop5_'):
   final=row['caller']-8;row.update(final_packet=final,trailing_idle=4 if name=='bnop5_wrong_idle' else 5,declared_writes=['B4'] if name=='bnop5_stale_hazards' else [])
   # SPRUFE8B F-18: fixed-five branch with an unsigned <<1 target.
   # The BNOP and NOP1 share the last payload word, then skip the header.
   struct.pack_into('<HHI',image,final-0x1000,0xc40a|int(name=='bnop5_idle_s2'),0x0c6e,0xe8009000)
  if name=='omitted_B4':struct.pack_into('<I',image,row['final_packet']-0x1000,(4<<23)|(9<<7)|0x2a)
  if name=='unreachable_data':row['callee_end']=at+0x40
  if name=='header_start':struct.pack_into('<I',image,at-0x1000+28,0xe0000000);row.update(at=at+28,callee_end=at+36)
  if name=='halfword_start':row['at']=at+2
  if name=='caller_target_spans':
   caller=row['caller']+28;row.update(caller=caller,caller_end=caller+8,setup_end=caller,final_packet=caller-4,packets=[caller]);struct.pack_into('<II',image,caller-0x1000,1,0)
  if name=='outside_callee_branch':
   old=struct.unpack_from('<I',image,at-0x1000+8)[0];word=(old&0xe0000000)|0x12|(((((at+128)-((at+8)&~31))>>2)&0x1fffff)<<7);struct.pack_into('<I',image,at-0x1000+8,word)
 if be:
  image=bytearray(b''.join(image[k:k+4][::-1] for k in range(0,len(image),4)))
  # Compact slots retain their physical halfword order in both languages.
  for row in rows:
   if row['name'].startswith('bnop5_'):struct.pack_into('>I',image,row['final_packet']-0x1000,0x0c6e<<16|0xc40a|int(row['name']=='bnop5_idle_s2'))
 image_path.write_bytes(image);manifest_path.write_text(json.dumps(rows,indent=2)+'\n')
if __name__=='__main__':main()
