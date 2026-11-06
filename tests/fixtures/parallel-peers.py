#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Stock-free same-EP discovery fixtures. IMAGE CASES.json [be]."""
from pathlib import Path
import importlib.util,json,os,struct,subprocess,sys

def main():
 output,cases=map(Path,sys.argv[1:3]);big=len(sys.argv)>3 and sys.argv[3]=='be';output.parent.mkdir(parents=True,exist_ok=True)
 helper=Path(__file__).with_name('pipeline-caller-continuation.py')
 if not helper.exists():helper=Path(__file__).parents[2]/'plugin-fix/tests/fixtures/pipeline-caller-continuation.py'
 spec=importlib.util.spec_from_file_location('elf_fixture',helper);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
 asm=output.with_suffix('.asm');obj=output.with_suffix('.obj');asm.write_text(' .sect ".ct_opcodes"\n .nocmp\n B.S1 local_target\n || MVK.S2 7,B4\n NOP 5\n B.S2 B5\nlocal_target:\n NOP\n .sect ".ct_idle"\n .nocmp\n IDLE\n .sect ".ct_overlap"\n .nocmp\n LDW.D1T1 *-A27[16],A24\n')
 binary=Path(os.environ.get('TI_C6000_BIN','/Applications/ti/ti-cgt-c6000_8.3.15/bin'));compiler=str(binary/'cl6x' if binary.is_dir() else binary)
 result=subprocess.run([compiler,'-mv6740','--abi=eabi','-c',str(asm),'--output_file='+str(obj)],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True);output.with_suffix('.asm.log').write_text(result.stdout);assert result.returncode==0,result.stdout;sections=module.object_sections(obj);words=struct.unpack_from('<5I',sections['.ct_opcodes']);idle=struct.unpack_from('<I',sections['.ct_idle'])[0];overlap=struct.unpack_from('<I',sections['.ct_overlap'])[0]
 names=['full32','mixed16','nested_window','cross_fetch','cross_header','p0','data_start','data_suffix','instruction_suffix','foreign_owner','partial_owner','stale_context','opaque_peer','invalid_peer','already_defined','defined_partial_bridge','annotations','bound_cut','header_eight','oversized','anchor_partial_owner','late_data','compact_p0_tail','control_peer'];image=bytearray(len(names)*0x100);rows=[]
 for i,name in enumerate(names):
  at=0x1000+i*0x100;anchor=at;peer=at+4;width=4;expected=1 if name in ['full32','mixed16','nested_window','cross_fetch','cross_header','annotations'] else 0
  struct.pack_into('<I',image,at-0x1000,words[0]);struct.pack_into('<I',image,at-0x1000+4,words[1]);struct.pack_into('<I',image,at-0x1000+12,words[3])
  if name in ['mixed16','stale_context']:
   # SPRUFE8B H-9 NOP1 halfword; header Table3-16 marks word1 compact.
   struct.pack_into('<HH',image,at-0x1000+4,0x0c6e,0x0c6e);struct.pack_into('<I',image,at-0x1000+28,0xe0400000);width=2
  if name=='cross_fetch':
   anchor=at+28;peer=at+32;struct.pack_into('<I',image,anchor-0x1000,words[0]);struct.pack_into('<I',image,peer-0x1000,words[1])
  if name=='cross_header':
   anchor=at+26;peer=at+32;struct.pack_into('<HH',image,at-0x1000+24,0x0c6e,0xa1ef);struct.pack_into('<I',image,at-0x1000+28,0xe8002000);struct.pack_into('<I',image,peer-0x1000,words[1])
  if name in ['defined_partial_bridge','late_data']:
   struct.pack_into('<I',image,peer-0x1000,words[1]|1);struct.pack_into('<I',image,peer-0x1000+4,words[1])
  if name=='compact_p0_tail':
   anchor=at+24;peer=at+26;width=2;struct.pack_into('<HH',image,anchor-0x1000,0xa1ef,0x0c6e);struct.pack_into('<I',image,at-0x1000+28,0xe8000000)
  if name=='control_peer':struct.pack_into('<I',image,peer-0x1000,words[3])
  if name=='p0':struct.pack_into('<I',image,anchor-0x1000,words[0]&~1)
  if name=='instruction_suffix':struct.pack_into('<I',image,peer-0x1000,overlap)
  if name=='opaque_peer':struct.pack_into('<I',image,peer-0x1000,idle)
  if name=='invalid_peer':struct.pack_into('<I',image,peer-0x1000,0xffffffff)
  if name=='header_eight':
   for k in range(4,20,2):struct.pack_into('<H',image,at-0x1000+k,0x0c6e)
   struct.pack_into('<I',image,at-0x1000+28,0xe3c000fc)
  if name=='oversized':
   for k in range(1,9):struct.pack_into('<I',image,at-0x1000+k*4,1 if k<8 else 0)
  rows.append(dict(name=name,base=at,anchor=anchor,peer=peer,width=width,expected=expected,allowed_end=peer+width-(1 if name=='bound_cut' else 0)))
 # Wide reviewed bounds for chains intentionally rejected on length/layout, not bound first.
 for row in rows:
  if row['name'] in ['defined_partial_bridge','late_data']:row['allowed_end']=row['peer']+8
  if row['name'] in ['header_eight','oversized','invalid_peer']:row['allowed_end']=row['anchor']+64
 if big:image=b''.join(image[i:i+4][::-1] for i in range(0,len(image),4))
 output.write_bytes(image);cases.write_text(json.dumps(rows,indent=2)+'\n')
if __name__=='__main__':main()
