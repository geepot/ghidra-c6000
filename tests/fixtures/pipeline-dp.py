#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Independent DP temporal cases from SPRUFE8B 4.2.7--4.2.16. IMAGE CASES.json [be]."""
from pathlib import Path
import json, re, struct, sys


def main():
    image=bytearray(0x2000); rows=[]; endian='>' if len(sys.argv)>3 and sys.argv[3]=='be' else '<'
    source=(Path(__file__).resolve().parents[2]/'data/languages/c6000_decode.sinc').read_text().splitlines()
    def opcode(name,unit='L',side=1,a=0,b=2,d=4):
        line=next(s for s in source if f'"{name}.{unit}{side}" ' in s)
        fixed={int(bit):int(value) for bit,value in re.findall(r'\bi(\d+)=(\d)\b',line)}
        return sum(value<<bit for bit,value in fixed.items()) | (a<<13) | (b<<18) | (d<<23)
    def mv(src,dst):return (dst<<23)|(src<<18)|0x58
    def mvd(src,dst):return (dst<<23)|(src<<18)|0x8f0
    def mvkh(value,dst):return (dst<<23)|((value&0xffff)<<7)|0x68
    def case(name,words,inputs,expected):
        entry=0x1000+len(rows)*0x100
        for k,word in enumerate(words):struct.pack_into(endian+'I',image,entry-0x1000+4*k,word)
        rows.append(dict(name=name,entry=entry,input=inputs,expected=expected))
    case('add_late_high_split',[opcode('ADDDP')|1,mvkh(0x4008,3),0x6000,mv(4,6)|1,mvd(5,7),mv(4,8)|1,mvd(5,9),mv(5,10),0xc0362,0x8000],{'A1':0x3ff00000,'A3':0x40000000,'A4':0x1234,'A5':0x5678},{'A6':0x1234,'A7':0x5678,'A8':0,'A9':0x5678,'A10':0x40100000})
    case('subdp_reversed_late_high',[opcode('SUBDP','S')|0x81,mv(6,3),0x10000,0xc0362,0x8000],{'A1':0x3ff00000,'A3':0x40000000,'A6':0x40080000},{'A4':0,'A5':0x40000000})
    case('spdp_split',[opcode('SPDP','S',b=2)|1,mv(4,6)|1,mvd(5,7),mv(4,8)|1,mvd(5,9),mv(5,10),0xc0362,0x8000],{'A2':0x3f800000,'A4':0x1234,'A5':0x5678},{'A6':0x1234,'A7':0x5678,'A8':0,'A9':0x5678,'A10':0x3ff00000})
    case('compare_late_high',[opcode('CMPEQDP','S')|1,mv(6,3),mv(4,6),mv(4,7),0xc0362,0x8000],{'A1':0x3ff00000,'A3':0x40000000,'A4':0x55,'A6':0x3ff00000},{'A6':0x55,'A7':1})
    case('mpydp_late_high_split',[opcode('MPYDP','M'),mvkh(0x4008,1),0xa000,mv(4,6)|1,mvd(5,7),mv(4,8)|1,mvd(5,9),mv(5,10),0xc0362,0x8000],{'A1':0x3ff00000,'A3':0x40000000,'A4':0x1234,'A5':0x5678},{'A6':0x1234,'A7':0x5678,'A8':0,'A9':0x5678,'A10':0x40180000})
    case('intdp_split',[opcode('INTDP',b=2),0x2000,mv(4,6)|1,mvd(5,7),mv(4,8)|1,mvd(5,9),mv(5,10),0xc0362,0x8000],{'A2':3,'A4':0x1234,'A5':0x5678},{'A6':0x1234,'A7':0x5678,'A8':0,'A9':0x5678,'A10':0x40080000})
    case('dpsp_e4',[opcode('DPSP',a=2,b=3),mv(4,6),0x2000,mv(4,7),0xc0362,0x8000],{'A3':0x3ff00000,'A4':0x55},{'A6':0x55,'A7':0x3f800000})
    case('predicate_captured_with_late_alias',[opcode('ADDDP',a=2,b=0)|0x80000001,(1<<23)|0x28,0xa000,0xc0362,0x8000],{'A1':0x3ff00000,'A3':0x40000000},{'A4':0,'A5':0x40000000})
    # SPRUFE8B MVD pipeline (p.379): .M use E1, result E4.
    case('mvd_e4',[opcode('MVD','M',b=2),mv(4,6),0x2000,mv(4,7),0xc0362,0x8000],{'A2':0x12345678,'A4':0x55},{'A6':0x55,'A7':0x12345678})
    case('dint_field_timing',[0x10004000,(4<<23)|(1<<18)|0x3e2,(5<<23)|(26<<18)|0x3e2,0xc0362,0x8000],{'CSR':0x201,'TSR':0x8001},{'B4':0x200,'B5':0x8002,'CSR':0x200,'TSR':0x8002})
    case('rint_field_timing',[0x10006000,(4<<23)|(1<<18)|0x3e2,(5<<23)|(26<<18)|0x3e2,0xc0362,0x8000],{'CSR':0x200,'TSR':0x8002},{'B4':0x201,'B5':0x8001,'CSR':0x201,'TSR':0x8001})
    case('same_count_multicycle_nops',[mv(2,4),0x2001,0x2000,0xc0362,0x8000],{'A2':0x12345678},{'A4':0x12345678})
    for name,words,reason in [
        ('mpydp_unstable_low',[opcode('MPYDP','M')|1,mvkh(0x4008,0),0x10000,0xc0362,0x8000],'source-read stability'),
        ('mpydp_unstable_high',[opcode('MPYDP','M'),0,mvkh(0x4008,3),0x10000,0xc0362,0x8000],'source-read stability'),
        ('adddp_unit_occupied',[opcode('ADDDP'),mv(6,7),0x10000,0xc0362,0x8000],'still occupied'),
        ('compare_duplicate_unit',[opcode('CMPEQDP','S')|1,mvkh(0x4008,3),0x10000,0xc0362,0x8000],'functional-unit collision'),
        ('loop_reload_not_guessed',[0x80038000,0x34000,0xc0362,0x8000],'requires reload state'),
        ('recent_ilc_load',[(13<<23)|(4<<18)|0x3a2,0x38000,0,0x34000,0xc0362,0x8000],'ILC load too close'),
        ('ilc_read_during_loading',[0x3a000,0x30001|(8<<18),(4<<23)|(13<<18)|0x3e2,0x34000,0xc0362,0x8000],'ILC access inside counted loop body'),
        ('bnop_and_multicycle_nop',[0x008c0363|(5<<13),0x2000],'multiple multicycle NOP generators'),
        ('bnop0_and_addkpc0',[0x008c0363,(4<<23)|0x162],'multiple multicycle NOP generators'),
        ('two_multicycle_nops',[0x2001,0x4000,0xc0362,0x8000],'multiple multicycle NOP generators'),
        ('loop_interval_invalid',[0x38000|(14<<23),0x34000,0xc0362,0x8000],'invalid loop interval')]:
        case(name,words,{},{});rows[-1]['refused']=reason
    Path(sys.argv[1]).write_bytes(image);Path(sys.argv[2]).write_text(json.dumps(rows,indent=2))


if __name__=='__main__':main()
