#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Stock-free predicate timing fixture: IMAGE CASES.json [be].

Requires TI's C6000 assembler. TI_C6000_BIN may name its bin directory or
cl6x executable; otherwise use /Applications/ti/ti-cgt-c6000_8.3.15/bin.
Assembly, object, and compiler logs stay beside IMAGE. This fixture contains
only full32 .nocmp instructions, so BE changes each word's byte order only.
"""
from pathlib import Path
import json
import os
import struct
import subprocess
import sys


specs=[
 ('parallel_copy',True,[], 'B0',[' || MV.D2 B0,B2'], [' [!B2] ZERO.S2 B0'],2),
 ('parallel_old_with_repair',True,[], 'B0',[' || MV.D2 B0,B2',' || MVK.S2 1,B0'], [' [!B2] ZERO.S2 B0'],2),
 ('earlier_copy_alias',True,[' MV.D2 B0,B2'], 'B2',[], [' NOP'],2),
 ('old_sample_changed_same_packet',False,[], 'B0',[' || MVK.S2 1,B0'],[' NOP'],2),
 ('copy_does_not_track_new_source',False,[' MV.D2 B0,B2'], 'B2',[' || MVK.S2 1,B0'],[' NOP'],2),
 ('unknown_arithmetic',False,[], 'B0',[' || ADD.L2 B4,B5,B0'],[' NOP'],2),
 ('late_unknown_write',False,[' LDW.D2 *B4,B0'], 'B0',[],[' NOP 3'],4),
 ('late_false_write',True,[' MVK.S1 0,A0',' [A0] LDW.D2 *B4,B0'], 'B0',[],[' NOP 3'],4),
 ('late_true_write',False,[' MVK.S1 1,A0',' [A0] LDW.D2 *B4,B0'], 'B0',[],[' NOP 3'],4),
 ('late_unknown_predicate',False,[' [A0] LDW.D2 *B4,B0'], 'B0',[],[' NOP 3'],4),
 ('late_write_parallel_branch_sample',False,[' LDW.D2 *B4,B0',' NOP 3'], 'B0',[],[' NOP'],2),
 ('backward_widens_aliases',False,[' MVK.S2 0,B0',' MV.D2 B0,B2','$LOOP:',' [B1] B.S1 $LOOP',' NOP 5'], 'B2',[],[' NOP'],2),
 ('constant_zero',True,[' MVK.S2 0,B0'], 'B0',[],[' NOP'],2),
 ('constant_nonzero',True,[' MVK.S2 1,B0'], 'B0',[],[' NOP'],2),
 ('same_zero_predicated_write_loop',True,[' MVK.S2 0,B0',' AND.L1 A5,3,A1','$LOOP: [B0] B.S1 $LOOP',' || [!A1] ZERO.S2 B0',' [B0] B.S1 $LOOP',' || [!A1] ZERO.S2 B0',' [B0] B.S1 $LOOP',' || [!A1] ZERO.S2 B0',' LDHU.D1 *A4,A3'], 'B0',[' NOP'],[' NOP',' [B0] ZERO.S1 A3'],2,None,[0,1,2,3],{'B0':0,'A3':1}),
 ('different_truth_must_widen',False,[' MVK.S2 0,B0',' AND.L1 A5,3,A1',' [!A1] MVK.S2 1,B0',' LDHU.D1 *A4,A3'], 'B0',[' NOP'],[' NOP',' [B0] ZERO.S1 A3'],2,'potential simultaneous memory/register writes'),
 ('different_truth_keeps_both_paths',True,[' MVK.S2 0,B0',' AND.L1 A5,3,A1',' [!A1] MVK.S2 1,B0'], 'B0',[],[' NOP'],2,None,[1,2,3],{'A0':0,'B0':0}),
 ('unknown_value_must_widen',False,[' MVK.S2 0,B0',' AND.L1 A5,3,A1',' [!A1] ADD.L2 B4,B5,B0',' LDHU.D1 *A4,A3'], 'B0',[' NOP'],[' NOP',' [B0] ZERO.S1 A3'],2,'potential simultaneous memory/register writes'),
 ('nonzero_predicated_write_fresh_token',True,[' MVK.S2 1,B0',' MV.D2 B0,B2',' AND.L1 A5,3,A1',' [!A1] MVK.S2 2,B0'], 'B0',[],[' NOP'],2,None,[0,1,2,3],None,{'register':'B0','other':'B2','truth':1}),
]


def object_sections(path):
    """Read bounded TI ELF32 sections and reject unresolved opcode relocations."""
    raw = path.read_bytes()
    if len(raw) < 52 or raw[:7] != b'\x7fELF\x01\x01\x01':
        raise ValueError('Expected little-endian ELF32')
    header = struct.unpack_from('<16sHHIIIIIHHHHHH', raw)
    offset, stride, count, names_index = header[6], header[11], header[12], header[13]
    if header[1] != 1 or header[2] != 140:
        raise ValueError('Expected relocatable EM_TI_C6000 object')
    if stride != 40 or not 0 < names_index < count or offset + count * stride > len(raw):
        raise ValueError('Invalid ELF section table')
    rows = [struct.unpack_from('<10I', raw, offset + stride * index) for index in range(count)]
    for row in rows:
        if row[1] != 8 and row[4] + row[5] > len(raw):
            raise ValueError('ELF section outside object')
    def data(index):
        row = rows[index]
        return raw[row[4]:row[4] + row[5]]
    names = data(names_index)
    section_names = []
    for index, row in enumerate(rows):
        end = names.find(b'\0', row[0])
        if not 0 <= row[0] <= end:
            raise ValueError('Invalid ELF section name')
        section_names.append(names[row[0]:end].decode('utf-8'))
    sections = {}
    for index, row in enumerate(rows):
        name = section_names[index]
        if name.startswith('.pf_'):
            if name in sections:
                raise ValueError('Duplicate fixture section name')
            sections[name] = data(index)
        if row[1] in (4, 9):
            size = 12 if row[1] == 4 else 8
            if row[9] != size or row[5] % size or not 0 < row[7] < count:
                raise ValueError('Invalid ELF relocation section')
            # TI permits repeated debug section names and their relocations;
            # only instruction-bearing fixture sections feed this image.
            if not section_names[row[7]].startswith('.pf_'):
                continue
            for place in range(row[4], row[4] + row[5], size):
                location, info = struct.unpack_from('<II', raw, place)
                if location >= rows[row[7]][5] or (info & 255) not in (0, 254, 255):
                    raise ValueError('Unresolved opcode relocation')
    return sections


def main():
    if len(sys.argv) not in (3, 4) or len(sys.argv) == 4 and sys.argv[3] != 'be':
        raise SystemExit('Usage: pipeline-predicate-facts.py IMAGE CASES.json [be]')
    image_path, manifest_path = map(Path, sys.argv[1:3])
    image_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    prefix = image_path.parent / (image_path.stem + '.predicate-facts')
    source_path, object_path, log_path = (Path(str(prefix) + suffix) for suffix in ('.asm', '.obj', '.log'))
    lines, manifest = [], []
    for index, spec in enumerate(specs):
        name, accepted, prefix_lines, guard, peers, middle, second_cycle = spec[:7]
        tag = 'pf_' + name
        good, bad = tag + '_good', tag + '_bad'
        lines += [' .sect ".' + tag + '"', ' .nocmp', tag + ':']
        lines += [text.replace('$LOOP', tag + '_loop') for text in prefix_lines]
        lines += [' [!' + guard + '] B.S1 ' + good] + peers + middle
        lines += [' [B0] B.S1 ' + bad, ' NOP 5', ' B.S2 B3', ' NOP 5', good + ':',
                  ' B.S2 B3', ' NOP 5', bad + ':', ' LDW.D1 *A4,A0', ' NOP 5', ' B.S2 B3', ' NOP 5']
        item = dict(name=name, at=0x1000 + index * 512, accepted=accepted)
        if len(spec) > 7 and spec[7] is not None:
            item['refused'] = spec[7]
        if len(spec) > 8 and spec[8] is not None:
            item['a5_values'] = spec[8]
        if len(spec) > 9 and spec[9] is not None:
            item['expected'] = spec[9]
        if len(spec) > 10 and spec[10] is not None:
            item['fresh_token'] = dict(pc=item['at'] + 4 * len(prefix_lines), **spec[10])
        manifest.append(item)
    source_path.write_text('\n'.join(lines) + '\n')
    binary = Path(os.environ.get('TI_C6000_BIN', '/Applications/ti/ti-cgt-c6000_8.3.15/bin'))
    compiler = binary / 'cl6x' if binary.is_dir() else binary
    command = [str(compiler), '-mv6740', '--abi=eabi', '-c', str(source_path), '--output_file=' + str(object_path)]
    completed = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    log_path.write_text(completed.stdout)
    if completed.returncode:
        raise RuntimeError('TI assembly failed; see ' + str(log_path))
    sections = object_sections(object_path)
    image = bytearray(len(specs) * 512)
    for index, item in enumerate(manifest):
        data = sections['.pf_' + item['name']]
        if len(data) > 512 or len(data) % 4:
            raise ValueError('Invalid full32 fixture section length')
        image[index * 512:index * 512 + len(data)] = data
    if len(sys.argv) == 4:
        image = b''.join(image[index:index + 4][::-1] for index in range(0, len(image), 4))
    image_path.write_bytes(image)
    manifest_path.write_text(json.dumps(manifest, indent=2) + '\n')
    print('PREDICATE_FACTS_FIXTURE_OK cases=' + str(len(manifest)))


if __name__ == '__main__':
    main()
