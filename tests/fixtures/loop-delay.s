# C674x restart idle-cycle fixture. Assemble with GNU tic6x-as -march=c674x.
# The two source packets each issue for four cycles (instruction plus 3 NOPs).
    .text
    .global bnop_loop
bnop_loop:
    sploop 2
    bnop bnop_target,3
    nop
    spkernel 0,0
bnop_target:
    nop

    .global addkpc_loop
addkpc_loop:
    sploop 2
    spmask
||^ addkpc .S2 addkpc_target,b3,3
    nop
    spkernel 0,0
addkpc_target:
    nop

    .global bnop_register_loop
bnop_register_loop:
    sploop 2
    spmask
||^ bnop .S2 b3,3
    nop
    spkernel 0,0
    nop

    # PROT is bit 20 of the compact fetch-packet header. The header at
    # word 7 covers all seven preceding 32-bit words as well as compact slots.
    .p2align 5
    .global protected_load_loop
protected_load_loop:
    sploop 2
    spmask
||^ ldw .D1T1 *A4,A5
    nop
    spkernel 0,0
    nop
    nop
    .word 0xe0100000
