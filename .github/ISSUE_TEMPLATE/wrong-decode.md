---
name: Wrong decode or semantics
about: An instruction disassembles, lifts or decompiles incorrectly
title: "Wrong decode/semantics: <MNEMONIC> at <address>"
---

**Versions**
- Ghidra:
- Extension (release or commit):
- Language id (e.g. `C6000:LE:32:default`):

**Location**
- Address:
- Raw bytes of the whole 32-byte fetch packet, in file byte order (the header
  word of a compact packet changes how the other words decode):

```
```

**What Ghidra shows** (listing line, and p-code or decompiler output if the
problem is semantics):

```
```

**What you expected**, and the SPRUFE8B / SPRU732J figure, table or section
that says so:

**Oracle output**, if available, e.g.
`objdump -D -b binary -m tic6x --endian=little --adjust-vma=<base> packet.bin`
(the input must be at least 32 bytes):

```
```

Please post only bytes you are allowed to share; one fetch packet is usually
enough.
