#!/usr/bin/env python3
"""Generate a Ghidra Function ID database for the TI C6000 run-time library.

WHY THIS IS A SCRIPT AND NOT A SHIPPED .fidbf
---------------------------------------------
A Function ID database is derived from binaries built by the TI code generation
tools out of TI's own run-time library sources.  The TI CGT licence does not
clearly permit redistributing such a derived database, so this repository ships
the generator and each user builds the database from their own CGT install.
Read <https://www.ti.com/lit/...> and the CGT LICENSE.txt before you
redistribute anything this script produces.

WHAT IT DOES
------------
1. Compiles the TI RTS for the requested target (`-mv6740` for C674x by
   default) with the CGT you point it at, pulling in the helper routines that
   compiler-generated code calls into:
       memcpy, memset, memmove, __divi, __divu, __remi, __remu,
       __divli, __divlu, __remli, __remlu, __addf, __subf, __mpyf, __divf,
       __addd, __subd, __mpyd, __divd, __fixdi, __fltidi, ...
2. Adds a set of tiny wrappers that force the compiler to emit each of the
   integer and floating-point helper entry points, so that even a routine the
   library only exposes weakly gets a signature.
3. Runs Ghidra's `FunctionID` headless tool over the resulting ELF to build
   `c6000-rts.fidbf`.

REQUIREMENTS
------------
* A TI C6000 CGT install (7.x or later) with `cl6x`, `ar6x`, `ofd6x`.  It is a
  32-bit x86 Linux toolchain; on modern hosts run it under an x86 Linux
  container with 32-bit support, or on a 32-bit-capable machine.
* Ghidra 12.x and JDK 21, and this extension installed (Function ID needs the
  C6000 language to disassemble the RTS objects).

USAGE
-----
    tools/gen_fid.py --cgt /opt/ti/cgt-c6x --out dist/c6000-rts.fidbf
    tools/gen_fid.py --cgt ... --mv 6740 --ghidra /opt/homebrew/opt/ghidra/libexec

Everything is written under --work (default: scratch/fid) and nothing derived
from TI code is placed in the repository's tracked tree.
"""
import argparse
import os
import shutil
import subprocess
import sys

WRAPPERS = r"""
/* Force emission of the C6000 run-time helper entry points. */
#include <string.h>

volatile int   vi_a, vi_b, vi_r;
volatile long  vl_a, vl_b, vl_r;
volatile unsigned vu_a, vu_b, vu_r;
volatile float vf_a, vf_b, vf_r;
volatile double vd_a, vd_b, vd_r;
volatile long long vll_a, vll_b, vll_r;
volatile unsigned long long vull_a, vull_b, vull_r;

void c6000_fid_wrappers(void *dst, const void *src, unsigned n)
{
    memcpy(dst, src, n);          /* _memcpy / memcpy  */
    memset(dst, 0, n);            /* _memset / memset  */
    memmove(dst, src, n);         /* memmove           */

    vi_r = vi_a / vi_b;           /* __divi            */
    vi_r = vi_a % vi_b;           /* __remi            */
    vu_r = vu_a / vu_b;           /* __divu            */
    vu_r = vu_a % vu_b;           /* __remu            */
    vl_r = vl_a / vl_b;           /* __divli           */
    vl_r = vl_a % vl_b;           /* __remli           */
    vull_r = vull_a / vull_b;     /* __divlu           */
    vull_r = vull_a % vull_b;     /* __remlu           */

    vf_r = vf_a + vf_b;           /* __addf            */
    vf_r = vf_a - vf_b;           /* __subf            */
    vf_r = vf_a * vf_b;           /* __mpyf            */
    vf_r = vf_a / vf_b;           /* __divf            */
    vi_r = (int)vf_a;             /* __fixfi           */
    vf_r = (float)vi_a;           /* __fltif           */

    vd_r = vd_a + vd_b;           /* __addd            */
    vd_r = vd_a - vd_b;           /* __subd            */
    vd_r = vd_a * vd_b;           /* __mpyd            */
    vd_r = vd_a / vd_b;           /* __divd            */
    vd_r = (double)vi_a;          /* __fltid           */
    vi_r = (int)vd_a;             /* __fixdi           */
    vd_r = (double)vf_a;          /* __fltf2d / __spdp */
    vf_r = (float)vd_a;           /* __fltd2f / __dpsp */
}
"""


def run(cmd, **kw):
    print("+", " ".join(cmd), file=sys.stderr)
    return subprocess.run(cmd, check=True, **kw)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cgt", required=True,
                    help="TI C6000 CGT install root (contains bin/cl6x)")
    ap.add_argument("--mv", default="6740",
                    help="CGT -mv target; 6740 selects C674x (default)")
    ap.add_argument("--out", default="dist/c6000-rts.fidbf")
    ap.add_argument("--work", default="scratch/fid")
    ap.add_argument("--ghidra", default=os.environ.get("GHIDRA_INSTALL_DIR"),
                    help="Ghidra install root (or set GHIDRA_INSTALL_DIR)")
    ap.add_argument("--jdk", default=os.environ.get("JAVA_HOME"),
                    help="JDK 21 home (or set JAVA_HOME)")
    args = ap.parse_args()

    cl6x = os.path.join(args.cgt, "bin", "cl6x")
    if not os.path.exists(cl6x):
        sys.exit("no cl6x under %s" % args.cgt)
    if not args.ghidra:
        sys.exit("set --ghidra or GHIDRA_INSTALL_DIR")

    os.makedirs(args.work, exist_ok=True)
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    src = os.path.join(args.work, "c6000_fid_wrappers.c")
    obj = os.path.join(args.work, "c6000_fid_wrappers.obj")
    with open(src, "w") as f:
        f.write(WRAPPERS)

    env = dict(os.environ)
    if args.jdk:
        env["PATH"] = os.path.join(args.jdk, "bin") + os.pathsep + env.get("PATH", "")

    # Compile the wrappers and link them against the RTS for this target.  The
    # RTS source ships with the CGT; building it here keeps the database in step
    # with the exact toolchain version in use.
    run([cl6x, "-mv" + args.mv, "-c", src, "-o", obj], env=env)
    run([cl6x, "-mv" + args.mv, "--run_linker", obj, "-o",
         os.path.join(args.work, "c6000_rts.out"),
         "-l", "rts" + args.mv + ".lib",
         "-i", os.path.join(args.cgt, "lib")], env=env)

    # Ghidra's Function ID tool needs the C6000 language, so the extension has
    # to be installed in the Ghidra tree being used.
    fid = os.path.join(args.work, "fid")
    os.makedirs(fid, exist_ok=True)
    run([os.path.join(args.ghidra, "support", "analyzeHeadless"),
         args.work, "c6000-fid",
         "-import", os.path.join(args.work, "c6000_rts.out"),
         "-processor", "C6000:LE:32:default",
         "-scriptPath", os.path.join(args.ghidra, "Ghidra", "Features",
                                     "FunctionID", "ghidra_scripts"),
         "-postScript", "CreateFunctionID.py", args.out], env=env)

    print("wrote %s" % args.out, file=sys.stderr)
    print("NOTE: check your TI CGT licence before redistributing this file.",
          file=sys.stderr)


if __name__ == "__main__":
    main()
