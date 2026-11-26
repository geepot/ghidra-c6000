# Changelog

## Unreleased

### Changed

* The analysis languages lift `LDNW`, `LDNDW`, `STNW` and `STNDW` as one 4- or 8-byte
  access instead of one access per byte. The decompiler merged the byte loads step by
  step and could keep some of them, so a device word read through `LDNDW` was read twice
  in the C. The default and c67x languages keep the bytewise model, which wraps each byte
  in a circular buffer (SPRUFE8B 3.9.2.3).
* Loads and stores through A4-A7 and B4-B7 no longer hide switches and clutter the C with
  the AMR circular-addressing mask. `c6000_circular_mask` computed the mask with four
  conditional branches, inlined at every such access, so the decompiler's jump-table
  recovery stopped at "Too many branches" on a dispatch that loads its index and its table
  through those registers. The mask is now computed without branches, with the same value.
  The cspec states what the EABI guarantees (SPRAB89 3.2): AMR is zero at each function's
  entry and is unchanged by a call, so the mask folds away in compiled code. Circular
  addressing is still modelled exactly where code sets AMR.

* An unpredicated instruction is lifted with no predicate guard. Every ordinary instruction
  had one constructor whose semantics sat behind `if (Cond == 0) goto <skip>`, a constant
  test when there is no predicate. The decompiler works out a call's arguments before it
  folds that test away, so a register loaded just before a second call looked conditional
  and the argument was dropped (issue #101). `tools/gen_decode.py` now emits an unguarded
  constructor for `creg=0, z=0` beside the predicated one, and 14 hand-written forms are
  split the same way. The listing text is unchanged; the p-code of every unpredicated
  instruction is, so a reviewed exact schedule may need recording again. Side effects seen
  in the fixtures: constant propagation no longer offers the low half of an `MVK`/`MVKH`
  pair as a branch target when the `MVKH` is unpredicated, and the decompiler recovers an
  undeclared 64-bit result as a pair where it sees both halves written (and, for one leaf
  that rewrites `A5` after a 40-bit `SUBU`, as no result).

* The call walker reads each instruction's context once to tell whether staging or a latch
  changed it, takes its flow type once, and decides whether two instructions share an
  execute packet from the issue cycles it already has. Analysis is about a third faster on
  a large image, with the same results.
* Where jumps from elsewhere enter the call walker's look-back, it no longer follows the
  entering jumps once it holds no register value to merge, and it checks whether the label
  is an entry only once. With the change above, analysis takes about 57% of the time it
  did, with the same results.
* Delay-window recovery, which runs over the whole program, returns at once when the
  program is unchanged since a recovery that changed nothing. With the two changes above,
  analysis takes under half the time it did, with the same results.
* The analyzers read an instruction's mnemonic once per instruction prototype instead of
  printing it again on every call, check it before reading the latch fields, and find the
  switch overrides to repair by name instead of walking every symbol. With the three
  changes above, analysis takes about a third of the time it did, with the same results.
* The `analysis` and `c67x-analysis` languages give `ABSSP`, `ABSDP`, `ADDDP`, `SUBDP`,
  `MPYDP`, `MPYSPDP`, `MPYSP2DP`, `SPDP`, `DPSP`, `SPINT`, `SPTRUNC`, `DPINT`, `DPTRUNC`
  and the DP comparisons plain floating-point p-code, as they already did for the
  single-precision arithmetic. The bit-exact models with rounding modes and status
  flags made each of these a long block of integer code in the decompiled output. The
  plain forms round to nearest and report status through the same opaque
  `c6000_fp_status` userop; the `default` and `c67x` languages keep the exact models.
* Exact schedules accept the analysis languages' `c6000_fp_status` update as the
  instruction's status write (its result joins the register's event bits at writeback).
  Before, any float instruction in an analysis-language function refused the schedule as
  "opaque semantics".

* All eight languages are now version 3.0: the context register is 128 bits, which makes
  room for the latched-branch fields (bits 64-122). Programs saved with version 2, or with
  version 1, upgrade on open with every context field carried over by name. As with
  version 2.0, review the exact schedules of an upgraded program again, and note that
  Ghidra's re-disassembly during the upgrade can drop an instruction after a delay window
  that mixes 32-bit and compact instructions (Ghidra #10242).

### Added

* A jump into another function that is reached with a link of its own function in B3 on one
  path and something else on another is warned (`C6000 Split Link`, issue #151): the callee
  returns to that address on the first path and to the caller on the other, and the jump is
  lifted one way.

* `C6000 Unowned Code` notes each run of decoded code that belongs to no function, at its first
  instruction that is not padding. Such code is not decompiled or checked; where nothing calls
  it, jumps to it or names it, nothing says where a function starts in it, so making one is
  left to the user.

* `C6000 Code Pointers` analyzer. A function passed as a callback or stored in a pointer is
  only named by its address. Where an instruction of a function takes an address as a value
  and that address starts code that no function owns, this makes it a function. It leaves
  alone an address written to `B3` (a return link), one inside an execute packet, one that
  other code reads or writes as data, and one that a function's own code jumps or falls
  into; an address with no code yet must decode as a subroutine.

* Exact schedules accept `SSHL`, `SHR2`, `CMPEQ2` and `PACKHL2` (single-cycle) and the
  `MPY32`, `MPY32U`, `MPY32US`, `MPY32SU`, `DOTP2` and `DOTPU4` forms (result in E4, 32-
  or 64-bit). They were refused as an unimplemented phase contract. `pipeline-scalar-ops`
  checks each form's writeback cycle, source capture and E1 predicate sampling against an
  independent oracle and the instruction's own p-code.

* Latched branches (issue #73). A branch issued in another branch's delay window lands
  after it, and native lifting gives each branch one window that holds no other branch.
  Where the hardware and the listing then run different instructions, the new `C6000
  Nested Branch Lifting` analyzer latches the branches of the stretch: each records its
  predicate, and its register target, as it issues and does not transfer, and the
  instruction it lands behind carries its jump, call or return. A lifting is kept only when
  it runs what the hardware runs on every consistent outcome of the predicates, by the same
  comparison that decides the nested-window warning. It covers 32-bit and compact branches,
  up to eight in flight, including two that are both taken: the second then lands in the
  code the first went to, behind the instruction the hardware lands it behind. A branch
  that lands with a return link freshly written to `B3` is lifted as a call that returns
  there. A landing whose branch is taken on every path that reaches it is unconditional,
  so flow stops where the hardware leaves. A loop that comes round with a branch still in
  flight, a landing in a native delay slot, `CALLP`, `BDEC` and `BPOS` keep the warning,
  which now says why latching does not fix it. A branch with a user's flow override is
  left alone.
* Staged execute-packet writes. Every member of an execute packet reads its operands before
  any member writes (SPRUFE8B 3.5), but p-code runs the members in order. Where a member
  reads a register that an earlier member of its packet writes, the new `C6000 Packet
  Staging` analyzer now holds that write: the register keeps its old value and the result
  waits in a `C6000_NEW_` register until the last member that reads the old value has run.
  A branch that is the last such reader commits the result after reading its predicate and
  target. The decompiled C is then the hardware's, for example `b - a` for
  `MV B4,A4 || MV A4,A5` followed by `SUB A4,A5,A4`, which was `0`. One whole A or B
  register or one register pair per writer, and two commits per member, are staged; anything else, such as a
  control register, keeps its same-packet hazard warning. Exact schedules and the
  analyzers that model the pipeline read the instruction without staging. New context
  fields `c_staged`, `c_defer`, `c_defer_reg`, `c_cm1`, `c_cm1_reg`, `c_cm2` and `c_cm2_reg`
  use bits 24-31 and 48-61 in both byte orders.
* A `C6000 Nested Delay Windows` warning bookmark where native lifting cannot place a
  transfer, so the function's C is wrong with no other sign: a branch issued in a delay
  cycle of another branch, which lands after it, and a predicated call whose return
  address in B3 is at or before it (SPRUFE8B 3.5, 4.2.6; issues #64, #65, #66). Functions
  with an active reviewed schedule are skipped, and so is a jump continued past the
  return that preempts it (#50). A transfer is warned only where native lifting runs
  something other than the hardware: on each consistent outcome of the predicates
  involved, the analyzer compares the hardware's issue order (packets, idle cycles,
  landings, calls) with the listing's lifted order, and the warning names the first
  difference. A chain of transfers each nested in the one before, as in a
  software-pipelined loop's prolog, gets one warning naming them all.
* A `C6000 Same-Packet Hazards` warning where a packet member reads a register that an
  earlier member of its execute packet writes. Every member reads before any writes
  (SPRUFE8B 3.5), but native lifting runs them in order, so the C uses the new value. The
  reader gets a warning bookmark, and the function's header comment, which the decompiler
  shows, gets a warning line. Two updates that only OR sticky flags into CSR, FADCR,
  FAUCR or FMCR commute and are not warned, and neither are members under opposite
  predicates on a register the writer leaves alone, of which at most one runs. Functions with an active reviewed schedule
  are skipped (issue #71).

### Fixed

* A nest that starts at a function's entry is compared with the hardware from that entry. The
  comparison began at the last branch that could still be in flight, which for a function right
  behind another's return window is that return: it has landed before the entry issues, the
  run ended there, and a jump in the function's first execute packet with a branch in its
  window was never looked at (issue #154).

* After a call, B3 is taken to hold the return address only where the callee is followed and
  every way out of it is a branch through B3 itself. It was assumed for every call. A callee
  that returns through a copy of its link, having used B3 for a call of its own (cl6x does
  this within one file), leaves something else there, and so may one that cannot be followed:
  B3 is then unknown, a jump into another function behind such a call stays a tail call, and
  where B3 was not written again it is warned (`C6000 Split Link`).

* A call whose link is an address of its own function other than the end of its delay window
  is a call that returns there (issue #155): it was lifted as a tail call, or predicated as a
  jump into the callee, and everything after the return was lost. A jump into another
  function's entry is now compared with the hardware like a nested branch and lifted by
  latching as the call and a jump to its return point; where that cannot be done it is warned.
  In that comparison a tail call the listing has is a jump whose return B3 decides, and stays
  the tail call it is when B3 holds no address of the function.
* The link known before a stretch is not trusted where the stretch begins on a label that
  another path jumps to.

* A return through a copy of B3 is proven past a callee that leaves for another function with
  B3 as it found it: that function is walked too, to its return (issue #153).
* A landing that every run passes with its latch set is lifted as certain also where unreached
  code lies between it and a later instruction of the plan; such code was taken for a way in.
  The decompiler then no longer sees a path past an unconditional latched return, which hid
  the value the function returns.

* `C6000 Link Copy Warnings` covers a latched branch too: one through a copy of B3 that lands
  as a computed jump, because the call before it is not proven to leave the copy alone, had no
  warning (issue #153).

* A load's result lands four delay slots after it issues, a 16-bit multiply's one. Where a
  later instruction issues before that and reads the register, or writes it and must be
  overwritten by it, native lifting now holds the write until the last such instruction has
  run, as it does for a same-packet read (issue #152). It does so in straight-line code only;
  elsewhere the reader gets a `C6000 Same-Packet Hazards` warning that says why. Before, the C
  read the new value there with no warning.

* `C6000 Code Pointers` follows a word of data that holds the address of code (a table of
  handlers, a pointer a structure keeps), and reads the constants built in decoded code that no
  function owns. The same test as before decides: the start of code no function owns and
  nothing falls into. On a raw image whose functions are reached through such tables this
  finds most of the program; nothing is made where nothing names an address.

* The entries a stretch is planned and checked from include each label inside it that a jump
  from outside the stretch comes in at: such a path runs without what was in flight before the
  label. A plan that left it out passed its check and was dropped after relifting.
* A lifting keeps a branch that another stretch latched inside its stretch, as it keeps that
  stretch's landings.

* A value's origin is not disturbed by a write that has issued and not yet landed, such as a
  load in the packet that copies the register: the copy still has the value from before. Two
  predicates that are copies of one value were not recognised as such there, so an outcome
  that cannot happen was run.

* Code reached only by a jump with another transfer of its window still in flight keeps the registers
  that jump arrives with, for a branch that issues once that transfer has landed: it is reached only
  where the transfer was not taken. They were forgotten for all the code there, so a call whose link
  was set before became a jump, with no warning (issue #137).
* A nest that issues as the last branch of a latched one lands is lifted with it: the landing that one
  put outside the stretch is the plan's own and is replaced, where the latch it reads is set by a
  branch the plan latches, for the same target. The plan was refused (issue #139).
* A predicated branch issued in a jump's target with another branch in flight is run one way only where
  what the run has issued, and the outcomes it took, decide its predicate. The outcome that cannot
  happen was run too, and a nest whose lifting could not carry it kept its warning (issue #141).
* A branch nested in an unconditional jump's window, which is in no function until the nest is lifted,
  is judged as code of the function its stretch starts in: one to that function's own code is a jump,
  not a call that returns to a link written in the window for another branch (issue #136).
* Two writes to a predicate register in one packet under opposite predicates (SPRUFE8B 3.8.8) leave the
  one that runs, where the path says which; it was given up, so an outcome that cannot happen was run
  and a nest kept its warning (issue #138).
* A call two paths join at is recognised where the path falling in writes its link under a predicate
  that the jump it fell through decides. Those facts were dropped for the whole path when the branch,
  or an instruction before it, is a label; they now hold up to the label, where the paths' registers
  are compared. Such a call became a jump, and the code at its return point was left out (issue #135).
  They are compared at a label that is a jump not taken on the way, too: a call could be made there of
  a branch that returns to another place when it is reached by the label.
* A stretch is planned and checked from every place it can be entered, not only from its
  start: code behind a return or an unconditional jump inside it is reached some other way,
  and its branches were latched as jumps without any run saying how they land. Calls there
  are now latched as calls; where such an entry cannot be lifted, the nest is refused with
  its reason instead of being lifted unchecked.

* `C6000 Low-Half References` also drops Ghidra's data reference from an `MVKH` to its bare operand:
  the operand is the register's high half (SPRUFE8B p. 383), so the register never holds that address.
  `C6000 Code Pointers` made a function there, in the middle of any code loaded at the address that
  the high half of a float constant spells (issue #134).
* `C6000 Code Pointers` decodes a callback before making it a function; one found behind words
  that do not decode was a function of one byte that no analyzer had seen. A callback right
  behind the last delay slot of a jump or return that always goes is found too: that slot's
  fall-through is where the listing goes on, not the program (issue #130).

* A nest whose stretch holds a landing of another stretch is lifted: the instruction carries
  that landing beside the plan's own, and the plan takes latches the other stretch does not
  use. Such a plan was dropped without a word (issue #140). Where a plan that passed its check
  is still dropped, the nested-window warning now says why.

* A branch through a scratch register that holds the function's entry link is a return also in a
  function that makes calls, if each callee is proven to leave that register alone: cl6x 8.3.15
  keeps the link in one when it knows what a callee in the same file writes. It was lifted as a call
  through an unrecovered jump table, with no warning (issue #131). Where a callee is not proven to, or
  the copy issues beside the function's first branch or in its delay slots, the new `C6000 Link Copy
  Warnings` analyzer bookmarks the branch.
* The offset of a load or store from DP (`*+B14(offset)`, SPRUFE8B 3.9.3) is no longer taken for an
  address. Where DP was not known, constant propagation gave the instruction a data reference to the
  bare offset, and Ghidra's Scalar Operand References did the same for a large word index, so
  `C6000 Code Pointers` made functions in the middle of code loaded at such addresses (issue #130).
* `C6000 Code Pointers` joins `MVK`/`MVKL` and `MVKH` on one register itself. Ghidra's constant
  tracking gives no reference where the halves are apart or a call lands between them, so a
  callback whose address is loaded that way was missed.
* A `CALLP` whose callee never returns through the link it is given ends its function: the
  callee returns for it, as cl6x's `__c6xabi_pop_rts` does (called with A3, it reloads B3 and
  branches through that). The code after it was taken for part of the function, which hid a
  function that starts right there.

* A switch whose setup is entered through a second jump, or through a latched one, gets its
  table: the search follows the latched branch behind a landing, takes what runs before the
  jump into the tail as an entry path of its own, knows that nothing falls in past two jumps on
  opposite outcomes of one flag, and tracks `SUBAB`/`SUBAH`/`SUBAW`.
* When an earlier jump on a branch's own predicate is still in flight as the branch issues,
  the branch's delay cycles continue at that jump's target once it lands. A link written in
  the code after the branch past that point is not its link (this made two false functions
  inside `__TI_scanfi` of a compiled runtime image); a link the target writes is, which is how
  cl6x gives a call its link through a jump to a shared `ADDKPC`.

* A value left in A3 is no longer printed as the first argument of a call whose callee has no
  committed prototype (issue #132). The compiler spec gains `__c6000_unknown`, the default
  model without the entry for a large result's buffer address, and names it as the model the
  decompiler assumes of a callee whose prototype is not committed. Declared functions, and the
  function being decompiled, keep `__c6000`.
* The pipeline analyses keep each instruction's hardware form between changes to the program,
  which took a third off the analysis time on a compiled test image.

* A call's link is found however far before its branch it was written: the look-back reaches to
  B3's last write in the straight-line code before it, where it stopped 40 words back (issue
  #129) or at the cycles a transfer stays in flight (issue #106's `jcallpre8`).
* A register branch in a latched nest that lands just before the address B3 holds from before
  the nest is the call that link was written for (issue #133).

* A call that does not come back at the next instruction is lifted as the call and a jump to
  where it returns: a predicated call whose link is earlier code (issue #66), a jump into a
  function while B3 still holds an earlier call's return address (issue #105), and a call
  that returns past instructions it skips. B3 is known to hold a call's return address once
  that call has come back.
* A call reached through a jump whose window holds a predicated branch that may go is a call
  again when its link is set in its own window; only a branch that certainly goes makes the
  look-back fall back to the code before the call.
* Switch tables are found when the switch is set up before a jump into a shared dispatch
  tail, with the table base and index written in the jump's delay slots, and when the
  guard's flag is set to a nonzero constant between the compare and the branch it guards.

* A predicate's known value carries to another register that holds the same value: both are
  copies of one write, as `MV A4,A1` and `MV A4,A2` at a function's entry are. With it, a
  branch in a jump's window whose predicate that path has cleared is known not to go, the
  look-back through the jump reaches a call that nothing falls into with its link intact, and
  the call is a call instead of a tail call (issue #114). The code a landed call returns to
  is decoded if it never was.
* Asking the decompiler whether a lifting pushed its function past the overlap limit (issue
  #99) is done only when a landing's target is a native delay slot. It was done for every
  lifting, which cost minutes on a large function.

* A branch the hardware issues in the code a jump went to, while a branch of the nest is
  still in flight, is nested with it too: the comparison runs both outcomes of its
  predicate and the lifting latches it, outside the stretch (issue #123).
* Whose link is in B3 when a transfer lands is decided by what its target does with it:
  another function returns through it by the calling convention; code of the same function
  does only if every way through it ends in a branch through B3 with B3 unwritten. A jump to
  code that sets B3 or issues the call itself is a jump (issue #112), and so #65's
  jump-and-call pair is lifted.
* Two landings behind one instruction fire in the order their branches issued.

* A branch that is not first in its execute packet gets its delay window in code no
  function owns too (issue #115).
* A function that jumps into another function's code carries a `C6000 Nested Delay Window
  (entered)` warning on that jump when the code has a nested-window warning: the decompiler
  follows the jump, so its C has the same fault (issue #108).

* A second transfer in a branch's own execute packet counts as nested with it, like one in
  its delay cycles: both land after the packet's delay cycles, and native lifting gave
  neither its window, with no warning (issue #98). A call the listing already recognises is
  latched with the others where that is what the hardware runs; `C6000 Delayed Calls`'s
  `CALL` flow then sits on the instruction the call lands behind.
* A branch through a register that holds the link its function was entered with is a return
  (`C6000 Link Copy Returns`, issue #104).
* After a callee returns, B3 holds the address it returned through until something writes
  it. A branch to another function's entry while B3 still holds such an address returns
  there: a nest with its link set before its branches is latched with the call as a call
  (issue #106), and a predicated one that returns to earlier code is warned (issues #105,
  #66).

* A lifting whose landing enters another branch's native delay window is taken back when it
  pushes the function past the decompiler's overlapping-instruction limit: the function
  then failed to decompile at all (issue #99). The nest keeps its warning.

* A predicated write was evaluated as if its predicate register held 1, when all that is
  known is that it is not zero. `[B0] SUB B0,1,B0` came out as the constant 0, so a second
  branch on `B0` counted as never taken, paths with two taken branches were left out of
  the nested-window comparison, and a software-pipelined loop was latched as if it ran
  once (issue #103). The value is now a constant only if it does not depend on which
  nonzero value the register holds.

* A latched branch no longer keeps a flow override. One that also carries another branch's
  landing had that landing changed by its own `CALL` or `RETURN` override, so a jump could
  lift as a call and its target become a function. What a latched branch is now comes from
  the landing that reads its latch, and the call analyzer leaves latched branches alone.
* A jump that lands with a fresh link in `B3` is not a call when it goes to its own
  function's code and a branch on the opposite predicate shares the link: it is the
  else-branch, and the link is the other arm's.
* The instructions a lifting puts landings on are reported to auto-analysis, so a call that
  lands there gets a function at its target.

* Code that the call, delay-window and switch-table analyzers decode themselves is now
  reported to auto-analysis. It was not, so no analyzer saw it and a call in it never got
  a function at its target: on a cl6x-compiled test image 39 called addresses with decoded
  code had no function. That image goes from 116 functions to 167.
* A switch table whose dispatch sits behind a label that only one jump reaches is found by
  following that jump: the table's address is often built in its delay slots. Ghidra's own
  switch analysis found these until the jump was latched with others (issue #73). The
  analyzer also reads compact `LDW` loads, which list base and offset as separate operands,
  and tells a delay carrier by its prototype: `getDelaySlotDepth()` is 0 for some windows,
  and a carrier's followers' writes were then counted as its own.

* Latched returns (issue #73). A `B B3` latched in another branch's delay window is a
  return wherever it issues, so the instruction it lands behind now returns instead of
  making a computed jump; a caller that jumps in with B3 set to a link no longer fails to
  decompile ("Bad relative branch"). `C6000 Returns` now skips latched branches: its
  return override on a branch that also carries an earlier jump's landing turned that jump
  into a return, and the code after it was removed as unreachable.
* Switch tables are found again when the index reaches the table load through `SHL` and
  `ADD` (`(idx << 2) + table`), or when the compare tests a biased copy of the index
  (`idx - k`, with the bias folded into the address), as compilers emit for a switch whose
  cases don't start at zero. The bound came only from a compare of the very register the
  load indexed with, so these dispatches got no targets.
* Exact schedules no longer refuse a return that lands while an instruction disabled at
  issue is still in flight (`[A1] LDW` issued after A1 was cleared). Such an instruction
  does nothing more, so it is not a pending effect, also for a store-tail return. Its
  predicate is sampled when it issues, so this holds for one issued in the return's own
  landing packet too.
* Exact schedules accept a predicated write inside a double-precision instruction's
  repeated source-read window when the two can't both run: the writer's predicate is
  known false, or the writer and the reader test opposite senses of one predicate value.
  Every write in the window was refused before. Two writers on the same sense still are.
* A store-tail schedule accepts a return taken while a software-pipelined loop drains,
  as in a word copy that issues its return in the first epilog cycle. The taken return
  idles the non-reloading buffer (SPRUFE8B 7.14), so nothing more issues from it in the
  caller's cycles; the stores it issued in the delay slots stay pending under the
  store-tail contract, and TSR.SPLX is cleared. It was refused as an unresolved control
  effect. The refusals now name the landing and the branch or store in the way.
* An instruction in flight whose predicate sampled a value that a later branch decides
  (`[!A0] LDW`, then `[!A0] B` on the same A0) is known to run or not on each path.
  Exact schedules refused a complementary writer landing in the same cycle
  (`[A0] MVK … ,B0` with the load's `B0`) as a potential simultaneous write.
* Exact schedules accept the time-stamp counter's reads (`MVC TSCL`/`TSCH`) and start
  (`MVC … ,TSCL`). They lift to the `c6000_tscl_read`, `c6000_tsch_read` and
  `c6000_tsc_start` userops, which the compiler refused as opaque semantics, so any
  function that reads the clock had no exact schedule.
* Exact schedules for functions whose entry packet issues a branch accept a native delay
  window of compact (16-bit) instructions or one that holds a fetch-packet header. The
  window was walked by Ghidra's delay-slot depth, which doesn't count such slots, so it
  was refused as "does not match its N delay bytes" or "is not straight-line code". It is
  now walked by its bytes.
* The decompiler no longer takes a callee-saved pair (`A11:A10` … `B15:B14`) as an
  input when a function saves it with `STDW` and calls another function before restoring
  it. The default calling convention listed only the single registers as unaffected, so
  across the call the pair's value was unknown and the save read `in_A11_A10`. The six
  pairs are now listed as well.
* Both arms of an if/else call pair (`[!A1] B f || [A1] B g`, one B3) become calls when
  both targets are function entries. Between two immediate arms the nearer target was
  always taken for the local else-block, so the call to the nearer function stayed a
  conditional jump. A known function entry or external entry point is never an
  else-block.

* Lost return points (issue #107). `C6000 Delayed Calls` now decodes a call's return
  point when it is still undefined. Where the call's delay window had been laid while its
  `B` was still read as a jump, the code from the return point on was never decoded: the
  function ended at the window, and its own `B B3` became an unrecovered jump table.
* Relifting past a sure landing (issue #111). `C6000DelaySlots.relift` now also decodes
  code in the stretch that follows an instruction with no fall-through, such as a sure
  landing, and that only another branch's landing reaches. It decoded by flow from the
  stretch's start only, so the relift failed, the lifting was taken back, and the nest kept
  a warning that gave no reason.
* A return beside a call to a local label (issue #116). A `B B3` in the delay window of a
  call on the other predicate is now a return when nothing from the function's entry to it
  writes B3, so it still holds the caller's link. Where the call went to a label in the
  same function, `C6000 Delayed Calls` made the return a call, and the latched nest called
  through the caller's return address.
* A landing in another branch's delay slot (issue #109). A nest whose branch lands behind
  an instruction outside it that is a native delay slot of another branch is now latched
  with that branch too, which lands where its window ends as it does natively, so the slot
  becomes plain code and carries the landing. The nest was refused with "a branch lands
  behind X, which cannot carry it". The other branch is not latched when it is already
  latched elsewhere, untimed, a `CALLP`, `BDEC` or `BPOS`, has a transfer in its window,
  or has no single direct or register target, or when no latch is free or the landing
  instruction would carry more than two landings.
* A call issued in another branch's delay window (issue #110). Comparing a nest, a call
  that lands now returns where B3 points on that path when the straight-line code before
  the stretch, or the stretch itself, sets it, instead of to its listed fall-through, which
  is only the next instruction of the stretch. Predicate facts are dropped only on paths
  where the call is taken, from the cycle it lands. The model returned into the middle of
  the stretch and ran paths the predicates exclude, so the nest was refused with a warning.
  A link half written before an earlier transfer that lands before the stretch is still not
  seen, and such a nest keeps its warning. A latch moves a call off its own instruction, so
  only a listed call issued in the window of transfers it excludes is latched; one issued
  with nothing in flight, or with a taken transfer in flight, keeps its CALL flow and its
  warning (the if/else pairs at 1908 and 1c4c in `delayed-call`).
* The call analyzer's look-back treats every register the ABI lets a callee change as
  unknown once an earlier call has returned (all but A10-A15 and B10-B15), and at code that
  nothing falls into, after a jump or return that always goes, it takes the registers from
  the jumps that enter it instead of from the code physically before. A register call
  after another call kept a target loaded into a scratch register before that call.
* A register branch's target is checked against what its register holds at E1 wherever the
  call analyzer's look-back proves that value, not only for an `MVK`/`MVKH` pair directly
  before the branch. A write in the branch's own execute packet, or one that only runs when
  the branch's predicate is false, no longer adds a second, wrong target.
* The loop-buffer analysis and the exact-schedule compiler's caller-entry check use the
  shared cycle count, and a predicated `BNOP` is no longer treated as buffered.
* The call analyzer's look-back no longer carries a register constant or a fall-through
  fact across code that a jump from elsewhere enters, unless every entering jump arrives
  with the same value or has not written the register since the label (a loop's back
  edge). A register call entered with two different target values was given the one the
  code physically before it set.
* A call's return address is what B3 holds when the branch lands, after the instructions
  the hardware issues until then, and the branch is a call only when that address is where
  this arm or the other arm of its if/else pair stops issuing. That replaces a walk that
  stopped at whatever address B3 held and a list of accepted distances (a compact slack, a
  header, the partner's window). A `B` whose B3 pointed into its own window, such as a tail
  call that reloads B3 in its slots, was made a call. A laid call falls through to that
  return address.
* The call analyzer's register constants come from each instruction's p-code, with the
  known registers as inputs, instead of a list of mnemonics (`MVK`/`MVKL`/`MVKH`/`ADDKPC`
  and copies, with 32-bit `MVK.L`/`MVK.D` dropped). A return address finished by other
  arithmetic, such as `ADDK`, in a call's window was lost and the call became a tail call.
* A jump preempted by a return in its window (#50) is continued whenever the proposed
  lifting, the jump run straight on and the return's window cut where the jump lands,
  runs what the hardware runs on every predicate outcome. That replaces a list of
  accepted shapes, so a `BNOP B3,n` return, compact code and NOP generators in the jump's
  packet are accepted where exact. `BNOP` returns kept their jump's target before.
* One cycle count serves the call analyzer, the delay-slot window layer and the low-half
  reference analyzer (C6000ExecutionPackets.cycles). The window layer did not count a
  `BNOP`'s NOP cycles in its packet, so a `BNOP` return's cut window overshot its cut by one
  instruction, and the call analyzer charged a predicated protected load the four NOP
  cycles SPRUFE8B specifies only for an unconditional one; both now treat that as untimed.
* A switch table's bound comes only from an unsigned compare of the register the table is
  indexed with, unchanged until the load, whose result keeps the dispatch from issuing
  past it: the dispatch is predicated on it, or a branch taken on it lands first. The last
  `CMPLTU`/`CMPGTU` before the dispatch was taken, whatever it compared, so an unrelated
  compare could add cases past the table.
* The two arms of an if/else call pair are matched by issue cycle, not by being within
  24 bytes: an arm still in flight when the other issues is its partner, however wide
  the execute packets between. A jump arm past wide packets was recovered as a call.
* Which arm of an if/else call pair is the call is decided by where the targets lie when
  the function bodies say: the arm targeting another function is the call, and the one
  targeting the caller's own code is the jump. Choosing the nearer target as the local
  block turned a call to a helper placed right after the caller into a jump.
* Auto-analysis no longer loops for ever on a jump preempted by a return when the
  return's cut window runs past a fetch-packet header. Once that window was laid, the
  header decoded as a delay-slot instruction (`_CPKT`) and counted as a cycle of the
  jump's window, so the cut no longer matched: each recovery pass restored the jump and
  released the window, and the next continued and laid them again (SPRUFE8B 3.10).
* Exact schedules decode a predicated full32 register return, `[B0] BNOP B3,N`. The
  schedule decodes returns as terminal branches, and only the unpredicated `BNOP` and
  the predicated `B` had a terminal form, so the predicated `BNOP` failed with "Unable
  to resolve constructor". Its terminal form takes the branch on the predicate and
  falls through otherwise, like the predicated `B.S2`.
* A `BNOP` whose delay window sets B3 to its return address is a call, as the same
  shape written with `B` already was (SPRUFE8B 3.12 BNOP, 4.2.6). It was lifted as a tail
  call or a jump, leaving its window and return point undecoded. A `BNOP n` window is the
  5 - n delay cycles after its NOPs (issue #69).
* A predicated register `B` that is not a call now gets its delay window, so work in its
  slots runs on both paths, as on hardware (SPRUFE8B 4.2.6, B). A jump such as
  `[A1] B B4` and a return such as `[A1] B B3` were lifted with their slots on the
  not-taken path only. A predicated return whose cut window no cut supports any more is
  still released when its full window cannot be proven (issue #70).

## 1.3.0 - 2026-11-18

### Changed

* Little-endian languages are now version 2.0: their context register is 64 bits, as in
  big-endian, with every field at the same position in both byte orders. That leaves
  room for new decode and recovery fields (bits 24-31 and 48-63). Programs saved with
  version 1 upgrade on open, with every context field carried over by name. Review the
  exact schedules of an upgraded program again, because a review hashes the context
  register's value.

### Added

* Exact schedules for functions whose entry packet issues a branch. Enabling
  re-decodes the entry's native delay-slot window as ordinary instructions the schedule
  issues, and disabling restores the native window and its annotations exactly. A window
  another function owns or starts in, or that any other reference enters, is refused.
  Such entries were refused as "Entry must be a defined instruction without native delay
  slots" (SPRUFE8B 3.5, 4.2.6).
* Exact schedules for `SAT`: E1 read and result, `CSR.SAT` and the `SSR` unit bit one
  cycle later (SPRUFE8B p. 437, Table 2-9, 2.9.13). Functions using it were refused as
  "unimplemented phase contract". An MVC write to CSR in the cycle the flags land, and a
  `SAT` whose flags land after a return, are refused.

### Fixed

* A conditional jump with a native delay window falls through to the next execute packet
  after the window, and its function keeps the whole window. Ghidra measures delay slots
  with the jump's own context ([Ghidra #10242](https://github.com/NationalSecurityAgency/ghidra/issues/10242)),
  so where 32-bit and compact instructions mix, the default fall-through landed inside
  the window or past the next instruction. That affected the packet primer's
  parallel-peer windows and windows that recovery did not lay itself (SPRUFE8B 3.5, 3.10).
* Retain a known predicate truth across an unknown-predicated write only when both the
  prior and written values have that truth; different-truth and unknown writes still
  widen facts, and nonzero writes break old-value aliases (SPRUFE8B 3.5, 3.7, 4.2.5).
* Exact schedules keep a predicate register's known truth across a backward branch when
  every write to it in the loop is predicated on that register with a condition false
  under that truth (`[R]` while R is zero, `[!R]` while nonzero), and no write to it is
  in flight: a predicated instruction whose condition is false does not write its
  destination, so the truth holds on every later pass (SPRUFE8B 3.5). After a
  software-pipelined `[A1] SUB A1,1,A1` / `[A1] B loop` countdown fell through, the
  widened facts let the next loop branch be taken, so an epilogue write landing with the
  kernel's first write was refused as "potential simultaneous memory/register writes".
  Any other write to the register, a guard on another register, or the opposite sense
  still widens.
* A label in hand-written TI assembly no longer starts a function when code falls into
  it or a conditional branch reaches it and nothing calls it (`C6000 Local Code Labels`).
  `cl6x` gives such labels the local, size-0 `STT_FUNC` symbol of a C static function,
  so each loop head, join and return point was a function and an unconditional `B` to
  one was a tail call, although B only loads the PC (SPRUFE8B 3.12). Entries nothing
  reaches, and targets of only an unconditional `B`, stay functions.
* Exact schedules refuse `B IRP` and `B NRP` as "unresolved branch target" instead of
  failing with a NullPointerException: their target is IRP or NRP, neither a register
  operand nor a displacement (SPRUFE8B pp. 155, 157).
* An MVK no longer keeps a data reference to its sign-extended low half when an
  unpredicated MVKH completes the register to another value within five cycles, with no
  read of the register and no branch landing in between: nothing uses that value as an
  address (`C6000 Low-Half References`; SPRUFE8B pp. 380, 383, 4.2.6).
* Continue a jump whose target only idles until a return issued in its delay window
  lands (the compiler's jump into a shared epilogue's NOP tail). Natively the jump kept
  only its own packet: taken, it skipped the rest of its window and ran through the NOPs
  into the following code, which are often another return's delay slots
  (SPRUFE8B 3.5, 4.2.6, NOP). The jump is continued only after the return's shortened window is proven and laid,
  and an analysis override whose condition no longer holds, or whose return's window is
  released for the decompiler, is removed.
* Exact schedules accept two writers of one register that land in the same cycle from
  different execute packets when their predicates test one unchanged value with opposite
  senses: only one of them writes (SPRUFE8B 3.6, 3.8.8). Such functions were refused as
  "potential simultaneous memory/register writes"; only writers issued in one packet
  were exempt.
* When a function exceeds Ghidra 12.2's overlap limit (issue #52) and the window the
  decompiler names is entered only at NOP slots, the window now ends before those slots
  instead of being released, so its other slots keep their delay-slot lifting. A NOP only
  idles (SPRUFE8B p. 388). Released windows lifted every slot after the transfer, so a
  return dropped their writes and a branch skipped them on its taken path.
* A `B` call whose delay window holds more than 24 instructions is recognized as a call.
  The call analyzer gave up on such windows, so the call was lifted as a jump. A window
  can hold 47: the rest of an eight-instruction execute packet and five full ones
  (SPRUFE8B 3.5).
* `C6000 Compact Packet Tails` no longer rolls back all of auto-analysis when it is
  cancelled while completing an execute packet (SPRUFE8B 3.5): it ended its own nested
  transaction uncommitted, and Ghidra then aborts the enclosing analysis transaction. It
  now checks every peer before writing, commits, and on a mismatch clears only that
  packet's new peers and logs it.
* A returning `B` call with an instruction in its own execute packet (`B f || STW`)
  left its delay slots and everything after its return point undecoded: C6000
  Delayed Calls decoded only from the next instruction, which is the companion.
  Decoding now also starts after the branch's execute packet (SPRUFE8B 3.5, 4.2.6).
* Tail calls that Shared Return Calls marks `CALL_RETURN` kept their delay slots
  undecoded, so the epilogue and outgoing arguments were missing from the caller.
  Their windows are now recovered unless the packet or window writes B3 other than
  by a load, or B3 holds the window's return address: such a `B` is a call
  (SPRUFE8B 4.2.6, B, ADDKPC).
* Cancelling auto-analysis while `C6000 Register Branch Flow` recovers delay windows, or
  while `C6000 Entered Delay Windows` releases them, no longer rolls back all of
  auto-analysis: both ended their own nested transaction uncommitted on any exception,
  and Ghidra then aborts the enclosing analysis transaction. Both now always commit. A
  window's rewrite never polls the monitor, and a window whose rewrite fails part-way is
  put back as it was before the failure is reported (SPRUFE8B 3.5, 4.2.6).

## 1.2.1-hotfix - 2026-11-10

### Fixed

* P-code emulation now matches SPRU733A for these cases (issue #40):
  * `SPINT`/`DPINT` round negative ties with an odd truncation away from zero (−1.5 → −2).
  * `DPINT`/`DPTRUNC` overflow for sources between 2^31 − 1 and 2^31 instead of wrapping
    to 8000 0000h.
  * `RCPSP`/`RSQRSP` keep the correct exponent just above 1.0.
  * `MVC` writes to ICR/ISR clear/set IFR bits, ECR clears EFR bits, and CSR keeps its
    read-only fields.
* The SPINT and reciprocal emulator regressions now run in the release suite.

### Changed

* Floating-point overflow follows IEEE 754: it is judged after rounding with an unbounded
  exponent, not on the exact value. `ADDSP` of LFPN + 1.0 now gives LFPN with INEX in
  round-to-nearest instead of +infinity with OVER, and DPSP/MPYSP/ADDDP/MPYDP results just
  above LFPN overflow only when RMODE rounds them up. SPRU733A does not say which rule the
  hardware uses; this replaces an unsourced before-rounding model (issue #40).

## 1.2.1 - 2026-11-09

### Added

* Exact schedules for the remaining 16 x 16 multiplies (`MPYH`, `MPYHL`, `MPYLH` and
  their unsigned and mixed-sign forms, E2), `ADDU`/`SUBU` (40-bit), `SUBC`,
  `RCPSP`/`RSQRSP` (E1) and `INTSPU` (E4). Functions using them were refused as
  "unimplemented phase contract", so their same-packet and delay-slot reads kept the
  native per-instruction lifting (issue #16; SPRUFE8B pp.135-136, 278, 320-350,
  411-412, 420-421, 539-540, 546-547).

### Changed

* Release builds and CI cover Ghidra 12.1.4 and 12.2. Ghidra 12.1.3 is no longer built
  or tested; use the 12.1.4 build on 12.1.x.

### Fixed

* Choose circular addressing at decode time: loads and stores through a base other
  than A4-A7/B4-B7, including the stack pointer B15, no longer run the AMR check in
  p-code, whose branches the decompiler had to prove dead (issue #38; SPRUFE8B 2.8.3).
  Run the `circular-addressing` and `nonalign-circular` fixtures, with repaired
  encoders and every base register.
* Take a displacement `B` to another function's entry as a call when its delay slots set
  B3 to earlier code of the same function, as in an idle loop; it was a tail call whose
  delay slots were not lifted (issue #41; SPRUFE8B 4.2.6). The `B` must be unpredicated
  and B3 set after every earlier branch's window (CALLP leaves none, BNOP n leaves 5-n
  cycles) by a write that executes and sets its low half.
* Recover the delay window of a call through a register (`B reg` whose slots set B3),
  predicated or not. Its argument and B3 set-up were lifted after the call, so the
  callee got no arguments (SPRUFE8B 4.2.6, B). A window ending before a fetch-packet
  header returns to the next execute packet, and the constant propagator no longer adds
  its own computed reference to a register call whose target the call analyzer did not
  prove.
* Keep functions with entered delay windows decompilable on Ghidra 12.2 (issue #52). A
  jump into another branch's delay slots is legal (SPRUFE8B 3.5, 4.2.6); the decompiler
  re-reads such a native window with an "overlaps instruction" warning and correct C,
  but Ghidra 12.2 counts each overlap as bad data and abandons a function after four.
  The new `C6000 Entered Delay Windows` analyzer decompiles each function holding an
  entered window and, only while it fails on an overlap, releases the window the error
  names (bookmarked under `C6000 Released Delay Window`), keeping the branch's override,
  references and slot annotations. Released branches lift their slots after the transfer,
  as before #34 and #48; every other window is kept.
* Take a `B B3` as a call when its delay slots set B3 to the address past the window, as
  for any other register (issue #39; SPRUFE8B 4.2.6, B; SPRU187U 7.4.2). It was always a
  return by name, so `fp()` and `callee()` reached through B3 decompiled to `return;`.
  An existing `RETURN` override on such a branch is reclassified, delay-window recovery
  keeps the call, and an exact schedule refuses it without a closed-call contract instead
  of returning. A `B B3` whose B3 already held the address past the window stays a jump.
* Write analyzer result counts (primed packets, recovered calls and windows, matched
  loops) to the application log instead of the analysis message log, so a clean
  auto-analysis no longer opens the "warnings/errors" summary dialog. Real
  diagnostics such as uncorrectable branches and refused schedules still appear there.
* Pass and return 64-bit values in register pairs (A5:A4, B5:B4, ...) as the C6000
  ABI does. A declared `long long` or `double` argument or result had no storage, and
  the prototype now uses the `standard` strategy, which keeps an untouched
  pass-through argument. Undeclared functions keep a 4-byte A4 result. A result over
  8 bytes is returned through a buffer whose address is passed in A3, with arguments
  still from A4 (cl6x 8.3.15 EABI); 4- and 8-byte structs return in A4 and A5:A4.
* Review an exact schedule whose covered code includes adjacent unowned code, such as
  the delay slots of a nested window that native recovery refused. Review required every
  covered byte in the function's body, and those slots belong to no function, so such a
  function kept the native lifting (SPRUFE8B 4.2.6). The code must continue the body
  straight-line and no function may own it; enable absorbs it. Absorbing is refused when
  a recorded schedule, or another schedule in the same review batch, reads the same fetch
  packets, since it would change the source that schedule pins. A schedule's pinned
  entry-source windows count as packets it reads, as its source hash reads them.

## 1.2.0 - 2026-11-02

### Added

* Native CodeBrowser C6000 plugin: dockable processor/packet/schedule inspector,
  entry setup, source-bound schedule preview/activation, validation and explicit
  disable. Use native tasks, analysis workers, Undo/Redo, program lifecycle events
  and bundled JavaHelp without invoking scripts. Add isolated headed integration
  checks for real actions/dialogs, persistence, tool restore and disposal, plus native
  Decompiler integration. Run the headed checks under a virtual display in CI.
* Keep fixture-only test scripts out of release archives and Script Manager,
  preserving the public corpus audit and batch tools.

### Upgrade notes

* The big-endian languages are version 2.0: their context register holds each
  compact slot's halfword (issue #31). Ghidra migrates `C6000:BE:32:default` and
  `C6000:BE:32:analysis` programs on open. Keep a packed backup, then re-run
  auto-analysis so delay windows and calls follow the corrected order.
  Little-endian languages are unchanged.

### Fixed

* Decode big-endian compact packets in program order (issue #31). Each word's first
  instruction is its 16 LSBs (SPRUFE8B 3.10.2.3, Table 3-16); big-endian slots were
  decoded from their own address, which holds the other one. The primer now copies
  each slot's halfword into context. Delay recovery corrects the fallthrough of any
  windowed branch whose generic value is wrong.
* Retire every delayed-call register result at its own latency, not only `LD*` in E5:
  `MPY32`/`ADDSP` (three delay slots), `MPYI` (eight), and `LL`/`CMTL` (four) to B3
  no longer let a later ADDKPC make a B a call, and a result landing after the callee
  is entered refuses the link (issue #23; SPRUFE8B 4.2, SPRU733A). Count a `BNOP`'s
  NOP cycles even when it is not taken, so a load beside it lands before the next
  packet (issue #30; SPRUFE8B 3.12 BNOP). 33 more timing cases per language and byte
  order.
* Remove code past an unpredicated register `B`/`BNOP`'s delay window from the
  branch's function once the branch is re-decoded as terminal (issue #32; SPRUFE8B
  4.2.6). The decoded tail stays in the listing: in a raw image it is usually the
  next function, and clearing it lost about half the code of a stock DSP image.
* Recover native delay windows for displacement `B` calls and predicated `B`/`BNOP`
  (issue #34). Their slot work was lifted after the transfer: a call saw stale
  arguments and a taken predicated branch skipped its slots. A delayed call now
  returns after its window. Register-target forms keep the conservative treatment.
* Prime compact packet context in ELF imports with initialized overlay blocks such as
  `.TI.section.flags`; rounding a fetch packet out of the overlay threw and left all
  compact code undecoded (issue #33). Overlays over OTHER, which hold no code, are
  no longer primed.
* Correct delayed-call recovery for E5 load writes and E1 packet snapshots
  (issues #23 and #24). A pending load can invalidate B3 after ADDKPC; a
  parallel target-register writer cannot change the branch's captured target.
  Preserve E1 base updates, pair aliases, predicate sample timing and protected
  load idle cycles (SPRUFE8B 3.5, 3.6, 3.10.2.2, Tables 4-6/4-10/4-11).
  Add 202 independent cases per language and byte order with native reference,
  callee creation, data preservation, read-only recognition and repeat-analysis
  checks.

* Refuse exact schedules whose execute packets reuse a functional unit or a
  memory-transfer path, including complementary and known-false predicates.
  Keep legal predicated writes on separate units and T1/T2 transfers available
  (SPRUFE8B 3.6, 3.8.1, 3.8.5; SPRU733A 3.6, 3.7.1, 3.7.4). Add an
  independent 244-case matrix across all timing profiles and byte orders,
  including compact RS selections, plus native-dialog refusal checks. Correct the
  earlier read-before-store fixture to use independent T1/T2 paths.

* Hide internal decoder and scheduler registers using native processor-spec flags
  so Listing assumptions show architectural state. Honor changed-byte scopes in
  packet analysis, propagate cancellation, and prime ordinary instructions in
  truncated raw fetch packets. Handle compact headers split across memory blocks,
  avoid context writes into sparse holes, clear obsolete compact halfword context,
  and handle the top of the 32-bit address space. Make ordinary schedule compilation
  cancellable. Guard immutable program views, retain review inputs for renewal,
  and clear validation messages after navigation or program edits.
* Add LE/BE `c67x` and `c67x-analysis` language variants so opted-in exact
  schedules omit the C64x/C674x cross-path stall on C67x/C67x+ (SPRU198K
  6.3.2.2). Preserve existing default/analysis timing and language-bound review
  contracts. Cover both cross paths, predicates, incoming hazards, pending loads
  and late DP reads. Preserve the CPU family when switching a comparison copy to
  concise floating-point analysis, with native-decompiler and conversion checks.
  Decoder legality filtering remains a documented limitation;
  C66x-specific instruction support remains a known gap.
* Decode `ABSDP`, `RCPDP` and `RSQRDP` as TI `cl6x` and GNU `as` encode them:
  `src2` the pair's odd register and `src1` its low register. Only the opcode
  diagram's even-`src2`, `src1` = 0 form decoded before; it is kept for
  compatibility, but no longer with `x` = 1, which decoded as the other register
  file although both halves are read in E1 (SPRUFE8B 2.4, 3.12 ABSDP, RCPDP, RSQRDP).
* Decode `DPINT`, `DPTRUNC` and `DPSP` only as TI `cl6x` and GNU `as` encode them:
  `src2` the pair's odd register and `src1` its even/low register. Any `src1` was
  decoded as the `src2` pair although the low word is read through `src1`
  (SPRUFE8B 3.12 DPINT/DPSP/DPTRUNC).
* Decode `MVC` writes to `TSCL`, which start the time-stamp counter
  (SPRUFE8B 2.9.14.2, although Table 3-27 marks `TSCL` read-only); they were
  Bad Instructions. The write and the
  `TSCL`/`TSCH` reads lift to the `c6000_tsc_start`, `c6000_tscl_read` and
  `c6000_tsch_read` userops, so the decompiler no longer folds two reads to one
  value. `TSCH` writes and nonzero-crhi forms stay undefined. `tools/verify.py`
  now also runs the existing `mvc-control` fixture.
* Decode `SMPY32` and `RPACK2` with an even destination. Predicated constructors now
  also exclude the reserved `creg=0, z=1` encoding, which unconditional-only opcodes
  use for bits 31:28, so the predicated twins `MPY32US` and `DMV` no longer shadow
  them and fail inside `Cond` (SPRUFE8B 3.6 Table 3-9; 3.12 MPY32US, SMPY32, DMV,
  RPACK2).
* The TI assembler gives every code label a size-0 `STT_FUNC` symbol. Load the
  compiler's branch and return labels (`$C$L<n>`, `$C$RL<n>`) as code labels instead
  of functions, so jumps to them are no longer marked as tail calls (SPRUFE8B 3.12
  B/BNOP). Other local symbols, such as C `static` functions, stay functions. The
  release suite imports the new ELF fixture in both byte orders.
* Honor native parallel-follower predicate guards in all delayed-call path proofs,
  including B3 constant tracking. Refuse skipped or unproved guarded links, retain
  known links across skipped copies, and cover all six predicates in both senses
  and byte orders (SPRUFE8B 3.5, 3.6, 4.2.6).
* Keep a delayed call's predicate fact across a parallel follower's guard and
  across constant writes (`MVK`, `MVKL`, `SUB x,x,dst`) that cannot change it on
  the call path, so compiler predicate-nullify calls stay calls and a never-taken
  jump at another call's return is not one (SPRUFE8B 3.5, 3.6, 3.12 MVK/SUB/ZERO,
  4.2.6).

## 1.1.1 - 2026-10-29

### Upgrade notes

* All four language definitions are version 1.2 so Ghidra rebuilds persisted
  prototypes after the compact predicate and memory corrections. Keep a packed
  backup and annotation inventory before the native language upgrade.
* Native migration can clear existing Bad Instruction error bookmarks while rebuilding
  prototypes. Record them in the backup inventory and restore them when preservation
  is required; migration does not enable exact schedules automatically.

### Added

* Schedule `PACK2` (`.L`/`.S`) and `PACKL4` (`.L`) with E1 input capture and
  writeback (SPRUFE8B pp. 397-398, 407-408).
* Add an explicit, source-bound post-return store-tail observation contract.
  Capture individual byte/word/pair effects and mature only pending E3 stores
  during one or two declared idle advances. Keep ordinary pending-return
  refusals and real caller traces unchanged (SPRUFE8B 3.5, 4.2.3, 4.2.6).
* Support `ANDN` on `.L`, `.S` and `.D` in exact packet schedules, with
  E1 source capture and writeback, predication and register aliases
  (SPRUFE8B pp. 145-146).
* Integrate exact same-packet reads and delayed writeback into reviewed function
  analysis using the existing scheduling backend. Add read-only report/review/apply
  tooling, a contract-gated analyzer, and source-bound decompiler injection.
  Refuse stale bytes, context, ownership, entry assumptions and alternate entries
  instead of silently using sequential effects (SPRUFE8B 3.5, 3.8.3 and 4.2).
* Integrate explicitly reviewed, complete closed-call traces into normal decompilation
  through `enableClosedCalls`, persisted plans and the existing source-bound injection
  library. Preserve separate callee owners; reject stale plans, interior entries and
  bounded-only traces. Cover native decompilation and pending stores in both endians.
* Schedule sequential leaf calls, including repeated callees, with invocation-specific
  continuations and live pipeline effects. Accept proved early MVK/MVKH/ADDKPC links.
* Schedule full32/compact CALLP on both S units: E1 A3/B3 link, next execute-packet
  return address and five implicit NOP advances. Track saved return-link provenance
  for returns through registers such as A0, while rejecting unknown/clobbered links
  (SPRUFE8B 3.5, 3.7, 3.8.10, 4.2.6, CALLP p.172).
* Prove closed-call register destinations and MVK/MVKH return links from packet-old
  raw p-code; expose the captured call destination and ordered link writers. Permit
  validated direct branches and ordinary counter loops within the callee while
  retaining separate owners and pending effects across call/return boundaries.
  Cover target overwrites, cross-path/B3 calls, split-link refusals and internal
  branches in both endians (SPRUFE8B 3.5, 3.7, 3.12, 4.2.6).

### Fixed

* Capture both ADDDP/SUBDP upper source words in E2, preserving E1 lower
  words and issue predicates, including reversed operands and cross-path
  stalls (SPRUFE8B Table 4-16; SPRU733A Table 4-12; issue #20).
* Read the implicit five NOPs of compact `BNOP` Sbu8/Sbu8c from their
  encoding when no scalar operand exists (SPRUFE8B Figures F-18/F-21).
  Share the count reader across exact schedules, caller-entry evidence and
  loop-buffer timing; preserve variable-count and full-width forms.
* Apply AMR circular addressing to compact memory forms, including per-byte
  wrapping for nonaligned transfers, and preserve the incoming store source
  when predecrement updates an overlapping pointer (SPRUFE8B 3.9.2 and
  Figures C-8..C-15). Add native and exact-schedule regressions in both byte
  orders, including E1 pointer and E5 load observations.
* Correct the skip-condition polarity of compact predicated `MVK` for `[A0]`,
  `[!A0]`, `[B0]` and `[!B0]` (SPRUFE8B Figure G-3). Add raw and exact-schedule
  regression checks for enabled, disabled and predicate-aliasing writes in both
  byte orders.
* Refine delayed-call B3 ownership, restrict header adjustments to the actual
  window boundary, and require stable predicates and unique incoming paths
  before propagating return-address constants (SPRUFE8B 3.5, 3.12 B).
* Display compact cross-path functional units with `X`, including A-side
  `ADDAW` from B15 (SPRUFE8B 3.8.3 and Figures C-17/C-18, D-4/D-5/D-7,
  E-5, F-22/F-23/F-29, G-1/G-2).
* Route `SUBU` opfield `0111111` through cross-path src1, and decode
  unconditional `GMPY4` by treating compound-M bit 28 as predicate z
  (SPRUFE8B 3.12 SUBU and Figure E-1).
* Mask scalar `SHL`, `SHR` and `SHRU` register counts to six bits
  (SPRUFE8B 3.12 SHL/SHR/SHRU).
* Correct the `DPSP` fixture's INEX expectation when rounding, update compact
  unit expectations, and run the added accuracy regressions in both byte orders.
* Decode predicated full32 register `B.S2` in the exact scheduler's terminal
  context. Capture the predicate and target before delay work while retaining
  the existing discovery form and unresolved-target refusals. Cover both
  predicate polarities and all six predicate registers in both endian modes
  (SPRUFE8B pp. 153-154, section 4.2.6).

### Validation

* `bitstream_flush` recovered through stock `DecompInterface`, compiled with TI CGT
  C6000 8.3.15 and compression enabled, matches the original production schedule
  and independent oracle in all 1,056 boundary/random/AMR cases. No custom export
  payload is needed. Pre-activation C and an output mutant remain failing controls.
* Add CALLP, repeated-callee, saved-link and native decompiler execution regressions
  in both endians, including stale-contract and unsafe-entry refusals. Correct an
  older CALLP fixture's illegal NOP 2 peer.
* Release verification covers Ghidra 12.1.3, 12.1.4 and 12.2 in both byte orders,
  including TI-assisted checks and the additional parallel-peer recovery fixtures.
  See [release guidance](docs/release.md) for commands and coverage counts.

### Limitations

* Exact packet timing requires explicit reviewed entry assumptions and source-bound
  activation. Default instruction lifting still handles parallel instructions
  separately; installing or migrating does not make every function timing-correct.
* Closed-call schedules permit up to sixteen sequential nonrecursive leaf calls.
  Nested calls, arbitrary indirect targets, memory-restored return links and more
  general caller control flow remain unsupported. Recovered helper effects may be
  inlined rather than emitted as separate C calls.
* Round-trip results establish behavior on the tested corpus, not byte-identical
  recompilation, exhaustive correctness, portable-C overflow safety or silicon
  equivalence. Floating-point status, reciprocal estimates, interrupts and exceptional
  software-loop behavior retain the [documented limitations](docs/limitations.md).

## 1.1 - 2026-10-28

### Upgrade notes

* All four C6000 language definitions are now version 1.1. Ghidra's native
  migration rebuilds persisted instruction prototypes after the compact
  operand fixes. Back up existing programs and annotations before upgrading;
  see [migration notes](docs/internals.md#language-prototype-migration).
* Full32 scalar move aliases now display their actual ADD/OR-zero encoding;
  equal-source SUB and 40-bit MV retain their own identities. Identically
  spelled short/long memory forms are exposed by `C6000EncodingInfo` and
  `C6000ExportEncodingInfo.java` (SPRUFE8B 2.4, 3.9.3, 3.10.2).

### Added

* Complete proved full-width and compact execute-packet peers during ordinary
  analysis, sharing the reviewed recovery proof and preserving code/data, context
  and function bodies. Stop speculative compact fetch-tail decoding.
* Add opt-in physical parallel-peer reports and reviewed-hash recovery of undefined
  instructions while retaining existing code/data, context and annotations
  (SPRUFE8B 3.5, 3.10.2, 3.10.4).
* Add strict source-bound caller/store-tail traces with exact callee/caller byte
  ownership, native E3 store carry, and verified final caller E1 hazards
  (SPRUFE8B 3.5, 3.10, 4.2.3, 4.2.5, 4.2.6).
* Explicit per-function exact packet schedules preserve raw exact p-code,
  captured predicates and targets, old parallel reads, delayed sticky flags,
  X-path stalls and overlapping B/BNOP transfers. Supported phases extend
  through E10, including independent DP read ports and split writes.
  Enabling requires a documented drained entry and incoming E1 hazards,
  preserves annotations transactionally, and refuses unsupported contracts
  (SPRUFE8B 3.5, 3.8, 4.2). See [pipeline schedules](docs/pipeline-schedules.md).
* Normal SPLOOP/D/W loading, fetch and drain states in the exact compiler,
  including delayed ILC/RILC availability, SPMASK overlays, branch aborts and
  zero/one-iteration padding. Nested reload and interrupt/restart remain
  guarded there (SPRUFE8B 7.4, 7.7–7.10, 7.14).
* Read-only closed direct-call traces carry pending effects across explicit
  call/return windows, with byte hashes, ownership bounds and raw p-code link
  proof. Ordinary function schedules retain their call and pending-return
  guards (SPRUFE8B 3.5, 3.7, 3.10.2, 4.2).
* `tools/verify.py` builds and tests the packaged extension in an isolated
  Ghidra copy in both endian modes, retaining logs, completion markers and a
  JSON summary with the archive SHA-256. `--with-ti` requires the additional
  TI-assembled regressions. CI runs the core suite on all supported versions.
* Archive checks require all four compiled languages, loader opinion, extension
  JAR and compatibility metadata, and reject research, scratch and cache files.
  Builds record the exact Gradle output path for subsequent verification.

### Fixed

* Verification scripts use the PcodeExecutor constructor and PcodeProgram
  entry point shared by Ghidra 12.1.x and 12.2, so newer pipeline checks compile
  on the full support matrix.
* Recover proven unconditional B/BNOP delay windows, including IRP/NRP,
  parallel companions, multicycle NOPs, ADDKPC, PROT loads and compact
  headers. Targets and predicates are captured before delay work; tail stores
  and interrupt-enable restoration remain in the owning function. Unsafe
  windows are refused without changing annotations, references or explicit
  fallthrough overrides (SPRUFE8B 3.5, 3.10.2, 4.2.6).
* CALLP runs parallel companions before writing its A3/B3 link and links to
  the next execute packet. Mixed-width native instruction stepping retains
  a Ghidra delay-context limitation; listing p-code is tested directly.
* Correct compact stack offsets, signed five-bit MVK, narrow-store widths,
  operand display, absolute five-bit move registers, fixed low comparison
  destinations and unscaled NDW offset/indirect addresses
  (SPRUFE8B C-9/C-11/C-16, D-7/D-9/D-10, G-1/G-2/G-4, MVK/STB/STH).
* Updating loads capture addresses before base modification and preserve
  distinct E1 pointer and E5 data writes when registers alias
  (SPRUFE8B 4.2.5/Table 4-10). Constant-copy recovery follows the corrected
  full32 move primitives.
* Schedule ROTL result writes in E2 and MPYLI pair writes simultaneously in
  E4, with E1 operand capture, E1-only .M occupancy and conflicting write-port
  refusals (SPRUFE8B pp. 344–345, 414–415, 3.8.2).
* Schedule BDEC/BPOS from the raw predicate/counter decision through five
  delay cycles, with gated E1 decrement and cross-path hazards
  (SPRUFE8B pp. 159–160, 170–171).
* Prune only proved-impossible loading exits and predicate paths, retaining
  E1 snapshots, delayed counter visibility, unit checks and pending-return
  guards. Prove dominated constant suffixes across closed earlier control
  flow; reject invalid counted-loop ILC accesses (SPRUFE8B 3.5, 3.8.8,
  7.4.3, 7.9.7).
* Correct MVD E4 timing, SPLOOPW counter preservation and delayed predicate
  sampling, displacement-BNOP restart recognition and compact NOP counts
  (SPRUFE8B MVD pipeline, 7.7–7.10, 7.14, Appendix H).
* Resume normal post-loop dispatch at the SPKERNEL execution delay without
  an inferred six-cycle frontend refill. Refuse buffered missed X-path/AMR
  stalls while retaining program-memory stalls
  (SPRUFE8B p. 481, 7.9.4, 7.12, 7.15.2).
* Reject conflicting multicycle NOP generators before context priming or
  pipeline issue; preserve equal counts and whole execute-packet prefix timing
  (SPRUFE8B 3.5, 3.8.10, 3.8.11.5, 4.2.6).

## 1.0.4 - 2026-10-27

### Fixed
* Exact single-precision arithmetic and shared DP-to-SP rounding use equivalent
  mask selections instead of internal p-code branch trees. This preserves
  rounding modes, special values and sticky status flags while allowing large
  float-heavy functions to decompile within the same timeout. Add alias,
  predication and branch-count regressions, and repair affected fixture lookup
  for the predicated decoder constructors.
* Repair generated switch overrides left on a former function after body
  recovery. Code-verified cases are rehomed or retained outside function
  namespaces without deleting labels; detached duplicates no longer crash
  the decompiler. Correct override ownership checks also avoid rewriting
  unchanged tables on repeated analysis.
* Computed branch references no longer retain the intermediate signed `MVK`
  value when an adjacent, unconditional `MVKH` proves the final target.
  Predicated writes, same-execute-packet writes and alternate entries remain
  conservative. Synthetic reference tests cover both endian modes.
* Builds reject an explicitly configured JDK older than Ghidra's declared
  minimum, with a clear error before SLEIGH starts. JDK discovery reads
  `application.java.min` and handles missing JDKs without silently exiting.

### Added
* Read-only closed caller-continuation traces retain captured STW E3 effects
  through an immutable caller window and export the exit PC/E1 hazards.
  Ordinary function scheduling keeps its pending-return refusal.
* `C6000RepairSwitchOverrides.java` repairs legacy switch metadata on a copy.
  `C6000UseAnalysisLanguage.java` prepares a reading copy with concise float
  p-code, keeping the default language available for detailed semantic checks.

## 1.0.3 - 2026-10-27

### Added
* Ghidra 12.2 release and CI builds using JDK 25. The build script selects the
  JDK version required by the chosen Ghidra installation.

### Fixed
* Late branch analysis walks loaded, initialized memory instead of a min/max
  address range, avoiding exceptions when ELF metadata occupies another
  address space.
* A predicated register `B` (`src2`, `IRP`, `NRP`) or `BNOP`, and `SWE` /
  `SWENR`, no longer make the decompiler fail the whole function with "Bad
  relative branch" when it cannot resolve the indirect jump: they skip to
  `inst_next` instead of a label after `goto [x]`
  (`predicated-register-branch.py`, `C6000PredicatedBranchTest.java`).
* Predicated `B IRP` and `B NRP` decode; they decoded as `B` through `B6` / `B7`.
* `B IRP` restores GIE from PGIE and `B NRP` sets NMIE.

## 1.0.2 - 2026-10-13

### Added
* `C6000JumpTableAnalyzer` recovers the TI compiler's switch dispatch
  (guarded `LDW` from an `MVK`/`MVKH` table, then `B`/`BNOP` through the
  entry), recovering bounded case targets and their function ownership when
  Ghidra's decompiler cannot infer the table bounds.
* CI builds and smoke-tests the extension against Ghidra 12.1.4 as well as
  12.1.3, and uploads one zip per version.

### Fixed
* The CI artifact no longer contains the Ghidra release, JDK and scratch
  directories that the workflow unpacked into the workspace. It was about
  920 MB; the extension itself is about 1 MB.
* A 32-bit `BNOP` in a header-based (compact) fetch packet scaled its
  displacement by four instead of two, sending its CFG edge into the middle
  of an instruction.
* `B` calls whose delay slots set `B3` are modelled as returning calls: the
  register form (`B reg` after `MVKL`/`MVKH`), the `MVK`/`MVKH` return-address
  form, and unconditional immediate calls, which previously had no
  fall-through and left their delay slots and the code after the return
  point undecoded.
* Predicated `B` calls are recognised in the compiler's if/else call-pair
  form, with the other arm in the delay slots and `B3` set before the branch.
  Ambiguous overlapping-branch schedules remain conservative.
* In a "call Y if p, else jump to X" pair only the call arm is a call; the
  jump arm (a register arm is always the call; otherwise the nearer target)
  stays a conditional jump, so the local else-block is no longer made a
  function.
* Register calls get their `MVK`/`MVKH` target reference in far more cases:
  the look-back now decodes undecoded delay slots and pointer-typed code
  words, follows register moves, skips oppositely predicated writes, and is
  retried when preceding code is discovered. Targets loaded from memory or
  supplied by another routine may remain unresolved.
* Ghidra's heuristic non-returning-function discovery is disabled for the
  C6000 languages. It marked returning functions no-return because a call's
  delay slots and return point are not decoded until the call is
  recognised, then cleared code needed to establish their fall-through.

### Documentation
* The README is now a short overview (install, quick start, features and
  limitations, build, testing). Verification guidance and test fixtures moved to
  `docs/verification.md`, packet, delay-slot, branch and ABI internals to
  `docs/internals.md`, and the detailed limitations (including the
  software-loop model) to `docs/limitations.md`.
* Added `CONTRIBUTING.md` and a "wrong decode or semantics" issue template.
* The ELF loader opinion is documented as matching little-endian files only.

## 1.0.0 - 2026-09-25

First public release.

### Added
* `C6000:LE:32:default` and `C6000:BE:32:default` SLEIGH languages for the
  TMS320C674x DSP and, by subsetting, the C64x, C64x+, C67x and C67x+ parts.
* `C6000:LE:32:analysis` and `C6000:BE:32:analysis` variants with native
  single-precision p-code and an opaque status userop, for reading
  float-heavy code.
* Broad 32-bit instruction decode generated from the SPRUFE8B section 3.12
  opcode tables, with unresolved encodings left undefined for investigation.
* Compact 16-bit instruction decode driven by the fetch-packet header word,
  covering supported forms in SPRUFE8B appendices C.4, D.4, E.4, F.4,
  G.3 and H.4; unsupported halfwords remain undefined.
* The context fields are declared `noflow`. Without that attribute a compact
  slot reached by fall-through inherits the preceding instruction's decode
  parameters and is decoded as a 32-bit instruction.
* Modelled p-code semantics for the integer ALU, immediate construction,
  scalar loads and stores, single-precision floating point arithmetic and
  conversions, branches and calls; other decoded instructions lift to an
  explicit userop rather than to silently wrong data flow.
* `C6000PacketAnalyzer` and `C6000PacketContext`, which prime the decode
  context from compact fetch-packet headers before disassembly.
* ELF loader opinion mapping `EM_TI_C6000` (140) to the language.
* C6000 compiler spec implementing the TI C6000 calling convention.
* `C6000CorpusTest.java` corpus/regression script and a GNU-objdump oracle
  harness, plus GitHub Actions CI that builds against Ghidra 12.x and runs the
  tests.
* `tools/gen_fid.py`, which generates Function ID databases from a TI
  run-time library built with the TI C6000 code generation tools.

### Fixed
* `DPINT` and `DPTRUNC` now read a double-precision register pair and perform
  FADCR-aware integer conversion, including ties-to-even and warning bits.
* `SPINT` and `SPTRUNC` now use the `.L1`/`.L2` FADCR rounding mode and update
  conversion warning bits, including exceptional inputs. `SPINT` no longer
  lifts to an unimplemented-operation placeholder.
* `NORM` now distinguishes 32-bit and 40-bit sources, counts the 40-bit sign
  width correctly, and `SUBU` writes its signed 40-bit result to a register
  pair. Both have executable p-code instead of placeholders.
* Compact fetch-packet headers now decode as `CPKT` instead of selecting a
  conflicting 32-bit opcode before predicate validation.
* Signed immediates and `ADDKPC` operands use their documented fields; .L-unit
  five-bit constants use bits 22..18. Both directions of 32-bit `MVC` now move
  between general and named control registers, including `FADCR` and `FMCR`.
* Immediate exports carry a four-byte width, so Ghidra's constant-propagation
  analyzers no longer receive zero-width p-code operands.
* The register forms of `CLR`, `EXT`, `EXTU` and `SET` display their packed
  `src1` operand and lift the manual's bit-field operation; previously they
  showed two immediate fields from the sibling encoding.
* Packet-context priming is safe to repeat on a disassembled image, and the
  headless corpus test reports actual p-code placeholders and unknown slots,
  including Ghidra's one-byte `BAD-Instruction` rows.
* `.D` arithmetic units now use the `s` bit, while short load/store units use
  `y`; long load/store forms execute on `.D2`. Memory offsets are scaled by
  access size, and pre/post addressing modes update the base register after the
  transfer, preserving the old store source when it is also the base register.
* Scalar stores now read their data source from bits 27..23 instead of the
  base-register field at bits 22..18. Doubleword load/store operands display
  register pairs in 32-bit and compact formats; nonaligned doubleword address
  offsets follow their encoded scaled/nonscaled `sc` bit. Odd pair selectors
  in 32-bit aligned doubleword forms remain undefined.
* The TI manual's grouped `LDB(U)` and `LDH(U)` headings now produce separate
  signed and unsigned load encodings. The previous table parse attached their
  layouts to the preceding mnemonics and could display `LDW` words as `INTSPU`.
  Generation now rejects memory diagrams under nonmemory mnemonics and any
  unconstrained opcode-map field.
* CI's synthetic image test scans its actual 48-byte size and checks that all
  12 instructions decode.
* Doubleword loads and stores now lift 64-bit transfers through overlapping
  odd:even register pairs in both endian modes, including compact stack forms.
  The common 16-bit integer multiplies and 16-by-32 `MPYLI` also lift to
  p-code; immediate multiply operands are signed five-bit values.
* `BDEC` and `BPOS` now show their signed fetch-packet-relative target and
  lift conditional branch behavior. Compact register `BNOP` branches through
  its register; compact `MVC` to `ILC` and common `EXT`/`EXTU` forms lift to
  data-flow p-code.
* Selected double-precision conversions, addition, multiplication and
  comparisons now use pair operands and floating-point p-code. `MVD` lifts
  its register copy; pipeline timing and floating-point status side effects
  remain outside the p-code model.
* `SUBC`, `ROTL` and `LMBD` lift their documented integer operations.
  Nonaligned word loads and stores use word-scaled offsets; nonaligned
  doubleword transfers retain doubleword scaling.
* `MPYLHU` and `PACK2` now lift their unsigned halfword multiply and
  halfword packing operations.
* The reverse cross-path forms of `SUBDP` now display the architectural
  source order and lift 64-bit subtraction. `MPY32` and its mixed-sign and
  unsigned pair forms, `MPYHL`/`MPYLH` halfword forms, `MPYI`, and `PACKL4`
  now lift their documented integer operations.

### Notes
* `buildExtension` does not compile SLEIGH. `tools/build.sh` (and CI) run
  `support/sleigh` first and verify that the produced zip contains the `.sla`
  files; without them the zip installs cleanly and then fails at import with
  "Unsupported language".
* Ghidra 12.1.3 has a defect in `GhidraSourceBundle.tryBuild`: a `javac`
  diagnostic with a null source turns the whole script-directory build into a
  `NullPointerException`, which is reported as the misleading
  `Failed to get OSGi bundle containing script`. If every Java script in a
  script directory suddenly stops loading, look for a compile error in a
  sibling `.java` file.
