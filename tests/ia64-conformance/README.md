# IA-64 conformance tests

The required IA-64 gate is self-contained in this QEMU repository. It has no
filesystem or runtime dependency on the private Vibtanium suitcase repository.

In an MSYS2 MINGW64 shell with `curl`, `pdftotext`, and the normal QEMU build
dependencies installed, configure, build, fetch the public manuals, run all 59
required registrations, and generate sanitized closure reports with:

```sh
./scripts/ia64-build-and-test.sh
```

For an existing `build-ia64-debug` tree, run only the required gate with:

```sh
./scripts/ia64-run-required-conformance.sh
```

Reports are written to `conformance-results/`. Raw Meson commands and
environment values are not copied into them. `QEMU_IA64_BUILD_DIR`,
`QEMU_IA64_CONFORMANCE_OUTPUT_DIR`, `QEMU_IA64_CONFORMANCE_PROFILE`, and
`QEMU_IA64_TEST_JOBS` override the corresponding defaults.
`QEMU_IA64_BUILD_JOBS` changes the conservative four-job build parallelism.
`QEMU_IA64_AR` overrides the archiver; the public build wrapper prefers
`llvm-ar` when installed because current MINGW64 GNU `ar` can spend more than
15 minutes rebuilding QEMU's thin utility archive without producing output.

Implementation-surface schema version 2 treats only source-proven live or
guest-selectable state as implemented. Register storage alone is not enough.
Each register row names one of 20 bank/scalar coverage groups so table-driven
tests can close complete architectural index spaces without creating one test
executable per register.

The first twenty exact speculation contracts live in
`speculation-semantic-tranche.json`. Their public data-plane registration
covers all four integer widths through NaTPage deferral, base updates, NaT
state, and checked recovery without requiring the architecturally
implementation-specific data portion of a NaT'ed GR. A second 20-program
matrix proves that `.s` and `.sa` translated misses and alignment conditions
remain immediate in the no-recovery model. Its alignment half runs both alone
and below an always-deferred NaTPage condition, so deferral cannot incorrectly
hide a lower non-deferred fault. The third contract adds 62 complete
width/class probes for Page Not Present, Key Miss, Key Permission, Access
Rights, Access Bit, and Data Debug. Debug runs aligned, with a concurrent
non-deferred Unaligned condition, and below an always-deferred NaTPage to lock
both priority directions. The fourth adds 16 complete width/class probes for
short-format VHPT selection: a mapped invalid leaf must raise Data TLB, while
missing walker backing must raise VHPT Translation, with exact original IFA,
derived IHA, default ITIR, R|SP ISR, and fault-slot evidence. The fifth adds
the 72-program recovery-model truth table for `DCR.dm`: all
three translation selections, all integer widths and both classes must defer
only when both code-page ITLB.ed and DCR.dm are set. Deferred cases take
checked recovery after the exact base update; either clear input produces the
exact immediate vector and matching ISR.ed. The sixth adds the 144-program
recovery-model truth tables for `DCR.dp/dk/dx/dr/da/dd`: every integer width
and both classes cross Page Not Present, Key Miss, Key Permission, Access
Rights, Access Bit, and Data Debug with the condition-specific bit plus
ITLB.ed set, that DCR bit clear, and ITLB.ed clear. It therefore distinguishes
all six DCR bits and proves both hardware deferral with checked recovery and
precise immediate delivery. The seventh adds the complete 78-program
`PSR.ic=0` always-defer matrix from Volume 2 Table 5-4: all nine translated
conditions cover every integer width and both classes, while Unaligned covers
all six naturally applicable width/class forms. Each case proves no delivered
interruption, destination NaT, exact width-sized base retirement, CHK.S or
absent-entry CHK.A recovery, preserved condition controls, and an exact zero
DCR. The matching `PSR.ic=1` rows provide the immediate-fault contrast.
The eighth adds the complete 110-program first-restart `PSR.ed=1` matrix:
all eight integer `.s`/`.sa` width/class forms cross a valid WB reference and
the thirteen non-alignment Table 5-4 conditions, while Unaligned covers its
six naturally applicable forms. Every case proves that software-forced
deferral precedes address, translation, protection, debug, alignment, and
data access; retires the exact update; purges the corresponding `.sa` ALAT
entry; clears `PSR.ed`; takes checked recovery; and lets the following
same-form safe load return its exact WB value normally.
The ninth adds the complete 96-program non-faulting integer matrix from
Volume 2 Tables 4-13, 4-14, and 4-17. Thirty-six `.s`/`.a`/`.sa` cases cross
all widths with speculative WB, limited WBL, and non-speculative UC; sixty
`.c.clr`/`.c.clr.acq`/`.c.nc` cases cover every defined exact-hit and clean-
miss class. Exact values, advanced-load zero, NaT, post-increments, mandatory
entry absence, and the architecture-permitted pessimistic ALAT-check outcomes
are checked without assuming that a conforming implementation must report a
hit.
The tenth adds 15 ALAT-identity programs: distinct GR targets across all four
widths, same-number GR/FR type separation in both directions, address- and
size-mismatched clear checks across all widths, and banked GR16 physical-tag
identity. The bank case caught and now guards the former false hit in which a
bank-0 advanced load could satisfy a bank-1 `chk.a`; PSR.bn transitions now
perform an architecturally permitted conservative eviction of GR16--GR31
entries. Undefined mismatch destination data is deliberately not an oracle.
The eleventh adds 11 invalidation programs. Matching-width `st1/2/4/8` and
successful `xchg1/2/4/8` commit exact values and force an overlapping-entry
miss, while `invala` and the GR/FR forms of `invala.e` force mandatory misses
for all or selected represented tags. The twelfth adds 16 nonzero-predicate
programs: every integer `.a` and `.sa` width executes through true p1, while
false p2 points at an otherwise faulting unimplemented address and must leave
destination, NaT, base, memory-access, and ALAT state unchanged.
The thirteenth adds all 16 integer advanced-load/store width pairs through two
distinct virtual pages mapped to one physical page. Exact store/reload values
and mandatory CHK.A recovery prove that invalidation uses physical ranges,
not coincident virtual addresses. The fourteenth adds 176 overlap/semaphore
programs: all 104 nonempty byte intersections across the sixteen load/store
width pairs, sixteen cross-width XCHG cases, thirty-two acquire/release
successful CMPXCHG cases, eight failed-CMPXCHG controls, and sixteen
acquire/release FETCHADD cases. Successful stores must force recovery; failed
CMPXCHG must leave memory unchanged while its ALAT edge remains within
Intel's explicit pessimistic-eviction allowance. The fifteenth adds every
legal nonzero GR rotating-region size, one rotating-FR case, and one stacked
call-frame transition. Each prevents an ALAT tag for the former physical
target from creating a false hit under the remapped logical r32 or f32 name.
The sixteenth and seventeenth jointly add 96 physical-register-stack programs,
one for every legal SOF=SOL size. They target every one of QEMU's 96 physical
stacked-register slots and use the complete `96 / gcd(96, SOF)` call cycle to
return to the same physical phase. Deep calls force real RSE backing-store
spills, including RNAT collection-slot crossings; the unwind verifies the
exact spilled word, restored value and NaT, terminal CFM, BOF, BSP, BSPSTORE,
and backing-store load pointer. A descendant CHK.A must recover rather than
falsely hit the parent tag after physical-stack wrap, while Intel's permitted
earlier pessimistic eviction remains valid.
The eighteenth through twentieth contracts close the remaining applicable
single-processor ALAT software-coherency sequences. One rotation creates GR
and FR physical-target aliases across `clrrrb`, followed by the required full
`invala`. One virtual page is proven to move between distinct physical pages
through `ptc.l` and `itc.d` before old GR/FR tags are invalidated. Finally, a
real timer involuntarily interrupts CPL3 after user GR/FR advanced loads; the
handler reuses both target names, executes `invala`, and returns by typed
`rfi` to mandatory user misses. Remote stores, semaphores, and `ptc.ga` are
multiprocessor coherence obligations and are not applicable to the enforced
single-CPU `vibtanium-strict-up` and `vibtanium-default-up` profiles.
A separate five-case `alat-lifecycle-tranche.json` now owns the lifecycle
boundary instead of overloading instruction-semantic rows. Its E2 program
establishes physical GR20 and FR21 tags, stops on a real GDB breakpoint,
saves in one QEMU, loads in a fresh QEMU, accepts the same-type hit or
pessimistic miss Intel permits, and requires cross-type GR/FR checks to
recover. Its focused E1 registration round-trips all eight legal GR/FR width
classes at target and cursor boundaries, both address modes, and exact
persistent fields, then rejects representative lower, gap, upper, version,
and cursor members of every malformed semantic partition on both load and
save. Inactive non-type payload remains explicitly ignored rather than being
misclassified as malformed. A second focused E1 registration requires every
persistent and transient ALAT reset field to equal an independent zero literal
after the CPU environment begins nonzero. Two further E2 probes issue a real
HMP `system_reset` with loader-independent RAM continuity and run one icount
recording through two fresh replays. Reset must reject both stale typed tags;
each replay must exactly reproduce the recorded architectural result while
retaining Intel's permitted same-type hit-or-miss result class.
The register tranche also executes Intel Volume 2 sections 6.11.1 and 6.11.2
as one interrupted-context oracle. Four BREAK handlers cover an empty frame,
an immediate RNAT slot, one complete RNAT collection, and the maximum
96-register frame with both completed and partial collections. Each handler
saves the interrupted RSE record, uses a disjoint equal-offset backing store,
executes the exact COVER/FLUSHRS/LOADRS switch-away and return sequences, and
returns through typed RFI. The continuation verifies every defined backing
word and RNAT bit, every logical value and NaT, the restored CFM/BOF/RSE
pointers, and that the interrupted backing memory was never modified.
Other data-plane cases remain
candidate evidence until they receive equally atomic contracts and complete
variant matrices.

The long-running tests are intentionally quiet while their internal TAP
matrices execute. On the 2026-07-22 default four-worker public gate after the
ALAT software-coherency checkpoint, `test-ia64-system-tcg` took 49.56 seconds,
`test-ia64-full-tcg` 50.62 seconds, and `test-ia64-register-tcg` 48.90
seconds. The established data-plane shard passed 637 subtests in 180.23
seconds, checkpoint 28 passed 42 in 12.50 seconds, checkpoint 29 passed 206
in 58.77 seconds, checkpoint 30 passed 96 in 36.76 seconds, and checkpoint 32
passed three in 2.30 seconds; all 54 selected tests passed in 200.536 seconds
of report wall time. The ALAT lifecycle checkpoint raises the current gate to
56/56 in 205.622 seconds:
`test-ia64-system-tcg` took 49.93 seconds, `test-ia64-full-tcg` 52.79 seconds,
`test-ia64-register-tcg` 50.87 seconds, the 637-case data-plane shard 183.21
seconds, the focused two-case ALAT VMState registration 0.07 seconds, and the
lifecycle contract validator 0.37 seconds. The 117-row catalogue now has 88
exact row-closing claims. Its 2,112-row executed join contains 88
`implemented-tested`, 1,974 `implemented-untested`, 7
`advertised-untested`, and 43 `known-unimplemented` rows, leaving 1,981
blockers with no test or infrastructure failure.

The reset/replay checkpoint raises the current gate to 57/57 in 206.529
seconds: `test-ia64-full-tcg` passed 38 subtests in 55.10 seconds, the focused
reset image passed in 0.04 seconds, `test-ia64-system-tcg` took 49.87 seconds,
`test-ia64-register-tcg` 51.48 seconds, and the 637-case data-plane shard
184.69 seconds. The 120-row catalogue has 91 exact row-closing claims. Its
2,115-row executed join contains 91 `implemented-tested`, 1,974
`implemented-untested`, 7 `advertised-untested`, and 43
`known-unimplemented` rows, leaving 1,981 blockers with no test or
infrastructure failure. The former single 180-second registration limit was
an infrastructure timeout once the
combined inventory reached 679 programs, not a semantic hang. The current
986-program inventory remains deliberately split by evidence ownership. The
gate defaults to four workers to avoid unrestricted host contention without
weakening any per-test timeout. The
RSE suites include five fresh-process
save/load/RFI continuations across mandatory-instruction and current-frame
fill faults. With parallel execution Meson may pause near the end of the
progress display until these processes complete; the per-test timeouts still
detect a genuine hang.

The PMU selector/PAL checkpoint raises the gate to 58/58 in 203.5 seconds.
`test-ia64-system-tcg` passes 17 subtests in 51.35 seconds, including every
one of the 256 PMC and 256 PMD selectors plus exact `PAL_PERF_MON_INFO`
success and invalid-argument buffers. Full-TCG passes 38 subtests in 53.56
seconds, register-TCG 25 in 49.21 seconds, and the 637-case data-plane shard
in 181.22 seconds. The 123-row catalogue has 94 exact row-closing claims. Its
2,106-row executed join contains 94 `implemented-tested`, 1,462
`implemented-untested`, 7 `advertised-untested`, and 543
`known-unimplemented` rows, leaving 1,469 blockers and no test or
infrastructure failure. The 512-blocker reduction is mainly an inventory
correction: 500 PMC/PMD selectors that the product does not implement are now
classified honestly instead of being counted as live untested storage, while
the twelve implemented selectors and PAL discovery contract have passing E2
ownership. Performance-event selection and counting remain unadvertised and
unclaimed.

The CPUID selector checkpoint raises the gate to 59/59 in 196.848 seconds of
runtime report time (307 seconds including the one-time host rebuild).
`test-ia64-system-tcg` passes 18 subtests in 50.21 seconds. Its new program
checks the exact CPUID0-4 profile, proves that selector bits above bit 7 are
ignored, and validates/repairs all 251 Reserved Register/Field faults for
CPUID5-255. CPUID4 now advertises the implemented long-branch facility along
with the existing `cz` and `x2` facilities. The 124-row catalogue has 95
exact row-closing claims. Its 2,103-row executed join contains 95
`implemented-tested`, 1,458 `implemented-untested`, 7
`advertised-untested`, and 543 `known-unimplemented` rows, leaving 1,465
blockers and no test or infrastructure failure. PMU profile logic now lives
in a shared module, so migration post-load sanitization is linked and tested
without coupling the VMState unit to the target-only system transaction
module.

The debug-register selector/PAL checkpoint raises the public gate to 60/60 in
197.746 seconds. `test-ia64-system-tcg` passes 20 subtests in 55.70 seconds.
Its two new selector programs give every IBR0-15 and DBR0-15 a distinct valid
image, delay readback until the complete bank is populated, verify the exact
even-address and odd-control masks, prove selector bits above bit 7 are
ignored, and execute both access directions for every reserved selector
16-255. Each bank therefore validates 480 Reserved Register/Field faults and
repairs every CR.IIP with RFI; the combined run requires zero ISR or value
mismatches. Existing admission, NaT, privilege, reserved-form, and real
instruction/data debug probes remain part of the declared evidence set.

`PAL_DEBUG_INFO` now derives its eight instruction and eight data pair counts
from the product register-bank constants, receives all three PAL arguments,
and rejects each nonzero reserved argument with status -2. The five atomic
catalogue rows and their validator are entirely public and require no
Vibtanium checkout. Broader debug address/access variants, hardware-debugger
pair reservation, and IA-32 debug behavior remain explicit later units. The
129-row catalogue has 100 exact row-closing claims. Its 2,074-row join contains
100 `implemented-tested`, 1,424 `implemented-untested`, 7
`advertised-untested`, and 543 `known-unimplemented` rows, leaving 1,431
blockers with no test or infrastructure failure.

The protection-key checkpoint raises the public gate to 61/61 in 194.468
seconds. `test-ia64-system-tcg` passes 23 subtests in 57.58 seconds. Its new
register-file program gives PKR0-15 distinct valid keys before delayed
readback, proves that only selector bits7:0 participate, exercises read and
write for every nonexistent selector 16-255, and rejects all 36 reserved
field bits without changing a committed sentinel. A second state machine
proves that a new valid duplicate key clears only the old entry's valid bit;
an invalid same-key write neither steals ownership nor mutates prior fields.

Translated read, write, and instruction-fetch programs independently select
read-disable, write-disable, execute-disable, data-key-miss, and
instruction-key-miss paths. Their handlers publish exact fault metadata,
install a permissive key, issue the access-class serialization, and RFI to a
single successful retry. The instruction handler has its own identity ITR
and distinct key because interruption delivery preserves `PSR.it` and
`PSR.pk`. Separate cases prove that clearing `PSR.pk` bypasses both data and
instruction key checks.

Static inspection also found that `PAL_VM_SUMMARY` encoded PKR/DTR/ITR counts
where the PAL ABI requires maximum indices. It now returns 15/7/7, validates
all three reserved arguments, and is cross-checked against the executable
register banks. Five new public atomic contracts raise the catalogue to 134
rows and 105 row-closing claims. The 2,061-row executed join contains 105
`implemented-tested`, 1,406 `implemented-untested`, 7
`advertised-untested`, and 543 `known-unimplemented` rows, leaving 1,413
blockers. No Vibtanium checkout, restricted source, private workflow, or
guest-specific behavior is needed to build or run this coverage.
