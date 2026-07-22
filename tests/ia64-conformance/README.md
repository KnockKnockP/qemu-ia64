# IA-64 conformance tests

The required IA-64 gate is self-contained in this QEMU repository. It has no
filesystem or runtime dependency on the private Vibtanium suitcase repository.

In an MSYS2 MINGW64 shell with `curl`, `pdftotext`, and the normal QEMU build
dependencies installed, configure, build, fetch the public manuals, run all 53
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

Implementation-surface schema version 2 treats only source-proven live or
guest-selectable state as implemented. Register storage alone is not enough.
Each register row names one of 20 bank/scalar coverage groups so table-driven
tests can close complete architectural index spaces without creating one test
executable per register.

The first seventeen exact speculation contracts live in
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
interrupted-context RSE checkpoint, `test-ia64-system-tcg` took 47.53 seconds,
`test-ia64-full-tcg` 49.26 seconds, and `test-ia64-register-tcg` 47.87
seconds. The established data-plane shard passed 637 subtests in 173.32
seconds, checkpoint 28 passed 42 in 11.92 seconds, checkpoint 29 passed 206
in 56.25 seconds, and checkpoint 30 passed 96 in 36.23 seconds; all 53
selected tests passed in 193.407 seconds of report wall time. The former
single 180-second registration limit was an infrastructure timeout once the
combined inventory reached 679 programs, not a semantic hang. The current
981-program inventory remains deliberately split by evidence ownership. The
gate defaults to four workers to avoid unrestricted host contention without
weakening any per-test timeout. The
RSE suites include five fresh-process
save/load/RFI continuations across mandatory-instruction and current-frame
fill faults. With parallel execution Meson may pause near the end of the
progress display until these processes complete; the per-test timeouts still
detect a genuine hang.
