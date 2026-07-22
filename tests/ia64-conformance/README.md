# IA-64 conformance tests

The required IA-64 gate is self-contained in this QEMU repository. It has no
filesystem or runtime dependency on the private Vibtanium suitcase repository.

In an MSYS2 MINGW64 shell with `curl`, `pdftotext`, and the normal QEMU build
dependencies installed, configure, build, fetch the public manuals, run all 50
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

The first nine exact speculation contracts live in
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
Other data-plane cases remain
candidate evidence until they receive equally atomic contracts and complete
variant matrices.

The long-running tests are intentionally quiet while their internal TAP
matrices execute. On the 2026-07-22 serialized public gate after the
non-faulting speculation-attribute checkpoint, `test-ia64-system-tcg` took
47.05 seconds, `test-ia64-full-tcg` 48.39 seconds, and
`test-ia64-register-tcg` 45.56 seconds. The expanded data-plane registration
passed 637 subtests in 172.87 seconds, and all 50 selected tests passed in
423.4 seconds. The serialized lane avoids the fixed five-second HMP-startup
contention seen under unrestricted host parallelism without weakening any
per-test timeout. The
RSE suites include five fresh-process
save/load/RFI continuations across mandatory-instruction and current-frame
fill faults. With parallel execution Meson may pause near the end of the
progress display until these processes complete; the per-test timeouts still
detect a genuine hang.
