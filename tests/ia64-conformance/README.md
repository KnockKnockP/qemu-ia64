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

The first two exact speculation contracts live in
`speculation-semantic-tranche.json`. Their public data-plane registration
covers all four integer widths through NaTPage deferral, base updates, NaT
state, and checked recovery without requiring the architecturally
implementation-specific data portion of a NaT'ed GR. A second 20-program
matrix proves that `.s` and `.sa` translated misses and alignment conditions
remain immediate in the no-recovery model. Its alignment half runs both alone
and below an always-deferred NaTPage condition, so deferral cannot incorrectly
hide a lower non-deferred fault. Other data-plane cases remain candidate
evidence until they receive equally atomic contracts and complete variant
matrices.

The three long-running tests are intentionally quiet while their internal TAP
matrices execute. On the 2026-07-22 two-way public gate after the no-recovery
fault checkpoint, `test-ia64-system-tcg` took 47.06 seconds,
`test-ia64-full-tcg` 48.80 seconds, and `test-ia64-register-tcg` 45.53
seconds. The expanded data-plane registration passed 59 subtests in 16.09
seconds. The RSE suites include five fresh-process
save/load/RFI continuations across mandatory-instruction and current-frame
fill faults. With parallel execution Meson may pause near the end of the
progress display until these processes complete; the per-test timeouts still
detect a genuine hang.
