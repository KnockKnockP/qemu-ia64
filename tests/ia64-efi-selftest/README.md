# IA-64 in-emulator EFI self-test

A tiny EFI application that boots through the vibtanium firmware and exercises
newly implemented CPU opcodes and EFI services from *inside* the guest, then
prints a machine-greppable verdict to the serial/EFI console. It gives a fast,
deterministic regression signal (seconds, no OS install) that complements the
host-side unit tests under `tests/unit/` — those poke emulator internals in
process; this one runs real IA-64 code through the real firmware handoff.

## What it checks

| Check | What it proves |
|-------|----------------|
| `opcode add` | basic A-type ALU + the test harness itself |
| `opcode movl + cmp.eq` | 64-bit immediate (MLX) and compare |
| `opcode chk.a.clr fp takes recovery branch` | the ALAT advanced-load check for FP regs (M22/M23) — with no preceding `ldf.a` it must branch to recovery |
| `efi ConOut->OutputString returns SUCCESS` | the EFI boot-services call path (plabel + call gate) |
| `efi SetVariable/GetVariable round-trip` | the EFI **runtime** variable services backing NVRAM boot vars |

Add a check by writing the test in `selftest.S` (compute a 0/1 flag, call
`report`) and adding its name string to `gen_strings.py`.

## Running

```sh
bash run.sh            # builds selftest.efi, boots it, prints PASS/FAIL, sets exit code
```

Exit status is `0` only when the guest prints
`VIBTANIUM-SELFTEST-RESULT: ALL PASS`. A per-check `[FAIL]` line, an emulator
`execution frontier` (unimplemented opcode), or a timeout all yield exit `1`.

`run.sh` launches qemu in the background and stops **only its own** guest by
Windows PID — it never kills qemu by image name, so it is safe to run while
another qemu (e.g. an OS install) is up.

Useful overrides: `QEMU=`, `TIMEOUT=` (default 40s), `NVRAM=<file>` (attach a
persistent EFI variable store so the SetVariable write is observable on disk),
`NO_BUILD=1` (reuse the existing `selftest.efi`).

## Build pipeline

There is no IA-64 C compiler on this host, only the cross **binutils**
(`/c/msys64/opt/ia64-binutils/bin`), so the app is hand-written assembly:

```
gen_strings.py  ->  strings.S        (UTF-16LE CHAR16 tables; the GNU as '\c
                                       char-value idiom is unreliable)
ia64-...-as     ->  selftest.o
ia64-...-ld     ->  selftest.elf     (link.ld: fixed base 0x01001000)
ia64-...-objcopy -O binary -> selftest.bin
mkpe.py         ->  selftest.efi     (PE32+, ImageBase 0x01000000, no relocs)
```

`build.sh` runs the whole pipeline (`build.sh -v` also dumps a disassembly).

### Why it loads with no relocations

The vibtanium loader (`hw/ia64/efi.c`) reads the entry point from a 16-byte
IA-64 function descriptor (plabel) at `AddressOfEntryPoint` and, when the file
has no base-relocation directory, loads at the PE's preferred `ImageBase`. We
set `ImageBase = VIBTANIUM_EFI_APP_BASE (0x01000000)` and link the code at that
base + text RVA, so every absolute address (the plabel, `movl` operands) is
already correct. The loader does not inspect the PE Subsystem field.

The same `selftest.efi` can also be dropped onto an ESP as
`\EFI\BOOT\BOOTIA64.EFI` to exercise the media-discovery / boot-manager path
instead of `-kernel`; `run.sh` uses `-kernel` for simplicity.

## Guest entry contract

From `vibtanium_efi_prepare_cpu`: `r32 = ImageHandle`, `r33 = SystemTable`,
`r1 = gp`, `r12 = sp`, `PSR.bn = 1`. EFI services are reached with a normal
`br.call` through the plabel in the relevant table field; the call gate reads
arguments from `r32+` and returns the status in `r8`.
