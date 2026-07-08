# IA-64 EFI Built In Test (BIT)

BIT is a small EFI application that boots through the vibtanium firmware and
exercises implemented EFI services from *inside* the guest, then prints a
machine-greppable verdict to the serial/EFI console. It gives a fast,
deterministic regression signal (seconds, no OS install) that complements the
host-side unit tests under `tests/unit/` - those poke emulator internals in
process; this one runs real IA-64 code through the real firmware handoff.

`bit.efi` is intentionally committed and embedded into the vibtanium firmware
menu. Rebuild it after changing `bit.c`; `build.sh` also refreshes
`hw/ia64/efi-bit-blob.c`, and both generated files must be committed with the
source.

## Toolchain Setup

Use an MSYS2 MINGW64 shell and keep the IA-64 tools in the standard local
locations:

```sh
export PATH=/c/msys64/opt/ia64-gcc/bin:/c/msys64/opt/ia64-binutils/bin:$PATH
ia64-linux-gnu-gcc --version
ia64-linux-gnu-objcopy --version
```

`build.sh` defaults to:

```sh
IA64_GCC=/c/msys64/opt/ia64-gcc/bin/ia64-linux-gnu-gcc
IA64_BINUTILS=/c/msys64/opt/ia64-binutils/bin
```

Override those variables only if the toolchain is installed elsewhere.

## What it checks

| Check family | What it proves |
|--------------|----------------|
| IA-64 opcode smoke | Basic guest execution plus the `chk.a.clr` recovery branch helper that originally motivated this app |
| System table / LoadedImage | Firmware handoff registers, table layout, image handle, image base/size, and configuration table plumbing |
| Simple Text Output/Input | Console protocol dispatch, mode state, cursor/attribute methods, and WaitForKey not-ready behavior |
| Boot memory services | TPL, watchdog/stall, pool allocation, page allocation/free, memory-map sizing/content, and ExitBootServices key validation |
| Event/timer services | CreateEvent, SignalEvent, CheckEvent, WaitForEvent, SetTimer time warp, and CloseEvent |
| Protocol database | HandleProtocol, LocateHandle, InstallProtocolInterface, OpenProtocol, CloseProtocol, LocateProtocol, and UninstallProtocolInterface |
| Boot utility services | CalculateCrc32, CopyMem, and SetMem |
| Runtime services | Get/SetTime, wakeup time, Set/Get/GetNextVariableName, high monotonic count, ConvertPointer, SetVirtualAddressMap, and ResetSystem |
| Graphics Output Protocol | QueryMode, SetMode, and all implemented Blt operations |
| Block/File media services | BlockIO reset/read/write-protected/flush plus SimpleFS and EFI_FILE open/read/get-info/position/write-protected paths |

Add checks in `bit.c`. Keep only IA-64 entry/ABI mechanics or opcodes that
C cannot express in `entry.S`.

## Running

```sh
bash run.sh            # builds bit.efi, boots from a temp ESP, prints PASS/FAIL
```

Exit status is `0` only when the guest prints
`VIBTANIUM-BIT-RESULT: ALL PASS`. A per-check `[FAIL]` line, an emulator
`execution frontier` (unimplemented opcode), or a timeout all yield exit `1`.

`run.sh` launches qemu in the background and stops **only its own** guest by
Windows PID — it never kills qemu by image name, so it is safe to run while
another qemu (e.g. an OS install) is up.

Useful overrides: `QEMU=`, `TIMEOUT=` (default 40s), `NVRAM=<file>` (attach a
persistent EFI variable store), `BOOT_MODE=kernel` (old `-kernel bit.efi`
path; media protocol checks require the default `BOOT_MODE=media`), and
`NO_BUILD=1` (reuse the existing `bit.efi`).

## Firmware Menu

The vibtanium firmware embeds the committed `bit.efi` blob. In the EFI boot
manager, press `Esc` for maintenance, then press `B` to run Built In Test. BIT
prints all results to the EFI console and then spins, leaving the final screen
visible.

Disable the menu entry with:

```sh
qemu-system-ia64 -M vibtanium,built-in-test=off ...
```

## Build pipeline

The app is C-first and uses the local IA-64 GCC cross compiler installed at
`/c/msys64/opt/ia64-gcc/bin/ia64-linux-gnu-gcc` plus the existing IA-64
binutils at `/c/msys64/opt/ia64-binutils/bin`:

```
ia64-...-as     ->  entry.o     (EFI plabel, _start, opcode helper)
ia64-...-gcc    ->  bit.o       (C EFI service stress test)
ia64-...-gcc    ->  bit.elf     (link.ld: fixed base 0x01001000)
ia64-...-objcopy -O binary -> bit.bin
mkpe.py         ->  bit.efi     (PE32+, ImageBase 0x01000000, no relocs)
gen_blob.py     ->  hw/ia64/efi-bit-blob.c
```

`build.sh` runs the whole pipeline (`build.sh -v` also dumps a disassembly).

### Why it loads with no relocations

The vibtanium loader (`hw/ia64/efi.c`) reads the entry point from a 16-byte
IA-64 function descriptor (plabel) at `AddressOfEntryPoint` and, when the file
has no base-relocation directory, loads at the PE's preferred `ImageBase`. We
set `ImageBase = VIBTANIUM_EFI_APP_BASE (0x01000000)` and link the code at that
base + text RVA, so every absolute address is already correct. The second word
of the entry descriptor is `__gp`, allowing GCC-generated IA-64 small-data/GOT
accesses to work after firmware handoff. The loader does not inspect the PE
Subsystem field.

`run.sh` copies `bit.efi` to a temporary ESP as
`\EFI\BOOT\BOOTIA64.EFI`; this exercises the media-discovery/cache path and
makes BlockIO/SimpleFS/File protocol checks meaningful.

Firmware BIT launch builds an equivalent in-memory FAT ESP, so the embedded
menu path still exercises BlockIO/SimpleFS/File without depending on any user
disk image.

## Guest entry contract

From `vibtanium_efi_prepare_cpu`: `r32 = ImageHandle`, `r33 = SystemTable`,
`r1 = gp`, `r12 = sp`, `PSR.bn = 1`. EFI services are reached with a normal
`br.call` through the plabel in the relevant table field; the call gate reads
arguments from `r32+` and returns the status in `r8`.
