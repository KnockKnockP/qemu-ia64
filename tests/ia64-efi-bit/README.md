# IA-64 EFI Built In Test (BIT)

BIT is a standalone IA-64 EFI application that boots through the packaged
guest-executed firmware and exercises EFI services from inside the guest.  It
prints a machine-greppable verdict to the serial console, providing a fast
system-level complement to the no-OS translator fixtures.

The committed `bit.efi` lets the test run without an IA-64 cross toolchain.
`build.sh` rebuilds it when the toolchain is available; the application is no
longer compiled into the host emulator or dispatched by host EFI callbacks.

## Running

From an MSYS2 shell:

```sh
SKIP_BIT_BUILD=1 bash run.sh
```

The script creates a temporary FAT ESP containing
`EFI/BOOT/BOOTIA64.EFI`, starts `qemu-system-ia64` with the normal
`pc-bios/ia64-firmware.bin`, and waits for
`VIBTANIUM-BIT-RESULT: ALL PASS`.  `QEMU`, `TIMEOUT`, and `NVRAM` may be
overridden.  `BOOT_MODE=kernel` retains the direct loader smoke path, while
the default `media` mode covers the real removable-media boot path.

## Coverage

The application covers the system table and loaded-image contract, console
protocols, pool/page allocation, memory maps and ExitBootServices, events and
timers, protocol lookup/open/close, runtime variables and time services,
graphics output, and block/simple-file-system access.  Its small hand-written
entry sequence also exercises IA-64 function descriptors, stacked calls, and
`chk.a.clr` recovery.

## Rebuilding

The build uses `ia64-linux-gnu-gcc` plus IA-64 binutils.  Defaults are the
local MSYS2 paths under `/c/msys64/opt`; use `IA64_GCC` and
`IA64_BINUTILS` to override them.

```text
entry.S + bit.c -> bit.elf -> bit.bin -> bit.efi
```

The PE image is linked at its preferred fixed base and contains an IA-64
function descriptor carrying the entry IP and GP.  The guest firmware loads
the image from the ESP and enters it using the standard IA-64 EFI calling
convention; services are ordinary guest calls through the EFI tables.
