==========================
Vibtanium IA-64 EFI bridge
==========================

The ``vibtanium`` machine keeps its project-owned EFI frontend in QEMU.  It
discovers EFI applications on legacy IDE media, presents the graphical boot
manager and EFI protocols, builds the PAL/SAL/EFI tables, and transfers control
to the selected IA-64 image.  Firmware services are ordinary host-side device
transactions reached through reserved IA-64 call-gate bundles.

The call gates are a narrow firmware ABI, not a second instruction engine.
All EFI applications, boot loaders, kernels, and drivers execute in the typed
IA-64 TCG translator.  The translator recognizes only the address ranges
reserved by Vibtanium for EFI, PAL, SAL, child-image return, and event-return
gates.  It synchronizes architectural state, invokes the matching project
service, and returns to the TCG main loop at the address selected by that
service.

The vendored ``syunnPC/qemu-system-ia64`` tree is an implementation reference
for CPU behavior and platform research.  Its compiled guest firmware is not
part of this machine, is not installed by the build, and does not define the
Vibtanium frontend or firmware ABI.

Machine and storage contract
============================

The default platform contains the rewritten IA-64 PCI host, PIIX3 IDE, E1000,
ISA VGA, i8042, UART, IOSAPIC, RTC, ACPI power-management registers, and USB.
The EFI frontend exposes matching device paths and Block I/O handles for the
legacy IDE media used by existing Vibtanium guests.

``-M vibtanium,nvram=PATH`` selects the QEMU ``UefiVarStore`` JSON version 2
file used for persistent EFI variables.  The text format is intentionally
human-editable and follows QEMU's standard variable-store schema.  ``none``
disables persistence.  The frontend processes ``BootOrder`` and the usual
removable-media fallback before handing control to an EFI application.

Build and verification
======================

``-Dvibtanium_efi=false`` (or ``--disable-vibtanium-efi``) disables both the
host EFI frontend and the Vibtanium BIT application.  When enabled, the BIT is
built as a genuine IA-64 PE32+ EFI application, embedded for the machine's
``efi-bit`` mode, and installed as ``vibtanium-bit.efi``.  It is an application
that tests the frontend; it is not the firmware implementation.

The IA-64 ACPI and input qtests cover reset, shutdown, and i8042 behavior.  The
standalone ``tests/ia64-efi-bit`` harness exercises EFI tables and services by
booting the compiled BIT application from a FAT ESP through the normal media
path.

The typed-only CPU rewrite deliberately starts a new migration boundary.  CPU
VMState version 6 contains environment version 8 and RSE version 5; snapshots
from the former interpreter prototype are intentionally unsupported.
