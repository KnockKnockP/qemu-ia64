=======================
IA-64 guest firmware ABI
=======================

The ``vibtanium`` machine boots the installed ``ia64-firmware.bin`` image as
ordinary IA-64 code.  QEMU loads it through the standard firmware search path;
the generic, legacy-named ``-bios`` option remains an explicit firmware
override.  The image owns SAL, EFI tables, services, boot policy, and OS
handoff.  The host supplies only devices and a private PAL transaction portal
for operations that require CPU-model support.

The firmware began as the compatibility baseline in the vendored reference
tree, whose QEMU lineage is attributed to
`syunnPC/qemu-system-ia64 <https://github.com/syunnPC/qemu-system-ia64>`_.
It is an implementation reference rather than an architectural authority;
the Intel architecture manuals and independent guest observations take
precedence when they disagree with it.

The pre-rewrite host code provided a graphical EFI maintenance front end.  The
current guest firmware does not reproduce that interface yet.  Its old design
remains useful as a front-end reference, but a future port must execute as EFI
guest code and must not restore host EFI-service dispatch.

Platform handoff
================

At reset, QEMU places the firmware at ``0x00100000`` and writes the version 7
handoff block at ``0x000ff000``.  The block describes RAM size, primary-console
selection, IDE bus-master support, debug-UART presence, and i8042 presence.
Explicit aliases expose the UART, IOSAPIC, sparse I/O, PCI configuration and
MMIO windows, VGA framebuffer, RTC, ACPI reset byte, and the 64 KiB variable
store at the addresses consumed by the firmware.

The source image's syscall-valued PAL break is patched once while loading to a
platform-private immediate.  Only that immediate reaches the PAL portal; normal
``break 0x100000`` instructions remain architectural system calls.  There are
no translator IP recognizers or host EFI/SAL dispatch gates.

NVRAM and compatibility boundary
================================

``-M vibtanium,nvram=PATH`` selects a raw 64 KiB variable store.  The default
is ``auto``, which resolves to a writable file named ``nvram`` beside the
resolved firmware.  A separate explicit path is recommended for each VM;
``none`` disables persistence.  Writes become durable only when firmware
writes the documented commit token, at which point QEMU rewrites the complete
64 KiB file.  A read-only firmware installation therefore produces a save
warning under ``auto`` rather than silently falling back elsewhere.

FPSWA compatibility boundary
============================

The current firmware publishes the IA-64 FPSWA protocol, Loaded Image, and
Device Path interfaces so software can discover the expected handle.  This is
only a visibility fallback: the FPSWA callback returns ``UNHANDLED`` and does
not perform floating-point software assist.  Windows boot behavior can also
depend on an NVRAM policy bit that selects or exposes FPSWA.  Automatic policy
registration and a functional software-assist implementation are therefore
still open work, not evidence that the underlying CPU model is complete.

The typed-only CPU rewrite deliberately starts a new migration boundary.  CPU
VMState version 6 contains environment version 8 and RSE version 5; their
minimum versions equal their current versions.  Snapshots from the former
interpreter/host-firmware prototype are intentionally unsupported.

Verification
============

``ia64-guest-firmware-test`` verifies default-name lookup, the handoff, PAL
portal patch, device aliases, and NVRAM persistence.  The standalone
``tests/ia64-efi-bit`` application additionally boots from a FAT ESP and calls
EFI services entirely in guest context.  It is a real IA-64 PE32+ EFI
application, not a host callback or embedded firmware-menu blob, and is
installed as ``vibtanium-bit.efi``.  The ``vibtanium_efi`` build option
packages or omits both it and ``ia64-firmware.bin`` as one EFI artifact set.
