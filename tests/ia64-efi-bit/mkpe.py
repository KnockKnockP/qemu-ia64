#!/usr/bin/env python3
"""Wrap a flat IA-64 binary into a minimal PE32+ EFI image.

The vibtanium EFI loader (hw/ia64/efi.c) is intentionally small: it validates
the MZ/PE headers, requires machine==IA-64 (0x0200) and a PE32/PE32+ optional
header, maps each section at its VirtualAddress, and reads the entry point from
a 16-byte IA-64 function descriptor (plabel) located at AddressOfEntryPoint:

    code_entry     = *(u64 *)(image + entry_rva + 0)
    global_pointer = *(u64 *)(image + entry_rva + 8)

Both are absolute addresses. To avoid needing base relocations we set the PE
ImageBase equal to the -kernel load base (VIBTANIUM_EFI_APP_BASE = 0x01000000)
and link the flat binary at that base + text RVA, so the plabel already holds
correct absolute addresses. The Subsystem field is not checked by the loader.

The flat binary is placed as a single section at RVA 0x1000, and the entry
descriptor is expected to be the very first bytes of that binary (so the PE
AddressOfEntryPoint is exactly the text RVA).
"""

import struct
import sys

IMAGE_BASE = 0x01000000          # must match VIBTANIUM_EFI_APP_BASE
TEXT_RVA = 0x1000
FILE_ALIGN = 0x200
SECT_ALIGN = 0x1000
HEADERS_SIZE = 0x200             # file offset of the first section's raw data
PE_MACHINE_IA64 = 0x0200
PE32P_MAGIC = 0x20b
SUBSYSTEM_EFI_APPLICATION = 10


def roundup(value, align):
    return (value + align - 1) & ~(align - 1)


def build(flat: bytes) -> bytes:
    virt_size = len(flat)
    raw_size = roundup(virt_size, FILE_ALIGN)
    size_of_image = roundup(TEXT_RVA + virt_size, SECT_ALIGN)

    out = bytearray(HEADERS_SIZE)

    # --- DOS/MZ header --------------------------------------------------
    out[0:2] = b"MZ"
    struct.pack_into("<I", out, 0x3c, 0x80)   # e_lfanew -> PE header

    pe = 0x80
    out[pe:pe + 4] = b"PE\0\0"

    # --- COFF file header (20 bytes) ------------------------------------
    coff = pe + 4
    num_sections = 1
    size_of_optional = 240                     # 112 + 16 data directories
    characteristics = 0x0202                   # EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
    struct.pack_into("<HHIIIHH", out, coff,
                     PE_MACHINE_IA64,           # Machine
                     num_sections,              # NumberOfSections
                     0,                         # TimeDateStamp
                     0,                         # PointerToSymbolTable
                     0,                         # NumberOfSymbols
                     size_of_optional,          # SizeOfOptionalHeader
                     characteristics)

    # --- Optional header (PE32+) ----------------------------------------
    opt = coff + 20
    struct.pack_into("<H", out, opt + 0, PE32P_MAGIC)      # Magic
    out[opt + 2] = 14                                       # MajorLinkerVersion
    out[opt + 3] = 0                                        # MinorLinkerVersion
    struct.pack_into("<I", out, opt + 4, raw_size)         # SizeOfCode
    struct.pack_into("<I", out, opt + 16, TEXT_RVA)        # AddressOfEntryPoint
    struct.pack_into("<I", out, opt + 20, TEXT_RVA)        # BaseOfCode
    struct.pack_into("<Q", out, opt + 24, IMAGE_BASE)      # ImageBase (PE32+)
    struct.pack_into("<I", out, opt + 32, SECT_ALIGN)      # SectionAlignment
    struct.pack_into("<I", out, opt + 36, FILE_ALIGN)      # FileAlignment
    struct.pack_into("<H", out, opt + 40, 4)               # MajorOperatingSystemVersion
    struct.pack_into("<H", out, opt + 44, 1)               # MajorImageVersion
    struct.pack_into("<H", out, opt + 48, 4)               # MajorSubsystemVersion
    struct.pack_into("<I", out, opt + 56, size_of_image)   # SizeOfImage
    struct.pack_into("<I", out, opt + 60, HEADERS_SIZE)    # SizeOfHeaders
    struct.pack_into("<H", out, opt + 68, SUBSYSTEM_EFI_APPLICATION)  # Subsystem
    struct.pack_into("<Q", out, opt + 72, 0x100000)        # SizeOfStackReserve
    struct.pack_into("<Q", out, opt + 80, 0x10000)         # SizeOfStackCommit
    struct.pack_into("<Q", out, opt + 88, 0x100000)        # SizeOfHeapReserve
    struct.pack_into("<Q", out, opt + 96, 0x10000)         # SizeOfHeapCommit
    struct.pack_into("<I", out, opt + 108, 16)             # NumberOfRvaAndSizes
    # Data directories start at opt+112; leave all zero -> no base relocations.

    # --- Section header (40 bytes) --------------------------------------
    sect = opt + size_of_optional
    name = b".text\0\0\0"
    out[sect:sect + 8] = name
    struct.pack_into("<I", out, sect + 8, virt_size)       # VirtualSize
    struct.pack_into("<I", out, sect + 12, TEXT_RVA)       # VirtualAddress
    struct.pack_into("<I", out, sect + 16, raw_size)       # SizeOfRawData
    struct.pack_into("<I", out, sect + 20, HEADERS_SIZE)   # PointerToRawData
    struct.pack_into("<I", out, sect + 36, 0xE0000020)     # CODE|EXECUTE|READ|WRITE

    body = bytes(out) + flat + b"\0" * (raw_size - virt_size)
    return body


def main():
    if len(sys.argv) != 3:
        sys.stderr.write("usage: mkpe.py <flat.bin> <out.efi>\n")
        return 1
    with open(sys.argv[1], "rb") as f:
        flat = f.read()
    if len(flat) < 16:
        sys.stderr.write("mkpe.py: flat binary too small (need entry descriptor)\n")
        return 1
    with open(sys.argv[2], "wb") as f:
        f.write(build(flat))
    return 0


if __name__ == "__main__":
    sys.exit(main())
