#!/usr/bin/env python3
"""Generate the compiled EFI BIT byte array from bit.efi."""

from pathlib import Path
import sys


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: gen_blob.py bit.efi hw/ia64/efi-bit-blob.c",
              file=sys.stderr)
        return 2

    source = Path(sys.argv[1])
    output = Path(sys.argv[2])
    data = source.read_bytes()
    lines = [
        "/* SPDX-License-Identifier: GPL-2.0-or-later */",
        "/* Generated from tests/ia64-efi-bit/bit.efi. */",
        "",
        '#include "qemu/osdep.h"',
        '#include "hw/ia64/efi-bit.h"',
        "",
        "const uint8_t vibtanium_efi_bit_blob[] = {",
    ]
    for offset in range(0, len(data), 12):
        chunk = data[offset:offset + 12]
        lines.append("    " + ", ".join(f"0x{byte:02x}"
                                         for byte in chunk) + ",")
    lines.extend([
        "};",
        "",
        "const size_t vibtanium_efi_bit_blob_size = "
        "sizeof(vibtanium_efi_bit_blob);",
        "",
    ])
    output.write_text("\n".join(lines), newline="\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
