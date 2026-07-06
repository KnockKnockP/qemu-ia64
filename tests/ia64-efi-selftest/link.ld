OUTPUT_FORMAT("elf64-ia64-little")
ENTRY(_start)

/*
 * Link everything contiguously at VIBTANIUM_EFI_APP_BASE (0x01000000) + text
 * RVA (0x1000). mkpe.py maps the flat binary as one section at that RVA with
 * ImageBase 0x01000000, so all absolute addresses (movl, the entry descriptor)
 * are already correct and no PE base relocations are required.
 *
 * The 16-byte IA-64 entry descriptor (.head) is placed first so its RVA equals
 * the PE AddressOfEntryPoint (0x1000).
 */
SECTIONS
{
  . = 0x01001000;
  .text : {
    *(.head)
    . = ALIGN(16);
    *(.text)
    *(.text.*)
    . = ALIGN(8);
    *(.rodata)
    *(.rodata.*)
    . = ALIGN(8);
    *(.data)
    *(.data.*)
    . = ALIGN(8);
    *(.bss)
    *(.bss.*)
    . = ALIGN(16);
  }
  /DISCARD/ : {
    *(.note*)
    *(.comment)
    *(.IA_64.unwind*)
    *(.IA_64.unwind_info*)
    *(.dynamic)
    *(.hash)
    *(.gnu.hash)
  }
}
