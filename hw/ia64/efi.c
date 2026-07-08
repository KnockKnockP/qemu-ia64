/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "qemu/osdep.h"
#include "hw/acpi/aml-build.h"
#include "hw/ia64/efi.h"
#include "hw/ia64/efi-storage.h"
#include "hw/ia64/vibtanium.h"
#include "target/ia64/bundle.h"
#include "target/ia64/insn.h"
#include "target/ia64/mem.h"

#define PE32_MAGIC  0x10b
#define PE32P_MAGIC 0x20b

#define PE_SIGNATURE_OFFSET 0x3c
#define PE_SIGNATURE_SIZE   4
#define COFF_HEADER_SIZE    20
#define SECTION_HEADER_SIZE 40
#define PE32_DATA_DIRECTORY_OFFSET  96
#define PE32P_DATA_DIRECTORY_OFFSET 112
#define PE_DIRECTORY_BASE_RELOCATION 5
#define PE_BASE_RELOCATION_ABSOLUTE 0
#define PE_BASE_RELOCATION_IA64_IMM64 9
#define PE_BASE_RELOCATION_DIR64    10

#define MAX_EFI_IMAGE_SIZE (128 * 1024 * 1024)
#define IA64_PSR_BN_BIT UINT64_C(0x0000100000000000)
#define SAL_SYSTEM_TABLE_LENGTH 144
#define SAL_SYSTEM_TABLE_HEADER_LENGTH 96
#define SAL_SYSTEM_TABLE_ENTRY_COUNT 1
#define HCDP_TABLE_LENGTH 88
#define HCDP_UART_OFFSET 40
#define HCDP_UART_LENGTH 48
#define ACPI_TABLE_HEADER_LENGTH 36
#define ACPI_RSDP_LENGTH 36
#define ACPI_RSDT_ENTRY_COUNT 2
#define ACPI_RSDT_LENGTH (ACPI_TABLE_HEADER_LENGTH + \
                          ACPI_RSDT_ENTRY_COUNT * 4)
#define ACPI_XSDT_LENGTH (ACPI_TABLE_HEADER_LENGTH + \
                          ACPI_RSDT_ENTRY_COUNT * 8)
#define ACPI_FADT_LENGTH 244
#define ACPI_MADT_LOCAL_SAPIC_LENGTH 16
#define ACPI_MADT_IO_SAPIC_LENGTH 16
#define ACPI_MADT_LENGTH \
    (ACPI_TABLE_HEADER_LENGTH + 8 + ACPI_MADT_LOCAL_SAPIC_LENGTH + \
     ACPI_MADT_IO_SAPIC_LENGTH)
#define ACPI_FACS_LENGTH 64
#define ACPI_ADR_SPACE_SYSTEM_IO 1
#define ACPI_OEM_ID "VIBTAN"
#define ACPI_OEM_TABLE_ID "VIBTANIU"
#define PCDP_CONSOLE_UART 0
#define PCDP_UART_PRIMARY_CONSOLE (1 << 2)
#define VIBTANIUM_FIRMWARE_TABLE_LIMIT VIBTANIUM_EFI_GOP

typedef struct VibtaniumFirmwareLayout {
    uint64_t sal_system_table;
    uint64_t hcdp_table;
    uint64_t acpi_rsdp;
    uint64_t acpi_rsdt;
    uint64_t acpi_xsdt;
    uint64_t acpi_fadt;
    uint64_t acpi_dsdt;
    uint64_t acpi_madt;
    uint64_t acpi_facs;
} VibtaniumFirmwareLayout;

static bool range_ok(size_t size, uint64_t offset, uint64_t length)
{
    return offset <= size && length <= size - offset;
}

static uint16_t rd16(const uint8_t *p)
{
    return p[0] | ((uint16_t)p[1] << 8);
}

static void wr16(uint8_t *p, uint16_t value)
{
    p[0] = value;
    p[1] = value >> 8;
}

static uint32_t rd32(const uint8_t *p)
{
    return p[0] |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static void wr32(uint8_t *p, uint32_t value)
{
    for (int i = 0; i < 4; i++) {
        p[i] = value >> (i * 8);
    }
}

static uint64_t rd64(const uint8_t *p)
{
    return (uint64_t)rd32(p) | ((uint64_t)rd32(p + 4) << 32);
}

static void wr64(uint8_t *p, uint64_t value)
{
    for (int i = 0; i < 8; i++) {
        p[i] = value >> (i * 8);
    }
}

static void blob_wr32(uint8_t *blob, size_t size, uint64_t address,
                      uint32_t value)
{
    g_assert(address >= VIBTANIUM_EFI_BLOB_BASE);
    g_assert(address + sizeof(uint32_t) <=
             VIBTANIUM_EFI_BLOB_BASE + size);
    wr32(blob + (address - VIBTANIUM_EFI_BLOB_BASE), value);
}

static void blob_wr64(uint8_t *blob, size_t size, uint64_t address,
                      uint64_t value)
{
    g_assert(address >= VIBTANIUM_EFI_BLOB_BASE);
    g_assert(address + sizeof(uint64_t) <=
             VIBTANIUM_EFI_BLOB_BASE + size);
    wr64(blob + (address - VIBTANIUM_EFI_BLOB_BASE), value);
}

static uint8_t *blob_ptr(uint8_t *blob, size_t size, uint64_t address,
                         size_t bytes)
{
    g_assert(address >= VIBTANIUM_EFI_BLOB_BASE);
    g_assert(address + bytes <= VIBTANIUM_EFI_BLOB_BASE + size);
    return blob + (address - VIBTANIUM_EFI_BLOB_BASE);
}

static uint64_t firmware_alloc_range(uint64_t *cursor, uint64_t length,
                                     uint64_t alignment)
{
    uint64_t address;

    g_assert(is_power_of_2(alignment));
    address = ROUND_UP(*cursor, alignment);
    g_assert_cmphex(address, >=, VIBTANIUM_EFI_BLOB_BASE);
    g_assert_cmphex(address + length, <=, VIBTANIUM_FIRMWARE_TABLE_LIMIT);
    *cursor = address + length;
    return address;
}

static void firmware_layout_build(VibtaniumFirmwareLayout *layout,
                                  size_t dsdt_length)
{
    uint64_t cursor = VIBTANIUM_EFI_SAL_SYSTEM_TABLE;

    layout->sal_system_table =
        firmware_alloc_range(&cursor, SAL_SYSTEM_TABLE_LENGTH, 0x100);
    layout->hcdp_table =
        firmware_alloc_range(&cursor, HCDP_TABLE_LENGTH, 0x100);
    layout->acpi_rsdp =
        firmware_alloc_range(&cursor, ACPI_RSDP_LENGTH, 0x100);
    layout->acpi_rsdt =
        firmware_alloc_range(&cursor, ACPI_RSDT_LENGTH, 0x40);
    layout->acpi_xsdt =
        firmware_alloc_range(&cursor, ACPI_XSDT_LENGTH, 0x40);
    layout->acpi_fadt =
        firmware_alloc_range(&cursor, ACPI_FADT_LENGTH, 0x80);
    layout->acpi_dsdt =
        firmware_alloc_range(&cursor, dsdt_length, 0x100);
    layout->acpi_madt =
        firmware_alloc_range(&cursor, ACPI_MADT_LENGTH, 0x100);
    layout->acpi_facs =
        firmware_alloc_range(&cursor, ACPI_FACS_LENGTH, 0x40);
}

static void firmware_copy_table(uint8_t *blob, size_t size, uint64_t address,
                                const GArray *table)
{
    memcpy(blob_ptr(blob, size, address, table->len), table->data,
           table->len);
}

static uint32_t efi_crc32(const uint8_t *data, size_t size)
{
    uint32_t crc = 0xffffffff;

    for (size_t i = 0; i < size; i++) {
        crc ^= data[i];
        for (int bit = 0; bit < 8; bit++) {
            crc = (crc & 1) ? (crc >> 1) ^ 0xedb88320U : crc >> 1;
        }
    }

    return ~crc;
}

static uint8_t byte_checksum(const uint8_t *table, size_t size)
{
    uint32_t sum = 0;

    for (size_t i = 0; i < size; i++) {
        sum = (sum + table[i]) & 0xff;
    }
    return (uint8_t)((0x100 - sum) & 0xff);
}

static void write_table_header(uint8_t *table, size_t size,
                               uint64_t signature)
{
    wr64(table, signature);
    wr32(table + 8, 0x00010000);
    wr32(table + 12, size);
    wr32(table + 16, 0);
    wr32(table + 20, 0);
    wr32(table + 16, efi_crc32(table, size));
}

static void write_acpi_gas(uint8_t *gas, uint8_t address_space,
                           uint8_t bit_width, uint8_t access_width,
                           uint64_t address)
{
    gas[0] = address_space;
    gas[1] = bit_width;
    gas[2] = 0;
    gas[3] = access_width;
    wr64(gas + 4, address);
}

static void write_ia64_bundle(uint8_t *blob, size_t size, uint64_t address,
                              uint8_t tmpl, uint64_t slot0, uint64_t slot1,
                              uint64_t slot2)
{
    unsigned __int128 raw = (tmpl & 0x1f) |
        ((unsigned __int128)(slot0 & IA64_SLOT_MASK) << 5) |
        ((unsigned __int128)(slot1 & IA64_SLOT_MASK) << 46) |
        ((unsigned __int128)(slot2 & IA64_SLOT_MASK) << 87);
    uint8_t *p = blob_ptr(blob, size, address, IA64_BUNDLE_SIZE);

    for (int i = 0; i < IA64_BUNDLE_SIZE; i++) {
        p[i] = raw >> (i * 8);
    }
}

static unsigned __int128 ia64_bundle_raw_from_bytes(const uint8_t *bundle)
{
    unsigned __int128 raw = 0;

    for (int i = IA64_BUNDLE_SIZE - 1; i >= 0; i--) {
        raw = (raw << 8) | bundle[i];
    }
    return raw;
}

static void ia64_bundle_raw_to_bytes(uint8_t *bundle, unsigned __int128 raw)
{
    for (int i = 0; i < IA64_BUNDLE_SIZE; i++) {
        bundle[i] = raw >> (i * 8);
    }
}

static void ia64_bundle_store_lx_slots(uint8_t *bundle,
                                       uint64_t l_raw,
                                       uint64_t x_raw)
{
    unsigned __int128 raw = ia64_bundle_raw_from_bytes(bundle);
    const unsigned __int128 slot1_mask =
        (unsigned __int128)IA64_SLOT_MASK << 46;
    const unsigned __int128 slot2_mask =
        (unsigned __int128)IA64_SLOT_MASK << 87;

    raw &= ~(slot1_mask | slot2_mask);
    raw |= (unsigned __int128)(l_raw & IA64_SLOT_MASK) << 46;
    raw |= (unsigned __int128)(x_raw & IA64_SLOT_MASK) << 87;
    ia64_bundle_raw_to_bytes(bundle, raw);
}

static void ia64_lx_movl_set_imm64(uint64_t *l_raw, uint64_t *x_raw,
                                   uint64_t value)
{
    const uint64_t x_imm_mask = (0x7fULL << 13) |
                                (1ULL << 21) |
                                (0x1fULL << 22) |
                                (0x1ffULL << 27) |
                                (1ULL << 36);

    *l_raw = (value >> 22) & IA64_SLOT_MASK;
    *x_raw &= ~x_imm_mask;
    *x_raw |= (value & 0x7fULL) << 13;
    *x_raw |= ((value >> 21) & 0x1ULL) << 21;
    *x_raw |= ((value >> 16) & 0x1fULL) << 22;
    *x_raw |= ((value >> 7) & 0x1ffULL) << 27;
    *x_raw |= ((value >> 63) & 0x1ULL) << 36;
}

static bool apply_ia64_imm64_relocation(uint8_t *memory_image,
                                        uint32_t size_of_image,
                                        uint32_t fixup_rva,
                                        uint64_t delta,
                                        Error **errp)
{
    uint32_t bundle_rva = fixup_rva & ~(IA64_BUNDLE_SIZE - 1);
    uint8_t *bundle;
    IA64DecodedBundle decoded;
    uint64_t value;

    if (bundle_rva > size_of_image ||
        IA64_BUNDLE_SIZE > size_of_image - bundle_rva) {
        error_setg(errp,
                   "EFI image IA64_IMM64 relocation target 0x%x is outside "
                   "image",
                   fixup_rva);
        return false;
    }

    bundle = memory_image + bundle_rva;
    if (!ia64_decode_bundle(bundle, &decoded) ||
        !decoded.info->long_immediate ||
        decoded.info->slot_type[1] != IA64_SLOT_TYPE_L ||
        decoded.info->slot_type[2] != IA64_SLOT_TYPE_X ||
        !ia64_slot_pair_is_lx_movl(decoded.slot[1], decoded.slot[2])) {
        error_setg(errp,
                   "EFI image IA64_IMM64 relocation target 0x%x is not an "
                   "MLX movl bundle",
                   fixup_rva);
        return false;
    }

    value = ia64_lx_movl_imm64(decoded.slot[1], decoded.slot[2]);
    ia64_lx_movl_set_imm64(&decoded.slot[1], &decoded.slot[2],
                           value + delta);
    ia64_bundle_store_lx_slots(bundle, decoded.slot[1], decoded.slot[2]);
    return true;
}

static void write_return_gate(uint8_t *blob, size_t size, uint64_t address)
{
    const uint64_t nop = 1ULL << 27;
    const uint64_t br_ret_b0 = 0x21ULL << 27;

    write_ia64_bundle(blob, size, address, 0x11, nop, nop, br_ret_b0);
}

static void write_branch_gate(uint8_t *blob, size_t size, uint64_t address)
{
    const uint64_t nop = 1ULL << 27;
    const uint64_t br_b0 = 0x20ULL << 27;

    write_ia64_bundle(blob, size, address, 0x11, nop, nop, br_b0);
}

static uint64_t service_descriptor_address(unsigned service_index)
{
    return VIBTANIUM_EFI_DESCRIPTOR_BASE + service_index * 16;
}

static uint64_t service_gate_address(unsigned service_index)
{
    return VIBTANIUM_EFI_CALL_GATE_BASE +
           (uint64_t)service_index * IA64_BUNDLE_SIZE;
}

static void write_service_descriptor(uint8_t *blob, size_t size,
                                     unsigned service_index)
{
    uint64_t descriptor = service_descriptor_address(service_index);
    uint64_t gate = service_gate_address(service_index);

    blob_wr64(blob, size, descriptor, gate);
    blob_wr64(blob, size, descriptor + 8, VIBTANIUM_EFI_SYSTEM_TABLE);
    write_return_gate(blob, size, gate);
}

static void write_guid(uint8_t *blob, size_t size, uint64_t address,
                       const uint8_t guid[16])
{
    memcpy(blob_ptr(blob, size, address, 16), guid, 16);
}

static void write_fixed_ascii(uint8_t *p, size_t size, const char *text)
{
    size_t text_len = strlen(text);

    memset(p, ' ', size);
    memcpy(p, text, MIN(size, text_len));
}

static uint8_t sal_checksum(const uint8_t *table, size_t size)
{
    return byte_checksum(table, size);
}

static void efi_image_reset(VibtaniumEfiImage *image)
{
    memset(image, 0, sizeof(*image));
}

static bool apply_base_relocations(uint8_t *memory_image,
                                   uint32_t size_of_image,
                                   uint64_t delta,
                                   uint32_t reloc_rva,
                                   uint32_t reloc_size,
                                   Error **errp)
{
    uint32_t offset;
    uint32_t end;

    if (delta == 0) {
        return true;
    }
    if (reloc_rva == 0 || reloc_size == 0) {
        error_setg(errp,
                   "EFI image relocation required but no relocation "
                   "directory is present");
        return false;
    }
    if (reloc_rva > size_of_image || reloc_size > size_of_image - reloc_rva) {
        error_setg(errp, "EFI image relocation directory is outside image");
        return false;
    }

    offset = reloc_rva;
    end = reloc_rva + reloc_size;
    while (offset + 8 <= end) {
        uint32_t page_rva = rd32(memory_image + offset);
        uint32_t block_size = rd32(memory_image + offset + 4);
        uint32_t count;

        if (block_size < 8 || block_size > end - offset) {
            error_setg(errp, "EFI image relocation block is malformed");
            return false;
        }

        count = (block_size - 8) / 2;
        for (uint32_t i = 0; i < count; i++) {
            uint16_t entry = rd16(memory_image + offset + 8 + i * 2);
            uint16_t type = entry >> 12;
            uint32_t fixup_rva = page_rva + (entry & 0x0fff);
            uint64_t value;

            switch (type) {
            case PE_BASE_RELOCATION_ABSOLUTE:
                break;
            case PE_BASE_RELOCATION_IA64_IMM64:
                if (!apply_ia64_imm64_relocation(memory_image,
                                                 size_of_image,
                                                 fixup_rva, delta,
                                                 errp)) {
                    return false;
                }
                break;
            case PE_BASE_RELOCATION_DIR64:
                if (fixup_rva > size_of_image ||
                    8 > size_of_image - fixup_rva) {
                    error_setg(errp,
                               "EFI image DIR64 relocation target 0x%x is "
                               "outside image",
                               fixup_rva);
                    return false;
                }
                value = rd64(memory_image + fixup_rva);
                wr64(memory_image + fixup_rva, value + delta);
                break;
            default:
                error_setg(errp, "unsupported EFI image relocation type %u",
                           type);
                return false;
            }
        }

        offset += block_size;
    }

    return true;
}

bool vibtanium_efi_image_from_buffer(const char *path,
                                     const uint8_t *file,
                                     size_t file_size,
                                     uint64_t load_base,
                                     VibtaniumEfiImage *image,
                                     Error **errp)
{
    uint32_t pe_offset;
    const uint8_t *pe;
    const uint8_t *coff;
    const uint8_t *optional;
    const uint8_t *section_table;
    uint16_t machine;
    uint16_t sections;
    uint16_t optional_size;
    uint16_t optional_magic;
    uint32_t entry_rva;
    uint32_t size_of_image;
    uint32_t size_of_headers;
    uint32_t section_alignment;
    uint32_t number_of_rva_and_sizes = 0;
    uint32_t data_directory_offset;
    uint32_t reloc_rva = 0;
    uint32_t reloc_size = 0;
    uint64_t preferred_image_base;
    uint64_t requested_load_base;
    uint64_t entry_descriptor;
    uint64_t code_entry;
    uint64_t global_pointer;
    uint8_t *memory_image;
    bool fixed_preferred_load = false;

    g_return_val_if_fail(image != NULL, false);
    efi_image_reset(image);

    if (!file || file_size < 0x40) {
        error_setg(errp, "EFI image is too small");
        return false;
    }
    if (file[0] != 'M' || file[1] != 'Z') {
        error_setg(errp, "EFI image does not have an MZ header");
        return false;
    }
    if (!range_ok(file_size, PE_SIGNATURE_OFFSET, sizeof(uint32_t))) {
        error_setg(errp, "EFI image DOS header is truncated");
        return false;
    }

    pe_offset = rd32(file + PE_SIGNATURE_OFFSET);
    if (!range_ok(file_size, pe_offset,
                  PE_SIGNATURE_SIZE + COFF_HEADER_SIZE)) {
        error_setg(errp, "EFI image PE header is outside the file");
        return false;
    }

    pe = file + pe_offset;
    if (memcmp(pe, "PE\0\0", PE_SIGNATURE_SIZE) != 0) {
        error_setg(errp, "EFI image does not have a PE signature");
        return false;
    }

    coff = pe + PE_SIGNATURE_SIZE;
    machine = rd16(coff);
    sections = rd16(coff + 2);
    optional_size = rd16(coff + 16);

    if (machine != VIBTANIUM_EFI_PE_MACHINE_IA64) {
        error_setg(errp, "EFI image machine 0x%04x is not IA-64", machine);
        return false;
    }
    if (sections == 0) {
        error_setg(errp, "EFI image has no sections");
        return false;
    }
    if (!range_ok(file_size, pe_offset + PE_SIGNATURE_SIZE + COFF_HEADER_SIZE,
                  optional_size)) {
        error_setg(errp, "EFI image optional header is truncated");
        return false;
    }

    optional = coff + COFF_HEADER_SIZE;
    optional_magic = rd16(optional);
    if (optional_magic != PE32_MAGIC && optional_magic != PE32P_MAGIC) {
        error_setg(errp, "EFI image optional header magic 0x%04x is unsupported",
                   optional_magic);
        return false;
    }
    if (optional_size < 64) {
        error_setg(errp, "EFI image optional header is too small");
        return false;
    }

    entry_rva = rd32(optional + 16);
    preferred_image_base = optional_magic == PE32P_MAGIC ?
                           rd64(optional + 24) : rd32(optional + 28);
    requested_load_base = load_base;
    section_alignment = rd32(optional + 32);
    size_of_image = rd32(optional + 56);
    size_of_headers = rd32(optional + 60);
    data_directory_offset = optional_magic == PE32P_MAGIC ?
                            PE32P_DATA_DIRECTORY_OFFSET :
                            PE32_DATA_DIRECTORY_OFFSET;
    if (optional_size >= data_directory_offset) {
        uint32_t number_offset = data_directory_offset - 4;

        number_of_rva_and_sizes = rd32(optional + number_offset);
        if (number_of_rva_and_sizes > PE_DIRECTORY_BASE_RELOCATION &&
            optional_size >= data_directory_offset +
                             (PE_DIRECTORY_BASE_RELOCATION + 1) * 8) {
            const uint8_t *reloc_dir =
                optional + data_directory_offset +
                PE_DIRECTORY_BASE_RELOCATION * 8;

            reloc_rva = rd32(reloc_dir);
            reloc_size = rd32(reloc_dir + 4);
        }
    }

    if (section_alignment == 0) {
        error_setg(errp, "EFI image has zero section alignment");
        return false;
    }
    if (size_of_image == 0 || size_of_image > MAX_EFI_IMAGE_SIZE) {
        error_setg(errp, "EFI image size 0x%x is unsupported", size_of_image);
        return false;
    }
    if (size_of_headers > size_of_image) {
        error_setg(errp, "EFI image headers exceed image size");
        return false;
    }
    if (entry_rva >= size_of_image) {
        error_setg(errp, "EFI image entry RVA 0x%x is outside image size 0x%x",
                   entry_rva, size_of_image);
        return false;
    }
    if (entry_rva > size_of_image || 16 > size_of_image - entry_rva) {
        error_setg(errp,
                   "EFI image IA-64 entry descriptor RVA 0x%x is truncated",
                   entry_rva);
        return false;
    }
    if (load_base != preferred_image_base &&
        reloc_rva == 0 && reloc_size == 0) {
        load_base = preferred_image_base;
        fixed_preferred_load = true;
    }
    if (UINT64_MAX - load_base < size_of_image) {
        error_setg(errp, "EFI image load address overflows");
        return false;
    }

    section_table = optional + optional_size;
    if (!range_ok(file_size, section_table - file,
                  (uint64_t)sections * SECTION_HEADER_SIZE)) {
        error_setg(errp, "EFI image section table is truncated");
        return false;
    }

    memory_image = g_malloc0(size_of_image);
    memcpy(memory_image, file, MIN((size_t)size_of_headers, file_size));

    for (uint16_t i = 0; i < sections; i++) {
        const uint8_t *section = section_table + i * SECTION_HEADER_SIZE;
        uint32_t virtual_size = rd32(section + 8);
        uint32_t virtual_address = rd32(section + 12);
        uint32_t raw_size = rd32(section + 16);
        uint32_t raw_pointer = rd32(section + 20);
        uint32_t copy_size = raw_size;

        if (raw_size == 0) {
            continue;
        }
        if (!range_ok(file_size, raw_pointer, raw_size)) {
            error_setg(errp, "EFI image section %u raw data is truncated", i);
            g_free(memory_image);
            return false;
        }
        if (virtual_address >= size_of_image) {
            error_setg(errp, "EFI image section %u VA 0x%x is outside image",
                       i, virtual_address);
            g_free(memory_image);
            return false;
        }
        if (virtual_size != 0 && virtual_size < copy_size) {
            copy_size = virtual_size;
        }
        if (copy_size > size_of_image - virtual_address) {
            error_setg(errp, "EFI image section %u exceeds image size", i);
            g_free(memory_image);
            return false;
        }

        memcpy(memory_image + virtual_address, file + raw_pointer, copy_size);
    }

    if (!apply_base_relocations(memory_image, size_of_image,
                                load_base - preferred_image_base,
                                reloc_rva, reloc_size, errp)) {
        g_free(memory_image);
        return false;
    }

    entry_descriptor = load_base + entry_rva;
    code_entry = rd64(memory_image + entry_rva);
    global_pointer = rd64(memory_image + entry_rva + 8);
    if (code_entry == 0) {
        error_setg(errp, "EFI image IA-64 entry descriptor has zero entry");
        g_free(memory_image);
        return false;
    }

    image->data = memory_image;
    image->size = size_of_image;
    image->load_base = load_base;
    image->entry_descriptor = entry_descriptor;
    image->entry = code_entry;
    image->global_pointer = global_pointer;
    image->preferred_image_base = preferred_image_base;
    image->entry_rva = entry_rva;
    image->size_of_image = size_of_image;
    image->section_alignment = section_alignment;
    image->number_of_sections = sections;
    g_strlcpy(image->source_path, path ? path : "<buffer>",
              sizeof(image->source_path));
    g_snprintf(image->message, sizeof(image->message),
               "loaded IA-64 EFI image path=%s load=0x%016" PRIx64
               " requested=0x%016" PRIx64 "%s"
               " descriptor=0x%016" PRIx64 " entry=0x%016" PRIx64
               " gp=0x%016" PRIx64 " size=0x%x sections=%u",
               image->source_path, image->load_base, requested_load_base,
               fixed_preferred_load ? " fixed-preferred-base" : "",
               image->entry_descriptor,
               image->entry, image->global_pointer, image->size_of_image,
               image->number_of_sections);

    return true;
}

bool vibtanium_efi_image_from_file(const char *path,
                                   uint64_t load_base,
                                   VibtaniumEfiImage *image,
                                   Error **errp)
{
    g_autoptr(GError) gerr = NULL;
    g_autofree gchar *contents = NULL;
    gsize length = 0;

    if (!path || !*path) {
        error_setg(errp, "EFI image path is empty");
        return false;
    }

    if (!g_file_get_contents(path, &contents, &length, &gerr)) {
        error_setg(errp, "%s", gerr->message);
        return false;
    }

    return vibtanium_efi_image_from_buffer(path, (const uint8_t *)contents,
                                           length, load_base, image, errp);
}

bool vibtanium_efi_decode_uint32_arg(uint64_t raw, uint32_t *value)
{
    uint32_t low = raw;
    uint64_t zero_extended = low;
    uint64_t sign_extended = (low & UINT32_C(0x80000000))
        ? (UINT64_MAX << 32) | low
        : zero_extended;

    if (raw != zero_extended && raw != sign_extended) {
        return false;
    }
    if (value) {
        *value = low;
    }
    return true;
}

uint32_t vibtanium_efi_page_allocation_memory_type(uint64_t allocate_type,
                                                   uint64_t memory_type)
{
    if (allocate_type == VIBTANIUM_EFI_ALLOCATE_ADDRESS &&
        (memory_type == VIBTANIUM_EFI_LOADER_CODE ||
         memory_type == VIBTANIUM_EFI_LOADER_DATA)) {
        return VIBTANIUM_EFI_RESERVED_MEMORY_TYPE;
    }

    return (uint32_t)memory_type;
}

bool vibtanium_efi_timer_due(uint64_t now, uint64_t deadline)
{
    return (int64_t)(now - deadline) >= 0;
}

void vibtanium_efi_image_destroy(VibtaniumEfiImage *image)
{
    if (!image) {
        return;
    }

    g_free(image->data);
    g_free(image->load_options);
    efi_image_reset(image);
}

enum {
    EFI_BOOT_SERVICE_BASE = 0,
    EFI_RUNTIME_SERVICE_BASE =
        EFI_BOOT_SERVICE_BASE + VIBTANIUM_EFI_BOOT_SERVICE_COUNT,
    EFI_CON_OUT_SERVICE_BASE =
        EFI_RUNTIME_SERVICE_BASE + VIBTANIUM_EFI_RUNTIME_SERVICE_COUNT,
    EFI_CON_IN_SERVICE_BASE =
        EFI_CON_OUT_SERVICE_BASE + VIBTANIUM_EFI_CON_OUT_SERVICE_COUNT,
    EFI_BLOCK_IO_SERVICE_BASE =
        EFI_CON_IN_SERVICE_BASE + VIBTANIUM_EFI_CON_IN_SERVICE_COUNT,
    EFI_SIMPLE_FILE_SYSTEM_SERVICE_BASE =
        EFI_BLOCK_IO_SERVICE_BASE + VIBTANIUM_EFI_BLOCK_IO_SERVICE_COUNT,
    EFI_FILE_SERVICE_BASE =
        EFI_SIMPLE_FILE_SYSTEM_SERVICE_BASE +
        VIBTANIUM_EFI_SIMPLE_FILE_SYSTEM_SERVICE_COUNT,
    EFI_GOP_SERVICE_BASE =
        EFI_FILE_SERVICE_BASE + VIBTANIUM_EFI_FILE_SERVICE_COUNT,
    EFI_SERVICE_DESCRIPTOR_COUNT =
        EFI_GOP_SERVICE_BASE + VIBTANIUM_EFI_GOP_SERVICE_COUNT,
};

static const uint8_t efi_sal_system_table_guid[16] = {
    0x32, 0x2d, 0x9d, 0xeb, 0x88, 0x2d, 0xd3, 0x11,
    0x9a, 0x16, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d,
};

static const uint8_t efi_hcdp_table_guid[16] = {
    0x8d, 0x93, 0x51, 0xf9, 0x0b, 0x62, 0xef, 0x42,
    0x82, 0x79, 0xa8, 0x4b, 0x79, 0x61, 0x78, 0x98,
};

static const uint8_t efi_acpi20_table_guid[16] = {
    0x71, 0xe8, 0x68, 0x88, 0xf1, 0xe4, 0xd3, 0x11,
    0xbc, 0x22, 0x00, 0x80, 0xc7, 0x3c, 0x88, 0x81,
};

static void write_utf16_ascii(uint8_t *blob, size_t size, uint64_t address,
                              const char *text)
{
    uint8_t *p = blob_ptr(blob, size, address, (strlen(text) + 1) * 2);

    while (*text) {
        p[0] = *text++;
        p[1] = 0;
        p += 2;
    }
    p[0] = 0;
    p[1] = 0;
}

static void write_loaded_image(uint8_t *blob, size_t size,
                               const VibtaniumEfiImage *image)
{
    uint64_t image_base = image ? image->load_base : 0;
    uint64_t image_size = image ? image->size : 0;
    size_t load_options_size = image ? image->load_options_size : 0;

    if (load_options_size > VIBTANIUM_EFI_LOAD_OPTIONS_SIZE) {
        load_options_size = VIBTANIUM_EFI_LOAD_OPTIONS_SIZE;
    }

    blob_wr32(blob, size, VIBTANIUM_EFI_LOADED_IMAGE, 0x1000);
    blob_wr64(blob, size, VIBTANIUM_EFI_LOADED_IMAGE + 16,
              VIBTANIUM_EFI_SYSTEM_TABLE);
    blob_wr64(blob, size, VIBTANIUM_EFI_LOADED_IMAGE + 24,
              VIBTANIUM_EFI_BOOT_DEVICE_HANDLE);
    blob_wr64(blob, size, VIBTANIUM_EFI_LOADED_IMAGE + 32,
              VIBTANIUM_EFI_DEVICE_PATH);
    if (load_options_size != 0) {
        memcpy(blob_ptr(blob, size, VIBTANIUM_EFI_LOAD_OPTIONS,
                        load_options_size),
               image->load_options, load_options_size);
        blob_wr32(blob, size, VIBTANIUM_EFI_LOADED_IMAGE + 48,
                  load_options_size);
        blob_wr64(blob, size, VIBTANIUM_EFI_LOADED_IMAGE + 56,
                  VIBTANIUM_EFI_LOAD_OPTIONS);
    }
    blob_wr64(blob, size, VIBTANIUM_EFI_LOADED_IMAGE + 64, image_base);
    blob_wr64(blob, size, VIBTANIUM_EFI_LOADED_IMAGE + 72, image_size);
    blob_wr32(blob, size, VIBTANIUM_EFI_LOADED_IMAGE + 80, 1);
    blob_wr32(blob, size, VIBTANIUM_EFI_LOADED_IMAGE + 84, 2);
}

static void write_configuration_table(uint8_t *blob, size_t size,
                                      const VibtaniumFirmwareLayout *layout,
                                      bool hcdp_serial_console)
{
    write_guid(blob, size, VIBTANIUM_EFI_CONFIGURATION_TABLE,
               efi_acpi20_table_guid);
    blob_wr64(blob, size, VIBTANIUM_EFI_CONFIGURATION_TABLE + 16,
              layout->acpi_rsdp);
    write_guid(blob, size, VIBTANIUM_EFI_CONFIGURATION_TABLE + 24,
               efi_sal_system_table_guid);
    blob_wr64(blob, size, VIBTANIUM_EFI_CONFIGURATION_TABLE + 40,
              layout->sal_system_table);
    if (hcdp_serial_console) {
        write_guid(blob, size, VIBTANIUM_EFI_CONFIGURATION_TABLE + 48,
                   efi_hcdp_table_guid);
        blob_wr64(blob, size, VIBTANIUM_EFI_CONFIGURATION_TABLE + 64,
                  layout->hcdp_table);
    }
}

static void write_sal_system_table(uint8_t *blob, size_t size,
                                   const VibtaniumFirmwareLayout *layout)
{
    uint8_t *table = blob_ptr(blob, size, layout->sal_system_table,
                              SAL_SYSTEM_TABLE_LENGTH);
    uint8_t *entry = table + SAL_SYSTEM_TABLE_HEADER_LENGTH;

    wr32(table, 0x5f545353); /* "SST_" */
    wr32(table + 4, SAL_SYSTEM_TABLE_LENGTH);
    table[8] = 1; /* SAL revision minor. */
    table[9] = 0; /* SAL revision major. */
    table[10] = SAL_SYSTEM_TABLE_ENTRY_COUNT;
    table[11] = 0;
    write_fixed_ascii(table + 24, 32, "Vibtanium");
    write_fixed_ascii(table + 56, 32, "Vibtanium IA-64");

    entry[0] = 0; /* SAL_DESC_ENTRY_POINT */
    wr64(entry + 8, VIBTANIUM_EFI_PAL_PROC);
    wr64(entry + 16, VIBTANIUM_EFI_SAL_PROC);
    wr64(entry + 24, VIBTANIUM_EFI_SAL_GP);
    table[12] = sal_checksum(table, SAL_SYSTEM_TABLE_LENGTH);

    /*
     * PAL/SAL procedure entry points may be reached through PAL's static
     * br.cond calling convention, which does not allocate a stacked frame.
     */
    write_branch_gate(blob, size, VIBTANIUM_EFI_PAL_PROC);
    write_branch_gate(blob, size, VIBTANIUM_EFI_SAL_PROC);
    blob_wr64(blob, size, VIBTANIUM_EFI_SAL_GP, 0);
}

static void write_hcdp_table(uint8_t *blob, size_t size,
                             const VibtaniumFirmwareLayout *layout)
{
    uint8_t *table = blob_ptr(blob, size, layout->hcdp_table,
                              HCDP_TABLE_LENGTH);
    uint8_t *uart = table + HCDP_UART_OFFSET;

    memcpy(table, "HCDP", 4);
    wr32(table + 4, HCDP_TABLE_LENGTH);
    table[8] = 3; /* PCDP 2.0 / HCDP revision. */
    memcpy(table + 10, "VIBTAN", 6);
    memcpy(table + 16, "VIBHCDP ", 8);
    wr32(table + 24, 1);
    memcpy(table + 28, "VIBT", 4);
    wr32(table + 32, 1);
    wr32(table + 36, 1);

    uart[0] = PCDP_CONSOLE_UART;
    uart[1] = 8;
    uart[2] = 0;
    uart[3] = 1;
    wr64(uart + 8, 115200);
    uart[16] = ACPI_ADR_SPACE_SYSTEM_IO;
    uart[17] = 8;
    uart[18] = 0;
    uart[19] = 1;
    wr64(uart + 20, VIBTANIUM_LEGACY_COM1_BASE);
    wr32(uart + 32, 0);
    wr32(uart + 36, 1843200);
    uart[41] = PCDP_UART_PRIMARY_CONSOLE;

    table[9] = sal_checksum(table, HCDP_TABLE_LENGTH);
}

static GArray *acpi_table_array_new(void)
{
    return g_array_new(false, true, 1);
}

static void write_acpi_root_pointer(uint8_t *blob, size_t size,
                                    const VibtaniumFirmwareLayout *layout)
{
    uint8_t *rsdp = blob_ptr(blob, size, layout->acpi_rsdp,
                             ACPI_RSDP_LENGTH);

    memcpy(rsdp, "RSD PTR ", 8);
    memcpy(rsdp + 9, ACPI_OEM_ID, 6);
    rsdp[15] = 2;
    wr32(rsdp + 16, layout->acpi_rsdt);
    wr32(rsdp + 20, ACPI_RSDP_LENGTH);
    wr64(rsdp + 24, layout->acpi_xsdt);
    rsdp[8] = byte_checksum(rsdp, 20);
    rsdp[32] = byte_checksum(rsdp, ACPI_RSDP_LENGTH);
}

static GArray *build_acpi_rsdt_table(const VibtaniumFirmwareLayout *layout)
{
    GArray *table_data = acpi_table_array_new();
    AcpiTable table = {
        .sig = "RSDT",
        .rev = 1,
        .oem_id = ACPI_OEM_ID,
        .oem_table_id = ACPI_OEM_TABLE_ID,
    };

    g_assert_cmphex(layout->acpi_fadt, <=, UINT32_MAX);
    g_assert_cmphex(layout->acpi_madt, <=, UINT32_MAX);
    acpi_table_begin(&table, table_data);
    build_append_int_noprefix(table_data, layout->acpi_fadt, 4);
    build_append_int_noprefix(table_data, layout->acpi_madt, 4);
    acpi_table_end(NULL, &table);
    return table_data;
}

static GArray *build_acpi_xsdt_table(const VibtaniumFirmwareLayout *layout)
{
    GArray *table_data = acpi_table_array_new();
    AcpiTable table = {
        .sig = "XSDT",
        .rev = 1,
        .oem_id = ACPI_OEM_ID,
        .oem_table_id = ACPI_OEM_TABLE_ID,
    };

    acpi_table_begin(&table, table_data);
    build_append_int_noprefix(table_data, layout->acpi_fadt, 8);
    build_append_int_noprefix(table_data, layout->acpi_madt, 8);
    acpi_table_end(NULL, &table);
    return table_data;
}

static GArray *build_acpi_fadt_table(const VibtaniumFirmwareLayout *layout)
{
    GArray *table_data = acpi_table_array_new();
    AcpiTable table = {
        .sig = "FACP",
        .rev = 3,
        .oem_id = ACPI_OEM_ID,
        .oem_table_id = ACPI_OEM_TABLE_ID,
    };
    uint8_t *fadt;

    g_assert_cmphex(layout->acpi_facs, <=, UINT32_MAX);
    g_assert_cmphex(layout->acpi_dsdt, <=, UINT32_MAX);
    acpi_table_begin(&table, table_data);
    g_array_set_size(table_data, ACPI_FADT_LENGTH);
    fadt = (uint8_t *)table_data->data + table.table_offset;

    wr32(fadt + 36, layout->acpi_facs);
    wr32(fadt + 40, layout->acpi_dsdt);
    fadt[45] = 4; /* Enterprise server. */
    wr16(fadt + 46, 9);
    wr32(fadt + 56, 0x400);
    wr32(fadt + 64, 0x404);
    wr32(fadt + 76, 0x408);
    fadt[88] = 4;
    fadt[89] = 2;
    fadt[91] = 4;
    wr16(fadt + 109, 0);
    wr32(fadt + 112, (1 << 0) | (1 << 2) | (1 << 4) |
                       (1 << 5) | (1 << 6) | (1 << 8) |
                       (1 << 12));
    wr64(fadt + 132, layout->acpi_facs);
    wr64(fadt + 140, layout->acpi_dsdt);
    write_acpi_gas(fadt + 148, ACPI_ADR_SPACE_SYSTEM_IO, 32, 1, 0x400);
    write_acpi_gas(fadt + 172, ACPI_ADR_SPACE_SYSTEM_IO, 16, 1, 0x404);
    write_acpi_gas(fadt + 208, ACPI_ADR_SPACE_SYSTEM_IO, 32, 1, 0x408);
    acpi_table_end(NULL, &table);
    return table_data;
}

static Aml *build_acpi_com1_device(void)
{
    Aml *dev = aml_device("COM1");
    Aml *crs = aml_resource_template();

    aml_append(dev, aml_name_decl("_HID", aml_eisaid("PNP0501")));
    aml_append(dev, aml_name_decl("_UID", aml_int(1)));
    aml_append(dev, aml_name_decl("_STA", aml_int(0x0f)));
    aml_append(crs, aml_io(AML_DECODE16, 0x03f8, 0x03f8, 0x00, 0x08));
    aml_append(crs, aml_irq_no_flags(4));
    aml_append(dev, aml_name_decl("_CRS", crs));
    return dev;
}

static Aml *build_acpi_keyboard_device(void)
{
    Aml *dev = aml_device("KBD_");
    Aml *crs = aml_resource_template();

    aml_append(dev, aml_name_decl("_HID", aml_eisaid("PNP0303")));
    aml_append(dev, aml_name_decl("_STA", aml_int(0x0f)));
    aml_append(crs, aml_io(AML_DECODE16, 0x0060, 0x0060, 0x01, 0x01));
    aml_append(crs, aml_io(AML_DECODE16, 0x0064, 0x0064, 0x01, 0x01));
    aml_append(crs, aml_irq_no_flags(1));
    aml_append(dev, aml_name_decl("_CRS", crs));
    return dev;
}

static Aml *build_acpi_pci0_device(void)
{
    Aml *dev = aml_device("PCI0");
    Aml *crs = aml_resource_template();
    Aml *prt = aml_package(128);

    aml_append(dev, aml_name_decl("_HID", aml_eisaid("PNP0A03")));
    aml_append(dev, aml_name_decl("_ADR", aml_int(0)));
    aml_append(dev, aml_name_decl("_BBN", aml_int(0)));
    aml_append(crs,
               aml_word_bus_number(AML_MIN_FIXED, AML_MAX_FIXED,
                                   AML_POS_DECODE, 0x0000, 0x0000, 0x00ff,
                                   0x0000, 0x0100));
    aml_append(crs,
               aml_word_io(AML_MIN_FIXED, AML_MAX_FIXED, AML_POS_DECODE,
                           AML_ENTIRE_RANGE, 0x0000, VIBTANIUM_PCI_IO_BASE,
                           VIBTANIUM_PCI_IO_BASE +
                           VIBTANIUM_PCI_IO_SIZE - 1,
                           0x0000, VIBTANIUM_PCI_IO_SIZE - 1));
    aml_append(crs,
               aml_dword_memory(AML_POS_DECODE, AML_MIN_FIXED,
                                AML_MAX_FIXED, AML_NON_CACHEABLE,
                                AML_READ_WRITE, 0x00000000,
                                VIBTANIUM_PCI_MMIO_BASE,
                                VIBTANIUM_PCI_MMIO_BASE +
                                VIBTANIUM_PCI_MMIO_SIZE - 1,
                                0x00000000, VIBTANIUM_PCI_MMIO_SIZE));
    aml_append(dev, aml_name_decl("_CRS", crs));

    for (int slot = 0; slot < 32; slot++) {
        for (int pin = 0; pin < 4; pin++) {
            Aml *pkg = aml_package(4);
            int irq = VIBTANIUM_PCI_INTX_IRQ_BASE + ((slot + pin) & 3);

            aml_append(pkg, aml_int((slot << 16) | 0xffff));
            aml_append(pkg, aml_int(pin));
            aml_append(pkg, aml_int(0));
            aml_append(pkg, aml_int(irq));
            aml_append(prt, pkg);
        }
    }
    aml_append(dev, aml_name_decl("_PRT", prt));
    return dev;
}

static GArray *build_acpi_dsdt_table(void)
{
    GArray *table_data = acpi_table_array_new();
    AcpiTable table = {
        .sig = "DSDT",
        .rev = 2,
        .oem_id = ACPI_OEM_ID,
        .oem_table_id = ACPI_OEM_TABLE_ID,
    };
    Aml *dsdt;
    Aml *scope;

    acpi_table_begin(&table, table_data);
    dsdt = init_aml_allocator();
    scope = aml_scope("_SB");
    aml_append(scope, build_acpi_com1_device());
    aml_append(scope, build_acpi_keyboard_device());
    aml_append(scope, build_acpi_pci0_device());
    aml_append(dsdt, scope);
    g_array_append_vals(table_data, dsdt->buf->data, dsdt->buf->len);
    acpi_table_end(NULL, &table);
    free_aml_allocator();
    return table_data;
}

static GArray *build_acpi_madt_table(void)
{
    GArray *table_data = acpi_table_array_new();
    AcpiTable table = {
        .sig = "APIC",
        .rev = 3,
        .oem_id = ACPI_OEM_ID,
        .oem_table_id = ACPI_OEM_TABLE_ID,
    };
    uint8_t *madt;
    uint8_t *lsapic;
    uint8_t *iosapic;

    acpi_table_begin(&table, table_data);
    g_array_set_size(table_data, ACPI_MADT_LENGTH);
    madt = (uint8_t *)table_data->data + table.table_offset;
    lsapic = madt + 44;
    iosapic = lsapic + ACPI_MADT_LOCAL_SAPIC_LENGTH;

    wr32(madt + 36, VIBTANIUM_LOCAL_SAPIC_IPI_BASE);
    wr32(madt + 40, 1);

    lsapic[0] = 7; /* ACPI_MADT_TYPE_LOCAL_SAPIC */
    lsapic[1] = ACPI_MADT_LOCAL_SAPIC_LENGTH;
    lsapic[2] = 0;
    lsapic[3] = 0;
    lsapic[4] = 0;
    wr32(lsapic + 8, 1);
    wr32(lsapic + 12, 0);

    iosapic[0] = 6; /* ACPI_MADT_TYPE_IO_SAPIC */
    iosapic[1] = ACPI_MADT_IO_SAPIC_LENGTH;
    iosapic[2] = 0;
    wr32(iosapic + 4, 0);
    wr64(iosapic + 8, VIBTANIUM_IOSAPIC_BASE);

    acpi_table_end(NULL, &table);
    return table_data;
}

static void write_acpi_facs(uint8_t *blob, size_t size,
                            const VibtaniumFirmwareLayout *layout)
{
    uint8_t *facs = blob_ptr(blob, size, layout->acpi_facs,
                             ACPI_FACS_LENGTH);

    memcpy(facs, "FACS", 4);
    wr32(facs + 4, ACPI_FACS_LENGTH);
    facs[32] = 2;
}

static void write_acpi_tables(uint8_t *blob, size_t size,
                              const VibtaniumFirmwareLayout *layout,
                              const GArray *dsdt)
{
    GArray *rsdt = build_acpi_rsdt_table(layout);
    GArray *xsdt = build_acpi_xsdt_table(layout);
    GArray *fadt = build_acpi_fadt_table(layout);
    GArray *madt = build_acpi_madt_table();

    write_acpi_root_pointer(blob, size, layout);
    firmware_copy_table(blob, size, layout->acpi_rsdt, rsdt);
    firmware_copy_table(blob, size, layout->acpi_xsdt, xsdt);
    firmware_copy_table(blob, size, layout->acpi_fadt, fadt);
    firmware_copy_table(blob, size, layout->acpi_dsdt, dsdt);
    firmware_copy_table(blob, size, layout->acpi_madt, madt);
    write_acpi_facs(blob, size, layout);

    g_array_free(rsdt, true);
    g_array_free(xsdt, true);
    g_array_free(fadt, true);
    g_array_free(madt, true);
}

static void write_system_table(uint8_t *blob, size_t size,
                               unsigned configuration_table_count)
{
    uint8_t *table = blob_ptr(blob, size, VIBTANIUM_EFI_SYSTEM_TABLE, 120);

    blob_wr64(blob, size, VIBTANIUM_EFI_SYSTEM_TABLE + 24,
              VIBTANIUM_EFI_FIRMWARE_VENDOR);
    blob_wr32(blob, size, VIBTANIUM_EFI_SYSTEM_TABLE + 32, 1);
    blob_wr64(blob, size, VIBTANIUM_EFI_SYSTEM_TABLE + 40,
              VIBTANIUM_EFI_BOOT_DEVICE_HANDLE);
    blob_wr64(blob, size, VIBTANIUM_EFI_SYSTEM_TABLE + 48,
              VIBTANIUM_EFI_CON_IN);
    blob_wr64(blob, size, VIBTANIUM_EFI_SYSTEM_TABLE + 56,
              VIBTANIUM_EFI_BOOT_DEVICE_HANDLE);
    blob_wr64(blob, size, VIBTANIUM_EFI_SYSTEM_TABLE + 64,
              VIBTANIUM_EFI_CON_OUT);
    blob_wr64(blob, size, VIBTANIUM_EFI_SYSTEM_TABLE + 72,
              VIBTANIUM_EFI_BOOT_DEVICE_HANDLE);
    blob_wr64(blob, size, VIBTANIUM_EFI_SYSTEM_TABLE + 80,
              VIBTANIUM_EFI_CON_OUT);
    blob_wr64(blob, size, VIBTANIUM_EFI_SYSTEM_TABLE + 88,
              VIBTANIUM_EFI_RUNTIME_SERVICES);
    blob_wr64(blob, size, VIBTANIUM_EFI_SYSTEM_TABLE + 96,
              VIBTANIUM_EFI_BOOT_SERVICES);
    blob_wr64(blob, size, VIBTANIUM_EFI_SYSTEM_TABLE + 104,
              configuration_table_count);
    blob_wr64(blob, size, VIBTANIUM_EFI_SYSTEM_TABLE + 112,
              VIBTANIUM_EFI_CONFIGURATION_TABLE);
    write_table_header(table, 120, 0x5453595320494249ULL);
}

static void write_service_table(uint8_t *blob, size_t size, uint64_t address,
                                uint64_t signature, unsigned service_base,
                                unsigned service_count, int reserved_index)
{
    size_t table_size = 24 + service_count * sizeof(uint64_t);
    uint8_t *table = blob_ptr(blob, size, address, table_size);

    for (unsigned i = 0; i < service_count; i++) {
        uint64_t slot = i == (unsigned)reserved_index
            ? 0
            : service_descriptor_address(service_base + i);
        blob_wr64(blob, size, address + 24 + i * sizeof(uint64_t), slot);
    }
    write_table_header(table, table_size, signature);
}

static void write_console_protocols(uint8_t *blob, size_t size)
{
    for (unsigned i = 0; i < VIBTANIUM_EFI_CON_OUT_SERVICE_COUNT; i++) {
        blob_wr64(blob, size, VIBTANIUM_EFI_CON_OUT + i * sizeof(uint64_t),
                  service_descriptor_address(EFI_CON_OUT_SERVICE_BASE + i));
    }
    blob_wr64(blob, size,
              VIBTANIUM_EFI_CON_OUT +
              VIBTANIUM_EFI_CON_OUT_SERVICE_COUNT * sizeof(uint64_t),
              VIBTANIUM_EFI_CON_OUT_MODE);
    blob_wr32(blob, size, VIBTANIUM_EFI_CON_OUT_MODE, 1);
    blob_wr32(blob, size, VIBTANIUM_EFI_CON_OUT_MODE + 4, 0);
    blob_wr32(blob, size, VIBTANIUM_EFI_CON_OUT_MODE + 8, 0x07);
    blob_ptr(blob, size, VIBTANIUM_EFI_CON_OUT_MODE + 20, 1)[0] = 1;

    for (unsigned i = 0; i < VIBTANIUM_EFI_CON_IN_SERVICE_COUNT; i++) {
        blob_wr64(blob, size, VIBTANIUM_EFI_CON_IN + i * sizeof(uint64_t),
                  service_descriptor_address(EFI_CON_IN_SERVICE_BASE + i));
    }
    blob_wr64(blob, size,
              VIBTANIUM_EFI_CON_IN +
              VIBTANIUM_EFI_CON_IN_SERVICE_COUNT * sizeof(uint64_t),
              VIBTANIUM_EFI_CON_IN_WAIT_EVENT);
}

static void write_gop_protocol(uint8_t *blob, size_t size)
{
    uint8_t *info = blob_ptr(blob, size, VIBTANIUM_EFI_GOP_MODE_INFO, 36);

    for (unsigned i = 0; i < VIBTANIUM_EFI_GOP_SERVICE_COUNT; i++) {
        blob_wr64(blob, size, VIBTANIUM_EFI_GOP + i * sizeof(uint64_t),
                  service_descriptor_address(EFI_GOP_SERVICE_BASE + i));
    }
    blob_wr64(blob, size, VIBTANIUM_EFI_GOP + 24, VIBTANIUM_EFI_GOP_MODE);

    blob_wr32(blob, size, VIBTANIUM_EFI_GOP_MODE, 1);
    blob_wr32(blob, size, VIBTANIUM_EFI_GOP_MODE + 4, 0);
    blob_wr64(blob, size, VIBTANIUM_EFI_GOP_MODE + 8,
              VIBTANIUM_EFI_GOP_MODE_INFO);
    blob_wr64(blob, size, VIBTANIUM_EFI_GOP_MODE + 16, 36);
    blob_wr64(blob, size, VIBTANIUM_EFI_GOP_MODE + 24,
              VIBTANIUM_FRAMEBUFFER_BASE);
    blob_wr64(blob, size, VIBTANIUM_EFI_GOP_MODE + 32,
              VIBTANIUM_FRAMEBUFFER_SIZE);

    wr32(info, 0);
    wr32(info + 4, VIBTANIUM_FRAMEBUFFER_WIDTH);
    wr32(info + 8, VIBTANIUM_FRAMEBUFFER_HEIGHT);
    wr32(info + 12, 1); /* PixelBlueGreenRedReserved8BitPerColor */
    wr32(info + 32, VIBTANIUM_FRAMEBUFFER_WIDTH);
}

#define EFI_DP_HARDWARE_DEVICE_PATH       0x01
#define EFI_DP_MESSAGING_DEVICE_PATH      0x03
#define EFI_DP_MEDIA_DEVICE_PATH          0x04
#define EFI_DP_END_DEVICE_PATH            0x7f
#define EFI_DP_HW_PCI                     0x01
#define EFI_DP_MSG_ATAPI                  0x01
#define EFI_DP_MEDIA_CDROM                0x02
#define EFI_DP_END_ENTIRE                 0xff
#define EFI_DP_PCI_LENGTH                 6
#define EFI_DP_ATAPI_LENGTH               8
#define EFI_DP_CDROM_LENGTH               24
#define EFI_DP_END_LENGTH                 4
#define VIBTANIUM_IDE_PCI_DEVICE          1
#define VIBTANIUM_IDE_PCI_FUNCTION        0
#define VIBTANIUM_IDE_CD_PRIMARY_SECONDARY 1
#define VIBTANIUM_IDE_CD_SLAVE_MASTER     0
#define VIBTANIUM_IDE_CD_LUN              0

static uint8_t *write_device_path_header(uint8_t *path, uint8_t type,
                                         uint8_t subtype, uint16_t length)
{
    path[0] = type;
    path[1] = subtype;
    wr16(path + 2, length);
    return path + length;
}

static void write_device_path(uint8_t *blob, size_t size,
                              const VibtaniumEfiBlockDevice *boot_media,
                              uint32_t block_size, uint64_t media_size)
{
    uint64_t media_blocks = block_size != 0 ? media_size / block_size : 0;
    size_t path_length = EFI_DP_END_LENGTH;
    uint8_t *path;

    if (boot_media && boot_media->cdrom) {
        path_length += EFI_DP_PCI_LENGTH + EFI_DP_ATAPI_LENGTH +
            EFI_DP_CDROM_LENGTH;
    }

    path = blob_ptr(blob, size, VIBTANIUM_EFI_DEVICE_PATH, path_length);
    if (boot_media && boot_media->cdrom) {
        /*
         * vibtanium wires the boot optical drive as the CMD646 secondary
         * master. Windows IA-64 uses these standard EFI nodes to recover its
         * BootContext and later rematch the Block I/O handle.
         */
        path = write_device_path_header(path, EFI_DP_HARDWARE_DEVICE_PATH,
                                        EFI_DP_HW_PCI, EFI_DP_PCI_LENGTH);
        path[-2] = VIBTANIUM_IDE_PCI_FUNCTION;
        path[-1] = VIBTANIUM_IDE_PCI_DEVICE;

        path = write_device_path_header(path, EFI_DP_MESSAGING_DEVICE_PATH,
                                        EFI_DP_MSG_ATAPI,
                                        EFI_DP_ATAPI_LENGTH);
        path[-4] = VIBTANIUM_IDE_CD_PRIMARY_SECONDARY;
        path[-3] = VIBTANIUM_IDE_CD_SLAVE_MASTER;
        wr16(path - 2, VIBTANIUM_IDE_CD_LUN);

        path = write_device_path_header(path, EFI_DP_MEDIA_DEVICE_PATH,
                                        EFI_DP_MEDIA_CDROM,
                                        EFI_DP_CDROM_LENGTH);
        wr32(path - 20, 0);
        wr64(path - 16, 0);
        wr64(path - 8, media_blocks);
    }

    path = write_device_path_header(path, EFI_DP_END_DEVICE_PATH,
                                    EFI_DP_END_ENTIRE, EFI_DP_END_LENGTH);
}

static void write_media_protocols(uint8_t *blob, size_t size,
                                  const VibtaniumEfiBlockDevice *boot_media)
{
    uint32_t block_size = boot_media && boot_media->block_size
        ? boot_media->block_size
        : 2048;
    uint64_t media_size = boot_media ? boot_media->size : 0;
    uint64_t last_block = media_size >= block_size && block_size != 0
        ? media_size / block_size - 1
        : 0;

    write_device_path(blob, size, boot_media, block_size, media_size);

    blob_wr64(blob, size, VIBTANIUM_EFI_BLOCK_IO,
              VIBTANIUM_EFI_PROTOCOL_REVISION);
    blob_wr64(blob, size, VIBTANIUM_EFI_BLOCK_IO + 8,
              VIBTANIUM_EFI_BLOCK_IO_MEDIA);
    for (unsigned i = 0; i < VIBTANIUM_EFI_BLOCK_IO_SERVICE_COUNT; i++) {
        blob_wr64(blob, size, VIBTANIUM_EFI_BLOCK_IO + 16 + i * 8,
                  service_descriptor_address(EFI_BLOCK_IO_SERVICE_BASE + i));
    }

    blob_wr32(blob, size, VIBTANIUM_EFI_BLOCK_IO_MEDIA, 1);
    blob_ptr(blob, size, VIBTANIUM_EFI_BLOCK_IO_MEDIA + 4, 1)[0] =
        boot_media && boot_media->removable;
    blob_ptr(blob, size, VIBTANIUM_EFI_BLOCK_IO_MEDIA + 5, 1)[0] =
        boot_media != NULL;
    blob_ptr(blob, size, VIBTANIUM_EFI_BLOCK_IO_MEDIA + 6, 1)[0] = 0;
    blob_ptr(blob, size, VIBTANIUM_EFI_BLOCK_IO_MEDIA + 7, 1)[0] =
        !boot_media || boot_media->read_only;
    blob_ptr(blob, size, VIBTANIUM_EFI_BLOCK_IO_MEDIA + 8, 1)[0] = 0;
    blob_wr32(blob, size, VIBTANIUM_EFI_BLOCK_IO_MEDIA + 12, block_size);
    blob_wr32(blob, size, VIBTANIUM_EFI_BLOCK_IO_MEDIA + 16, 1);
    blob_wr64(blob, size, VIBTANIUM_EFI_BLOCK_IO_MEDIA + 24, last_block);

    blob_wr64(blob, size, VIBTANIUM_EFI_SIMPLE_FILE_SYSTEM,
              VIBTANIUM_EFI_PROTOCOL_REVISION);
    blob_wr64(blob, size, VIBTANIUM_EFI_SIMPLE_FILE_SYSTEM + 8,
              service_descriptor_address(EFI_SIMPLE_FILE_SYSTEM_SERVICE_BASE));
}

uint8_t *vibtanium_efi_build_firmware_blob(size_t *size,
                                           const VibtaniumEfiImage *image,
                                           const VibtaniumEfiBlockDevice *boot_media,
                                           const VibtaniumEfiFirmwareOptions *options)
{
    uint8_t *blob;
    VibtaniumFirmwareLayout layout;
    GArray *dsdt;
    bool hcdp_serial_console = options && options->hcdp_serial_console;

    if (size) {
        *size = VIBTANIUM_EFI_BLOB_SIZE;
    }

    dsdt = build_acpi_dsdt_table();
    firmware_layout_build(&layout, dsdt->len);

    blob = g_malloc0(VIBTANIUM_EFI_BLOB_SIZE);
    write_utf16_ascii(blob, VIBTANIUM_EFI_BLOB_SIZE,
                      VIBTANIUM_EFI_FIRMWARE_VENDOR, "Vibtanium");
    for (unsigned i = 0; i < EFI_SERVICE_DESCRIPTOR_COUNT; i++) {
        write_service_descriptor(blob, VIBTANIUM_EFI_BLOB_SIZE, i);
    }
    write_return_gate(blob, VIBTANIUM_EFI_BLOB_SIZE,
                      VIBTANIUM_EFI_START_IMAGE_RETURN_GATE);

    write_loaded_image(blob, VIBTANIUM_EFI_BLOB_SIZE, image);
    write_console_protocols(blob, VIBTANIUM_EFI_BLOB_SIZE);
    write_gop_protocol(blob, VIBTANIUM_EFI_BLOB_SIZE);
    write_media_protocols(blob, VIBTANIUM_EFI_BLOB_SIZE, boot_media);
    write_service_table(blob, VIBTANIUM_EFI_BLOB_SIZE,
                        VIBTANIUM_EFI_BOOT_SERVICES,
                        0x56524553544f4f42ULL,
                        EFI_BOOT_SERVICE_BASE,
                        VIBTANIUM_EFI_BOOT_SERVICE_COUNT, 17);
    write_service_table(blob, VIBTANIUM_EFI_BLOB_SIZE,
                        VIBTANIUM_EFI_RUNTIME_SERVICES,
                        0x56524553544e5552ULL,
                        EFI_RUNTIME_SERVICE_BASE,
                        VIBTANIUM_EFI_RUNTIME_SERVICE_COUNT, -1);
    write_configuration_table(blob, VIBTANIUM_EFI_BLOB_SIZE,
                              &layout,
                              hcdp_serial_console);
    write_acpi_tables(blob, VIBTANIUM_EFI_BLOB_SIZE, &layout, dsdt);
    write_sal_system_table(blob, VIBTANIUM_EFI_BLOB_SIZE, &layout);
    if (hcdp_serial_console) {
        write_hcdp_table(blob, VIBTANIUM_EFI_BLOB_SIZE, &layout);
    }
    write_system_table(blob, VIBTANIUM_EFI_BLOB_SIZE,
                       hcdp_serial_console ? 3 : 2);

    g_array_free(dsdt, true);
    return blob;
}

bool vibtanium_efi_cpu_is_pristine_for_handoff(const CPUIA64State *env)
{
    if (!env) {
        return false;
    }

    return env->ip == 0 &&
           env->cr[IA64_CR_IIP] == 0 &&
           env->cr[IA64_CR_IVA] == 0 &&
           env->gr[12] == 0 &&
           env->rse.bsp == 0 &&
           env->rse.bspstore == 0 &&
           env->ar[IA64_AR_BSP] == 0 &&
           env->ar[IA64_AR_BSPSTORE] == 0;
}

bool vibtanium_efi_prepare_cpu(CPUIA64State *env,
                               const VibtaniumEfiImage *image)
{
    if (!env || !image) {
        return false;
    }
    if (!vibtanium_efi_cpu_is_pristine_for_handoff(env)) {
        return false;
    }

    env->ip = image->entry;
    env->cr[IA64_CR_IIP] = image->entry;
    /*
     * EFI/SAL hand off to OS loaders in the OS register bank. Linux/ia64
     * preserves ELILO's boot-parameter pointer through banked r28.
     */
    env->psr |= IA64_PSR_BN_BIT;
    ia64_write_gr(env, 0, 0);
    ia64_write_gr(env, 1, image->global_pointer);
    ia64_write_gr(env, 12,
                  VIBTANIUM_EFI_STACK_BASE + VIBTANIUM_EFI_STACK_SIZE - 16);
    ia64_write_gr(env, 32, VIBTANIUM_EFI_IMAGE_HANDLE);
    ia64_write_gr(env, 33, VIBTANIUM_EFI_SYSTEM_TABLE);

    env->rse.bsp = VIBTANIUM_EFI_BACKING_STORE_BASE;
    env->rse.bspstore = VIBTANIUM_EFI_BACKING_STORE_BASE;
    env->rse.bsp_load = VIBTANIUM_EFI_BACKING_STORE_BASE;
    env->ar[IA64_AR_BSP] = env->rse.bsp;
    env->ar[IA64_AR_BSPSTORE] = env->rse.bspstore;
    env->ar[IA64_AR_KR0] = VIBTANIUM_IO_PORT_BASE;
    ia64_firmware_identity_tlb_set(env, true);
    return true;
}

const char *vibtanium_efi_status_name(uint64_t status)
{
    switch (status) {
    case VIBTANIUM_EFI_SUCCESS:
        return "success";
    case VIBTANIUM_EFI_LOAD_ERROR:
        return "load-error";
    case VIBTANIUM_EFI_INVALID_PARAMETER:
        return "invalid-parameter";
    case VIBTANIUM_EFI_UNSUPPORTED:
        return "unsupported";
    case VIBTANIUM_EFI_BUFFER_TOO_SMALL:
        return "buffer-too-small";
    case VIBTANIUM_EFI_NOT_READY:
        return "not-ready";
    case VIBTANIUM_EFI_DEVICE_ERROR:
        return "device-error";
    case VIBTANIUM_EFI_WRITE_PROTECTED:
        return "write-protected";
    case VIBTANIUM_EFI_OUT_OF_RESOURCES:
        return "out-of-resources";
    case VIBTANIUM_EFI_ACCESS_DENIED:
        return "access-denied";
    case VIBTANIUM_EFI_NOT_FOUND:
        return "not-found";
    case VIBTANIUM_EFI_END_OF_FILE:
        return "end-of-file";
    default:
        return "unknown";
    }
}

const char *vibtanium_efi_service_name(VibtaniumEfiService service)
{
    switch (service) {
    case VIBTANIUM_EFI_SERVICE_LOADED_IMAGE_PROTOCOL:
        return "LoadedImageProtocol";
    case VIBTANIUM_EFI_SERVICE_OUTPUT_STRING:
        return "SimpleTextOutput.OutputString";
    case VIBTANIUM_EFI_SERVICE_EXIT:
        return "BootServices.Exit";
    case VIBTANIUM_EFI_SERVICE_EXIT_BOOT_SERVICES:
        return "BootServices.ExitBootServices";
    case VIBTANIUM_EFI_SERVICE_GET_VARIABLE:
        return "RuntimeServices.GetVariable";
    case VIBTANIUM_EFI_SERVICE_SET_VARIABLE:
        return "RuntimeServices.SetVariable";
    case VIBTANIUM_EFI_SERVICE_UNKNOWN:
    default:
        return "unknown-service";
    }
}

uint64_t vibtanium_efi_record_unimplemented_service(
    VibtaniumEfiServiceCall *call,
    VibtaniumEfiService service,
    uint64_t guest_ip,
    const uint64_t *args,
    uint8_t nargs)
{
    size_t offset;
    uint8_t count;

    g_return_val_if_fail(call != NULL, VIBTANIUM_EFI_INVALID_PARAMETER);

    memset(call, 0, sizeof(*call));
    count = MIN(nargs, (uint8_t)G_N_ELEMENTS(call->args));
    call->service = service;
    call->service_name = vibtanium_efi_service_name(service);
    call->guest_ip = guest_ip;
    call->nargs = count;
    call->status = VIBTANIUM_EFI_UNSUPPORTED;

    for (uint8_t i = 0; i < count; i++) {
        call->args[i] = args ? args[i] : 0;
    }

    offset = g_snprintf(call->message, sizeof(call->message),
                        "EFI service unimplemented service=%s ip=0x%016"
                        PRIx64 " args=[",
                        call->service_name, call->guest_ip);
    for (uint8_t i = 0; i < count && offset < sizeof(call->message); i++) {
        offset += g_snprintf(call->message + offset,
                             sizeof(call->message) - offset,
                             "%s0x%016" PRIx64, i == 0 ? "" : ",",
                             call->args[i]);
    }
    if (offset < sizeof(call->message)) {
        g_snprintf(call->message + offset, sizeof(call->message) - offset,
                   "] status=%s(0x%016" PRIx64 ")",
                   vibtanium_efi_status_name(call->status), call->status);
    }

    return call->status;
}

const char *vibtanium_efi_frontier_name(VibtaniumEfiFrontierKind kind)
{
    switch (kind) {
    case VIBTANIUM_EFI_FRONTIER_IMAGE_ENTRY:
        return "image-entry";
    case VIBTANIUM_EFI_FRONTIER_EFI_SERVICE_CALL:
        return "efi-service-call";
    case VIBTANIUM_EFI_FRONTIER_FILE_READ:
        return "file-read";
    case VIBTANIUM_EFI_FRONTIER_MEMORY_MAP:
        return "memory-map";
    case VIBTANIUM_EFI_FRONTIER_EXIT_BOOT_SERVICES:
        return "exit-boot-services";
    case VIBTANIUM_EFI_FRONTIER_KERNEL_ENTRY:
        return "kernel-entry";
    case VIBTANIUM_EFI_FRONTIER_BOOT_PARAMETERS:
        return "boot-parameters";
    case VIBTANIUM_EFI_FRONTIER_SAL_PAL_CALL:
        return "sal-pal-call";
    default:
        return "unknown-frontier";
    }
}

void vibtanium_efi_format_frontier(char *buffer,
                                   size_t buffer_size,
                                   VibtaniumEfiFrontierKind kind,
                                   uint64_t guest_ip,
                                   const char *state,
                                   const char *detail)
{
    if (!buffer || buffer_size == 0) {
        return;
    }

    g_snprintf(buffer, buffer_size,
               "vibtanium EFI frontier kind=%s ip=0x%016" PRIx64
               " state=%s detail=%s",
               vibtanium_efi_frontier_name(kind), guest_ip,
               state ? state : "unknown",
               detail ? detail : "none");
}
