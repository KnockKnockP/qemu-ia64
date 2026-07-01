/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "qemu/osdep.h"
#include "hw/ia64/efi.h"
#include "hw/ia64/efi-storage.h"
#include "hw/ia64/vibtanium.h"
#include "target/ia64/bundle.h"
#include "target/ia64/exec-smoke.h"

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
#define PE_BASE_RELOCATION_DIR64    10

#define MAX_EFI_IMAGE_SIZE (128 * 1024 * 1024)
#define IA64_PSR_BN_BIT UINT64_C(0x0000100000000000)
#define SAL_SYSTEM_TABLE_LENGTH 144
#define SAL_SYSTEM_TABLE_HEADER_LENGTH 96
#define SAL_SYSTEM_TABLE_ENTRY_COUNT 1
#define HCDP_TABLE_LENGTH 88
#define HCDP_UART_OFFSET 40
#define HCDP_UART_LENGTH 48
#define ACPI_RSDP_LENGTH 36
#define ACPI_RSDT_ENTRY_COUNT 2
#define ACPI_RSDT_LENGTH (36 + ACPI_RSDT_ENTRY_COUNT * 4)
#define ACPI_XSDT_LENGTH (36 + ACPI_RSDT_ENTRY_COUNT * 8)
#define ACPI_FADT_LENGTH 244
#define ACPI_DSDT_AML_LENGTH 166
#define ACPI_DSDT_LENGTH (36 + ACPI_DSDT_AML_LENGTH)
#define ACPI_MADT_LOCAL_SAPIC_LENGTH 16
#define ACPI_MADT_IO_SAPIC_LENGTH 16
#define ACPI_MADT_LENGTH \
    (36 + 8 + ACPI_MADT_LOCAL_SAPIC_LENGTH + ACPI_MADT_IO_SAPIC_LENGTH)
#define ACPI_FACS_LENGTH 64
#define ACPI_ADR_SPACE_SYSTEM_IO 1
#define PCDP_CONSOLE_UART 0
#define PCDP_UART_PRIMARY_CONSOLE (1 << 2)

static const uint8_t vibtanium_dsdt_aml[ACPI_DSDT_AML_LENGTH] = {
    /*
     * Scope (_SB) {
     *     Device (COM1) {
     *         Name (_HID, EisaId ("PNP0501"))
     *         Name (_UID, One)
     *         Name (_STA, 0x0f)
     *         Name (_CRS, ResourceTemplate () {
     *             IO (Decode16, 0x03f8, 0x03f8, 0x00, 0x08)
     *             IRQNoFlags () {4}
     *         })
     *     }
     *     Device (PCI0) {
     *         Name (_HID, EisaId ("PNP0A03"))
     *         Name (_ADR, Zero)
     *         Name (_BBN, Zero)
     *         Name (_CRS, ResourceTemplate () {
     *             WordBusNumber (ResourceProducer, MinFixed, MaxFixed,
     *                            PosDecode, 0x0000, 0x0000, 0x00ff,
     *                            0x0000, 0x0100)
     *             WordIO (ResourceProducer, MinFixed, MaxFixed, PosDecode,
     *                     EntireRange, 0x0000, 0x0000, 0xffff, 0x0000,
     *                     0x0000)
     *             DWordMemory (ResourceProducer, PosDecode, MinFixed, MaxFixed,
     *                          NonCacheable, ReadWrite, 0x00000000,
     *                          0x80000000, 0xefffffff, 0x00000000,
     *                          0x70000000)
     *         })
     *         Name (_PRT, Package () {})
     *     }
     * }
     */
    0x10, 0x45, 0x0a, 0x5f, 0x53, 0x42, 0x5f,
    0x5b, 0x82, 0x32, 0x43, 0x4f, 0x4d, 0x31,
    0x08, 0x5f, 0x48, 0x49, 0x44, 0x0c, 0x41, 0xd0, 0x05, 0x01,
    0x08, 0x5f, 0x55, 0x49, 0x44, 0x01,
    0x08, 0x5f, 0x53, 0x54, 0x41, 0x0a, 0x0f,
    0x08, 0x5f, 0x43, 0x52, 0x53, 0x11, 0x10, 0x0a, 0x0d,
    0x47, 0x01, 0xf8, 0x03, 0xf8, 0x03, 0x00, 0x08,
    0x22, 0x10, 0x00, 0x79, 0x00,
    0x5b, 0x82, 0x49, 0x06, 0x50, 0x43, 0x49, 0x30,
    0x08, 0x5f, 0x48, 0x49, 0x44, 0x0c, 0x41, 0xd0, 0x0a, 0x03,
    0x08, 0x5f, 0x41, 0x44, 0x52, 0x00,
    0x08, 0x5f, 0x42, 0x42, 0x4e, 0x00,
    0x08, 0x5f, 0x43, 0x52, 0x53, 0x11, 0x3f, 0x0a, 0x3c,
    0x88, 0x0d, 0x00, 0x02, 0x0c, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 0x01,
    0x88, 0x0d, 0x00, 0x01, 0x0c, 0x03,
    0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
    0x87, 0x17, 0x00, 0x00, 0x0c, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80,
    0xff, 0xff, 0xff, 0xef, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x70, 0x79, 0x00,
    0x08, 0x5f, 0x50, 0x52, 0x54, 0x12, 0x02, 0x00,
};

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

static void write_acpi_table_header(uint8_t *table, const char *signature,
                                    uint32_t length, uint8_t revision)
{
    memcpy(table, signature, 4);
    wr32(table + 4, length);
    table[8] = revision;
    table[9] = 0;
    memcpy(table + 10, "VIBTAN", 6);
    memcpy(table + 16, "VIBTANIU", 8);
    wr32(table + 24, 1);
    memcpy(table + 28, "VIBT", 4);
    wr32(table + 32, 1);
    table[9] = byte_checksum(table, length);
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

    blob_wr32(blob, size, VIBTANIUM_EFI_LOADED_IMAGE, 0x1000);
    blob_wr64(blob, size, VIBTANIUM_EFI_LOADED_IMAGE + 16,
              VIBTANIUM_EFI_SYSTEM_TABLE);
    blob_wr64(blob, size, VIBTANIUM_EFI_LOADED_IMAGE + 24,
              VIBTANIUM_EFI_BOOT_DEVICE_HANDLE);
    blob_wr64(blob, size, VIBTANIUM_EFI_LOADED_IMAGE + 32,
              VIBTANIUM_EFI_DEVICE_PATH);
    blob_wr64(blob, size, VIBTANIUM_EFI_LOADED_IMAGE + 64, image_base);
    blob_wr64(blob, size, VIBTANIUM_EFI_LOADED_IMAGE + 72, image_size);
    blob_wr32(blob, size, VIBTANIUM_EFI_LOADED_IMAGE + 80, 1);
    blob_wr32(blob, size, VIBTANIUM_EFI_LOADED_IMAGE + 84, 2);
}

static void write_configuration_table(uint8_t *blob, size_t size)
{
    write_guid(blob, size, VIBTANIUM_EFI_CONFIGURATION_TABLE,
               efi_acpi20_table_guid);
    blob_wr64(blob, size, VIBTANIUM_EFI_CONFIGURATION_TABLE + 16,
              VIBTANIUM_EFI_ACPI_RSDP);
    write_guid(blob, size, VIBTANIUM_EFI_CONFIGURATION_TABLE + 24,
               efi_sal_system_table_guid);
    blob_wr64(blob, size, VIBTANIUM_EFI_CONFIGURATION_TABLE + 40,
              VIBTANIUM_EFI_SAL_SYSTEM_TABLE);
    write_guid(blob, size, VIBTANIUM_EFI_CONFIGURATION_TABLE + 48,
               efi_hcdp_table_guid);
    blob_wr64(blob, size, VIBTANIUM_EFI_CONFIGURATION_TABLE + 64,
              VIBTANIUM_EFI_HCDP_TABLE);
}

static void write_sal_system_table(uint8_t *blob, size_t size)
{
    uint8_t *table = blob_ptr(blob, size, VIBTANIUM_EFI_SAL_SYSTEM_TABLE,
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

static void write_hcdp_table(uint8_t *blob, size_t size)
{
    uint8_t *table = blob_ptr(blob, size, VIBTANIUM_EFI_HCDP_TABLE,
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

static void write_acpi_root_pointer(uint8_t *blob, size_t size)
{
    uint8_t *rsdp = blob_ptr(blob, size, VIBTANIUM_EFI_ACPI_RSDP,
                             ACPI_RSDP_LENGTH);

    memcpy(rsdp, "RSD PTR ", 8);
    memcpy(rsdp + 9, "VIBTAN", 6);
    rsdp[15] = 2;
    wr32(rsdp + 16, VIBTANIUM_EFI_ACPI_RSDT);
    wr32(rsdp + 20, ACPI_RSDP_LENGTH);
    wr64(rsdp + 24, VIBTANIUM_EFI_ACPI_XSDT);
    rsdp[8] = byte_checksum(rsdp, 20);
    rsdp[32] = byte_checksum(rsdp, ACPI_RSDP_LENGTH);
}

static void write_acpi_root_tables(uint8_t *blob, size_t size)
{
    uint8_t *rsdt = blob_ptr(blob, size, VIBTANIUM_EFI_ACPI_RSDT,
                             ACPI_RSDT_LENGTH);
    uint8_t *xsdt = blob_ptr(blob, size, VIBTANIUM_EFI_ACPI_XSDT,
                             ACPI_XSDT_LENGTH);

    wr32(rsdt + 36, VIBTANIUM_EFI_ACPI_FADT);
    wr32(rsdt + 40, VIBTANIUM_EFI_ACPI_MADT);
    write_acpi_table_header(rsdt, "RSDT", ACPI_RSDT_LENGTH, 1);

    wr64(xsdt + 36, VIBTANIUM_EFI_ACPI_FADT);
    wr64(xsdt + 44, VIBTANIUM_EFI_ACPI_MADT);
    write_acpi_table_header(xsdt, "XSDT", ACPI_XSDT_LENGTH, 1);
}

static void write_acpi_fadt(uint8_t *blob, size_t size)
{
    uint8_t *fadt = blob_ptr(blob, size, VIBTANIUM_EFI_ACPI_FADT,
                             ACPI_FADT_LENGTH);

    wr32(fadt + 36, VIBTANIUM_EFI_ACPI_FACS);
    wr32(fadt + 40, VIBTANIUM_EFI_ACPI_DSDT);
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
    wr64(fadt + 132, VIBTANIUM_EFI_ACPI_FACS);
    wr64(fadt + 140, VIBTANIUM_EFI_ACPI_DSDT);
    write_acpi_gas(fadt + 148, ACPI_ADR_SPACE_SYSTEM_IO, 32, 1, 0x400);
    write_acpi_gas(fadt + 172, ACPI_ADR_SPACE_SYSTEM_IO, 16, 1, 0x404);
    write_acpi_gas(fadt + 208, ACPI_ADR_SPACE_SYSTEM_IO, 32, 1, 0x408);
    write_acpi_table_header(fadt, "FACP", ACPI_FADT_LENGTH, 3);
}

static void write_acpi_dsdt(uint8_t *blob, size_t size)
{
    uint8_t *dsdt = blob_ptr(blob, size, VIBTANIUM_EFI_ACPI_DSDT,
                             ACPI_DSDT_LENGTH);

    memcpy(dsdt + 36, vibtanium_dsdt_aml, sizeof(vibtanium_dsdt_aml));
    write_acpi_table_header(dsdt, "DSDT", ACPI_DSDT_LENGTH, 2);
}

static void write_acpi_madt(uint8_t *blob, size_t size)
{
    uint8_t *madt = blob_ptr(blob, size, VIBTANIUM_EFI_ACPI_MADT,
                             ACPI_MADT_LENGTH);
    uint8_t *lsapic = madt + 44;
    uint8_t *iosapic = lsapic + ACPI_MADT_LOCAL_SAPIC_LENGTH;

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

    write_acpi_table_header(madt, "APIC", ACPI_MADT_LENGTH, 3);
}

static void write_acpi_facs(uint8_t *blob, size_t size)
{
    uint8_t *facs = blob_ptr(blob, size, VIBTANIUM_EFI_ACPI_FACS,
                             ACPI_FACS_LENGTH);

    memcpy(facs, "FACS", 4);
    wr32(facs + 4, ACPI_FACS_LENGTH);
    facs[32] = 2;
}

static void write_acpi_tables(uint8_t *blob, size_t size)
{
    write_acpi_root_pointer(blob, size);
    write_acpi_root_tables(blob, size);
    write_acpi_fadt(blob, size);
    write_acpi_dsdt(blob, size);
    write_acpi_madt(blob, size);
    write_acpi_facs(blob, size);
}

static void write_system_table(uint8_t *blob, size_t size)
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
    blob_wr64(blob, size, VIBTANIUM_EFI_SYSTEM_TABLE + 104, 3);
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

static void write_device_path(uint8_t *blob, size_t size)
{
    uint8_t *path = blob_ptr(blob, size, VIBTANIUM_EFI_DEVICE_PATH, 4);

    path[0] = 0x7f; /* End device path. */
    path[1] = 0xff; /* End entire device path. */
    path[2] = 4;
    path[3] = 0;
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

    write_device_path(blob, size);

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
                                           const VibtaniumEfiBlockDevice *boot_media)
{
    uint8_t *blob;

    if (size) {
        *size = VIBTANIUM_EFI_BLOB_SIZE;
    }

    blob = g_malloc0(VIBTANIUM_EFI_BLOB_SIZE);
    write_utf16_ascii(blob, VIBTANIUM_EFI_BLOB_SIZE,
                      VIBTANIUM_EFI_FIRMWARE_VENDOR, "Vibtanium");
    for (unsigned i = 0; i < EFI_SERVICE_DESCRIPTOR_COUNT; i++) {
        write_service_descriptor(blob, VIBTANIUM_EFI_BLOB_SIZE, i);
    }

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
    write_configuration_table(blob, VIBTANIUM_EFI_BLOB_SIZE);
    write_acpi_tables(blob, VIBTANIUM_EFI_BLOB_SIZE);
    write_sal_system_table(blob, VIBTANIUM_EFI_BLOB_SIZE);
    write_hcdp_table(blob, VIBTANIUM_EFI_BLOB_SIZE);
    write_system_table(blob, VIBTANIUM_EFI_BLOB_SIZE);

    return blob;
}

void vibtanium_efi_prepare_cpu(CPUIA64State *env,
                               const VibtaniumEfiImage *image)
{
    if (!env || !image) {
        return;
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
    env->ar[IA64_AR_BSP] = env->rse.bsp;
    env->ar[IA64_AR_BSPSTORE] = env->rse.bspstore;
    env->ar[IA64_AR_KR0] = VIBTANIUM_IO_PORT_BASE;
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
